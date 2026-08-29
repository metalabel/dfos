package cmd

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/localrelay"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/vault"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
	"github.com/spf13/cobra"
)

func newIdentityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "identity",
		Short:   "Manage DID identities",
		Aliases: []string{"id"},
		GroupID: "identity",
	}
	cmd.AddCommand(newIdentityCreateCmd())
	cmd.AddCommand(newIdentityListCmd())
	cmd.AddCommand(newIdentityShowCmd())
	cmd.AddCommand(newIdentityLogCmd())
	cmd.AddCommand(newIdentityKeysCmd())
	cmd.AddCommand(newIdentityServicesCmd())
	cmd.AddCommand(newIdentityWellKnownCmd())
	cmd.AddCommand(newIdentityUpdateCmd())
	cmd.AddCommand(newIdentityAddKeyCmd())
	cmd.AddCommand(newIdentityDevicePubkeyCmd())
	cmd.AddCommand(newIdentityBindDomainCmd())
	cmd.AddCommand(newIdentityVerifyBindingCmd())
	cmd.AddCommand(newIdentityDeleteCmd())
	cmd.AddCommand(newIdentityRestoreCmd())
	cmd.AddCommand(newIdentityPublishCmd())
	cmd.AddCommand(newIdentityFetchCmd())
	cmd.AddCommand(newIdentityRemoveCmd())
	cmd.AddCommand(newIdentityForgetCmd())
	return cmd
}

// siwdCarriageCap is the identity_chain operation limit specified by specs/SIWD.md.
const siwdCarriageCap = 100

func newIdentityCreateCmd() *cobra.Command {
	var name string
	var peerName string
	var serviceSpecs []string
	var vaultFlag string
	var noVault bool

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new identity (mint keys + sign genesis)",
		Long: "Mint a controller key and an auth key and sign a genesis operation with them. The keys are " +
			"derived from a vault — --vault, else default-vault — so the vault's recovery phrase covers " +
			"them. With no vault selected, or with --no-vault, the keys are generated standalone and exist " +
			"only in the keystore. Nothing about the vault is published: the genesis carries public keys " +
			"and nothing else.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}

			services, err := parseServiceFlags(serviceSpecs)
			if err != nil {
				return err
			}

			// check name isn't taken in config
			if _, ok := cfg.Identities[name]; ok {
				return fmt.Errorf("identity name '%s' already exists", name)
			}

			vaultName, vaultSource, err := resolveVault(vaultFlag, noVault)
			if err != nil {
				return err
			}

			lr, err := getRelay()
			if err != nil {
				return err
			}

			// Mint both keys from the vault in one reservation, so an identity's
			// controller and auth keys land on consecutive indices and a scan that
			// finds one finds the other.
			minter, err := newKeyMinter(vaultName, 2)
			if err != nil {
				return err
			}

			// controller key
			controllerKeyID := protocol.GenerateKeyID()
			controllerPriv, controllerPub, controllerIndex, err := minter.next("pending:" + controllerKeyID)
			if err != nil {
				return fmt.Errorf("mint controller key: %w", err)
			}
			controllerMK := protocol.NewMultikeyPublicKey(controllerKeyID, controllerPub)

			// auth key
			authKeyID := protocol.GenerateKeyID()
			_, authPub, authIndex, err := minter.next("pending:" + authKeyID)
			if err != nil {
				return fmt.Errorf("mint auth key: %w", err)
			}
			authMK := protocol.NewMultikeyPublicKey(authKeyID, authPub)

			// sign genesis (services omitted entirely when none given — CID-neutral)
			jwsToken, did, opCID, err := protocol.SignIdentityCreateWithServices(
				[]protocol.MultikeyPublicKey{controllerMK},
				[]protocol.MultikeyPublicKey{authMK},
				nil,
				services,
				controllerKeyID,
				controllerPriv,
			)
			if err != nil {
				return fmt.Errorf("sign genesis: %w", err)
			}

			// rename keys from pending to final
			if err := keys.RenameKey("pending:"+controllerKeyID, did+"#"+controllerKeyID); err != nil {
				return fmt.Errorf("rename controller key: %w", err)
			}
			if err := keys.RenameKey("pending:"+authKeyID, did+"#"+authKeyID); err != nil {
				return fmt.Errorf("rename auth key: %w", err)
			}

			// ingest into local relay
			results := lr.Relay.Ingest([]string{jwsToken})
			if len(results) > 0 && results[0].Status == "rejected" {
				return fmt.Errorf("local relay rejected: %s", results[0].Error)
			}

			// push to peer if specified — do this before saving config so a
			// peer rejection doesn't leave an orphaned name mapping
			var publishedTo []string
			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn != "" {
				c, _, err := getPeerClient(rn)
				if err != nil {
					return err
				}
				peerResults, err := c.SubmitOperations([]string{jwsToken})
				if err != nil {
					return fmt.Errorf("submit to peer: %w", err)
				}
				if len(peerResults) > 0 && peerResults[0].Status == "rejected" {
					return fmt.Errorf("peer rejected: %s", peerResults[0].Error)
				}
				publishedTo = append(publishedTo, rn)
			}

			// Record which derivation indices became which published keys. This is
			// LOCAL provenance only — it is what `whoami` reports and what a
			// rotation reads to stay on the seed that minted the current keys. It
			// is written after the operation succeeds, so the trail describes keys
			// that actually exist in a chain.
			if vaultName != "" {
				if err := getVaults().Record(vaultName,
					vault.MintedKey{Index: controllerIndex, DID: did, KeyID: controllerKeyID, Role: "controller", PublicKey: controllerMK.PublicKeyMultibase},
					vault.MintedKey{Index: authIndex, DID: did, KeyID: authKeyID, Role: "auth", PublicKey: authMK.PublicKeyMultibase},
				); err != nil {
					return fmt.Errorf("record vault provenance: %w", err)
				}
			}

			// Register the name in config only after all operations succeed.
			// Creating an identity does NOT select it: nothing follows "last
			// created", because a default that moves on its own is a default an
			// operator cannot reason about and two processes can race on. Say so
			// and point at the three mechanisms instead.
			cfg.Identities[name] = config.IdentityConfig{DID: did}
			if err := config.Save(cfg); err != nil {
				return err
			}

			if jsonFlag {
				out := map[string]any{
					"did":           did,
					"name":          name,
					"operationCID":  opCID,
					"controllerKey": controllerKeyID,
					"authKey":       authKeyID,
					"services":      len(services),
					"publishedTo":   publishedTo,
				}
				if vaultName != "" {
					out["vault"] = map[string]any{
						"name":            vaultName,
						"fingerprint":     minter.fingerprint,
						"controllerIndex": controllerIndex,
						"authIndex":       authIndex,
					}
				}
				outputJSON(out)
			} else {
				fmt.Printf("Identity created:\n")
				fmt.Printf("  Name:           %s\n", name)
				fmt.Printf("  DID:            %s\n", did)
				fmt.Printf("  Controller key: %s  (%s)\n", controllerKeyID, keys.Backend())
				fmt.Printf("  Auth key:       %s  (%s)\n", authKeyID, keys.Backend())
				if vaultName != "" {
					fmt.Printf("  Vault:          %s [%s] at %s and %s — via %s\n",
						vaultName, minter.fingerprint,
						vault.DerivationPath(controllerIndex), vault.DerivationPath(authIndex), vaultSource)
				}
				if len(services) > 0 {
					fmt.Printf("  Services:       %d\n", len(services))
				}
				if len(publishedTo) > 0 {
					fmt.Printf("  Published to:   %s\n", joinComma(publishedTo))
				} else {
					fmt.Printf("  Status:         local only. Use 'dfos identity publish' to push to a peer.\n")
				}
				fmt.Printf("  Sign as it:     --as %s, DFOS_AS=%s, or 'dfos config set default-identity %s'\n", name, name, name)
				if vaultName == "" {
					fmt.Fprintf(os.Stderr, "\nWarning: these keys are standalone. They exist in %s and nowhere else.\n", keys.Backend())
					fmt.Fprintf(os.Stderr, "         Lose them and control of this identity is gone for good.\n")
					fmt.Fprintf(os.Stderr, "         Mint from a vault ('dfos vault create <name>') so a written-down phrase covers the keys, and register additional keys (e.g. on another device) with 'dfos identity add-key' while you still hold a controller key, so no single key loss is fatal.\n")
				} else {
					fmt.Fprintf(os.Stderr, "\nThese keys derive from vault '%s'. Its recovery phrase is the only copy: if it is not written down, write it down now with 'dfos vault show %s --reveal-mnemonic'.\n", vaultName, vaultName)
					fmt.Fprintf(os.Stderr, "Availability is still a multi-key story: register additional keys (e.g. on another device) with 'dfos identity add-key' while you still hold a controller key.\n")
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Human-readable name for this identity (required)")
	cmd.Flags().StringVar(&peerName, "peer", "", "Push to this peer immediately")
	cmd.Flags().StringArrayVar(&serviceSpecs, "service", nil, "Discovery service entry as key=value list (repeatable), e.g. id=relay,type=DfosRelay,endpoint=https://relay.dfos.com")
	cmd.Flags().StringVar(&vaultFlag, "vault", "", "Mint the keys from this vault (default: config default-vault)")
	cmd.Flags().BoolVar(&noVault, "no-vault", false, "Generate standalone keys, from no vault")
	return cmd
}

// keyMinter is the one place a private key comes into existence. It hands out
// keys either from a vault's reserved indices or from the keystore's own
// generator, and either way the key lands in the keystore under the account the
// caller names — so nothing downstream has to know or care where it came from.
//
// Reserving all of an operation's indices up front means a vault's counter moves
// exactly once per command, and the indices an operation consumes are contiguous.
type keyMinter struct {
	vaultName   string
	fingerprint string
	derived     []vault.Derived
	used        int
}

func newKeyMinter(vaultName string, count int) (*keyMinter, error) {
	m := &keyMinter{vaultName: vaultName}
	if vaultName == "" {
		return m, nil
	}
	meta, err := getVaults().Load(vaultName)
	if err != nil {
		return nil, err
	}
	derived, err := getVaults().Mint(vaultName, count)
	if err != nil {
		return nil, err
	}
	m.fingerprint = meta.Fingerprint
	m.derived = derived
	return m, nil
}

// next produces the next key and stores it under account. The index it returns
// is meaningful only for a vault-backed minter; a standalone key has no index
// and reports 0, which callers gate on vaultName rather than on the number.
func (m *keyMinter) next(account string) (ed25519.PrivateKey, ed25519.PublicKey, uint32, error) {
	if m.vaultName == "" {
		priv, pub, err := keys.GenerateKey(account)
		return priv, pub, 0, err
	}
	if m.used >= len(m.derived) {
		return nil, nil, 0, fmt.Errorf("vault '%s' reserved %d key(s) and a %d%s was asked for", m.vaultName, len(m.derived), m.used+1, ordinalSuffix(m.used+1))
	}
	d := m.derived[m.used]
	m.used++
	pub, err := keys.PutKey(account, d.Private)
	if err != nil {
		return nil, nil, 0, err
	}
	return d.Private, pub, d.Index, nil
}

func ordinalSuffix(n int) string {
	switch {
	case n%100 >= 11 && n%100 <= 13:
		return "th"
	case n%10 == 1:
		return "st"
	case n%10 == 2:
		return "nd"
	case n%10 == 3:
		return "rd"
	default:
		return "th"
	}
}

func newIdentityUpdateCmd() *cobra.Command {
	var peerName string
	var rotateAuth bool
	var rotateController bool
	var serviceSpecs []string
	var clearServices bool
	var vaultFlag string
	var noVault bool

	cmd := &cobra.Command{
		Use:   "update [name|did]",
		Short: "Update identity (rotate keys, set discovery services)",
		Long: "Sign an identity update operation for the named identity, or — with no name — for the one the " +
			"resolution stack resolves. A typed name or DID is the subject: it outranks --as, DFOS_AS, and " +
			"default-identity, and the announce line says it came from the command line. " +
			"Use --rotate-auth or --rotate-controller to mint new keys " +
			"and rotate out the old ones. Rotation is sticky: replacements are drawn from the vault that " +
			"minted this identity's CURRENT keys, so an identity stays on one seed unless --vault says " +
			"otherwise. An identity whose keys came from no vault rotates into standalone keys. " +
			"Use --service (repeatable) to REPLACE the discovery services set, or " +
			"--clear-services to empty it. Services left unspecified are carried forward unchanged.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			settingServices := len(serviceSpecs) > 0 || clearServices
			if !rotateAuth && !rotateController && !settingServices {
				return fmt.Errorf("specify --rotate-auth, --rotate-controller, --service, and/or --clear-services")
			}
			if len(serviceSpecs) > 0 && clearServices {
				return fmt.Errorf("--service and --clear-services are mutually exclusive")
			}

			newServices, err := parseServiceFlags(serviceSpecs)
			if err != nil {
				return err
			}

			// The positional target, when typed, IS the identity — ahead of the
			// whole resolution stack. Rotating a key is irreversible for the key
			// it retires, so "which identity did that just apply to" may never be
			// answered by an ambient default the operator did not name.
			_, chain, err := requireIdentityTarget(args)
			if err != nil {
				return err
			}

			lr, err := getRelay()
			if err != nil {
				return err
			}

			kid, err := selectHeldKey(chain.DID, chain.State.ControllerKeys, "controller")
			if err != nil {
				return err
			}
			controllerPriv, err := keys.GetPrivateKey(kid)
			if err != nil {
				return fmt.Errorf("controller key not in keychain: %w", err)
			}

			// determine head CID
			lastToken := chain.Log[len(chain.Log)-1]
			h, _, err := protocol.DecodeJWSUnsafe(lastToken)
			if err != nil {
				return fmt.Errorf("decode last operation: %w", err)
			}
			previousCID := h.CID

			newAuthKeys := chain.State.AuthKeys
			newControllerKeys := chain.State.ControllerKeys
			newAssertKeys := chain.State.AssertKeys
			var rotatedKeys []string

			// An update REPLACES the full services state. Carry the current set
			// forward unless --service replaces it or --clear-services empties it.
			services := chain.State.Services
			servicesChanged := false
			if len(serviceSpecs) > 0 {
				services = newServices
				servicesChanged = true
			} else if clearServices {
				services = nil
				servicesChanged = true
			}

			// Rotation is sticky to the seed that minted the identity's current
			// keys. That is the whole of the rule: a vault is a mint-time choice,
			// and an identity that already came out of one keeps coming out of it,
			// so its recovery phrase does not silently stop covering it. Note that
			// default-vault is NOT consulted here — it would quietly move an
			// identity onto a different seed the moment someone changed a default.
			rotationVault, rotationSource, err := resolveRotationVault(chain, vaultFlag, noVault)
			if err != nil {
				return err
			}
			// A minter is a RESERVATION against a vault's derivation counter, so
			// it is constructed only when a key is actually being minted. An
			// update that rotates nothing — a services-only change — mints
			// nothing, and asking a vault to reserve zero indices is not a
			// request it can serve: the guard in vault.Mint is right, and calling
			// it unconditionally is what turned every services-only update on a
			// vault-derived identity into an error about mint counts.
			var minter *keyMinter
			var vaultFingerprint string
			if rotateAuth || rotateController {
				minter, err = newKeyMinter(rotationVault, boolCount(rotateAuth, rotateController))
				if err != nil {
					return err
				}
				vaultFingerprint = minter.fingerprint
			}
			var mintedRecords []vault.MintedKey

			if rotateAuth {
				newAuthKeyID := protocol.GenerateKeyID()
				_, newAuthPub, index, err := minter.next(chain.DID + "#" + newAuthKeyID)
				if err != nil {
					return fmt.Errorf("mint new auth key: %w", err)
				}
				newAuthMK := protocol.NewMultikeyPublicKey(newAuthKeyID, newAuthPub)
				newAuthKeys = []protocol.MultikeyPublicKey{newAuthMK}
				rotatedKeys = append(rotatedKeys, "auth:"+newAuthKeyID)
				mintedRecords = append(mintedRecords, vault.MintedKey{
					Index: index, DID: chain.DID, KeyID: newAuthKeyID, Role: "auth", PublicKey: newAuthMK.PublicKeyMultibase,
				})
			}

			if rotateController {
				newControllerKeyID := protocol.GenerateKeyID()
				_, newControllerPub, index, err := minter.next(chain.DID + "#" + newControllerKeyID)
				if err != nil {
					return fmt.Errorf("mint new controller key: %w", err)
				}
				newControllerMK := protocol.NewMultikeyPublicKey(newControllerKeyID, newControllerPub)
				newControllerKeys = []protocol.MultikeyPublicKey{newControllerMK}
				rotatedKeys = append(rotatedKeys, "controller:"+newControllerKeyID)
				mintedRecords = append(mintedRecords, vault.MintedKey{
					Index: index, DID: chain.DID, KeyID: newControllerKeyID, Role: "controller", PublicKey: newControllerMK.PublicKeyMultibase,
				})
			}

			jwsToken, opCID, err := protocol.SignIdentityUpdateWithServices(
				previousCID,
				newControllerKeys, newAuthKeys, newAssertKeys,
				services,
				kid, controllerPriv,
			)
			if err != nil {
				return fmt.Errorf("sign update: %w", err)
			}

			// ingest into local relay
			results := lr.Relay.Ingest([]string{jwsToken})
			if len(results) > 0 && results[0].Status == "rejected" {
				return fmt.Errorf("local relay rejected: %s", results[0].Error)
			}

			// push to peer if specified
			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn != "" {
				c, _, err := getPeerClient(rn)
				if err != nil {
					return err
				}
				peerResults, err := c.SubmitOperations([]string{jwsToken})
				if err != nil {
					return fmt.Errorf("submit: %w", err)
				}
				if len(peerResults) > 0 && peerResults[0].Status == "rejected" {
					return fmt.Errorf("peer rejected: %s", peerResults[0].Error)
				}
			}

			if rotationVault != "" && len(mintedRecords) > 0 {
				if err := getVaults().Record(rotationVault, mintedRecords...); err != nil {
					return fmt.Errorf("record vault provenance: %w", err)
				}
			}

			if jsonFlag {
				out := map[string]any{
					"did":          chain.DID,
					"operationCID": opCID,
					"rotatedKeys":  rotatedKeys,
				}
				if servicesChanged {
					out["services"] = len(services)
				}
				if rotationVault != "" && len(mintedRecords) > 0 {
					indices := make([]uint32, 0, len(mintedRecords))
					for _, r := range mintedRecords {
						indices = append(indices, r.Index)
					}
					out["vault"] = map[string]any{
						"name":        rotationVault,
						"fingerprint": vaultFingerprint,
						"indices":     indices,
					}
				}
				outputJSON(out)
			} else {
				fmt.Printf("Identity updated:\n")
				fmt.Printf("  DID:            %s\n", chain.DID)
				fmt.Printf("  Operation CID:  %s\n", opCID)
				fmt.Printf("  Operations:     %d\n", len(chain.Log)+1)
				for _, rk := range rotatedKeys {
					fmt.Printf("  New key:        %s\n", rk)
				}
				if rotationVault != "" && len(mintedRecords) > 0 {
					for _, r := range mintedRecords {
						fmt.Printf("  Vault:          %s [%s] at %s (%s) — via %s\n",
							rotationVault, vaultFingerprint, vault.DerivationPath(r.Index), r.Role, rotationSource)
					}
				}
				if servicesChanged {
					fmt.Printf("  Services:       %d (replaced)\n", len(services))
				}
				if len(rotatedKeys) > 0 {
					fmt.Printf("  Old keys remain in keychain for chain re-verification.\n")
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&peerName, "peer", "", "Push to this peer immediately")
	cmd.Flags().BoolVar(&rotateAuth, "rotate-auth", false, "Mint a new auth key and rotate out old one(s)")
	cmd.Flags().BoolVar(&rotateController, "rotate-controller", false, "Mint a new controller key and rotate out old one(s)")
	cmd.Flags().StringArrayVar(&serviceSpecs, "service", nil, "Discovery service entry as key=value list (repeatable); REPLACES the entire services set")
	cmd.Flags().BoolVar(&clearServices, "clear-services", false, "Empty the discovery services set")
	cmd.Flags().StringVar(&vaultFlag, "vault", "", "Mint the replacements from this vault for THIS rotation only; a later bare rotate returns to the vault behind the identity's current controller key")
	cmd.Flags().BoolVar(&noVault, "no-vault", false, "Rotate into standalone keys, from no vault")
	return cmd
}

// resolveRotationVault answers which seed a rotation's replacement keys come
// from. --vault wins, --no-vault forces standalone, and otherwise the answer is
// whichever vault minted a key this identity currently publishes.
//
// Controller keys are checked before auth keys because the controller set is the
// authority over the identity; if the two disagree (one seed's controller key,
// another's auth key), the controller's seed is the identity's home.
func resolveRotationVault(chain *relay.StoredIdentityChain, vaultFlag string, noVault bool) (name, source string, err error) {
	if noVault || vaultFlag != "" {
		return resolveVault(vaultFlag, noVault)
	}
	var keyIDs []string
	for _, k := range chain.State.ControllerKeys {
		keyIDs = append(keyIDs, k.ID)
	}
	for _, k := range chain.State.AuthKeys {
		keyIDs = append(keyIDs, k.ID)
	}
	if meta, ok := getVaults().FindMintingVault(chain.DID, keyIDs); ok {
		return meta.Name, "the vault that minted this identity's keys", nil
	}
	return "", "", nil
}

func boolCount(bs ...bool) int {
	n := 0
	for _, b := range bs {
		if b {
			n++
		}
	}
	return n
}

// roleKeyCap is the maximum number of keys a single role set may hold. The
// protocol caps each role (auth/assert/controller) at 16 items (PROTOCOL.md
// "Identity Operation Field Limits"). The Go verifier does not currently
// enforce this — the TS Zod schemas do — so the CLI guards against producing
// an operation a conformant relay would reject.
const roleKeyCap = 16

// appendKeyGuarded returns a copy of set with newKey appended, after enforcing
// the per-role cap and rejecting a duplicate key id. It copies the input slice
// rather than appending in place so the caller never mutates the chain-state
// slice's backing array. Pure (no I/O) so it is unit-testable without a relay.
func appendKeyGuarded(set []protocol.MultikeyPublicKey, newKey protocol.MultikeyPublicKey) ([]protocol.MultikeyPublicKey, error) {
	for _, k := range set {
		if k.ID == newKey.ID {
			return nil, fmt.Errorf("key id %q is already present in this role set", newKey.ID)
		}
	}
	if len(set)+1 > roleKeyCap {
		return nil, fmt.Errorf("role set already holds %d keys (max %d per role)", len(set), roleKeyCap)
	}
	out := append([]protocol.MultikeyPublicKey{}, set...)
	out = append(out, newKey)
	return out, nil
}

// newIdentityDevicePubkeyCmd is the B-side of the multi-device handoff. It
// generates a fresh keypair on THIS device, stores the private seed locally
// under did#keyID, and prints ONLY the public Multikey for transport to a
// device holding a controller key. No secret material ever leaves this device:
// the public key is added to the chain by `dfos identity add-key` run on the
// controller-holding device. This is 1-of-N availability, not key recovery.
func newIdentityDevicePubkeyCmd() *cobra.Command {
	var controller bool

	cmd := &cobra.Command{
		Use:     "device-pubkey",
		Aliases: []string{"device-key"},
		Short:   "Generate a device keypair and print its public key for add-key on another device",
		Long: "Generate a fresh keypair on this device for multi-device 1-of-N availability. " +
			"The private seed stays here; the printed public Multikey is handed to a device holding a " +
			"controller key, which adds it to the chain with 'dfos identity add-key'. No secret material leaves this device.",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, chain, err := requireIdentity()
			if err != nil {
				return err
			}

			// The DID already exists locally (this device fetched the chain),
			// so store directly under did#keyID — no pending-then-rename dance.
			keyID := protocol.GenerateKeyID()
			_, pub, err := keys.GenerateKey(chain.DID + "#" + keyID)
			if err != nil {
				return fmt.Errorf("generate device key: %w", err)
			}
			mk := protocol.NewMultikeyPublicKey(keyID, pub)

			role := "auth"
			if controller {
				role = "controller"
			}

			if jsonFlag {
				outputJSON(map[string]any{
					"id":                 mk.ID,
					"type":               mk.Type,
					"publicKeyMultibase": mk.PublicKeyMultibase,
					"role":               role,
					"did":                chain.DID,
				})
			} else {
				fmt.Printf("Device key generated (private seed stored on this device only):\n")
				fmt.Printf("  ID:                 %s\n", mk.ID)
				fmt.Printf("  Public key:         %s\n", mk.PublicKeyMultibase)
				fmt.Printf("  Suggested role:     %s\n", role)
				fmt.Printf("\nGive the public key to a device holding a controller key and run there:\n")
				fmt.Printf("  dfos identity add-key --%s-key --id %s --pubkey %s\n", role, mk.ID, mk.PublicKeyMultibase)
				fmt.Printf("\nAfter that update propagates, re-run 'dfos identity fetch' here so this\n")
				fmt.Printf("device sees the in-chain key and can sign independently.\n")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&controller, "controller", false, "Suggest a controller role in the printed add-key hint (auth is the default)")
	return cmd
}

// newIdentityBindDomainCmd writes the chain's half of an origin binding: a
// DfosOrigin services entry naming the domain, signed by a controller key. The
// domain's half is served by the operator, so the command's real output is the
// instruction block telling them exactly what to publish. See
// specs/ORIGIN-BINDING.md (https://protocol.dfos.com/origin-binding).
func newIdentityBindDomainCmd() *cobra.Command {
	var peerName string
	var serviceID string

	cmd := &cobra.Command{
		Use:   "bind-domain <domain>",
		Short: "Claim a domain in the identity chain and print what the domain must serve",
		Long: "Append (or replace) this identity's DfosOrigin services entry so its chain claims <domain>, " +
			"then print the attestation the domain must serve back — a /.well-known/dfos-did document or a " +
			"_dfos TXT record, either one sufficient. The claim is an ordinary services full-state replacement " +
			"signed by a controller key: every other service entry is carried forward unchanged, and an " +
			"identity claims at most one domain. A binding proves control of the domain at verification time — " +
			"never personhood, endorsement, or trustworthiness. Normative spec: https://protocol.dfos.com/origin-binding",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, err := validateDomain(args[0])
			if err != nil {
				return err
			}

			_, chain, err := requireIdentity()
			if err != nil {
				return err
			}

			plan, err := planOriginBinding(chain.State.Services, domain, serviceID)
			if err != nil {
				return err
			}

			// Already claiming exactly this — signing an identical services set
			// would burn a chain operation to say nothing.
			if plan.Action == bindActionUnchanged {
				if jsonFlag {
					outputJSON(map[string]any{
						"did":       chain.DID,
						"domain":    domain,
						"unchanged": true,
						"wellKnown": map[string]string{"path": wellKnownDIDPath, "content": chain.DID},
						"dnsRecord": map[string]string{"name": originTXTName(domain) + ".", "type": "TXT", "value": dnsAttestationTag + chain.DID},
					})
					return nil
				}
				fmt.Printf("Already bound:\n")
				fmt.Printf("  DID:            %s\n", chain.DID)
				fmt.Printf("  Domain:         %s\n", domain)
				fmt.Printf("  Chain unchanged (no operation signed).\n")
				printBindInstructions(chain.DID, domain)
				return nil
			}

			lr, err := getRelay()
			if err != nil {
				return err
			}

			kid, err := selectHeldKey(chain.DID, chain.State.ControllerKeys, "controller")
			if err != nil {
				return err
			}
			controllerPriv, err := keys.GetPrivateKey(kid)
			if err != nil {
				return fmt.Errorf("controller key not in keychain: %w", err)
			}

			lastToken := chain.Log[len(chain.Log)-1]
			h, _, err := protocol.DecodeJWSUnsafe(lastToken)
			if err != nil {
				return fmt.Errorf("decode last operation: %w", err)
			}

			// Key sets carried forward untouched: this operation only moves the
			// services set.
			jwsToken, opCID, err := protocol.SignIdentityUpdateWithServices(
				h.CID,
				chain.State.ControllerKeys, chain.State.AuthKeys, chain.State.AssertKeys,
				plan.Services,
				kid, controllerPriv,
			)
			if err != nil {
				return fmt.Errorf("sign update: %w", err)
			}

			results := lr.Relay.Ingest([]string{jwsToken})
			if len(results) > 0 && results[0].Status == "rejected" {
				return fmt.Errorf("local relay rejected: %s", results[0].Error)
			}

			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn != "" {
				c, _, err := getPeerClient(rn)
				if err != nil {
					return err
				}
				peerResults, err := c.SubmitOperations([]string{jwsToken})
				if err != nil {
					return fmt.Errorf("submit: %w", err)
				}
				if len(peerResults) > 0 && peerResults[0].Status == "rejected" {
					return fmt.Errorf("peer rejected: %s", peerResults[0].Error)
				}
			}

			if jsonFlag {
				out := map[string]any{
					"did":          chain.DID,
					"domain":       domain,
					"serviceID":    plan.ID,
					"operationCID": opCID,
					"wellKnown":    map[string]string{"path": wellKnownDIDPath, "content": chain.DID},
					"dnsRecord":    map[string]string{"name": originTXTName(domain) + ".", "type": "TXT", "value": dnsAttestationTag + chain.DID},
				}
				if plan.Action == bindActionRebind && plan.Previous != "" {
					out["previousDomain"] = plan.Previous
				}
				if plan.Collapsed > 0 {
					out["collapsedEntries"] = plan.Collapsed
				}
				outputJSON(out)
				return nil
			}

			fmt.Printf("Domain claimed in chain:\n")
			fmt.Printf("  DID:            %s\n", chain.DID)
			fmt.Printf("  Domain:         %s\n", domain)
			fmt.Printf("  Service entry:  %s  [%s]\n", plan.ID, originServiceType)
			fmt.Printf("  Operation CID:  %s\n", opCID)
			if plan.Action == bindActionRebind && plan.Previous != domain {
				fmt.Printf("  Re-binding:     %s → %s\n", plan.Previous, domain)
			}
			if plan.Collapsed > 0 {
				fmt.Printf("  Collapsed:      %d extra %s entr(y|ies) removed — a set with more than one claims nothing\n", plan.Collapsed, originServiceType)
			}
			printBindInstructions(chain.DID, domain)
			return nil
		},
	}
	cmd.Flags().StringVar(&peerName, "peer", "", "Push to this peer immediately")
	cmd.Flags().StringVar(&serviceID, "id", "", "Service entry id to use (default: the existing entry's id, else \"origin\")")
	return cmd
}

// newIdentityVerifyBindingCmd runs both halves of the bidirectional check
// locally — chain claim plus the domain's HTTPS and DNS attestations — and
// folds them into the spec's three verdicts. No DFOS server is in the loop.
func newIdentityVerifyBindingCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify-binding [name|did|domain]",
		Short: "Verify an identity's origin binding (chain claim vs the domain's attestation)",
		Long: "Verify a DfosOrigin binding end to end. With no argument, or an identity name or DID, the walk " +
			"starts from the chain: read the claimed domain, then query the domain. With a bare hostname the walk " +
			"starts from the domain: read its attestation, resolve that DID's chain, and require the chain to claim " +
			"this exact domain. Both attestation methods are checked — https://<domain>/.well-known/dfos-did (falling " +
			"back to /.well-known/dfos-app.json only when the well-known document is ABSENT) and a did= TXT record at " +
			"_dfos.<domain>.\n\n" +
			"Verdicts and exit codes:\n" +
			"  bound     0   at least one method attests this DID and no method answers anything else\n" +
			"  broken    1   a method answers a different DID, the methods disagree, or DNS carries several did= records\n" +
			"  stale     2   a claim exists and every method is silent (silence is not contradiction — staleness is legal)\n" +
			"  no-claim  0   the chain claims no domain, so there is nothing to verify\n\n" +
			"Exit 1 is also the CLI's generic error status (unresolvable target, chain not held locally, malformed input); " +
			"those print an error on stderr instead of a verdict.\n\n" +
			"Normative spec: https://protocol.dfos.com/origin-binding",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lr, err := getRelay()
			if err != nil {
				return err
			}

			// No argument: the active identity, chain-first.
			if len(args) == 0 {
				_, chain, err := requireIdentity()
				if err != nil {
					return err
				}
				return verifyBindingFromChain(chain)
			}

			// An identity name, a DID, or a bare 31-char id resolves chain-first;
			// anything else must be a hostname. The two forms are structurally
			// disjoint (a DID id carries no dots, a hostname must), so this
			// dispatch never guesses.
			arg := args[0]
			_, named := cfg.Identities[arg]
			if named || strings.HasPrefix(arg, "did:") || protocol.IsValidDID("did:dfos:"+arg) {
				did, err := resolveIdentityDID(arg)
				if err != nil {
					return err
				}
				fetchIdentityFromPeerIfRequested(did)
				chain, _ := lr.Relay.GetIdentity(did)
				if chain == nil {
					return fmt.Errorf("identity '%s' not found in local relay (fetch it with 'dfos identity fetch %s --peer <peer>')", arg, did)
				}
				return verifyBindingFromChain(chain)
			}

			domain, err := validateDomain(arg)
			if err != nil {
				return fmt.Errorf("%q is not a known identity name, a did:dfos identifier, or a bare hostname: %w", arg, err)
			}
			return verifyBindingFromDomain(lr, domain)
		},
	}
}

// verifyBindingFromChain is the chain-first walk: the identity names a domain,
// the domain answers (or does not).
func verifyBindingFromChain(chain *relay.StoredIdentityChain) error {
	claim := readOriginClaim(chain.State.Services)
	if claim.Domain == "" {
		return bindingReport{DID: chain.DID, Verdict: verdictNoClaim, Reason: claim.Reason}.emit()
	}
	results := probeBinding(claim.Domain)
	return bindingReport{
		DID:     chain.DID,
		Domain:  claim.Domain,
		Claim:   claim.Domain,
		Verdict: foldVerdict(chain.DID, results),
		Results: results,
	}.emit()
}

// verifyBindingFromDomain is the domain-first walk: the domain names a DID, that
// DID's chain must name this exact domain back. Half a binding is no binding.
func verifyBindingFromDomain(lr *localrelay.LocalRelay, domain string) error {
	results := probeBinding(domain)

	// A domain that contradicts itself is broken before any chain is resolved.
	if foldVerdict("", results) == verdictBroken {
		return bindingReport{Domain: domain, Verdict: verdictBroken, Results: results}.emit()
	}

	candidate := ""
	for _, r := range results {
		if r.answered() {
			candidate = r.DID
			break
		}
	}
	if candidate == "" {
		// Nothing published at all: unverifiable, not contradicted.
		return bindingReport{
			Domain:  domain,
			Verdict: verdictStale,
			Results: results,
			Reason:  "the domain publishes no attestation, so no binding could be checked",
		}.emit()
	}

	fetchIdentityFromPeerIfRequested(candidate)
	chain, _ := lr.Relay.GetIdentity(candidate)
	if chain == nil {
		return fmt.Errorf(
			"%s attests %s, but that identity is not in the local relay (fetch it with 'dfos identity fetch %s --peer <peer>')",
			domain, candidate, candidate,
		)
	}

	claim := readOriginClaim(chain.State.Services)
	if claim.Domain == "" {
		return bindingReport{
			DID:     chain.DID,
			Domain:  domain,
			Verdict: verdictNoClaim,
			Reason:  claim.Reason + " — an attestation without a chain claim is not a binding",
			Results: results,
		}.emit()
	}
	if claim.Domain != domain {
		return bindingReport{
			DID:     chain.DID,
			Domain:  domain,
			Claim:   claim.Domain,
			Verdict: verdictBroken,
			Results: results,
			Reason:  fmt.Sprintf("%s attests this identity, but the chain claims %s — the two halves name different domains", domain, claim.Domain),
		}.emit()
	}

	return bindingReport{
		DID:     chain.DID,
		Domain:  domain,
		Claim:   claim.Domain,
		Verdict: foldVerdict(chain.DID, results),
		Results: results,
	}.emit()
}

// newIdentityAddKeyCmd is the A-side of the multi-device handoff. It appends an
// externally-supplied PUBLIC key (generated on another device via
// `dfos identity device-pubkey`) to a role set and signs the identity update
// with a controller key THIS device holds. It generates and stores no private
// key — the structural difference from `update`, which rotates by generating
// fresh local keys. The protocol layer is unchanged: SignIdentityUpdate already
// accepts N-key role slices, so "append" is expressed here by passing
// currentSet + newKey.
func newIdentityAddKeyCmd() *cobra.Command {
	var peerName string
	var authKey bool
	var controllerKey bool
	var idFlag string
	var pubkeyFlag string

	cmd := &cobra.Command{
		Use:   "add-key",
		Short: "Add a device's public key to a role set (multi-device 1-of-N availability)",
		Long: "Append a public key generated on another device (via 'dfos identity device-pubkey') to this " +
			"identity's auth or controller key set, signed with a controller key this device holds. The added " +
			"device can then publish independently once it fetches the update. This grants availability (any one " +
			"held key can act), not recovery.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !authKey && !controllerKey {
				return fmt.Errorf("specify --auth-key and/or --controller-key")
			}
			if idFlag == "" {
				return fmt.Errorf("--id is required (the key id printed by 'dfos identity device-pubkey')")
			}
			if pubkeyFlag == "" {
				return fmt.Errorf("--pubkey is required (the public Multikey printed by 'dfos identity device-pubkey')")
			}

			_, chain, err := requireIdentity()
			if err != nil {
				return err
			}

			lr, err := getRelay()
			if err != nil {
				return err
			}

			// sign with whatever controller key this device actually holds
			kid, err := selectHeldKey(chain.DID, chain.State.ControllerKeys, "controller")
			if err != nil {
				return err
			}
			controllerPriv, err := keys.GetPrivateKey(kid)
			if err != nil {
				return fmt.Errorf("controller key not in keychain: %w", err)
			}

			// validate the supplied public key and normalize its encoding.
			// DecodeMultikey only checks the multicodec prefix, not the key
			// length — guard it here since --pubkey is human-supplied (copy/
			// paste/QR) and a malformed key would otherwise be appended to the
			// published set and silently fail every future signature check.
			rawPub, err := protocol.DecodeMultikey(pubkeyFlag)
			if err != nil {
				return fmt.Errorf("invalid --pubkey: %w", err)
			}
			if len(rawPub) != ed25519.PublicKeySize {
				return fmt.Errorf("invalid --pubkey: expected a %d-byte ed25519 key, got %d bytes", ed25519.PublicKeySize, len(rawPub))
			}
			newKey := protocol.NewMultikeyPublicKey(idFlag, ed25519.PublicKey(rawPub))

			// determine head CID
			lastToken := chain.Log[len(chain.Log)-1]
			h, _, err := protocol.DecodeJWSUnsafe(lastToken)
			if err != nil {
				return fmt.Errorf("decode last operation: %w", err)
			}
			previousCID := h.CID

			// seed all three sets from current state, then append into targets
			newAuthKeys := chain.State.AuthKeys
			newControllerKeys := chain.State.ControllerKeys
			newAssertKeys := chain.State.AssertKeys
			var addedKeys []string

			if authKey {
				newAuthKeys, err = appendKeyGuarded(chain.State.AuthKeys, newKey)
				if err != nil {
					return fmt.Errorf("auth key set: %w", err)
				}
				addedKeys = append(addedKeys, "auth:"+newKey.ID)
			}
			if controllerKey {
				newControllerKeys, err = appendKeyGuarded(chain.State.ControllerKeys, newKey)
				if err != nil {
					return fmt.Errorf("controller key set: %w", err)
				}
				addedKeys = append(addedKeys, "controller:"+newKey.ID)
			}

			jwsToken, opCID, err := protocol.SignIdentityUpdate(
				previousCID,
				newControllerKeys, newAuthKeys, newAssertKeys,
				kid, controllerPriv,
			)
			if err != nil {
				return fmt.Errorf("sign update: %w", err)
			}

			// ingest into local relay
			results := lr.Relay.Ingest([]string{jwsToken})
			if len(results) > 0 && results[0].Status == "rejected" {
				return fmt.Errorf("local relay rejected: %s", results[0].Error)
			}

			// push to peer if specified
			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn != "" {
				c, _, err := getPeerClient(rn)
				if err != nil {
					return err
				}
				peerResults, err := c.SubmitOperations([]string{jwsToken})
				if err != nil {
					return fmt.Errorf("submit: %w", err)
				}
				if len(peerResults) > 0 && peerResults[0].Status == "rejected" {
					return fmt.Errorf("peer rejected: %s", peerResults[0].Error)
				}
			}

			if jsonFlag {
				outputJSON(map[string]any{
					"did":          chain.DID,
					"operationCID": opCID,
					"addedKeys":    addedKeys,
				})
			} else {
				fmt.Printf("Identity updated:\n")
				fmt.Printf("  DID:            %s\n", chain.DID)
				fmt.Printf("  Operation CID:  %s\n", opCID)
				fmt.Printf("  Operations:     %d\n", len(chain.Log)+1)
				for _, ak := range addedKeys {
					fmt.Printf("  Added key:      %s\n", ak)
				}
				fmt.Printf("  The device holding the private key for %s can sign once it fetches this update.\n", newKey.ID)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&peerName, "peer", "", "Push to this peer immediately")
	cmd.Flags().BoolVar(&authKey, "auth-key", false, "Add the key to the auth set (content/credential publishing)")
	cmd.Flags().BoolVar(&controllerKey, "controller-key", false, "Add the key to the controller set (higher trust: rotate/delete/add)")
	cmd.Flags().StringVar(&idFlag, "id", "", "Key id from 'dfos identity device-pubkey' (required)")
	cmd.Flags().StringVar(&pubkeyFlag, "pubkey", "", "Public Multikey from 'dfos identity device-pubkey' (required)")
	return cmd
}

func newIdentityDeleteCmd() *cobra.Command {
	var peerName string

	cmd := &cobra.Command{
		Use:   "delete [name|did]",
		Short: "Delete an identity (sign delete operation)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lr, err := getRelay()
			if err != nil {
				return err
			}

			var chain *relay.StoredIdentityChain
			if len(args) > 0 {
				did, err := resolveIdentityDID(args[0])
				if err != nil {
					return err
				}
				chain, _ = lr.Relay.GetIdentity(did)
				if chain == nil {
					return fmt.Errorf("identity '%s' not found", args[0])
				}
			} else {
				_, chain2, err := requireIdentity()
				if err != nil {
					return err
				}
				chain = chain2
			}

			kid, err := selectHeldKey(chain.DID, chain.State.ControllerKeys, "controller")
			if err != nil {
				return err
			}
			controllerPriv, err := keys.GetPrivateKey(kid)
			if err != nil {
				return fmt.Errorf("controller key not in keychain: %w", err)
			}

			lastToken := chain.Log[len(chain.Log)-1]
			h, _, err := protocol.DecodeJWSUnsafe(lastToken)
			if err != nil {
				return fmt.Errorf("decode last operation: %w", err)
			}

			jwsToken, opCID, err := protocol.SignIdentityDelete(h.CID, kid, controllerPriv)
			if err != nil {
				return fmt.Errorf("sign delete: %w", err)
			}

			results := lr.Relay.Ingest([]string{jwsToken})
			if len(results) > 0 && results[0].Status == "rejected" {
				return fmt.Errorf("local relay rejected: %s", results[0].Error)
			}

			// push to peer
			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn != "" {
				c, _, err := getPeerClient(rn)
				if err != nil {
					return err
				}
				peerResults, err := c.SubmitOperations([]string{jwsToken})
				if err != nil {
					return fmt.Errorf("submit: %w", err)
				}
				if len(peerResults) > 0 && peerResults[0].Status == "rejected" {
					return fmt.Errorf("peer rejected: %s", peerResults[0].Error)
				}
			}

			if jsonFlag {
				outputJSON(map[string]any{"did": chain.DID, "operationCID": opCID, "deleted": true})
			} else {
				fmt.Printf("Identity deleted:\n")
				fmt.Printf("  DID:            %s\n", chain.DID)
				fmt.Printf("  Operation CID:  %s\n", opCID)
				fmt.Printf("  This identity can no longer sign operations. 'dfos identity restore' undoes this.\n")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&peerName, "peer", "", "Push to this peer immediately")
	return cmd
}

func newIdentityRestoreCmd() *cobra.Command {
	var peerName string

	cmd := &cobra.Command{
		Use:   "restore [name|did]",
		Short: "Restore a deleted identity (sign restore operation)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lr, err := getRelay()
			if err != nil {
				return err
			}

			var chain *relay.StoredIdentityChain
			var identityArg string
			if len(args) > 0 {
				identityArg = args[0]
				did, err := resolveIdentityDID(identityArg)
				if err != nil {
					return err
				}
				chain, _ = lr.Relay.GetIdentity(did)
				if chain == nil {
					return fmt.Errorf("identity '%s' not found", identityArg)
				}
			} else {
				// requireIdentity() rejects deleted identities — correct for every
				// other signing command, but restore is the ONE operation whose
				// subject is necessarily deleted. Same resolution, minus that gate.
				ctx, err := resolveCtx()
				if err != nil {
					return err
				}
				if !ctx.HasIdentity() {
					return errNoIdentity()
				}
				identityArg = ctx.Principal()
				if ctx.IdentityDID == "" {
					return fmt.Errorf("identity '%s' not found in config (from %s)", ctx.IdentityName, ctx.IdentitySource)
				}
				announceSigner(ctx)
				chain, err = lr.Relay.GetIdentity(ctx.IdentityDID)
				if err != nil {
					return err
				}
				if chain == nil {
					return fmt.Errorf("identity '%s' (%s) not found in local relay", ctx.IdentityName, ctx.IdentityDID)
				}
			}

			if !chain.State.IsDeleted {
				return fmt.Errorf("identity '%s' is not deleted", identityArg)
			}

			kid, err := selectHeldKey(chain.DID, chain.State.ControllerKeys, "controller")
			if err != nil {
				return err
			}
			controllerPriv, err := keys.GetPrivateKey(kid)
			if err != nil {
				return fmt.Errorf("controller key not in keychain: %w", err)
			}

			lastToken := chain.Log[len(chain.Log)-1]
			h, _, err := protocol.DecodeJWSUnsafe(lastToken)
			if err != nil {
				return fmt.Errorf("decode last operation: %w", err)
			}

			jwsToken, opCID, err := protocol.SignIdentityRestore(h.CID, kid, controllerPriv)
			if err != nil {
				return fmt.Errorf("sign restore: %w", err)
			}

			results := lr.Relay.Ingest([]string{jwsToken})
			if len(results) > 0 && results[0].Status == "rejected" {
				return fmt.Errorf("local relay rejected: %s", results[0].Error)
			}

			// push to peer
			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn != "" {
				c, _, err := getPeerClient(rn)
				if err != nil {
					return err
				}
				peerResults, err := c.SubmitOperations([]string{jwsToken})
				if err != nil {
					return fmt.Errorf("submit: %w", err)
				}
				if len(peerResults) > 0 && peerResults[0].Status == "rejected" {
					return fmt.Errorf("peer rejected: %s", peerResults[0].Error)
				}
			}

			if jsonFlag {
				outputJSON(map[string]any{"did": chain.DID, "operationCID": opCID, "restored": true})
			} else {
				fmt.Printf("Identity restored:\n")
				fmt.Printf("  DID:            %s\n", chain.DID)
				fmt.Printf("  Operation CID:  %s\n", opCID)
				fmt.Printf("  Keys and services are restored to their state as of the delete.\n")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&peerName, "peer", "", "Push to this peer immediately")
	return cmd
}

// identityListEntry is one row of `identity list --json`. The operation log is
// deliberately absent: a roster that inlines every base64 operation of every
// chain is mostly bytes nobody asked for, and on a relay that has synced the
// network it is the whole corpus rendered to answer "which identities are
// here". The operation COUNT is the part a roster needs; the log itself is one
// 'dfos identity log <did>' away, and --include-log emits the full stored shape
// for a caller that wants everything in one document.
type identityListEntry struct {
	DID           string                 `json:"did"`
	Name          string                 `json:"name,omitempty"`
	HeadCID       string                 `json:"headCID"`
	LastCreatedAt string                 `json:"lastCreatedAt"`
	Operations    int                    `json:"operations"`
	State         protocol.IdentityState `json:"state"`
}

func newIdentityListCmd() *cobra.Command {
	var includeLog bool

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List all known identities",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			lr, err := getRelay()
			if err != nil {
				return err
			}

			allChains, err := lr.Store.ListIdentityChains()
			if err != nil {
				return err
			}
			// filter out the invisible relay identity
			var chains []relay.StoredIdentityChain
			for _, c := range allChains {
				if c.DID != lr.RelayDID {
					chains = append(chains, c)
				}
			}
			if len(chains) == 0 {
				if jsonFlag {
					fmt.Println("[]")
				} else {
					fmt.Println("No identities. Use 'dfos identity create --name <name>'")
				}
				return nil
			}

			if jsonFlag {
				if includeLog {
					outputJSON(chains)
					return nil
				}
				entries := make([]identityListEntry, 0, len(chains))
				for i := range chains {
					c := &chains[i]
					entries = append(entries, identityListEntry{
						DID:           c.DID,
						Name:          config.FindIdentityName(cfg, c.DID),
						HeadCID:       c.HeadCID,
						LastCreatedAt: c.LastCreatedAt,
						Operations:    len(c.Log),
						State:         c.State,
					})
				}
				outputJSON(entries)
				return nil
			}

			fmt.Printf("%-10s %-36s %-6s %s\n", "NAME", "DID", "KEYS", "OPS")
			unprobed := false
			for _, chain := range chains {
				name := config.FindIdentityName(cfg, chain.DID)
				// countKeysInChain probes the OS keychain once per key, which
				// is O(keys) slow — a list of many gossiped-in identities would
				// hang. Only probe identities we track by name (ours); for the
				// rest the count is not computed at all.
				//
				// That absence is marked "?", never "-": "-" reads as "holds no
				// keys", and this machine may well hold keys this chain
				// declares. The one fact established here is that no local name
				// points at the identity, so no probe was run.
				keysCol := "?"
				if name != "" {
					keysCol = fmt.Sprintf("%d/%d", countKeysInChain(&chain), len(distinctKeyIDs(&chain)))
				} else {
					name = "-"
					unprobed = true
				}
				// Deletion is one fact and it reads the same everywhere: `keys
				// list` marks a deleted identity's keys "(deleted)" and `whoami`
				// reports "State: deleted", so the roster says it too rather
				// than listing a deleted identity as if it were live.
				state := ""
				if chain.State.IsDeleted {
					state = "  (deleted)"
				}
				fmt.Printf("%-10s %-36s %-6s %d%s\n",
					name, chain.DID, keysCol, len(chain.Log), state)
			}
			if unprobed {
				fmt.Printf("\n  ?  no local name registers this identity, so its keys were not probed — 'dfos identity fetch <did> --name <name>' registers one.\n")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&includeLog, "include-log", false, "With --json, include each identity's full operation log (omitted by default; 'dfos identity log <did>' shows one)")
	return cmd
}

func newIdentityShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show [name|did]",
		Short: "Show identity state",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lr, err := getRelay()
			if err != nil {
				return err
			}

			var chain *relay.StoredIdentityChain

			if len(args) > 0 {
				did, err := resolveIdentityDID(args[0])
				if err != nil {
					return err
				}
				fetchIdentityFromPeerIfRequested(did)
				chain, _ = lr.Relay.GetIdentity(did)
			} else {
				_, chain2, err := requireIdentity()
				if err != nil {
					return err
				}
				chain = chain2
			}

			if chain == nil {
				return fmt.Errorf("identity not found")
			}

			if jsonFlag {
				outputJSON(chain)
				return nil
			}

			name := config.FindIdentityName(cfg, chain.DID)
			fmt.Printf("DID:         %s\n", chain.DID)
			if name != "" {
				fmt.Printf("Name:        %s\n", name)
			}
			totalKeys := len(distinctKeyIDs(chain))
			haveKeys := countKeysInChain(chain)
			fmt.Printf("Keys:        %d/%d (%s)\n", haveKeys, totalKeys, keys.Backend())
			fmt.Printf("Services:    %d\n", len(chain.State.Services))
			fmt.Printf("Operations:  %d\n", len(chain.Log))
			if chain.LastCreatedAt != "" {
				fmt.Printf("Updated:     %s\n", chain.LastCreatedAt)
			}
			fmt.Printf("Deleted:     %v\n", chain.State.IsDeleted)
			return nil
		},
	}
}

func newIdentityLogCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "log <name|did>",
		Short: "Show operation history",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			did, err := resolveIdentityDID(args[0])
			if err != nil {
				return err
			}
			lr, err := getRelay()
			if err != nil {
				return err
			}
			chain, err := lr.Relay.GetIdentity(did)
			if err != nil || chain == nil {
				return fmt.Errorf("identity '%s' not found", args[0])
			}

			if jsonFlag {
				type opInfo struct {
					Index  int    `json:"index"`
					CID    string `json:"cid,omitempty"`
					Type   string `json:"type,omitempty"`
					Signer string `json:"signer,omitempty"`
				}
				var ops []opInfo
				for i, token := range chain.Log {
					h, p, _ := protocol.DecodeJWSUnsafe(token)
					op := opInfo{Index: i}
					if h != nil {
						op.CID = h.CID
						op.Signer = didFromKid(h.Kid)
					}
					if p != nil {
						if t, ok := p["type"].(string); ok {
							op.Type = t
						}
					}
					ops = append(ops, op)
				}
				outputJSON(ops)
				return nil
			}

			fmt.Printf("Identity: %s (%d operations)\n\n", did, len(chain.Log))
			for i, token := range chain.Log {
				h, p, _ := protocol.DecodeJWSUnsafe(token)
				opType := "?"
				if p != nil {
					if t, ok := p["type"].(string); ok {
						opType = t
					}
				}
				cid := ""
				signer := ""
				if h != nil {
					cid = h.CID
					signer = didFromKid(h.Kid)
				}
				if signer != "" {
					fmt.Printf("  [%d] %-8s %s  (%s)\n", i, opType, cid, signer)
				} else {
					fmt.Printf("  [%d] %-8s %s\n", i, opType, cid)
				}
			}
			return nil
		},
	}
}

func newIdentityKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keys [name|did]",
		Short: "Show key state and keychain availability",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lr, err := getRelay()
			if err != nil {
				return err
			}

			var chain *relay.StoredIdentityChain
			if len(args) > 0 {
				did, err := resolveIdentityDID(args[0])
				if err != nil {
					return err
				}
				fetchIdentityFromPeerIfRequested(did)
				chain, _ = lr.Relay.GetIdentity(did)
			} else {
				_, chain2, err := requireIdentity()
				if err != nil {
					return err
				}
				chain = chain2
			}
			if chain == nil {
				return fmt.Errorf("identity not found")
			}

			if jsonFlag {
				type keyInfo struct {
					ID       string `json:"id"`
					Role     string `json:"role"`
					Keychain bool   `json:"keychain"`
				}
				var items []keyInfo
				for _, k := range chain.State.ControllerKeys {
					items = append(items, keyInfo{k.ID, "controller", keys.HasKey(chain.DID + "#" + k.ID)})
				}
				for _, k := range chain.State.AuthKeys {
					items = append(items, keyInfo{k.ID, "auth", keys.HasKey(chain.DID + "#" + k.ID)})
				}
				for _, k := range chain.State.AssertKeys {
					items = append(items, keyInfo{k.ID, "assert", keys.HasKey(chain.DID + "#" + k.ID)})
				}
				outputJSON(items)
				return nil
			}

			name := config.FindIdentityName(cfg, chain.DID)
			label := chain.DID
			if name != "" {
				label = chain.DID + " (" + name + ")"
			}
			fmt.Printf("Identity: %s\n\n", label)
			fmt.Printf("%-30s %-12s %s\n", "KEY ID", "ROLE", "HELD")
			printKeys := func(mkKeys []protocol.MultikeyPublicKey, role string) {
				for _, k := range mkKeys {
					has := "-"
					if keys.HasKey(chain.DID + "#" + k.ID) {
						has = "present"
					}
					fmt.Printf("%-30s %-12s %s\n", k.ID, role, has)
				}
			}
			printKeys(chain.State.ControllerKeys, "controller")
			printKeys(chain.State.AuthKeys, "auth")
			printKeys(chain.State.AssertKeys, "assert")
			return nil
		},
	}
}

// newIdentityServicesCmd prints the resolved discovery services for an identity.
// Services are full-state on each create/update op and projected into verified
// chain state; this just renders that state. The namespace is open, so unknown
// types are shown verbatim alongside the recognized DfosRelay/ContentAnchor ones.
func newIdentityServicesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "services [name|did]",
		Short: "Show resolved discovery services for an identity",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lr, err := getRelay()
			if err != nil {
				return err
			}

			var chain *relay.StoredIdentityChain
			if len(args) > 0 {
				did, err := resolveIdentityDID(args[0])
				if err != nil {
					return err
				}
				fetchIdentityFromPeerIfRequested(did)
				chain, _ = lr.Relay.GetIdentity(did)
			} else {
				_, chain2, err := requireIdentity()
				if err != nil {
					return err
				}
				chain = chain2
			}
			if chain == nil {
				return fmt.Errorf("identity not found")
			}

			services := chain.State.Services
			if jsonFlag {
				if services == nil {
					services = []protocol.ServiceEntry{}
				}
				outputJSON(services)
				return nil
			}

			name := config.FindIdentityName(cfg, chain.DID)
			label := chain.DID
			if name != "" {
				label = chain.DID + " (" + name + ")"
			}
			fmt.Printf("Identity: %s\n\n", label)
			if len(services) == 0 {
				fmt.Println("No services.")
				return nil
			}
			for _, e := range services {
				id, _ := e["id"].(string)
				typ, _ := e["type"].(string)
				recognized := ""
				if !protocol.IsRecognizedServiceType(typ) {
					recognized = "  (open)"
				}
				fmt.Printf("- %s  [%s]%s\n", id, typ, recognized)
				switch typ {
				case "DfosRelay":
					if ep, ok := e["endpoint"].(string); ok {
						fmt.Printf("    endpoint: %s\n", ep)
					}
				case "ContentAnchor":
					if lbl, ok := e["label"].(string); ok {
						fmt.Printf("    label:  %s\n", lbl)
					}
					if anchor, ok := e["anchor"].(string); ok {
						fmt.Printf("    anchor: %s  (%s)\n", anchor, protocol.ClassifyAnchor(anchor))
					}
				default:
					for k, v := range e {
						if k == "id" || k == "type" {
							continue
						}
						fmt.Printf("    %s: %v\n", k, v)
					}
				}
			}
			return nil
		},
	}
}

func validateCarriage(chain *relay.StoredIdentityChain) error {
	if chain == nil {
		return fmt.Errorf("identity not found")
	}
	if len(chain.Log) > siwdCarriageCap {
		return fmt.Errorf(
			"identity chain has %d operations; the SIWD carriage cap is %d — publish the chain to a relay instead of carrying it",
			len(chain.Log),
			siwdCarriageCap,
		)
	}
	return nil
}

func buildWellKnownPatch(chain *relay.StoredIdentityChain, doc map[string]any, path string) (map[string]any, error) {
	redirectURIs, hasRedirectURIs := doc["redirect_uris"].([]any)
	if !hasRedirectURIs || len(redirectURIs) == 0 {
		return nil, fmt.Errorf(
			"app description at %s is missing its required member (redirect_uris); author that first — see specs/SIWD.md \"The App Description Document\"",
			path,
		)
	}
	// name is optional; present-but-empty (or non-string) is malformed, not absent.
	if rawName, present := doc["name"]; present {
		if name, ok := rawName.(string); !ok || name == "" {
			return nil, fmt.Errorf(
				"app description at %s has an invalid name: present-but-empty is malformed — give it a value or omit it",
				path,
			)
		}
	}
	if existing, present := doc["client_did"]; present {
		existingDID, ok := existing.(string)
		if !ok {
			return nil, fmt.Errorf("app description at %s has invalid client_did: must be a string", path)
		}
		if existingDID != chain.DID {
			return nil, fmt.Errorf(
				"app description client_did %q differs from identity DID %q; refusing to rebind the document to a different identity",
				existingDID,
				chain.DID,
			)
		}
	}

	patched := make(map[string]any, len(doc)+2)
	for key, value := range doc {
		patched[key] = value
	}
	patched["client_did"] = chain.DID
	patched["identity_chain"] = chain.Log
	return patched, nil
}

// newIdentityWellKnownCmd emits or patches SIWD app-description chain carriage.
func newIdentityWellKnownCmd() *cobra.Command {
	var patchPath string

	cmd := &cobra.Command{
		Use:   "well-known [name|did]",
		Short: "Emit this identity's chain-carriage members for /.well-known/dfos-app.json",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lr, err := getRelay()
			if err != nil {
				return err
			}

			var chain *relay.StoredIdentityChain
			if len(args) > 0 {
				did, err := resolveIdentityDID(args[0])
				if err != nil {
					return err
				}
				chain, _ = lr.Relay.GetIdentity(did)
			} else {
				ctx, err := resolveCtx()
				if err != nil {
					return err
				}
				if !ctx.HasIdentity() {
					return errNoIdentity()
				}
				if ctx.IdentityDID == "" {
					return fmt.Errorf("identity '%s' not found in config (from %s)", ctx.IdentityName, ctx.IdentitySource)
				}
				chain, _ = lr.Relay.GetIdentity(ctx.IdentityDID)
			}

			if chain == nil {
				return fmt.Errorf("identity not found")
			}
			if err := validateCarriage(chain); err != nil {
				return err
			}
			if chain.State.IsDeleted {
				fmt.Fprintln(os.Stderr, "Warning: identity is deleted; current-state verifiers will reject it")
			}

			if patchPath == "" {
				output := struct {
					ClientDID     string   `json:"client_did"`
					IdentityChain []string `json:"identity_chain"`
				}{
					ClientDID:     chain.DID,
					IdentityChain: chain.Log,
				}
				outputJSON(output)
				return nil
			}

			data, err := os.ReadFile(patchPath)
			if err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf(
						"%s does not exist; create the app description at /.well-known/dfos-app.json first with redirect_uris",
						patchPath,
					)
				}
				return fmt.Errorf("read %s: %w", patchPath, err)
			}

			var doc map[string]any
			if err := json.Unmarshal(data, &doc); err != nil {
				return fmt.Errorf("parse %s: %w", patchPath, err)
			}
			patched, err := buildWellKnownPatch(chain, doc, patchPath)
			if err != nil {
				return err
			}
			patchedData, err := json.MarshalIndent(patched, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal %s: %w", patchPath, err)
			}
			patchedData = append(patchedData, '\n')
			if err := os.WriteFile(patchPath, patchedData, 0o644); err != nil {
				return fmt.Errorf("write %s: %w", patchPath, err)
			}
			if jsonFlag {
				status := struct {
					Path       string `json:"path"`
					ClientDID  string `json:"client_did"`
					Operations int    `json:"operations"`
				}{
					Path:       patchPath,
					ClientDID:  chain.DID,
					Operations: len(chain.Log),
				}
				outputJSON(status)
			} else {
				fmt.Printf("Patched %s with %s (%d operations)\n", patchPath, chain.DID, len(chain.Log))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&patchPath, "patch", "", "Patch client_did + identity_chain into this dfos-app.json, preserving its other members")
	return cmd
}

func newIdentityPublishCmd() *cobra.Command {
	var peerName string
	return &cobra.Command{
		Use:   "publish [name|did]",
		Short: "Push identity chain to a peer",
		Long:  "Push an identity's full operation chain to a peer relay. The target peer is taken from --peer, else the resolved peer; one or the other is required.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lr, err := getRelay()
			if err != nil {
				return err
			}

			var chain *relay.StoredIdentityChain
			if len(args) > 0 {
				did, err := resolveIdentityDID(args[0])
				if err != nil {
					return err
				}
				chain, _ = lr.Relay.GetIdentity(did)
			} else {
				_, chain2, err := requireIdentity()
				if err != nil {
					return err
				}
				chain = chain2
			}
			if chain == nil {
				return fmt.Errorf("identity not found")
			}

			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn == "" {
				ctx, _ := resolveCtx()
				if ctx != nil {
					rn = ctx.RelayName
				}
			}
			if rn == "" {
				return errNoPeer()
			}

			c, _, err := getPeerClient(rn)
			if err != nil {
				return err
			}

			peerResults, err := c.SubmitOperations(chain.Log)
			if err != nil {
				return fmt.Errorf("submit: %w", err)
			}

			hasRejection := false
			for _, r := range peerResults {
				if r.Status == "rejected" {
					hasRejection = true
					fmt.Printf("  Operation %s: %s (%s)\n", r.CID, r.Status, r.Error)
				}
			}
			if hasRejection {
				return fmt.Errorf("peer rejected one or more operations")
			}

			if jsonFlag {
				outputJSON(map[string]any{"status": "published", "peer": rn, "operations": len(peerResults)})
			} else {
				fmt.Printf("Identity published to '%s' (%d operation(s))\n", rn, len(peerResults))
			}
			return nil
		},
	}
}

func newIdentityFetchCmd() *cobra.Command {
	var name string
	var peerName string

	cmd := &cobra.Command{
		Use:   "fetch <did|name>",
		Short: "Download identity chain from peer into local relay",
		Long: "Pull an identity's operation chain from a peer and ingest it into the local relay. The peer is " +
			"taken from this command's --peer, else the global --relay (whose hidden alias is also --peer), else " +
			"config default-peer. The two flags name the same thing at the same tier; the command-local one wins " +
			"when both are given.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			did, err := resolveIdentityDID(target)
			if err != nil {
				return err
			}

			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn == "" {
				ctx, _ := resolveCtx()
				if ctx != nil {
					rn = ctx.RelayName
				}
			}
			if rn == "" {
				return fmt.Errorf("--peer is required for fetch")
			}

			c, _, err := getPeerClient(rn)
			if err != nil {
				return err
			}

			// Pull the operation chain from the peer's log endpoint. The
			// /identities/{did} response carries resolved state, not ops.
			log, err := c.GetIdentityLog(did)
			if err != nil {
				return fmt.Errorf("fetch identity: %w", err)
			}

			// ingest into local relay
			lr, err := getRelay()
			if err != nil {
				return err
			}
			results := lr.Relay.Ingest(log)
			for _, r := range results {
				if r.Status == "rejected" {
					fmt.Fprintf(os.Stderr, "  Warning: operation %s rejected: %s\n", r.CID, r.Error)
				}
			}

			// register in config if named
			if name != "" {
				cfg.Identities[name] = config.IdentityConfig{DID: did}
				config.Save(cfg)
			}

			if jsonFlag {
				outputJSON(map[string]any{"did": did, "name": name, "operations": len(log)})
			} else {
				fmt.Printf("Fetched identity: %s (%d operations)\n", did, len(log))
				if name != "" {
					fmt.Printf("  Name: %s\n", name)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Local name for this identity")
	cmd.Flags().StringVar(&peerName, "peer", "", "Peer to fetch from — same tier as the global --relay, and wins when both are given")
	return cmd
}

// identityRemoveResult is what `identity remove` reports. `remove` and `forget`
// clear overlapping config state, so they report it in the same field names:
// the caller of either learns whether a dangling default-identity or active
// context was cleared, rather than having to re-read config.toml to find out.
// `remove` drops a name and nothing else, so it carries no credential or
// context-removal fields — forget's job, not this one's.
type identityRemoveResult struct {
	Removed                string `json:"removed"`
	DID                    string `json:"did"`
	ActiveContextCleared   bool   `json:"activeContextCleared"`
	DefaultIdentityCleared bool   `json:"defaultIdentityCleared"`
}

func newIdentityRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove an identity name from config (data stays in relay)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			idCfg, ok := cfg.Identities[name]
			if !ok {
				return fmt.Errorf("identity '%s' not found in config", name)
			}

			result := identityRemoveResult{Removed: name, DID: idCfg.DID}
			delete(cfg.Identities, name)
			// Dropping the name that default-identity points at would leave the
			// config tier naming something that no longer resolves, so it is
			// cleared here. This is not a default that follows anything — it is
			// the removal of a dangling one.
			if cfg.DefaultIdentity == name || cfg.DefaultIdentity == idCfg.DID {
				cfg.DefaultIdentity = ""
				result.DefaultIdentityCleared = true
			}
			if cfg.ActiveContext != "" {
				parts := strings.SplitN(cfg.ActiveContext, "@", 2)
				if len(parts) > 0 && parts[0] == name {
					cfg.ActiveContext = ""
					result.ActiveContextCleared = true
				}
			}
			config.Save(cfg)

			if jsonFlag {
				outputJSON(result)
			} else {
				fmt.Printf("Removed identity name '%s' (%s) from config\n", name, idCfg.DID)
				if result.DefaultIdentityCleared {
					fmt.Println("  default-identity cleared because it pointed at the removed name.")
				}
				if result.ActiveContextCleared {
					fmt.Println("  Active context cleared because it referenced the removed name.")
				}
				fmt.Printf("  Data remains in local relay. Keys remain in keychain.\n")
			}
			return nil
		},
	}
}

type identityForgetResult struct {
	DID                    string   `json:"did"`
	Name                   string   `json:"name,omitempty"`
	RemovedContexts        []string `json:"removedContexts"`
	ActiveContextCleared   bool     `json:"activeContextCleared"`
	DefaultIdentityCleared bool     `json:"defaultIdentityCleared"`
	CredentialRemoved      bool     `json:"credentialRemoved"`
}

func newIdentityForgetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "forget <name|did>",
		Short: "Forget a local identity registration and cached login credential",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := forgetIdentityConfig(cfg, args[0])
			if err != nil {
				return err
			}
			// EVERY stored credential for this subject, not one: the store holds a
			// file per (subject, host), and forgetting an identity while leaving
			// some of its grants on disk would be a partial forget reported as a
			// whole one.
			paths, _, err := credentialFilesForSubject(result.DID)
			if err != nil {
				return err
			}
			for _, path := range paths {
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("remove stored login credential for %s: %w", result.DID, err)
				}
				result.CredentialRemoved = true
			}
			if err := config.Save(cfg); err != nil {
				return err
			}

			if jsonFlag {
				outputJSON(result)
				return nil
			}
			if result.Name != "" {
				fmt.Printf("Forgot local identity '%s' (%s).\n", result.Name, result.DID)
			} else {
				fmt.Printf("Forgot local references for %s.\n", result.DID)
			}
			if len(result.RemovedContexts) > 0 {
				fmt.Printf("  Removed context(s): %s\n", strings.Join(result.RemovedContexts, ", "))
			}
			if result.ActiveContextCleared {
				fmt.Println("  Active context cleared because it referenced the forgotten identity.")
			}
			if result.CredentialRemoved {
				fmt.Println("  Stored login credential removed.")
			}
			// Forget removes a NAME, and deliberately nothing else: no key is
			// touched and no chain is dropped. Saying which is which matters,
			// because the two halves have different consequences — the name is
			// re-registerable, the key is not re-derivable unless a vault minted
			// it. Both surfaces are named so neither has to be guessed at.
			fmt.Println("  Private keys are untouched — forgetting a name removes no key material.")
			fmt.Println("  See what this machine holds with 'dfos keys list'; 'dfos keys prune' removes keys no local chain declares.")
			fmt.Println("  Public chain data remains in the local relay, so this identity's keys still read as declared; use 'dfos relay gc' for space maintenance.")
			return nil
		},
	}
}

func forgetIdentityConfig(target *config.Config, nameOrDID string) (identityForgetResult, error) {
	result := identityForgetResult{RemovedContexts: []string{}}
	if identity, ok := target.Identities[nameOrDID]; ok {
		result.Name = nameOrDID
		result.DID = identity.DID
		delete(target.Identities, nameOrDID)
	} else {
		if !strings.HasPrefix(nameOrDID, "did:") {
			return result, fmt.Errorf("identity '%s' not found in config; pass a bare DID to forget unregistered local references", nameOrDID)
		}
		if err := protocol.ValidateDID(nameOrDID); err != nil {
			return result, fmt.Errorf("invalid identity DID: %w", err)
		}
		result.DID = nameOrDID
	}

	for name, context := range target.Contexts {
		if context.Identity == result.DID || (result.Name != "" && context.Identity == result.Name) {
			delete(target.Contexts, name)
			result.RemovedContexts = append(result.RemovedContexts, name)
		}
	}
	sort.Strings(result.RemovedContexts)

	active := target.ActiveContext
	clearActive := false
	for _, removed := range result.RemovedContexts {
		if active == removed {
			clearActive = true
			break
		}
	}
	if result.Name != "" && (active == result.Name || strings.HasPrefix(active, result.Name+"@")) {
		clearActive = true
	}
	if active == result.DID || strings.HasPrefix(active, result.DID+"@") {
		clearActive = true
	}
	if clearActive {
		target.ActiveContext = ""
		result.ActiveContextCleared = true
	}
	// Same reason as `identity remove`: a default-identity naming a forgotten
	// identity is a dangling pointer, not a preference worth keeping.
	if target.DefaultIdentity != "" &&
		(target.DefaultIdentity == result.DID || (result.Name != "" && target.DefaultIdentity == result.Name)) {
		target.DefaultIdentity = ""
		result.DefaultIdentityCleared = true
	}
	return result, nil
}

// helpers

// fetchIdentityFromPeerIfRequested best-effort pulls a DID's chain from an
// explicitly requested --peer into the local store before a read command
// (show/keys/services) resolves it, so `--peer X` reflects X's state rather
// than only what is already local. No-op when no --peer is set. Ingest is
// idempotent, so re-fetching an already-local chain is harmless.
//
// Best-effort by design: a peer that is down or doesn't carry the DID must NOT
// mask a locally-available chain, so failures warn to stderr and fall through
// to local resolution. This keeps the CLI's local-first contract (content
// fetch / operation show / countersigs all read local first and only error
// when local is missing) rather than turning a working local read into a hard
// error just because --peer was passed.
func fetchIdentityFromPeerIfRequested(did string) {
	if peerFlag == "" {
		return
	}
	c, _, err := getPeerClient(peerFlag)
	if err != nil {
		// Not "unavailable": this also catches a peer that no longer serves the
		// DID config pins it to, and calling that a reachability problem would
		// bury the one thing the operator needs to see.
		fmt.Fprintf(os.Stderr, "Warning: not reading from peer %q; using local state\n%v\n", peerFlag, err)
		return
	}
	log, err := c.GetIdentityLog(did)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: fetch from peer %q failed: %v; using local state\n", peerFlag, err)
		return
	}
	if len(log) == 0 {
		return
	}
	lr, err := getRelay()
	if err != nil {
		return
	}
	lr.Relay.Ingest(log)
}

func resolveIdentityDID(nameOrDID string) (string, error) {
	did := nameOrDID
	if idCfg, ok := cfg.Identities[nameOrDID]; ok {
		did = idCfg.DID
	} else if len(nameOrDID) > 4 && nameOrDID[:4] != "did:" {
		did = "did:dfos:" + nameOrDID
	}
	if err := protocol.ValidateDID(did); err != nil {
		return "", fmt.Errorf("invalid identity DID: %w", err)
	}
	return did, nil
}

func toStringSlice(v any) ([]string, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	result := make([]string, len(arr))
	for i, item := range arr {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		result[i] = s
	}
	return result, true
}

// publishIdentityIfNeeded ensures the identity's chain is on the peer before
// publishing content. Submits the full identity log — duplicates are idempotent
// on the peer side.
func publishIdentityIfNeeded(chain *relay.StoredIdentityChain, peerName string, c *client.Client) error {
	results, err := c.SubmitOperations(chain.Log)
	if err != nil {
		return fmt.Errorf("publish identity to '%s': %w", peerName, err)
	}
	for _, r := range results {
		if r.Status == "rejected" {
			return fmt.Errorf("peer rejected identity op: %s", r.Error)
		}
	}
	return nil
}
