package cmd

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
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
	cmd.AddCommand(newIdentityUpdateCmd())
	cmd.AddCommand(newIdentityAddKeyCmd())
	cmd.AddCommand(newIdentityDevicePubkeyCmd())
	cmd.AddCommand(newIdentityDeleteCmd())
	cmd.AddCommand(newIdentityPublishCmd())
	cmd.AddCommand(newIdentityFetchCmd())
	cmd.AddCommand(newIdentityRemoveCmd())
	return cmd
}

func newIdentityCreateCmd() *cobra.Command {
	var name string
	var peerName string
	var serviceSpecs []string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new identity (generate keys + sign genesis)",
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

			lr, err := getRelay()
			if err != nil {
				return err
			}

			// generate controller key
			controllerKeyID := protocol.GenerateKeyID()
			controllerPriv, controllerPub, err := keys.GenerateKey("pending:" + controllerKeyID)
			if err != nil {
				return fmt.Errorf("generate controller key: %w", err)
			}
			controllerMK := protocol.NewMultikeyPublicKey(controllerKeyID, controllerPub)

			// generate auth key
			authKeyID := protocol.GenerateKeyID()
			_, authPub, err := keys.GenerateKey("pending:" + authKeyID)
			if err != nil {
				return fmt.Errorf("generate auth key: %w", err)
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

			// register name in config only after all operations succeed
			cfg.Identities[name] = config.IdentityConfig{DID: did}
			// Select the first identity created so `status`/signing commands work
			// immediately, instead of leaving the user with "No active context".
			activated := ""
			if cfg.ActiveContext == "" {
				if rn != "" {
					cfg.ActiveContext = name + "@" + rn
				} else {
					cfg.ActiveContext = name
				}
				activated = cfg.ActiveContext
			}
			if err := config.Save(cfg); err != nil {
				return err
			}

			if jsonFlag {
				outputJSON(map[string]any{
					"did":           did,
					"name":          name,
					"operationCID":  opCID,
					"controllerKey": controllerKeyID,
					"authKey":       authKeyID,
					"services":      len(services),
					"publishedTo":   publishedTo,
					"activeContext": cfg.ActiveContext,
				})
			} else {
				fmt.Printf("Identity created:\n")
				fmt.Printf("  Name:           %s\n", name)
				fmt.Printf("  DID:            %s\n", did)
				fmt.Printf("  Controller key: %s  (%s)\n", controllerKeyID, keys.Backend())
				fmt.Printf("  Auth key:       %s  (%s)\n", authKeyID, keys.Backend())
				if len(services) > 0 {
					fmt.Printf("  Services:       %d\n", len(services))
				}
				if len(publishedTo) > 0 {
					fmt.Printf("  Published to:   %s\n", joinComma(publishedTo))
				} else {
					fmt.Printf("  Status:         local only. Use 'dfos identity publish' to push to a peer.\n")
				}
				if activated != "" {
					fmt.Printf("  Active context: %s\n", activated)
				}
				fmt.Fprintf(os.Stderr, "\nWarning: key loss is unrecoverable. There is no seed phrase, backup, or recovery flow.\n")
				fmt.Fprintf(os.Stderr, "         If you lose these keys (%s), control of this identity is gone for good.\n", keys.Backend())
				fmt.Fprintf(os.Stderr, "         Availability is a multi-key story, not a recovery one: register additional keys (e.g. on another device) with 'dfos identity add-key' while you still hold a controller key, so no single key loss is fatal.\n")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Human-readable name for this identity (required)")
	cmd.Flags().StringVar(&peerName, "peer", "", "Push to this peer immediately")
	cmd.Flags().StringArrayVar(&serviceSpecs, "service", nil, "Discovery service entry as key=value list (repeatable), e.g. id=relay,type=DfosRelay,endpoint=https://relay.dfos.com")
	return cmd
}

func newIdentityUpdateCmd() *cobra.Command {
	var peerName string
	var rotateAuth bool
	var rotateController bool
	var serviceSpecs []string
	var clearServices bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update identity (rotate keys, set discovery services)",
		Long: "Sign an identity update operation. Use --rotate-auth or --rotate-controller to generate new keys " +
			"and rotate out the old ones. Use --service (repeatable) to REPLACE the discovery services set, or " +
			"--clear-services to empty it. Services left unspecified are carried forward unchanged.",
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

			_, chain, err := requireIdentity()
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

			if rotateAuth {
				newAuthKeyID := protocol.GenerateKeyID()
				_, newAuthPub, err := keys.GenerateKey(chain.DID + "#" + newAuthKeyID)
				if err != nil {
					return fmt.Errorf("generate new auth key: %w", err)
				}
				newAuthKeys = []protocol.MultikeyPublicKey{protocol.NewMultikeyPublicKey(newAuthKeyID, newAuthPub)}
				rotatedKeys = append(rotatedKeys, "auth:"+newAuthKeyID)
			}

			if rotateController {
				newControllerKeyID := protocol.GenerateKeyID()
				_, newControllerPub, err := keys.GenerateKey(chain.DID + "#" + newControllerKeyID)
				if err != nil {
					return fmt.Errorf("generate new controller key: %w", err)
				}
				newControllerKeys = []protocol.MultikeyPublicKey{protocol.NewMultikeyPublicKey(newControllerKeyID, newControllerPub)}
				rotatedKeys = append(rotatedKeys, "controller:"+newControllerKeyID)
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

			if jsonFlag {
				out := map[string]any{
					"did":          chain.DID,
					"operationCID": opCID,
					"rotatedKeys":  rotatedKeys,
				}
				if servicesChanged {
					out["services"] = len(services)
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
	cmd.Flags().BoolVar(&rotateAuth, "rotate-auth", false, "Generate new auth key and rotate out old one(s)")
	cmd.Flags().BoolVar(&rotateController, "rotate-controller", false, "Generate new controller key and rotate out old one(s)")
	cmd.Flags().StringArrayVar(&serviceSpecs, "service", nil, "Discovery service entry as key=value list (repeatable); REPLACES the entire services set")
	cmd.Flags().BoolVar(&clearServices, "clear-services", false, "Empty the discovery services set")
	return cmd
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
		Short: "Permanently delete an identity (sign delete operation)",
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
				fmt.Printf("  This identity can no longer sign operations.\n")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&peerName, "peer", "", "Push to this peer immediately")
	return cmd
}

func newIdentityListCmd() *cobra.Command {
	return &cobra.Command{
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
				outputJSON(chains)
				return nil
			}

			fmt.Printf("%-10s %-36s %-6s %s\n", "NAME", "DID", "KEYS", "OPS")
			for _, chain := range chains {
				name := config.FindIdentityName(cfg, chain.DID)
				if name == "" {
					name = "-"
				}
				totalKeys := len(distinctKeyIDs(&chain))
				haveKeys := countKeysInChain(&chain)
				fmt.Printf("%-10s %-36s %d/%-3d %d\n",
					name, chain.DID, haveKeys, totalKeys, len(chain.Log))
			}
			return nil
		},
	}
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

func newIdentityPublishCmd() *cobra.Command {
	var peerName string
	return &cobra.Command{
		Use:   "publish [name|did]",
		Short: "Push identity chain to a peer",
		Long:  "Push an identity's full operation chain to a peer relay. The target peer is taken from --peer, else the active context's peer; one or the other is required.",
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
				return fmt.Errorf("--peer is required to publish: pass --peer <name> or set an active context with 'dfos use <identity@peer>'")
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
		Args:  cobra.ExactArgs(1),
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
	cmd.Flags().StringVar(&peerName, "peer", "", "Peer to fetch from")
	return cmd
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

			delete(cfg.Identities, name)
			if cfg.ActiveContext != "" {
				parts := strings.SplitN(cfg.ActiveContext, "@", 2)
				if len(parts) > 0 && parts[0] == name {
					cfg.ActiveContext = ""
				}
			}
			config.Save(cfg)

			if jsonFlag {
				outputJSON(map[string]string{"removed": name, "did": idCfg.DID})
			} else {
				fmt.Printf("Removed identity name '%s' (%s) from config\n", name, idCfg.DID)
				fmt.Printf("  Data remains in local relay. Keys remain in keychain.\n")
			}
			return nil
		},
	}
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
		fmt.Fprintf(os.Stderr, "Warning: peer %q unavailable (%v); using local state\n", peerFlag, err)
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
