package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	cmd.AddCommand(newIdentityStatusCmd())
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
		Short: "Create a new identity (mint one key + sign genesis)",
		Long: "Mint ONE key and sign a genesis operation that declares it in all three roles — controller, " +
			"auth, and assert. The key is derived from a vault — --vault, else default-vault — so the " +
			"vault's recovery phrase covers it. With no vault selected, or with --no-vault, the key is " +
			"generated standalone and exists only in the keystore. Nothing about the vault is published: " +
			"the genesis carries a public key and nothing else.\n\n" +
			"Custody splits at the first key-add, not at genesis. Two keys off one seed in one keychain " +
			"share every fate that matters; 'dfos identity add-key' and 'dfos keys add' are where a " +
			"second custodian actually appears.",
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

			// ONE key, ONE derivation index, all three roles.
			//
			// The split this genesis does not make is the point. Two keys minted
			// from one seed, into one keychain, on one machine, are one custody
			// arrangement wearing two names: every event that takes one takes the
			// other. A role separation only becomes real when a second custodian
			// holds a key the first cannot reach, and that happens at a key-add
			// ceremony ('dfos identity add-key', 'dfos keys prove') — the first
			// key-add IS the split. Until then, declaring one key three times says
			// exactly what is true.
			//
			// The chain grammar is untouched: PROTOCOL.md requires at least one
			// controller key and says nothing about separation or cross-array
			// uniqueness, and a key id is an opaque string. The same entry — same
			// id, same publicKeyMultibase — appears in each array.
			minter, err := newKeyMinter(vaultName, 1)
			if err != nil {
				return err
			}

			minted, err := minter.next()
			if err != nil {
				return fmt.Errorf("mint identity key: %w", err)
			}
			keyID := protocol.DeriveKeyID(minted.PublicMultibase)
			mk := protocol.NewMultikeyPublicKey(keyID, minted.Public)

			// The key is stored before the genesis is signed, so a create that dies
			// mid-flight leaves material an operator still holds rather than a
			// spent derivation index and nothing to show for it. Its account is the
			// key's own content address, which needs no DID and so needs no rename
			// once one exists.
			account := keyAccount(minted.PublicMultibase)
			if _, err := keys.PutKey(account, minted.Private); err != nil {
				return fmt.Errorf("store the identity key in %s: %w", keys.Backend(), err)
			}

			// sign genesis (services omitted entirely when none given — CID-neutral)
			jwsToken, did, opCID, err := protocol.SignIdentityCreateWithServices(
				[]protocol.MultikeyPublicKey{mk},
				[]protocol.MultikeyPublicKey{mk},
				[]protocol.MultikeyPublicKey{mk},
				services,
				keyID,
				minted.Private,
			)
			if err != nil {
				return fmt.Errorf("sign genesis: %w", err)
			}

			// ingest into local relay
			results := lr.Relay.Ingest([]string{jwsToken})
			if len(results) > 0 && results[0].Status == "rejected" {
				return fmt.Errorf("local relay rejected: %s", results[0].Error)
			}

			// Record which derivation indices became which published keys, on the
			// strength of the LOCAL ingest above and before anything is sent to a
			// peer. This is local provenance only — it is what `whoami` reports and
			// what a rotation reads to stay on the seed that minted the current
			// keys — and the chain it describes exists the moment the local relay
			// accepts it. Waiting for a peer put the trail behind an unreachable
			// network: the key was in the keystore and the chain was in the local
			// relay, and a later bare `identity update --rotate-*` found no vault
			// and minted a STANDALONE replacement for a phrase-backed identity.
			if vaultName != "" {
				if err := getVaults().Record(vaultName,
					vault.MintedKey{
						Index: minted.Index, DID: did, KeyID: keyID,
						Roles: genesisRoles, PublicKey: mk.PublicKeyMultibase,
					},
				); err != nil {
					return fmt.Errorf("record vault provenance: %w", err)
				}
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
					"did":          did,
					"name":         name,
					"operationCID": opCID,
					"key":          keyID,
					"publicKey":    mk.PublicKeyMultibase,
					"roles":        genesisRoles,
					// controllerKey and authKey name the SAME key now. They are kept
					// because a script reading either field is asking "which key
					// controls this identity", and the answer has not stopped
					// existing — it has stopped being two answers.
					"controllerKey": keyID,
					"authKey":       keyID,
					"services":      len(services),
					"publishedTo":   publishedTo,
				}
				if vaultName != "" {
					out["vault"] = map[string]any{
						"name":        vaultName,
						"fingerprint": minter.fingerprint,
						"index":       minted.Index,
						// Both role indices are the one index, for the same reason
						// the two key fields are the one key.
						"controllerIndex": minted.Index,
						"authIndex":       minted.Index,
					}
				}
				outputJSON(out)
			} else {
				fmt.Printf("Identity created:\n")
				fmt.Printf("  Name:           %s\n", name)
				fmt.Printf("  DID:            %s\n", did)
				fmt.Printf("  Key:            %s  (%s)\n", keyID, keys.Backend())
				fmt.Printf("  Roles:          %s — one key, declared in all three\n", joinComma(genesisRoles))
				if vaultName != "" {
					fmt.Printf("  Vault:          %s [%s] at %s — via %s\n",
						vaultName, minter.fingerprint, vault.DerivationPath(minted.Index), vaultSource)
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
					fmt.Fprintf(os.Stderr, "\nWarning: this key is standalone. It exists in %s and nowhere else.\n", keys.Backend())
					fmt.Fprintf(os.Stderr, "         Lose it and control of this identity is gone for good.\n")
					fmt.Fprintf(os.Stderr, "         Mint from a vault ('dfos vault create <name>') so a written-down phrase covers the key, and register a second key (e.g. on another device) with 'dfos identity add-key' while you still hold this one, so no single key loss is fatal.\n")
				} else {
					fmt.Fprintf(os.Stderr, "\nThis key derives from vault '%s'. Its recovery phrase is the only copy: if it is not written down, write it down now with 'dfos vault show %s --reveal-mnemonic'.\n", vaultName, vaultName)
					fmt.Fprintf(os.Stderr, "Availability is a multi-key story and this identity has one key: register a second (e.g. on another device) with 'dfos identity add-key' while you still hold this one. That add is also where controller and auth stop being the same custody.\n")
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

// genesisRoles is what `identity create` declares its one key in. The order is
// the protocol's own controller→auth→assert order, so every surface that prints
// a key's roles prints them the same way.
var genesisRoles = []string{"controller", "auth", "assert"}

// keyMinter is the one place a private key comes into existence. It hands out
// key MATERIAL — from a vault's reserved indices or from fresh entropy — and the
// caller stores it, because a key's account is its own public key and that is
// not known until the key exists.
//
// Reserving all of an operation's indices up front means a vault's counter moves
// exactly once per command, and the indices an operation consumes are contiguous.
type keyMinter struct {
	vaultName   string
	fingerprint string
	derived     []vault.Derived
	used        int
}

// mintedKey is one key the minter produced, with the index it came from. The
// index is meaningful only for a vault-backed minter; a standalone key has no
// index and reports 0, which callers gate on vaultName rather than on the number.
type mintedKey struct {
	Index           uint32
	Private         ed25519.PrivateKey
	Public          ed25519.PublicKey
	PublicMultibase string
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

// next produces the next key. It does NOT store it: the account a key is filed
// under is derived from the key's own public half (see keyaccount.go), so there
// is no name to write it under until it exists. The caller stores it, which is
// also where the caller decides whether a half-finished operation should leave
// the material behind.
func (m *keyMinter) next() (mintedKey, error) {
	if m.vaultName == "" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return mintedKey{}, fmt.Errorf("generate a key: %w", err)
		}
		return newMintedKey(0, priv), nil
	}
	if m.used >= len(m.derived) {
		return mintedKey{}, fmt.Errorf("vault '%s' reserved %d key(s) and a %d%s was asked for", m.vaultName, len(m.derived), m.used+1, ordinalSuffix(m.used+1))
	}
	d := m.derived[m.used]
	m.used++
	return newMintedKey(d.Index, d.Private), nil
}

func newMintedKey(index uint32, priv ed25519.PrivateKey) mintedKey {
	pub := priv.Public().(ed25519.PublicKey)
	return mintedKey{
		Index:           index,
		Private:         priv,
		Public:          pub,
		PublicMultibase: protocol.EncodeMultikey(pub),
	}
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

// --- possession proofs for the keys an update introduces ---
//
// A key's appearance in an identity chain is accompanied by that key's own
// signature over the appearance (specs/KEY-PROOF.md, PROTOCOL.md → Key
// Possession). Genesis is the one exception, and it proves itself: one key in all
// three roles, signing the operation that declares it. Every other introduction
// carries an embedded envelope, and a membership no envelope covers is VOID —
// excluded from effective state, never indexed, never resolving.
//
// So every write path in this file has to answer one question before it signs:
// what does this operation INTRODUCE, and can this machine prove it?

// declaredKeyState is the base an identity update builds its full-state key
// arrays from.
//
// DECLARED, NOT EFFECTIVE, and the difference is a chain's contents. The
// IdentityState key arrays are EFFECTIVE state — the memberships a possession
// proof admitted — so seeding an update from them would DROP every
// declared-but-unproved key on the next operation, silently, as a side effect of
// whatever unrelated command happened to run. A controller who wrote a key into
// their chain decides when it leaves; an `identity bind` does not decide that for
// them.
//
// THE IsZero FALLBACK IS NOT DEFENSIVE CLUTTER. A state deserialized from a store
// written before declared state existed records no declared arrays at all, and
// reading those absent arrays literally would author an update declaring NOTHING
// — every key in the chain gone in one operation. IsZero's contract covers
// exactly this case, and "the effective arrays are also the declared arrays" is
// true for any chain with no void memberships.
func declaredKeyState(chain *relay.StoredIdentityChain) protocol.DeclaredKeyState {
	if chain.State.Declared.IsZero() {
		return protocol.DeclaredKeyState{
			AuthKeys:       chain.State.AuthKeys,
			AssertKeys:     chain.State.AssertKeys,
			ControllerKeys: chain.State.ControllerKeys,
		}
	}
	return chain.State.Declared
}

// keyIntroduction is one key an operation introduces, and the roles it gains.
type keyIntroduction struct {
	Key   protocol.MultikeyPublicKey
	Roles []protocol.KeyRole
}

// keyIntroductions computes what an operation INTRODUCES: every (key, role) in
// the arrays about to be authored that prior EFFECTIVE state did not already
// carry.
//
// EFFECTIVE is the comparison, because effective is the comparison the chain walk
// makes — so it is the one that decides what needs an envelope. One consequence
// is worth stating plainly, because it surprises people: a membership that went
// void is introduced AGAIN by every subsequent operation that re-declares it. It
// keeps demanding a proof until one arrives or the key is dropped from the
// arrays, and that is the designed behavior rather than an edge case — a chain
// does not get to carry a key nobody proved and have the fact quietly stop
// mattering.
//
// Keys are grouped by MATERIAL rather than by id: one envelope proves one key,
// however many ids or roles name it.
func keyIntroductions(prior protocol.IdentityState, controller, auth, assert []protocol.MultikeyPublicKey) []keyIntroduction {
	effective := map[protocol.KeyRole]map[string]bool{
		"auth": {}, "assert": {}, "controller": {},
	}
	for _, k := range prior.AuthKeys {
		effective["auth"][k.ID] = true
	}
	for _, k := range prior.AssertKeys {
		effective["assert"][k.ID] = true
	}
	for _, k := range prior.ControllerKeys {
		effective["controller"][k.ID] = true
	}

	index := map[string]int{}
	var out []keyIntroduction
	add := func(set []protocol.MultikeyPublicKey, role protocol.KeyRole) {
		for _, k := range set {
			if effective[role][k.ID] {
				continue
			}
			i, seen := index[k.PublicKeyMultibase]
			if !seen {
				index[k.PublicKeyMultibase] = len(out)
				out = append(out, keyIntroduction{Key: k})
				i = len(out) - 1
			}
			out[i].Roles = append(out[i].Roles, role)
		}
	}
	add(auth, "auth")
	add(assert, "assert")
	add(controller, "controller")
	return out
}

// proveIntroductions self-signs a possession proof for every introduction whose
// private key this machine holds, and reports the ones it cannot prove.
//
// THIS IS KEY-PROOF'S CONTROLLER-VERIFIED LEG, in the degenerate form where the
// tool minting the challenge and the device holding the key are one process. The
// audience is the chain's OWN DID rather than a host authority — no host mediates
// this leg — and it byte-equals the payload's `did`, which is what makes an
// envelope signed here structurally unusable at a hosted ceremony and vice versa:
// a host authority is never a DID, so the two value domains cannot collide.
//
// What it cannot prove, it does not pretend to. A key generated on another device
// is exactly the case this returns rather than fabricates — a controller cannot
// vouch for material it does not hold, which is the entire point of the artifact.
func proveIntroductions(did, prevCID string, intros []keyIntroduction) (proofs []string, unprovable []keyIntroduction, err error) {
	for _, intro := range intros {
		account, held := heldKeyAccount(did, intro.Key.ID, intro.Key.PublicKeyMultibase)
		if !held {
			unprovable = append(unprovable, intro)
			continue
		}
		priv, err := keys.GetPrivateKey(account)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s from %s: %w", account, keys.Backend(), err)
		}
		roleSet, err := protocol.SerializeRoleSet(intro.Roles)
		if err != nil {
			return nil, nil, fmt.Errorf("the roles introduced for %s are not a role set: %w", intro.Key.ID, err)
		}
		nonce, err := mintProofNonce()
		if err != nil {
			return nil, nil, err
		}
		envelope, _, err := protocol.SignKeyProof(protocol.SignKeyProofInput{
			Typ:        protocol.KeyAddJWSTyp,
			Nonce:      nonce,
			Audience:   did,
			DID:        did,
			RoleSet:    roleSet,
			PrevCID:    prevCID,
			PrivateKey: priv,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("prove possession of %s: %w", intro.Key.ID, err)
		}
		proofs = append(proofs, envelope)
	}
	return proofs, unprovable, nil
}

// mintProofNonce mints the challenge for the controller-verified leg.
//
// On this leg the verifier and the signer are the same process, so the nonce is
// not defending against a challenge relayed by a third party — position binding
// already spends the envelope at one head of one chain. What it does is keep two
// envelopes for the same key at the same position from being byte-identical.
// 128 bits, per KEY-PROOF's minimum entropy SHOULD.
func mintProofNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("mint a proof nonce: %w", err)
	}
	return fmt.Sprintf("%x", b), nil
}

// errUnprovedIntroductions is the refusal for an operation that would introduce a
// key this machine cannot prove.
//
// It names every offending key and role at once, and offers the two ways forward
// that actually exist. There is deliberately no override flag: a --force here
// would author a chain whose new key resolves nowhere, which is not a power a
// human should be given by a flag they can pass in a hurry.
func errUnprovedIntroductions(did string, unprovable []keyIntroduction) error {
	lines := make([]string, 0, len(unprovable))
	for _, intro := range unprovable {
		roles := make([]string, 0, len(intro.Roles))
		for _, role := range intro.Roles {
			roles = append(roles, string(role))
		}
		lines = append(lines, fmt.Sprintf("  %s  (%s)\n    %s",
			intro.Key.ID, strings.Join(roles, ", "), intro.Key.PublicKeyMultibase))
	}
	return fmt.Errorf("nothing was signed: this operation would introduce %d key(s) into %s that this machine cannot prove.\n\n%s\n\n"+
		"A key enters a chain carrying its OWN signature over the introduction. A controller cannot vouch for a key it\n"+
		"does not hold, and a membership nobody proved is VOID — it never resolves, never indexes, and obligates nobody,\n"+
		"so authoring one would leave a chain that verifies and a key that does not work.\n\n"+
		"Two ways forward:\n"+
		"  REMOVE   — author this operation without those keys, and it signs exactly as it always did.\n"+
		"  RE-PROVE — have the device that holds each key present its own proof ('dfos keys add'), then run this again.",
		len(unprovable), did, strings.Join(lines, "\n"))
}

// authoredUpdate is one identity update this CLI is about to sign.
type authoredUpdate struct {
	// Prior is the verified state the update extends. The kit's writer needs it to
	// compute introductions the same way the chain walk will.
	Prior       protocol.IdentityState
	PreviousCID string
	// The full-state arrays being authored, seeded from DECLARED state.
	ControllerKeys, AuthKeys, AssertKeys []protocol.MultikeyPublicKey
	Services                             []protocol.ServiceEntry
	KeyProofs                            []string
	Kid                                  string
	PrivateKey                           ed25519.PrivateKey
}

// signAuthoredUpdate is the ONE place this CLI hands an identity update to the
// kit's writer. Every write site goes through it, so introductions are proved and
// carried one way rather than three ways that can drift.
//
// The kit runs its OWN writer door over what it is handed: it recomputes the
// introductions from Prior and refuses any the KeyProofs do not cover, through
// the same fold the chain walk uses. So this seam is checked twice, by two
// independent computations — proveAuthoredUpdate's above and the kit's — and they
// have to agree before an operation exists at all. The CLI's half is not the
// safety; it is what produces a useful refusal instead of a library error.
func signAuthoredUpdate(u authoredUpdate) (jwsToken string, operationCID string, err error) {
	return protocol.SignIdentityUpdateWithServices(
		u.Prior, u.PreviousCID, u.ControllerKeys, u.AuthKeys, u.AssertKeys, u.Services, u.KeyProofs,
		u.Kid, u.PrivateKey)
}

// proveAuthoredUpdate computes what an update introduces, proves what it can, and
// refuses what it cannot. The result is the KeyProofs the operation carries.
func proveAuthoredUpdate(did string, u *authoredUpdate) error {
	intros := keyIntroductions(u.Prior, u.ControllerKeys, u.AuthKeys, u.AssertKeys)
	if len(intros) == 0 {
		return nil
	}
	proofs, unprovable, err := proveIntroductions(did, u.PreviousCID, intros)
	if err != nil {
		return err
	}
	if len(unprovable) > 0 {
		return errUnprovedIntroductions(did, unprovable)
	}
	u.KeyProofs = proofs
	return nil
}

func newIdentityUpdateCmd() *cobra.Command {
	var peerName string
	var rotateAuth bool
	var rotateController bool
	var rotateAssert bool
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
			"Use --rotate-auth, --rotate-controller, and/or --rotate-assert to mint a replacement key " +
			"and rotate out the old ones. The named roles are replaced by ONE freshly minted key — one " +
			"custody, one key, the same rule 'identity create' follows — and a role no flag names carries " +
			"its keys forward unchanged, which means the retired key stays declared in it. " +
			"Rotation is sticky: the replacement is drawn from the vault that " +
			"minted this identity's CURRENT keys, so an identity stays on one seed unless --vault says " +
			"otherwise. An identity whose keys came from no vault rotates into a standalone key. " +
			"Use --service (repeatable) to REPLACE the discovery services set, or " +
			"--clear-services to empty it. Services left unspecified are carried forward unchanged.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			settingServices := len(serviceSpecs) > 0 || clearServices
			rotating := rotateController || rotateAuth || rotateAssert
			if !rotating && !settingServices {
				return fmt.Errorf("specify --rotate-controller, --rotate-auth, --rotate-assert, --service, and/or --clear-services")
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

			signer, err := selectHeldKey(chain.DID, chain.State.ControllerKeys, "controller")
			if err != nil {
				return err
			}
			controllerPriv, err := keys.GetPrivateKey(signer.Account)
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

			// Seeded from DECLARED state: an update carries a chain's contents
			// forward, and dropping a key the controller wrote — because no proof
			// admitted it — would be this command deciding that for them.
			declared := declaredKeyState(chain)
			newAuthKeys := declared.AuthKeys
			newControllerKeys := declared.ControllerKeys
			newAssertKeys := declared.AssertKeys
			var rotatedKeys []string
			var retainedRoles []retainedKeyRole

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
			if rotating {
				// ONE reservation, one index, one key — however many roles are being
				// rotated. Minting a key per role would put two fresh keys in one
				// keychain under one seed and call that a separation, which is the
				// arrangement `identity create` stopped making.
				minter, err = newKeyMinter(rotationVault, 1)
				if err != nil {
					return err
				}
				vaultFingerprint = minter.fingerprint
			}
			var mintedRecords []vault.MintedKey

			if rotating {
				minted, err := minter.next()
				if err != nil {
					return fmt.Errorf("mint the replacement key: %w", err)
				}
				newKeyID := protocol.DeriveKeyID(minted.PublicMultibase)
				newMK := protocol.NewMultikeyPublicKey(newKeyID, minted.Public)
				if _, err := keys.PutKey(keyAccount(minted.PublicMultibase), minted.Private); err != nil {
					return fmt.Errorf("store the replacement key in %s: %w", keys.Backend(), err)
				}

				var newRoles []string
				if rotateController {
					newControllerKeys = []protocol.MultikeyPublicKey{newMK}
					newRoles = append(newRoles, "controller")
				}
				if rotateAuth {
					newAuthKeys = []protocol.MultikeyPublicKey{newMK}
					newRoles = append(newRoles, "auth")
				}
				if rotateAssert {
					newAssertKeys = []protocol.MultikeyPublicKey{newMK}
					newRoles = append(newRoles, "assert")
				}
				for _, role := range newRoles {
					rotatedKeys = append(rotatedKeys, role+":"+newKeyID)
				}
				mintedRecords = append(mintedRecords, vault.MintedKey{
					Index: minted.Index, DID: chain.DID, KeyID: newKeyID,
					Roles: newRoles, PublicKey: newMK.PublicKeyMultibase,
				})

				// What the retired keys STILL are. A role no flag named carried its
				// keys forward, so a key rotated out of auth can remain the
				// identity's controller — which is exactly the shape a single-key
				// identity is in after --rotate-auth alone. Saying "rotated out"
				// and stopping there would be a sentence with its subject removed.
				retainedRoles = retainedRolesAfterRotation(chain, newControllerKeys, newAuthKeys, newAssertKeys)
			}

			// A rotation introduces the key it just minted, and this machine holds
			// it — so the introduction proves itself, on the controller-verified
			// leg, before the operation is signed.
			update := authoredUpdate{
				Prior: chain.State, PreviousCID: previousCID,
				ControllerKeys: newControllerKeys, AuthKeys: newAuthKeys, AssertKeys: newAssertKeys,
				Services: services, Kid: signer.KID, PrivateKey: controllerPriv,
			}
			if err := proveAuthoredUpdate(chain.DID, &update); err != nil {
				return err
			}
			jwsToken, opCID, err := signAuthoredUpdate(update)
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
				if rotating {
					out["retiredKeys"] = retainedRoles
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
							rotationVault, vaultFingerprint, vault.DerivationPath(r.Index),
							joinComma(r.RoleList()), rotationSource)
					}
				}
				if servicesChanged {
					fmt.Printf("  Services:       %d (replaced)\n", len(services))
				}
				for _, r := range retainedRoles {
					if len(r.Roles) > 0 {
						fmt.Printf("  Still declared: %s — %s (a role no flag named carries its keys forward)\n",
							r.KeyID, joinComma(r.Roles))
					} else {
						fmt.Printf("  Retired:        %s — declared in no role now; the seed stays in the keystore so the chain still re-verifies\n", r.KeyID)
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&peerName, "peer", "", "Push to this peer immediately")
	cmd.Flags().BoolVar(&rotateAuth, "rotate-auth", false, "Replace the auth key set with a freshly minted key")
	cmd.Flags().BoolVar(&rotateController, "rotate-controller", false, "Replace the controller key set with a freshly minted key")
	cmd.Flags().BoolVar(&rotateAssert, "rotate-assert", false, "Replace the assert key set with a freshly minted key")
	cmd.Flags().StringArrayVar(&serviceSpecs, "service", nil, "Discovery service entry as key=value list (repeatable); REPLACES the entire services set")
	cmd.Flags().BoolVar(&clearServices, "clear-services", false, "Empty the discovery services set")
	cmd.Flags().StringVar(&vaultFlag, "vault", "", "Mint the replacements from this vault for THIS rotation only; a later bare rotate returns to the vault behind the identity's current controller key")
	cmd.Flags().BoolVar(&noVault, "no-vault", false, "Rotate into standalone keys, from no vault")
	return cmd
}

// retainedKeyRole is one key a rotation displaced from at least one role, and
// the roles it is STILL declared in afterwards.
//
// It exists because a role-scoped rotation on a single-key identity has a result
// that "rotated out" does not describe: --rotate-auth mints a new auth key, and
// the key it displaced is still the identity's controller and assert key,
// because no flag named those roles and a full-state replacement carries an
// unnamed role forward untouched. An operator told only that the old key was
// rotated out would believe a key is retired that still controls the identity.
type retainedKeyRole struct {
	KeyID string   `json:"keyId"`
	Roles []string `json:"stillDeclaredIn"`
}

// retainedRolesAfterRotation compares the chain's key sets before and after, and
// reports every key that lost a role, with whatever roles it kept. Order is the
// chain's own controller→auth→assert order, so two runs print the same lines.
func retainedRolesAfterRotation(chain *relay.StoredIdentityChain, newController, newAuth, newAssert []protocol.MultikeyPublicKey) []retainedKeyRole {
	before := map[string][]string{}
	var order []string
	seen := map[string]bool{}
	note := func(set []protocol.MultikeyPublicKey, role string) {
		for _, k := range set {
			if !seen[k.ID] {
				seen[k.ID] = true
				order = append(order, k.ID)
			}
			before[k.ID] = append(before[k.ID], role)
		}
	}
	note(chain.State.ControllerKeys, "controller")
	note(chain.State.AuthKeys, "auth")
	note(chain.State.AssertKeys, "assert")

	after := map[string][]string{}
	keep := func(set []protocol.MultikeyPublicKey, role string) {
		for _, k := range set {
			after[k.ID] = append(after[k.ID], role)
		}
	}
	keep(newController, "controller")
	keep(newAuth, "auth")
	keep(newAssert, "assert")

	var out []retainedKeyRole
	for _, id := range order {
		if len(after[id]) == len(before[id]) {
			continue
		}
		out = append(out, retainedKeyRole{KeyID: id, Roles: after[id]})
	}
	return out
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
	meta, ok, err := getVaults().FindMintingVault(chain.DID, keyIDs)
	if err != nil {
		// A provenance read that FAILED is not an identity with no vault, and the
		// difference is custody. Falling through to standalone here would rotate a
		// mnemonic-backed identity onto a key no phrase can ever recover — quietly,
		// on the strength of an unrelated sibling file being unparseable. So this
		// stops, names the file, and hands back the two ways past it.
		return "", "", fmt.Errorf("cannot read vault provenance, so this rotation does not know which seed minted %s: %w\n"+
			"Rotating without that answer risks replacing a phrase-backed key with a standalone one. Either:\n"+
			"  fix or remove the unreadable vault file named above, then re-run\n"+
			"  --vault <name>   rotate onto that vault explicitly\n"+
			"  --no-vault       accept a standalone replacement key, out loud", chain.DID, err)
	}
	if ok {
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

// roleKeyCap is the maximum number of keys a single role set may hold, and it
// is the protocol's number rather than one of this CLI's own: PROTOCOL.md
// "Cardinality caps" puts `authKeys` / `assertKeys` / `controllerKeys` at 256
// items each, and packages/dfos-protocol/src/chain/schemas.ts enforces the same
// 256 as MAX_KEYS_PER_ROLE. The Go verifier does not enforce it, so the CLI
// guards against producing an operation a conformant relay would reject.
//
// It read 16 before, over a comment citing both surfaces for a number neither
// of them says. A local cap below the spec's is not a conservative guard — it
// refuses an operation every implementation would accept, which is a bug that
// only shows up on the seventeenth key.
const roleKeyCap = 256

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

			// The account is the key's own content address, so it is knowable
			// before any chain names the key — and the key id the other device
			// will publish is derived from the same public key, so both machines
			// compute the same handle without exchanging anything but the key.
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return fmt.Errorf("generate device key: %w", err)
			}
			pub := priv.Public().(ed25519.PublicKey)
			publicMultibase := protocol.EncodeMultikey(pub)
			if _, err := keys.PutKey(keyAccount(publicMultibase), priv); err != nil {
				return fmt.Errorf("store device key in %s: %w", keys.Backend(), err)
			}
			mk := protocol.NewMultikeyPublicKey(protocol.DeriveKeyID(publicMultibase), pub)

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

			signer, err := selectHeldKey(chain.DID, chain.State.ControllerKeys, "controller")
			if err != nil {
				return err
			}
			controllerPriv, err := keys.GetPrivateKey(signer.Account)
			if err != nil {
				return fmt.Errorf("controller key not in keychain: %w", err)
			}

			lastToken := chain.Log[len(chain.Log)-1]
			h, _, err := protocol.DecodeJWSUnsafe(lastToken)
			if err != nil {
				return fmt.Errorf("decode last operation: %w", err)
			}

			// Key sets carried forward untouched — from DECLARED state, so this
			// operation moves the services set and nothing else. That does mean a
			// chain already carrying a void membership re-declares it here, and
			// re-declaring is re-introducing: a services-only change refuses until
			// that key is proved or dropped. It is the designed behavior, not an
			// accident of this command — a chain does not get to carry a key nobody
			// proved and have the fact quietly stop mattering.
			declared := declaredKeyState(chain)
			update := authoredUpdate{
				Prior: chain.State, PreviousCID: h.CID,
				ControllerKeys: declared.ControllerKeys, AuthKeys: declared.AuthKeys, AssertKeys: declared.AssertKeys,
				Services: plan.Services, Kid: signer.KID, PrivateKey: controllerPriv,
			}
			if err := proveAuthoredUpdate(chain.DID, &update); err != nil {
				return err
			}
			jwsToken, opCID, err := signAuthoredUpdate(update)
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

// newIdentityAddKeyCmd appends an externally-supplied PUBLIC key to a role set
// and signs the identity update with a controller key THIS device holds. It
// generates and stores no private key — the structural difference from `update`,
// which rotates by generating fresh local keys.
//
// IT REFUSES, AND THE REFUSAL IS THE POINT. A key enters a chain carrying its own
// signature over the introduction, and the whole shape of this command is a
// controller speaking for a key that lives somewhere else. There is no signature
// it can supply and none it may invent, so `proveAuthoredUpdate` refuses every
// invocation whose key this machine does not hold — which is every ordinary one.
// Publishing anyway would append a membership no proof admits: void, resolving
// nowhere, indexed nowhere, and indistinguishable on the chain from a hostile
// listing of somebody else's key.
//
// What remains reachable is the case where the key is genuinely held here, which
// this command still serves without ceremony. Everything else goes through the
// device that holds the key proving it: `dfos keys prove`.
func newIdentityAddKeyCmd() *cobra.Command {
	var peerName string
	var authKey bool
	var controllerKey bool
	var idFlag string
	var pubkeyFlag string

	cmd := &cobra.Command{
		Use:   "add-key",
		Short: "Add a public key this machine holds to a role set",
		Long: "Append a public key to this identity's auth or controller key set, signed with a controller key " +
			"this device holds.\n\n" +
			"A key enters a chain carrying its OWN signature over the introduction, so this command signs only " +
			"for a key whose private half is in this machine's keystore. A key generated on another device is " +
			"refused: a controller cannot vouch for material it does not hold, and appending it would publish a " +
			"membership no proof admits — void, resolving nowhere, indexed nowhere. The refusal names the key and " +
			"the two ways forward.\n\n" +
			"The route for another device's key is that device proving it: the ceremony operator displays a code, " +
			"and 'dfos keys add' presents the key from the machine that holds it.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !authKey && !controllerKey {
				return fmt.Errorf("specify --auth-key and/or --controller-key")
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
			signer, err := selectHeldKey(chain.DID, chain.State.ControllerKeys, "controller")
			if err != nil {
				return err
			}
			controllerPriv, err := keys.GetPrivateKey(signer.Account)
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
			// The id defaults to the one the key derives for itself, so the device
			// that generated the key and the device that publishes it name it the
			// same way without passing an id between them. An explicit --id still
			// wins: a key id is an opaque string, and a ceremony run elsewhere may
			// have already told the world what this key is called.
			keyID := idFlag
			if keyID == "" {
				keyID = protocol.DeriveKeyID(protocol.EncodeMultikey(ed25519.PublicKey(rawPub)))
			}
			newKey := protocol.NewMultikeyPublicKey(keyID, ed25519.PublicKey(rawPub))

			// determine head CID
			lastToken := chain.Log[len(chain.Log)-1]
			h, _, err := protocol.DecodeJWSUnsafe(lastToken)
			if err != nil {
				return fmt.Errorf("decode last operation: %w", err)
			}
			previousCID := h.CID

			// Seed all three sets from DECLARED state, then append into targets.
			declared := declaredKeyState(chain)
			newAuthKeys := declared.AuthKeys
			newControllerKeys := declared.ControllerKeys
			newAssertKeys := declared.AssertKeys
			var addedKeys []string

			if authKey {
				newAuthKeys, err = appendKeyGuarded(declared.AuthKeys, newKey)
				if err != nil {
					return fmt.Errorf("auth key set: %w", err)
				}
				addedKeys = append(addedKeys, "auth:"+newKey.ID)
			}
			if controllerKey {
				newControllerKeys, err = appendKeyGuarded(declared.ControllerKeys, newKey)
				if err != nil {
					return fmt.Errorf("controller key set: %w", err)
				}
				addedKeys = append(addedKeys, "controller:"+newKey.ID)
			}

			// The key this command publishes lives on ANOTHER device, so this one
			// cannot prove it and does not pretend to. The refusal names the two
			// real ways forward, and the one that works here is the other device
			// presenting its own proof.
			update := authoredUpdate{
				Prior: chain.State, PreviousCID: previousCID,
				ControllerKeys: newControllerKeys, AuthKeys: newAuthKeys, AssertKeys: newAssertKeys,
				Kid: signer.KID, PrivateKey: controllerPriv,
			}
			if err := proveAuthoredUpdate(chain.DID, &update); err != nil {
				return err
			}
			jwsToken, opCID, err := signAuthoredUpdate(update)
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
	cmd.Flags().StringVar(&idFlag, "id", "", "Key id to publish this key under (default: derived from --pubkey, which is what 'dfos identity device-pubkey' prints)")
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

			signer, err := selectHeldKey(chain.DID, chain.State.ControllerKeys, "controller")
			if err != nil {
				return err
			}
			controllerPriv, err := keys.GetPrivateKey(signer.Account)
			if err != nil {
				return fmt.Errorf("controller key not in keychain: %w", err)
			}

			lastToken := chain.Log[len(chain.Log)-1]
			h, _, err := protocol.DecodeJWSUnsafe(lastToken)
			if err != nil {
				return fmt.Errorf("decode last operation: %w", err)
			}

			jwsToken, opCID, err := protocol.SignIdentityDelete(h.CID, signer.KID, controllerPriv)
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

			signer, err := selectHeldKey(chain.DID, chain.State.ControllerKeys, "controller")
			if err != nil {
				return err
			}
			controllerPriv, err := keys.GetPrivateKey(signer.Account)
			if err != nil {
				return fmt.Errorf("controller key not in keychain: %w", err)
			}

			lastToken := chain.Log[len(chain.Log)-1]
			h, _, err := protocol.DecodeJWSUnsafe(lastToken)
			if err != nil {
				return fmt.Errorf("decode last operation: %w", err)
			}

			jwsToken, opCID, err := protocol.SignIdentityRestore(h.CID, signer.KID, controllerPriv)
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

			// One row per KEY, not per role membership. A key declared in three
			// roles is one key; three rows carrying the same id and the same
			// held-flag read as three keys, and after `identity create` that is
			// the ordinary case rather than an edge one.
			rows := chainKeyRoles(chain)

			if jsonFlag {
				type keyInfo struct {
					ID        string   `json:"id"`
					Roles     []string `json:"roles"`
					PublicKey string   `json:"publicKey"`
					// held, not "keychain": the flag says this machine's keystore
					// holds the private half, and the keystore is whichever backend
					// is in use — under DFOS_NO_KEYCHAIN it is a file store, and a
					// field named for one backend would report true from another.
					// The human table's column says HELD for the same reason.
					Held bool `json:"held"`
					// Void: every role this chain names the key in is declared and
					// never proved, so the key resolves nowhere.
					Void bool `json:"void,omitempty"`
				}
				items := make([]keyInfo, 0, len(rows))
				for _, r := range rows {
					items = append(items, keyInfo{r.Key.ID, r.Roles, r.Key.PublicKeyMultibase, r.Held, r.Void})
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
			fmt.Printf("%-36s %-34s %s\n", "KEY ID", "ROLES", "HELD")
			voids := 0
			for _, r := range rows {
				has := "-"
				if r.Held {
					has = "present"
				}
				if r.Void {
					voids++
				}
				fmt.Printf("%-36s %-34s %s\n", r.Key.ID, joinComma(r.Roles), has)
			}
			// A void membership is the one row whose meaning is not readable off
			// the table: it looks like a key, and it is a key the chain names, but
			// it resolves nowhere. Saying so once under the table beats a marker
			// nobody knows how to read.
			if voids > 0 {
				fmt.Printf("\n%d key(s) marked (void) are declared by this chain and never proved: they are not in\n", voids)
				fmt.Printf("effective state, they never resolve, and they never enter the key index. A key becomes\n")
				fmt.Printf("real by being introduced with its own possession proof.\n")
			}
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

// --- status: this machine's chain against the identity's own relay ---
//
// Every other local surface answers questions about the chain in this machine's
// relay as though that chain were the chain. It is not: it is one copy, and a
// copy can be behind the identity's own relay, ahead of it with operations that
// were never published, or forked away from it entirely. Nothing in the CLI
// could say which — so `keys list` reported a live key as superseded off a
// locally forked chain, at full confidence, and there was no command an operator
// could run to find out otherwise.
//
// This is that command. It fetches the log the identity's relay serves, verifies
// it, and compares it token for token against the log this machine holds. The
// comparison is byte equality over the ordered JWS tokens, which is the only
// thing that can distinguish "behind" from "diverged": two chains with the same
// operation count and different histories are a fork, and a head CID alone says
// nothing about where they parted.
//
// The relay that answered is NAMED in every output, the same discipline
// `recover` holds its oracle to. `in-sync` here means one relay's head is this
// machine's head; it is not a claim about the network, and nothing about a
// silent, unreachable, or unverifiable relay is ever reported as agreement.
const (
	// identityStatusInSync: same tokens, same order. One relay's answer.
	identityStatusInSync = "in-sync"
	// identityStatusBehind: this machine's log is a proper PREFIX of the relay's.
	// The relay holds operations this machine has never seen.
	identityStatusBehind = "behind"
	// identityStatusAhead: the relay's log is a proper prefix of this machine's.
	// Operations were signed here and never published.
	identityStatusAhead = "ahead-unpublished"
	// identityStatusDiverged: a common prefix, then two different histories. Both
	// sides extended the same past; neither is wrong on its face, and choosing
	// between them is an operator's decision, not this command's.
	identityStatusDiverged = "diverged"
	// identityStatusNoLocalChain: this machine holds no chain for the DID at all.
	// A reportable state rather than a failure — the relay's side still answers.
	identityStatusNoLocalChain = "no-local-chain"
	// identityStatusUnknown: the comparison could not be made. No relay to ask, a
	// relay that did not answer, or a chain that does not verify. NEVER in-sync.
	identityStatusUnknown = "unknown"
)

// identityStatusSide is one side of the comparison: a head, how many operations
// stand behind it, and when the last of them was written.
type identityStatusSide struct {
	HeadCID       string `json:"headCID"`
	Operations    int    `json:"operations"`
	LastCreatedAt string `json:"lastCreatedAt,omitempty"`
}

// identityStatusPeerRef is the relay that answered, and how it was chosen. Both
// halves are reported: an answer from a relay the operator named and an answer
// from the relay the identity advertises are different claims.
type identityStatusPeerRef struct {
	URL    string `json:"url"`
	Source string `json:"source"`
	Name   string `json:"name,omitempty"`
}

func (p *identityStatusPeerRef) label() string {
	if p == nil {
		return "no relay"
	}
	if p.Name != "" {
		return fmt.Sprintf("%s (%s)", p.Name, p.URL)
	}
	return p.URL
}

type identityStatusResult struct {
	DID     string `json:"did"`
	Name    string `json:"name,omitempty"`
	Verdict string `json:"verdict"`
	// Local and Remote are null rather than zero-valued when that side has no
	// chain: a head of "" and an operation count of 0 read as a fact about a
	// chain, and the fact here is that there is no chain.
	Local  *identityStatusSide    `json:"local"`
	Relay  *identityStatusPeerRef `json:"relay"`
	Remote *identityStatusSide    `json:"remote"`
	// BehindBy and AheadBy count the operations the other side has and this one
	// does not. Only the verdict's own count is set.
	BehindBy int `json:"behindBy,omitempty"`
	AheadBy  int `json:"aheadBy,omitempty"`
	// ForkIndex is the length of the common prefix on a divergence: index of the
	// first operation the two sides disagree about. A pointer because 0 is a real
	// answer — two chains that share nothing but their DID fork at the genesis.
	ForkIndex           *int   `json:"forkIndex,omitempty"`
	LocalForkCreatedAt  string `json:"localForkCreatedAt,omitempty"`
	RemoteForkCreatedAt string `json:"remoteForkCreatedAt,omitempty"`
	Reason              string `json:"reason,omitempty"`
}

func newIdentityStatusCmd() *cobra.Command {
	var peerName string
	cmd := &cobra.Command{
		Use:   "status <name|did>",
		Short: "Compare this machine's chain for an identity against the identity's relay",
		Long: "Fetch the operation log a relay serves for an identity, verify it, and compare it against the " +
			"chain this machine holds in its local relay. The relay asked is --peer when one is given, and " +
			"otherwise the DfosRelay endpoint the identity's own chain advertises; it is named in the output " +
			"either way.\n\n" +
			"Verdicts:\n" +
			"  in-sync            the relay's log and this machine's are the same operations in the same order\n" +
			"  behind             this machine's log is a prefix of the relay's — the relay has operations this machine lacks\n" +
			"  ahead-unpublished  the relay's log is a prefix of this machine's — operations signed here and never published\n" +
			"  diverged           a shared history, then two different ones. Choosing between them is an operator's decision\n" +
			"  no-local-chain     this machine holds no chain for the identity, so only the relay's side is reported\n" +
			"  unknown            the comparison could not be made (exit 1)\n\n" +
			"in-sync means THIS RELAY's head is this machine's head. It is one relay's answer and not a claim " +
			"about the network: another relay can hold a different chain, and this command says nothing about " +
			"one it did not ask. A relay that cannot be reached, does not serve the identity, or serves a chain " +
			"that does not verify is reported as unknown, named, with the error — never as agreement.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIdentityStatus(args[0], peerName)
		},
	}
	cmd.Flags().StringVar(&peerName, "peer", "", "Relay to compare against — outranks the identity's advertised DfosRelay endpoint")
	return cmd
}

func runIdentityStatus(target, peerOverride string) error {
	did, err := resolveIdentityDID(target)
	if err != nil {
		return err
	}
	lr, err := getRelay()
	if err != nil {
		return err
	}

	result := &identityStatusResult{DID: did, Name: config.FindIdentityName(cfg, did)}

	// The local side. No chain here is a REPORTABLE STATE, not an error: the
	// relay's side is still worth asking about, and "this machine holds nothing"
	// is an answer an operator came for rather than a failure to produce one.
	local, err := lr.Relay.GetIdentity(did)
	if err != nil {
		return fmt.Errorf("read the chain for %s from the local relay: %w", did, err)
	}
	var localLog []string
	if local != nil {
		localLog = local.Log
		result.Local = &identityStatusSide{
			HeadCID:       local.HeadCID,
			Operations:    len(local.Log),
			LastCreatedAt: local.LastCreatedAt,
		}
	}

	c, peer, err := identityStatusPeer(peerOverride, local)
	if err != nil {
		return err
	}
	if c == nil {
		return result.unknown("no relay to compare against: the identity advertises no DfosRelay service and no --peer was given")
	}
	result.Relay = peer

	remoteLog, err := c.GetIdentityLog(did)
	if err != nil {
		// One sentence for every way the ask fails — unreachable, 404, a body
		// that did not parse. They differ in cause and not in consequence: no
		// chain came back, so there is nothing to compare, and a relay holding
		// no chain for a DID is not evidence that this machine's is current.
		return result.unknown(fmt.Sprintf("%s could not answer for %s: %v", peer.label(), did, err))
	}
	// Verified before compared. An unverifiable log is not a chain, and comparing
	// against one would produce a verdict about bytes rather than about a history
	// — the two agree right up until the moment the answer matters.
	verified, err := protocol.VerifyIdentityChain(remoteLog)
	if err != nil {
		return result.unknown(fmt.Sprintf("the chain %s serves for %s does not verify: %v", peer.label(), did, err))
	}
	result.Remote = &identityStatusSide{
		HeadCID:       verified.HeadCID,
		Operations:    len(remoteLog),
		LastCreatedAt: verified.LastCreatedAt,
	}

	common := commonPrefixLen(localLog, remoteLog)
	switch {
	case local == nil:
		result.Verdict = identityStatusNoLocalChain
	case common == len(localLog) && common == len(remoteLog):
		result.Verdict = identityStatusInSync
	case common == len(localLog):
		result.Verdict = identityStatusBehind
		result.BehindBy = len(remoteLog) - common
	case common == len(remoteLog):
		result.Verdict = identityStatusAhead
		result.AheadBy = len(localLog) - common
	default:
		result.Verdict = identityStatusDiverged
		fork := common
		result.ForkIndex = &fork
		result.LocalForkCreatedAt = opCreatedAt(localLog[common])
		result.RemoteForkCreatedAt = opCreatedAt(remoteLog[common])
	}
	return result.emit()
}

// identityStatusPeer picks the relay this comparison asks, and says where the
// choice came from.
//
// The two failures here are deliberately different shapes. A --peer that does
// not resolve — an unknown name, a peer whose DID pin has moved — is an error
// about the COMMAND: the operator named a relay this machine will not use, and
// no comparison was attempted against anything. Having no relay to ask at all is
// a fact about the IDENTITY, so it comes back as (nil, nil, nil) and the caller
// reports it as the unknown verdict it is, with the rest of the document intact.
func identityStatusPeer(peerOverride string, chain *relay.StoredIdentityChain) (*client.Client, *identityStatusPeerRef, error) {
	if peerOverride != "" {
		c, name, err := getPeerClient(peerOverride)
		if err != nil {
			return nil, nil, err
		}
		return c, &identityStatusPeerRef{URL: c.BaseURL, Source: "--peer", Name: name}, nil
	}
	// The identity's own advertised relay, read out of the chain this machine
	// holds. It is the relay the identity says is its own, which is the only one
	// whose head means anything about whether an operation is published — and it
	// is read from local state, so a chain this machine does not hold advertises
	// nothing and there is nothing to ask.
	if chain == nil {
		return nil, nil, nil
	}
	endpoints := protocol.RelayEndpoints(chain.State.Services)
	if len(endpoints) == 0 {
		return nil, nil, nil
	}
	return client.New(endpoints[0]), &identityStatusPeerRef{URL: endpoints[0], Source: "advertised DfosRelay"}, nil
}

// commonPrefixLen counts the leading operations two logs agree about, byte for
// byte. A JWS token is a signature over its own position in a chain, so equal
// tokens are the same operation and unequal ones are the fork.
func commonPrefixLen(a, b []string) int {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// opCreatedAt reads one operation's own timestamp for the report. A token that
// will not decode reports nothing rather than a guess: the index is what locates
// the fork, and the date is there to make it recognizable to a person.
func opCreatedAt(token string) string {
	_, payload, err := protocol.DecodeJWSUnsafe(token)
	if err != nil || payload == nil {
		return ""
	}
	createdAt, _ := payload["createdAt"].(string)
	return createdAt
}

// unknown records why no comparison could be made and emits the document. The
// verdict is never omitted and never softened: an absent answer reported as
// silence is exactly how "in-sync" gets inferred from a relay that said nothing.
func (r *identityStatusResult) unknown(reason string) error {
	r.Verdict = identityStatusUnknown
	r.Reason = reason
	return r.emit()
}

// emit renders the result and returns the exit status. The five verdicts that
// are ANSWERS exit 0, whatever they say; `unknown` exits 1, because a script
// that cannot tell "I asked and they differ" from "I could not ask" will read
// the second as the first.
func (r *identityStatusResult) emit() error {
	if jsonFlag {
		outputJSON(r)
	} else {
		r.print()
	}
	if r.Verdict == identityStatusUnknown {
		return &ExitCodeError{Code: 1}
	}
	return nil
}

func (r *identityStatusResult) print() {
	fmt.Printf("DID:         %s\n", r.DID)
	if r.Name != "" {
		fmt.Printf("Name:        %s\n", r.Name)
	}
	if r.Local != nil {
		fmt.Printf("Local:       head %s — %d operation(s), %s\n",
			truncateMiddle(r.Local.HeadCID, 20), r.Local.Operations, orDash(r.Local.LastCreatedAt))
	} else {
		fmt.Printf("Local:       no chain for this identity in the local relay\n")
	}
	if r.Relay != nil {
		fmt.Printf("Relay:       %s — via %s\n", r.Relay.label(), r.Relay.Source)
	} else {
		fmt.Printf("Relay:       none — no relay was asked\n")
	}
	if r.Remote != nil {
		fmt.Printf("Remote:      head %s — %d operation(s), %s\n",
			truncateMiddle(r.Remote.HeadCID, 20), r.Remote.Operations, orDash(r.Remote.LastCreatedAt))
	}

	fmt.Println()
	switch r.Verdict {
	case identityStatusInSync:
		fmt.Printf("VERDICT: in-sync — this relay's head is this machine's head.\n")
		fmt.Printf("  That is %s answering about its own copy. Another relay can hold another chain.\n", r.Relay.label())

	case identityStatusBehind:
		fmt.Printf("VERDICT: behind — %s holds %d operation(s) this machine has not seen.\n", r.Relay.label(), r.BehindBy)
		fmt.Printf("  %s\n", identityStatusFetchHint(r))

	case identityStatusAhead:
		fmt.Printf("VERDICT: ahead-unpublished — this machine holds %d operation(s) that %s does not.\n", r.AheadBy, r.Relay.label())
		fmt.Printf("  %s\n", identityStatusPublishHint(r))

	case identityStatusDiverged:
		fork := 0
		if r.ForkIndex != nil {
			fork = *r.ForkIndex
		}
		fmt.Printf("VERDICT: diverged — both sides extended a shared history of %d operation(s) and then parted.\n", fork)
		fmt.Printf("  Fork at operation %d: this machine's divergent operation is dated %s, and the one\n",
			fork, orDash(r.LocalForkCreatedAt))
		fmt.Printf("  %s serves is dated %s.\n", r.Relay.label(), orDash(r.RemoteForkCreatedAt))
		fmt.Printf("  Neither side is the answer. Two histories exist over one DID, and which one this\n")
		fmt.Printf("  machine keeps is a decision an operator makes deliberately — nothing here makes it.\n")

	case identityStatusNoLocalChain:
		fmt.Printf("VERDICT: no-local-chain — this machine holds no chain for this identity, so there is\n")
		fmt.Printf("  nothing to compare. %s serves %d operation(s).\n", r.Relay.label(), r.Remote.Operations)
		fmt.Printf("  %s\n", identityStatusFetchHint(r))

	default:
		fmt.Printf("VERDICT: unknown — %s\n", r.Reason)
		fmt.Printf("  This is NOT in-sync. Nothing here says whether this machine's chain is current.\n")
		if r.Relay == nil {
			fmt.Printf("  '--peer <name>' names a relay to ask. 'dfos identity update --service\n")
			fmt.Printf("  id=relay,type=DfosRelay,endpoint=<url>' is how an identity comes to advertise its own.\n")
		}
	}
}

// identityStatusFetchHint names the command that brings the relay's operations
// here — with the peer's registered name when it has one, and with the step that
// gives it one when the relay came out of the chain instead. `identity fetch`
// takes a registered peer, so pointing at a bare URL would be a command that
// does not run.
func identityStatusFetchHint(r *identityStatusResult) string {
	if r.Relay != nil && r.Relay.Name != "" {
		return fmt.Sprintf("'dfos identity fetch %s --peer %s' brings them here.", r.DID, r.Relay.Name)
	}
	url := ""
	if r.Relay != nil {
		url = r.Relay.URL
	}
	return fmt.Sprintf("'dfos peer add <name> %s' registers it, then 'dfos identity fetch %s --peer <name>'.", url, r.DID)
}

// identityStatusPublishHint is the same rule for the other direction.
func identityStatusPublishHint(r *identityStatusResult) string {
	subject := firstNonEmpty(r.Name, r.DID)
	if r.Relay != nil && r.Relay.Name != "" {
		return fmt.Sprintf("'dfos identity publish %s --peer %s' puts them there.", subject, r.Relay.Name)
	}
	url := ""
	if r.Relay != nil {
		url = r.Relay.URL
	}
	return fmt.Sprintf("'dfos peer add <name> %s' registers it, then 'dfos identity publish %s --peer <name>'.", url, subject)
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
	// UnreadableCredentialFiles names the files in the credential store this
	// forget could not open or parse. A file that will not parse may be a grant
	// for this identity, so a forget that stepped over one removed what it could
	// read and no more — and says which files it could not, rather than
	// reporting a whole job on a partial view.
	UnreadableCredentialFiles []string `json:"unreadableCredentialFiles,omitempty"`
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
			// whole one. A file that will not parse is the one thing this cannot
			// remove and cannot vouch for, so it is carried out of the scan and
			// named below rather than stepped over.
			paths, _, unreadable, err := credentialFilesForSubject(result.DID)
			if err != nil {
				return err
			}
			for _, path := range paths {
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("remove stored login credential for %s: %w", result.DID, err)
				}
				result.CredentialRemoved = true
			}
			for _, path := range unreadable {
				result.UnreadableCredentialFiles = append(result.UnreadableCredentialFiles, filepath.Base(path))
			}
			sort.Strings(result.UnreadableCredentialFiles)
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
			// The partial view, said as a partial view. Removing what parsed and
			// stopping there is the right thing to do — a file this command cannot
			// read is a file it cannot claim is not a grant — but reporting it as a
			// whole forget would leave the operator believing a credential is gone
			// that may still be on disk.
			if len(result.UnreadableCredentialFiles) > 0 {
				fmt.Printf("  Credentials: partial — %d file(s) in %s did not parse and were left in place: %s\n",
					len(result.UnreadableCredentialFiles), credentialStoreDir(),
					strings.Join(result.UnreadableCredentialFiles, ", "))
				fmt.Println("  Read or delete those files yourself; one of them may still hold a grant for this identity.")
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
