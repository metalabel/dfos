package cmd

// `dfos keys` — the manifest of private key material this machine holds.
//
// It is a FOLD, not a store. Every field is computed on the spot from something
// that already exists — the keystore backend, the vaults' minted-key records,
// the identity chains in the local relay, the login client file — and nothing
// here writes a manifest of its own. A cached list of keys is a list that can
// disagree with the keystore, and a list that disagrees with the keystore is
// worse than no list, because `prune` acts on it. A fold cannot lie; it can only
// be incomplete, and where it is incomplete it says so.
//
// Two things are absent from this ledger BY CONSTRUCTION rather than by filter:
//
//   - The local relay's own key. It lives in the relay.db `relay_meta` table
//     (internal/localrelay bootstraps it there), not in the keystore, so a fold
//     over the keystore cannot reach it, cannot list it, and cannot prune it.
//     That is machine infrastructure: deleting it would orphan every operation
//     this node has sequenced.
//   - Vault mnemonics. They share the OS keychain SERVICE with key seeds, so an
//     enumeration of that service does see them — internal/keystore drops them
//     inside the enumerator itself, and `prune` re-checks before every delete.
//     A phrase deleted as if it were a key takes every key it minted with it.

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/keystore"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/localrelay"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/vault"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/spf13/cobra"
)

// Where a key's seed came from.
const (
	originVault       = "vault"        // a vault's minted-key record names it
	originStandalone  = "standalone"   // generated straight into the keystore
	originPending     = "pending"      // a `pending:` account — an unfinished create
	originLoginClient = "login-client" // this installation's SIWD client key
	originUnknown     = "unknown"      // the account is not in a shape this CLI writes
)

// What, if anything, currently declares the key.
const (
	// statusDeclared: an identity chain in the local relay names this key in a
	// current role. It is in use.
	statusDeclared = "declared"
	// statusSuperseded: the identity's chain IS local, and no longer names this
	// key. A rotation left it behind. It is not an orphan — this machine's view
	// of a chain can be behind the network's, and "not current here" is a
	// statement about this relay, not about the world.
	statusSuperseded = "superseded"
	// statusLoginClient: the per-install SIWD client key. Infrastructure.
	statusLoginClient = "login-client"
	// statusOrphan: nothing in the local relay declares it and nothing else
	// claims it. This is the only status prune acts on.
	statusOrphan = "orphan"
	// statusUnreadable: the backend holds something under this account that
	// cannot be read back as a key. Uncertain, therefore untouchable.
	statusUnreadable = "unreadable"
	// statusUnnamed: the backend proved something is there and cannot name it.
	// Uncertain, therefore untouchable.
	statusUnnamed = "unnamed"
	// statusUnrecognized: a named account in no shape this CLI writes. Uncertain,
	// therefore untouchable.
	statusUnrecognized = "unrecognized"
)

// pendingAccountPrefix is the transient account `identity create` mints under,
// before the DID exists to name the key by. A leftover one is the signature of
// a create that was interrupted between minting and renaming.
const pendingAccountPrefix = "pending:"

type keyVaultProvenance struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	Index       uint32 `json:"index"`
	Path        string `json:"derivationPath"`
}

// keyLedgerEntry is one key, folded. Nothing on it is secret: an account, an
// id, a PUBLIC key, and where each came from.
type keyLedgerEntry struct {
	Account string `json:"account,omitempty"`
	// Ref is the backend's own handle, carried only when the account is unknown.
	Ref         string              `json:"ref,omitempty"`
	KeyID       string              `json:"keyId,omitempty"`
	DID         string              `json:"did,omitempty"`
	Identity    string              `json:"identity,omitempty"`
	PublicKey   string              `json:"publicKey,omitempty"`
	Origin      string              `json:"origin"`
	Backend     string              `json:"backend"`
	Status      string              `json:"status"`
	Roles       []string            `json:"roles,omitempty"`
	Deleted     bool                `json:"identityDeleted,omitempty"`
	Vault       *keyVaultProvenance `json:"vault,omitempty"`
	Recoverable bool                `json:"recoverableFromVault"`
	Prunable    bool                `json:"prunable"`
	Reason      string              `json:"reason,omitempty"`
}

// keyLedger is the whole fold, plus an honest account of its own limits.
type keyLedger struct {
	Backend string `json:"backend"`
	// Enumerated is whether the backend listed ITSELF. When it is false the
	// ledger holds exactly the keys some other local store already knows to ask
	// for, which is every key in use and no leftovers — a real limit, stated
	// rather than papered over.
	Enumerated bool             `json:"enumerated"`
	Limit      string           `json:"enumerationLimit,omitempty"`
	Entries    []keyLedgerEntry `json:"keys"`
}

func newKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "keys",
		Short:   "List, inspect, and prune the private keys this machine holds",
		GroupID: "identity",
		Long: "Report every key in this machine's keystore: where its seed came from, which backend holds " +
			"it, and which identity's chain declares it. The report is derived from the keystore, the vaults' " +
			"minted-key records, and the identity chains in the local relay — there is no separate manifest " +
			"file to drift out of step. `prune` removes keys nothing declares. Private key material is never " +
			"printed.",
	}
	cmd.AddCommand(newKeysListCmd())
	cmd.AddCommand(newKeysShowCmd())
	cmd.AddCommand(newKeysPruneCmd())
	return cmd
}

// --- the fold ---

// buildKeyLedger derives the manifest. It reads; it writes nothing.
//
// The fold runs over the keys this machine HOLDS, and resolves outward from
// each of them. It does not run over the identity chains in the local relay and
// filter down: a relay that has synced the network holds tens of thousands of
// chains this machine has no key for, and folding over them costs the whole
// corpus — a full scan plus a JSON decode per chain — to answer a question about
// four keys. Every held account already NAMES its DID (`<did>#<keyId>`), so the
// declaring chain is a point lookup, and the work is O(keys held) either way the
// store grows.
func buildKeyLedger() (*keyLedger, error) {
	lr, err := getRelay()
	if err != nil {
		return nil, fmt.Errorf("open local relay: %w", err)
	}

	// What the vaults minted. A record is written only after the operation that
	// published the key succeeded, so this is provenance for keys that exist in
	// a chain — and, when a chain has since gone missing from this relay, the
	// evidence that a written-down phrase still covers the key.
	mintedBy := map[string]*keyVaultProvenance{}
	mintedPublic := map[string]string{}
	if vaults, err := getVaults().List(); err == nil {
		for _, meta := range vaults {
			for _, rec := range meta.Minted {
				account := rec.DID + "#" + rec.KeyID
				mintedBy[account] = &keyVaultProvenance{
					Name:        meta.Name,
					Fingerprint: meta.Fingerprint,
					Index:       rec.Index,
					Path:        vault.DerivationPath(rec.Index),
				}
				if rec.PublicKey != "" {
					mintedPublic[account] = rec.PublicKey
				}
			}
		}
	}

	// The login client key. Read, not verified: a login-client.json this CLI
	// would refuse to USE still names a key, and a key with a claimant is not an
	// orphan. Any `login-client__` account is infrastructure regardless — the
	// prefix is reserved for exactly this (see internal/cmd/login.go).
	loginAccount, loginDID := readLoginClientAccount()

	ledger := &keyLedger{Backend: keys.Backend(), Enumerated: true}

	// Held: what the backend says it has, plus every candidate it confirms.
	type held struct {
		account string
		ref     string
	}
	var order []held
	seen := map[string]bool{}
	// unnamed records that enumeration proved something is there and could not
	// say what it is called. A listing holding one does not account for
	// everything the backend holds, even though it succeeded.
	unnamed := false
	if enumerator, ok := keys.(keystore.Enumerator); ok {
		entries, err := enumerator.Entries()
		// A backend that CANNOT list itself and one whose listing FAILED land in
		// the same place on purpose: either way this ledger is a partial view, and
		// the only safe thing to do with a partial view is say so. Nothing
		// downstream may treat "not listed" as "not held".
		if err != nil {
			ledger.Enumerated = false
			ledger.Limit = err.Error()
		} else {
			for _, e := range entries {
				key := e.Account
				if key == "" {
					key = "\x00ref:" + e.Ref
					unnamed = true
				}
				if seen[key] {
					continue
				}
				seen[key] = true
				order = append(order, held{account: e.Account, ref: e.Ref})
			}
		}
	} else {
		ledger.Enumerated = false
		ledger.Limit = keystore.ErrNoEnumeration.Error()
	}
	if !ledger.Enumerated {
		ledger.Limit = fmt.Sprintf("%s — this ledger lists the keys the local relay, the vaults, "+
			"and the login client already name, and cannot see leftovers none of them mention", ledger.Limit)
	}

	// Candidates: accounts something else already knows to ask for, each probed
	// with HasKey. This is what makes the ledger work on a backend that cannot
	// list itself. The vaults' records and the login client name a handful
	// between them, so they are always probed.
	candidates := make([]string, 0, len(mintedBy)+1)
	for account := range mintedBy {
		candidates = append(candidates, account)
	}
	if loginAccount != "" {
		candidates = append(candidates, loginAccount)
	}
	// The chains are the third namer, and the expensive one: naming what they
	// declare means reading every chain in the local relay, and probing what they
	// name means one HasKey per declared key across the whole synced corpus —
	// tens of thousands of them on a relay that has followed the network, each a
	// subprocess on a keychain-backed store. It buys exactly one thing: a held
	// key the backend's own listing did not account for. So it runs when, and
	// only when, the listing left something unaccounted for. When enumeration
	// succeeded and named every entry, everything held is already in `seen` and
	// this probe can add nothing — running it would be the same answer at the
	// price of the corpus.
	if !ledger.Enumerated || unnamed {
		declared, err := declaredAccounts(lr)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, declared...)
	}
	sort.Strings(candidates)
	for _, account := range candidates {
		if seen[account] || !keys.HasKey(account) {
			continue
		}
		seen[account] = true
		order = append(order, held{account: account, ref: account})
	}

	// What the chains declare — resolved outward from the held keys, one point
	// lookup per DID they name, not a fold over every chain this relay has
	// synced. `declaredRoles` is keyed by account (`<did>#<keyId>`) so a key
	// bound to several roles is one entry with several roles, which is the common
	// production shape.
	declaredRoles := map[string][]string{}
	declaredPublic := map[string]string{}
	knownDID := map[string]bool{}
	deletedDID := map[string]bool{}
	resolved := map[string]bool{}
	for _, h := range order {
		if h.account == "" || strings.HasPrefix(h.account, loginClientAccountPrefix) ||
			!strings.Contains(h.account, "#") {
			continue
		}
		did := didFromKid(h.account)
		if resolved[did] {
			continue
		}
		resolved[did] = true
		chain, err := lr.Store.GetIdentityChain(did)
		if err != nil {
			return nil, fmt.Errorf("read the identity chain for %s from the local relay: %w", did, err)
		}
		if chain == nil {
			// No chain for this DID here. classifyKey reads that absence off
			// knownDID and calls the key an orphan — the same answer the fold over
			// every chain gave, reached without reading them.
			continue
		}
		knownDID[chain.DID] = true
		deletedDID[chain.DID] = chain.State.IsDeleted
		declare := func(set []protocol.MultikeyPublicKey, role string) {
			for _, k := range set {
				account := chain.DID + "#" + k.ID
				declaredRoles[account] = append(declaredRoles[account], role)
				declaredPublic[account] = k.PublicKeyMultibase
			}
		}
		declare(chain.State.ControllerKeys, "controller")
		declare(chain.State.AuthKeys, "auth")
		declare(chain.State.AssertKeys, "assert")
	}

	// Reading a seed is the expensive step on a keychain-backed store — one
	// subprocess per key — and it is only needed for a key nothing else can
	// name a public key for. Say so before a long one rather than look hung.
	unresolved := 0
	for _, h := range order {
		if h.account == "" {
			continue
		}
		if declaredPublic[h.account] == "" && mintedPublic[h.account] == "" {
			unresolved++
		}
	}
	if unresolved >= 50 && !jsonFlag {
		fmt.Fprintf(os.Stderr, "Reading %d key(s) from %s to recover their public keys…\n", unresolved, keys.Backend())
	}

	for _, h := range order {
		ledger.Entries = append(ledger.Entries, classifyKey(h.account, h.ref, classifyInputs{
			declaredRoles:  declaredRoles,
			declaredPublic: declaredPublic,
			mintedBy:       mintedBy,
			mintedPublic:   mintedPublic,
			knownDID:       knownDID,
			deletedDID:     deletedDID,
			loginAccount:   loginAccount,
			loginDID:       loginDID,
		}))
	}
	sort.SliceStable(ledger.Entries, func(i, j int) bool {
		a, b := ledger.Entries[i], ledger.Entries[j]
		if a.Status != b.Status {
			return statusRank(a.Status) < statusRank(b.Status)
		}
		return a.Account+a.Ref < b.Account+b.Ref
	})
	return ledger, nil
}

// declaredAccounts names every `<did>#<keyId>` the identity chains in the local
// relay currently declare.
//
// This is the one O(whole synced corpus) read left in the fold, and it exists
// for one caller: a backend that cannot account for what it holds, which has no
// way to find a held key except by being handed a name and asked. Everything
// else resolves outward from the keys themselves. See its call site for the
// condition that gates it.
func declaredAccounts(lr *localrelay.LocalRelay) ([]string, error) {
	chains, err := lr.Store.ListIdentityChains()
	if err != nil {
		return nil, fmt.Errorf("read identity chains from the local relay: %w", err)
	}
	accounts := make([]string, 0, len(chains))
	for i := range chains {
		chain := &chains[i]
		for _, set := range [][]protocol.MultikeyPublicKey{
			chain.State.ControllerKeys, chain.State.AuthKeys, chain.State.AssertKeys,
		} {
			for _, k := range set {
				accounts = append(accounts, chain.DID+"#"+k.ID)
			}
		}
	}
	return accounts, nil
}

// statusRank orders the report so the keys in use come first and the ones an
// operator is being asked to decide about come last.
func statusRank(status string) int {
	switch status {
	case statusDeclared:
		return 0
	case statusLoginClient:
		return 1
	case statusSuperseded:
		return 2
	case statusOrphan:
		return 3
	default:
		return 4
	}
}

type classifyInputs struct {
	declaredRoles  map[string][]string
	declaredPublic map[string]string
	mintedBy       map[string]*keyVaultProvenance
	mintedPublic   map[string]string
	knownDID       map[string]bool
	deletedDID     map[string]bool
	loginAccount   string
	loginDID       string
}

// classifyKey decides what ONE key is, and whether prune may touch it.
//
// The rule underneath every branch: prunable is set in exactly one place, for
// exactly one status, and every path that cannot establish what a key is falls
// through to a status that is not that one. Uncertainty is not an orphan.
func classifyKey(account, ref string, in classifyInputs) keyLedgerEntry {
	entry := keyLedgerEntry{Account: account, Backend: keys.Backend(), Origin: originUnknown}

	if account == "" {
		entry.Ref = ref
		entry.Status = statusUnnamed
		entry.Reason = "the backend holds this and cannot name it — an older key file whose name maps back to more than one account"
		return entry
	}

	// Belt and braces. Enumeration already drops these; a caller that built its
	// own candidate list has not.
	if keystore.IsReservedAccount(account) {
		entry.Status = statusUnrecognized
		entry.Reason = "reserved account — not a key seed"
		return entry
	}

	switch {
	case strings.HasPrefix(account, loginClientAccountPrefix):
		entry.Origin = originLoginClient
		entry.Status = statusLoginClient
		entry.KeyID = strings.TrimPrefix(account, loginClientAccountPrefix)
		entry.DID = in.loginDID
		if account == in.loginAccount {
			entry.Reason = "this installation's sign-in client key, named by " + loginClientFileName
		} else {
			entry.Reason = "a sign-in client key; " + loginClientFileName + " names a different one"
		}
	case strings.Contains(account, "#"):
		entry.DID = didFromKid(account)
		entry.KeyID = account[strings.Index(account, "#")+1:]
		entry.Identity = config.FindIdentityName(cfg, entry.DID)
		entry.Deleted = in.deletedDID[entry.DID]
		if roles, ok := in.declaredRoles[account]; ok {
			entry.Status = statusDeclared
			entry.Roles = roles
			if entry.Deleted {
				entry.Reason = "declared by a DELETED identity's chain — deletion is not revocation, and 'identity restore' is real"
			}
		} else if in.knownDID[entry.DID] {
			entry.Status = statusSuperseded
			entry.Reason = "the chain for this DID is in the local relay and no longer names this key — a rotation left it behind"
		} else {
			entry.Status = statusOrphan
			entry.Reason = "no chain for " + entry.DID + " in the local relay"
		}
	case strings.HasPrefix(account, pendingAccountPrefix):
		entry.Origin = originPending
		entry.KeyID = strings.TrimPrefix(account, pendingAccountPrefix)
		entry.Status = statusOrphan
		entry.Reason = "an 'identity create' that was interrupted before its DID existed — no chain can ever name it"
	default:
		entry.Status = statusUnrecognized
		entry.Reason = "not an account shape this CLI writes"
	}

	// Provenance, and with it the answer to what deleting the key would cost.
	if prov, ok := in.mintedBy[account]; ok {
		entry.Origin = originVault
		entry.Vault = prov
		entry.Recoverable = true
	} else if entry.Origin == originUnknown {
		entry.Origin = originStandalone
	}

	// The public key: from the chain, then from the vault's record, then — only
	// when nothing else can say — from the seed itself. Deriving it is also the
	// proof that the backend really holds a key here, which is why a failure
	// downgrades the entry to uncertain instead of being ignored.
	entry.PublicKey = in.declaredPublic[account]
	if entry.PublicKey == "" {
		entry.PublicKey = in.mintedPublic[account]
	}
	if entry.PublicKey == "" {
		priv, err := keys.GetPrivateKey(account)
		if err != nil {
			entry.Status = statusUnreadable
			entry.Reason = fmt.Sprintf("held under this account and not readable as a key: %v", err)
			return entry
		}
		entry.PublicKey = protocol.EncodeMultikey(priv.Public().(ed25519.PublicKey))
	}

	entry.Prunable = entry.Status == statusOrphan
	return entry
}

// readLoginClientAccount returns the keystore account and DID of the login
// client this installation records, or empty strings when there is none.
func readLoginClientAccount() (account, did string) {
	data, err := os.ReadFile(loginClientPath())
	if err != nil {
		return "", ""
	}
	var lc loginClient
	if err := json.Unmarshal(data, &lc); err != nil || lc.KeyID == "" {
		return "", ""
	}
	return loginClientAccount(lc.KeyID), lc.DID
}

// --- list ---

func newKeysListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every key this machine holds and what declares it",
		Long: "Fold the keystore, the vaults' minted-key records, and the identity chains in the local " +
			"relay into one manifest: for each key, its public key, where its seed came from, which backend " +
			"holds it, and which identity declares it and in which roles. Reads only.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ledger, err := buildKeyLedger()
			if err != nil {
				return err
			}
			if jsonFlag {
				outputJSON(ledger)
				return nil
			}
			printKeyLedger(ledger)
			return nil
		},
	}
}

func printKeyLedger(l *keyLedger) {
	fmt.Printf("Keys:      %d held (%s)\n", len(l.Entries), l.Backend)
	if !l.Enumerated {
		fmt.Printf("  Listing: partial — %s\n", l.Limit)
	}
	if len(l.Entries) == 0 {
		fmt.Println("\nNo keys. 'dfos identity create --name <name>' mints one.")
		return
	}

	fmt.Printf("\n%s %s %s %s %s\n", pad("KEY", 26), pad("PUBLIC KEY", 16), pad("ORIGIN", 12), pad("STATUS", 13), "DECLARED BY")
	for _, e := range l.Entries {
		fmt.Printf("%s %s %s %s %s\n",
			pad(truncateMiddle(keyLabel(e), 26), 26),
			pad(truncateMiddle(orDash(e.PublicKey), 16), 16),
			pad(e.Origin, 12),
			pad(e.Status, 13),
			declaredBy(e))
	}

	counts := map[string]int{}
	for _, e := range l.Entries {
		counts[e.Status]++
	}
	fmt.Println()
	for _, status := range []string{statusDeclared, statusLoginClient, statusSuperseded, statusOrphan,
		statusUnreadable, statusUnnamed, statusUnrecognized} {
		if counts[status] > 0 {
			fmt.Printf("  %-14s %d\n", status, counts[status])
		}
	}
	if counts[statusOrphan] > 0 {
		fmt.Printf("\n%d key(s) nothing declares. 'dfos keys prune' shows what removing them would cost.\n", counts[statusOrphan])
	}
	fmt.Printf("'dfos keys show <key-id|public-key>' reports one key in full.\n")
}

// keyLabel is how a key is addressed on a terminal: its key id where it has
// one, and the raw account or backend reference where it does not.
func keyLabel(e keyLedgerEntry) string {
	switch {
	case e.KeyID != "" && e.Status == statusLoginClient:
		return "login-client:" + e.KeyID
	case e.KeyID != "" && strings.HasPrefix(e.Account, pendingAccountPrefix):
		return pendingAccountPrefix + e.KeyID
	case e.KeyID != "":
		return e.KeyID
	case e.Account != "":
		return e.Account
	default:
		return "ref:" + e.Ref
	}
}

// declaredBy answers "who claims this key" in one column. For a key nothing
// claims it still names the DID the account carries, because "none" alone
// throws away the only clue an operator has about what the key was for.
func declaredBy(e keyLedgerEntry) string {
	if e.Status != statusDeclared {
		switch {
		case e.Status == statusSuperseded:
			return identityLabel(e) + " — no longer current"
		case e.DID != "":
			return "none — was " + truncateMiddle(e.DID, 28)
		default:
			return "none"
		}
	}
	label := identityLabel(e)
	if len(e.Roles) > 0 {
		label += " — " + strings.Join(e.Roles, ", ")
	}
	if e.Deleted {
		label += " (deleted)"
	}
	return label
}

func identityLabel(e keyLedgerEntry) string {
	if e.Identity != "" {
		return e.Identity
	}
	if e.DID != "" {
		return truncateMiddle(e.DID, 24)
	}
	return "none"
}

// --- show ---

func newKeysShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <key-id|public-key|account>",
		Short: "Show one key's origin, backend, provenance, and DID association",
		Long: "Report one key in full: its public key, the account it is stored under, where its seed came " +
			"from, which backend holds it, the vault and derivation index that minted it, and which identity " +
			"declares it in which roles. Private key material is never printed.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ledger, err := buildKeyLedger()
			if err != nil {
				return err
			}
			entry, err := findKeyEntry(ledger, args[0])
			if err != nil {
				return err
			}
			if jsonFlag {
				outputJSON(entry)
				return nil
			}
			printKeyEntry(*entry)
			return nil
		},
	}
}

// findKeyEntry resolves a selector against the ledger. It matches on the whole
// of a key id, public key, or account — never on a prefix, because two keys
// sharing a prefix is not a reason to act on whichever sorted first.
func findKeyEntry(l *keyLedger, selector string) (*keyLedgerEntry, error) {
	var matches []*keyLedgerEntry
	for i := range l.Entries {
		e := &l.Entries[i]
		if selector == e.Account || selector == e.Ref ||
			(e.KeyID != "" && selector == e.KeyID) ||
			(e.PublicKey != "" && selector == e.PublicKey) {
			matches = append(matches, e)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return nil, fmt.Errorf("no key matching '%s' — 'dfos keys list' shows what this machine holds", selector)
	default:
		var accounts []string
		for _, m := range matches {
			accounts = append(accounts, m.Account)
		}
		return nil, fmt.Errorf("'%s' matches %d keys (%s) — name one by its account",
			selector, len(matches), strings.Join(accounts, ", "))
	}
}

func printKeyEntry(e keyLedgerEntry) {
	fmt.Printf("Key:         %s\n", orDash(e.KeyID))
	fmt.Printf("  Public:    %s\n", orDash(e.PublicKey))
	if e.Account != "" {
		fmt.Printf("  Account:   %s\n", e.Account)
	} else {
		fmt.Printf("  Reference: %s (this backend cannot name it)\n", e.Ref)
	}
	fmt.Printf("  Backend:   %s\n", e.Backend)
	fmt.Printf("  Origin:    %s\n", e.Origin)
	if e.Vault != nil {
		fmt.Printf("  Vault:     %s [%s] at %s\n", e.Vault.Name, e.Vault.Fingerprint, e.Vault.Path)
		fmt.Printf("  Recovery:  derivable from vault '%s' phrase at %s\n", e.Vault.Name, e.Vault.Path)
	} else {
		fmt.Printf("  Vault:     none — no vault record names this key, so this keystore is its only copy\n")
	}
	if e.DID != "" {
		label := e.DID
		if e.Identity != "" {
			label = fmt.Sprintf("%s (%s)", e.Identity, e.DID)
		}
		fmt.Printf("  Identity:  %s\n", label)
	} else {
		fmt.Printf("  Identity:  none\n")
	}
	fmt.Printf("  Status:    %s\n", e.Status)
	if len(e.Roles) > 0 {
		fmt.Printf("  Roles:     %s\n", strings.Join(e.Roles, ", "))
	}
	if e.Deleted {
		fmt.Printf("  Note:      the identity is deleted — deletion is not revocation, and 'identity restore' is real\n")
	}
	if e.Reason != "" {
		fmt.Printf("  Why:       %s\n", e.Reason)
	}
	if e.Prunable {
		fmt.Printf("  Prune:     'dfos keys prune' would remove this key\n")
	} else {
		fmt.Printf("  Prune:     never — 'dfos keys prune' removes only keys with status %s\n", statusOrphan)
	}
}

// --- prune ---

func newKeysPruneCmd() *cobra.Command {
	var armed bool
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Remove keys no identity in the local relay declares (dry run by default)",
		Long: "Remove ORPHANS: keys this machine holds that nothing declares — the leftovers of an " +
			"interrupted 'identity create', and keys whose identity chain is not in the local relay. It " +
			"prints what it would remove and why, and removes nothing until --yes.\n\n" +
			"A key any local identity declares is never an orphan, including a DELETED identity's: deletion " +
			"is not revocation and 'identity restore' is real. A key whose status cannot be established is " +
			"never an orphan either — it is listed as skipped and left alone. The local relay's own key is " +
			"not in the keystore at all, so nothing here can reach it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ledger, err := buildKeyLedger()
			if err != nil {
				return err
			}
			return runKeysPrune(ledger, armed)
		},
	}
	cmd.Flags().BoolVar(&armed, "yes", false, "Actually remove the orphans (without it, nothing is deleted)")
	return cmd
}

type prunedKey struct {
	Account     string `json:"account"`
	KeyID       string `json:"keyId,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	Reason      string `json:"reason"`
	Recoverable bool   `json:"recoverableFromVault"`
	Vault       string `json:"vault,omitempty"`
	Removed     bool   `json:"removed"`
	Error       string `json:"error,omitempty"`
}

type pruneResult struct {
	Armed    bool        `json:"armed"`
	Orphans  []prunedKey `json:"orphans"`
	Skipped  []prunedKey `json:"skipped"`
	Removed  int         `json:"removed"`
	Failed   int         `json:"failed"`
	Retained int         `json:"retained"`
	Limit    string      `json:"enumerationLimit,omitempty"`
}

func runKeysPrune(l *keyLedger, armed bool) error {
	result := pruneResult{Armed: armed, Orphans: []prunedKey{}, Skipped: []prunedKey{}, Limit: l.Limit}
	for _, e := range l.Entries {
		row := prunedKey{
			Account:     e.Account,
			KeyID:       e.KeyID,
			PublicKey:   e.PublicKey,
			Reason:      e.Reason,
			Recoverable: e.Recoverable,
		}
		if e.Vault != nil {
			row.Vault = e.Vault.Name
		}
		switch {
		case e.Prunable:
			result.Orphans = append(result.Orphans, row)
		case isUncertain(e.Status):
			result.Skipped = append(result.Skipped, row)
			if row.Account == "" {
				row.Account = "ref:" + e.Ref
				result.Skipped[len(result.Skipped)-1] = row
			}
		default:
			result.Retained++
		}
	}

	if armed {
		for i := range result.Orphans {
			row := &result.Orphans[i]
			// Three questions, asked again at the last possible moment: is this a
			// key at all, is it still there, and is it still the account we judged.
			// The ledger is a snapshot; the delete is the act.
			if keystore.IsReservedAccount(row.Account) {
				row.Error = "reserved account — not a key seed"
				result.Failed++
				continue
			}
			if row.Account == "" {
				row.Error = "no account to delete"
				result.Failed++
				continue
			}
			if !keys.HasKey(row.Account) {
				row.Error = "no longer in the keystore"
				result.Failed++
				continue
			}
			if err := keys.DeleteKey(row.Account); err != nil {
				row.Error = err.Error()
				result.Failed++
				continue
			}
			row.Removed = true
			result.Removed++
		}
	}

	if jsonFlag {
		outputJSON(result)
		return nil
	}
	printPruneResult(result, l)
	return nil
}

func isUncertain(status string) bool {
	switch status {
	case statusUnreadable, statusUnnamed, statusUnrecognized:
		return true
	}
	return false
}

func printPruneResult(r pruneResult, l *keyLedger) {
	if r.Limit != "" {
		fmt.Printf("Listing:   partial — %s\n", r.Limit)
	}
	fmt.Printf("Held:      %d key(s) in %s\n", len(l.Entries), l.Backend)
	fmt.Printf("Retained:  %d declared, in use, or infrastructure\n", r.Retained)

	if len(r.Skipped) > 0 {
		fmt.Printf("\nSkipped — status could not be established, so these are NOT orphans:\n")
		for _, s := range r.Skipped {
			fmt.Printf("  %s %s\n", pad(truncateMiddle(s.Account, 40), 40), s.Reason)
		}
	}

	if len(r.Orphans) == 0 {
		fmt.Printf("\nNo orphans. Nothing to remove.\n")
		return
	}

	if !r.Armed {
		fmt.Printf("\nWould remove %d orphan(s):\n\n", len(r.Orphans))
	} else {
		fmt.Printf("\nRemoving %d orphan(s):\n\n", len(r.Orphans))
	}
	fmt.Printf("%s %s %s\n", pad("ACCOUNT", 44), pad("RECOVERY", 16), "WHY IT IS AN ORPHAN")
	for _, o := range r.Orphans {
		recovery := "unrecoverable"
		if o.Recoverable {
			recovery = "vault:" + o.Vault
		}
		fmt.Printf("%s %s %s\n", pad(truncateMiddle(o.Account, 44), 44), pad(recovery, 16), o.Reason)
	}

	recoverable, unrecoverable := 0, 0
	for _, o := range r.Orphans {
		if o.Recoverable {
			recoverable++
		} else {
			unrecoverable++
		}
	}
	fmt.Println()
	if recoverable > 0 {
		fmt.Printf("  %d derivable again from a vault's recovery phrase.\n", recoverable)
	}
	if unrecoverable > 0 {
		fmt.Printf("  %d exist only in this keystore — once removed the seed is gone for good.\n", unrecoverable)
	}

	if !r.Armed {
		fmt.Printf("\nNothing was removed. Re-run with --yes to remove them.\n")
		return
	}
	fmt.Printf("\nRemoved:   %d\n", r.Removed)
	if r.Failed > 0 {
		fmt.Printf("Failed:    %d\n", r.Failed)
		for _, o := range r.Orphans {
			if o.Error != "" {
				fmt.Printf("  %s %s\n", pad(truncateMiddle(o.Account, 44), 44), o.Error)
			}
		}
	}
}

// --- small helpers ---

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// pad right-pads to a column width in RUNES. fmt's %-Ns counts bytes, and the
// ellipsis truncateMiddle inserts is three of them, so every truncated cell
// would otherwise pull its row two columns out of alignment.
func pad(s string, width int) string {
	if n := len([]rune(s)); n < width {
		return s + strings.Repeat(" ", width-n)
	}
	return s
}

// truncateMiddle keeps both ends of an identifier, which is how a person
// actually recognizes one: the head says what kind of thing it is and the tail
// is what distinguishes it from its neighbors.
func truncateMiddle(s string, width int) string {
	if width < 5 || len([]rune(s)) <= width {
		return s
	}
	runes := []rune(s)
	head := (width - 1) / 2
	tail := width - 1 - head
	return string(runes[:head]) + "…" + string(runes[len(runes)-tail:])
}
