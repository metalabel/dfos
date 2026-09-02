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
	"slices"
	"sort"
	"strings"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/keystore"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/localrelay"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/vault"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
	"github.com/spf13/cobra"
)

// Where a key's seed came from.
const (
	originVault       = "vault"        // a vault's minted-key record names it
	originStandalone  = "standalone"   // generated straight into the keystore
	originPending     = "pending"      // a `pending:` account — an unfinished create
	originCandidate   = "candidate"    // a `candidate:` account — a key-proof ceremony key
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
	// statusCandidate: a key `keys prove` presented to a key-add ceremony. No
	// chain here names it, and that is its normal state — the chain that adopts
	// it is custodied by the ceremony operator, not by this machine. It is not an
	// orphan and prune never removes it.
	statusCandidate = "candidate"
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

// chainAsOf is the basis of a verdict derived from a chain in THIS machine's
// local relay: the head that answered, and when that head was written.
type chainAsOf struct {
	HeadCID       string `json:"headCID"`
	LastCreatedAt string `json:"lastCreatedAt"`
}

// chainBasis renders that basis as one clause, and every negative verdict a
// local chain produces carries it.
//
// A chain in the local relay answers "this key is no longer named" with exactly
// the confidence of a chain that is up to date, whether or not it is one. A
// machine that forked its chain locally, or simply never synced, says the same
// sentence about a key its identity's own relay still declares live — and
// nothing in the sentence lets a reader tell the two apart. Naming the head and
// its date converts the verdict from a claim about the world into a claim about
// a specific, checkable piece of local state; saying no relay was asked is the
// other half, because the reader's next question is always whether one was.
//
// It carries NO em-dash of its own. The verdicts it attaches to already spend
// one on the finding, and a clause appended after that dash reads as a second
// half of the same thought rather than as the ground under it — so the callers
// bracket it instead, in parentheses or in a sentence of its own.
func chainBasis(headCID, lastCreatedAt string) string {
	head := truncateMiddle(orDash(headCID), 16)
	if lastCreatedAt == "" {
		return fmt.Sprintf("as of local head %s; the identity's relay was not consulted", head)
	}
	return fmt.Sprintf("as of local head %s, %s; the identity's relay was not consulted", head, lastCreatedAt)
}

type keyVaultProvenance struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	Index       uint32 `json:"index"`
	Path        string `json:"derivationPath"`
}

// vaultProvenanceIndex maps every account a minted key can answer to onto the
// vault record that minted it. It is the provenance half of the join
// buildKeyLedger performs inline, on its own for readers that want only "which
// phrase covers this key" and none of the ledger's enumeration or corpus work.
//
// A vault store that will not list is REPORTED, not papered over with an empty
// index. An empty index and an unreadable one produce the same lookups and
// opposite truths: the first says no phrase covers this key, the second says
// nobody knows — and a caller that renders the first sentence off the second
// condition tells an operator their only copy is a keystore that a written-down
// phrase in fact covers.
func vaultProvenanceIndex() (map[string]*keyVaultProvenance, error) {
	index := map[string]*keyVaultProvenance{}
	vaults, err := getVaults().List()
	if err != nil {
		return nil, err
	}
	for _, meta := range vaults {
		for _, rec := range meta.Minted {
			prov := &keyVaultProvenance{
				Name:        meta.Name,
				Fingerprint: meta.Fingerprint,
				Index:       rec.Index,
				Path:        vault.DerivationPath(rec.Index),
			}
			for _, account := range keyAccountsFor(rec.DID, rec.KeyID, rec.PublicKey) {
				index[account] = prov
			}
		}
	}
	return index, nil
}

// keyLedgerEntry is one key, folded. Nothing on it is secret: an account, an
// id, a PUBLIC key, and where each came from.
type keyLedgerEntry struct {
	Account string `json:"account,omitempty"`
	// Ref is the backend's own handle, carried only when the account is unknown.
	Ref       string `json:"ref,omitempty"`
	KeyID     string `json:"keyId,omitempty"`
	DID       string `json:"did,omitempty"`
	Identity  string `json:"identity,omitempty"`
	PublicKey string `json:"publicKey,omitempty"`
	Origin    string `json:"origin"`
	Backend   string `json:"backend"`
	Status    string `json:"status"`
	// Roles is what the chain says this key is for. On a declared key those are
	// its CURRENT roles; on a superseded one they are the roles it held before
	// the rotation that retired it, read back out of the log. The status field
	// is what distinguishes the two, and it is always set.
	//
	// A role the chain declares but no possession proof admitted is marked
	// `<role> (void)`. It is listed rather than dropped, because the chain really
	// does name the key there — and marked rather than merged, because a void
	// membership confers nothing: it is not in effective state, it never
	// resolves, and it never indexes.
	Roles []string `json:"roles,omitempty"`
	// Void is true when EVERY role this chain names the key in is void. Such a
	// key is claimed by a chain and effective in none of it — neither a working
	// key nor an orphan — and the two readers that care (this ledger's reason
	// line, and the one-key-one-DID pre-flight in `keys prove`) both have to tell
	// it apart from a key that works.
	Void        bool                `json:"void,omitempty"`
	Deleted     bool                `json:"identityDeleted,omitempty"`
	Vault       *keyVaultProvenance `json:"vault,omitempty"`
	Recoverable bool                `json:"recoverableFromVault"`
	Prunable    bool                `json:"prunable"`
	Reason      string              `json:"reason,omitempty"`
	// AsOf is the basis of a NEGATIVE chain-derived verdict about this key: the
	// local relay's head for the declaring identity, and when that head was
	// written. It is set on `superseded` and on nothing else, because that is the
	// verdict a stale local chain makes dangerous — a key the relay still names
	// live, reported here as retired, with no hint that the chain behind the
	// report is a fork or a month old.
	//
	// The prose reason carries the same two facts with the CID truncated for a
	// terminal; this carries it whole, so a caller can compare it byte for byte
	// against what a relay serves.
	AsOf *chainAsOf `json:"asOf,omitempty"`
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
		Short:   "List, inspect, prune, and remove the private keys this machine holds",
		GroupID: "identity",
		Long: "Report every key in this machine's keystore: where its seed came from, which backend holds " +
			"it, and which identity's chain declares it. The report is derived from the keystore, the vaults' " +
			"minted-key records, and the identity chains in the local relay — there is no separate manifest " +
			"file to drift out of step. `prune` sweeps the keys nothing declares; `remove` takes one key by " +
			"name. Private key material is never printed.",
	}
	cmd.AddCommand(newKeysListCmd())
	cmd.AddCommand(newKeysShowCmd())
	cmd.AddCommand(newKeysPruneCmd())
	cmd.AddCommand(newKeysRemoveCmd())
	cmd.AddCommand(newKeysProveCmd())
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
	// Each record is filed under BOTH accounts a key can answer to — its content
	// address and the DID-scoped account earlier versions wrote — so provenance
	// reaches a key whichever shape this machine holds it under. The record is
	// also the cheapest thing that can say which identity a content-addressed key
	// belongs to, which is why mintedDID exists.
	mintedBy := map[string]*keyVaultProvenance{}
	mintedPublic := map[string]string{}
	mintedDID := map[string]string{}
	mintedKeyID := map[string]string{}
	if vaults, err := getVaults().List(); err == nil {
		for _, meta := range vaults {
			for _, rec := range meta.Minted {
				prov := &keyVaultProvenance{
					Name:        meta.Name,
					Fingerprint: meta.Fingerprint,
					Index:       rec.Index,
					Path:        vault.DerivationPath(rec.Index),
				}
				for _, account := range keyAccountsFor(rec.DID, rec.KeyID, rec.PublicKey) {
					mintedBy[account] = prov
					if rec.PublicKey != "" {
						mintedPublic[account] = rec.PublicKey
					}
					mintedDID[account] = rec.DID
					mintedKeyID[account] = rec.KeyID
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
	// lookup per DID, not a fold over every chain this relay has synced.
	// `declaredRoles` is keyed by account so a key bound to several roles is one
	// entry with several roles, which is the shape `identity create` mints.
	//
	// A DID-scoped account NAMES its DID, so it is a point lookup on sight. A
	// content-addressed one does not — the address is a property of the key, and
	// which identity declares it is a property of a chain — so its DID comes from
	// a vault record or from the identity roster in config, both of which this
	// machine already holds. Only a held key NEITHER can place sends this to the
	// whole corpus, and it says so before it goes.
	declaredRoles := map[string][]string{}
	voidRoles := map[string][]string{}
	declaredPublic := map[string]string{}
	accountDID := map[string]string{}
	accountKeyID := map[string]string{}
	knownDID := map[string]bool{}
	deletedDID := map[string]bool{}
	chainByDID := map[string]*relay.StoredIdentityChain{}
	// basisByDID is what every chain-derived verdict below is derived FROM: the
	// head this fold read, and its date. It is carried beside knownDID because
	// the two are read together — a verdict that leans on "the chain is here"
	// has to be able to say which chain, at which head.
	basisByDID := map[string]chainAsOf{}
	resolved := map[string]bool{}

	declareChain := func(chain *relay.StoredIdentityChain) {
		knownDID[chain.DID] = true
		deletedDID[chain.DID] = chain.State.IsDeleted
		chainByDID[chain.DID] = chain
		basisByDID[chain.DID] = chainAsOf{HeadCID: chain.HeadCID, LastCreatedAt: chain.LastCreatedAt}
		place := func(account string, k protocol.MultikeyPublicKey) {
			declaredPublic[account] = k.PublicKeyMultibase
			accountDID[account] = chain.DID
			accountKeyID[account] = k.ID
		}
		declare := func(set []protocol.MultikeyPublicKey, role string) {
			for _, k := range set {
				for _, account := range keyAccountsFor(chain.DID, k.ID, k.PublicKeyMultibase) {
					declaredRoles[account] = append(declaredRoles[account], role)
					place(account, k)
				}
			}
		}
		// Effective state first — the memberships a possession proof admitted.
		declare(chain.State.ControllerKeys, "controller")
		declare(chain.State.AuthKeys, "auth")
		declare(chain.State.AssertKeys, "assert")
		// Then the VOID ones: memberships the chain declares and no proof ever
		// admitted. They are placed exactly like effective ones — same account,
		// same DID, same key id — because the fact they establish is the same one
		// the placement is for: this chain names this key. What differs is that
		// naming it did not make it work, and that difference is carried in the
		// role marker rather than by leaving the key unplaced.
		//
		// Leaving them out is what this fold used to do by accident, and it was
		// the worst of the three options: a held key under a void declaration fell
		// through every placement branch and came out an ORPHAN, with the reason
		// "no identity in the local relay declares this key" — which is precisely
		// backwards. A chain declares it. The declaration is just empty.
		for _, void := range chain.State.VoidKeys {
			for _, account := range keyAccountsFor(chain.DID, void.Key.ID, void.Key.PublicKeyMultibase) {
				voidRoles[account] = append(voidRoles[account], string(void.Role)+" (void)")
				place(account, void.Key)
			}
		}
	}
	lookupDID := func(did string) error {
		if did == "" || resolved[did] {
			return nil
		}
		resolved[did] = true
		chain, err := lr.Store.GetIdentityChain(did)
		if err != nil {
			return fmt.Errorf("read the identity chain for %s from the local relay: %w", did, err)
		}
		if chain == nil {
			// No chain for this DID here. classifyKey reads that absence off
			// knownDID and calls the key an orphan — the same answer the fold over
			// every chain gave, reached without reading them.
			return nil
		}
		declareChain(chain)
		return nil
	}

	for _, h := range order {
		if h.account == "" || strings.HasPrefix(h.account, loginClientAccountPrefix) {
			continue
		}
		switch {
		case didScopedAccount(h.account):
			if err := lookupDID(didFromKid(h.account)); err != nil {
				return nil, err
			}
		case strings.HasPrefix(h.account, keyAccountPrefix):
			if err := lookupDID(mintedDID[h.account]); err != nil {
				return nil, err
			}
		}
	}
	// The identity roster: every DID this machine has a name for. That is the set
	// whose keys it plausibly holds, and it covers the one case a vault record
	// cannot — an identity minted with --no-vault, whose key has no provenance
	// record to be found through.
	for _, ic := range cfg.Identities {
		if err := lookupDID(ic.DID); err != nil {
			return nil, err
		}
	}

	// Anything still unplaced. A content-addressed key no chain here declares may
	// be an orphan, or may belong to a chain this relay holds under a DID nothing
	// local names — and those two are not the same answer, so the corpus is read
	// rather than guessed at. See declaredAccounts for why this is the expensive
	// path and why it is gated.
	unplaced := 0
	for _, h := range order {
		if h.account == "" || !strings.HasPrefix(h.account, keyAccountPrefix) {
			continue
		}
		_, placed := declaredRoles[h.account]
		if _, void := voidRoles[h.account]; !placed && !void {
			unplaced++
		}
	}
	if unplaced > 0 {
		if !jsonFlag {
			fmt.Fprintf(os.Stderr, "Reading the local relay's identity chains to place %d key(s) nothing local names…\n", unplaced)
		}
		chains, err := lr.Store.ListIdentityChains()
		if err != nil {
			return nil, fmt.Errorf("read identity chains from the local relay: %w", err)
		}
		for i := range chains {
			if resolved[chains[i].DID] {
				continue
			}
			resolved[chains[i].DID] = true
			declareChain(&chains[i])
		}
	}

	// What a SUPERSEDED key used to be. Current state cannot say — that is what
	// superseded means — but the operation that retired the key is still in the
	// log, and a rotation the ledger reports without naming the role it retired
	// is a fact with its subject removed. The log is also the only place that can
	// say WHICH identity a retired content-addressed key belonged to: the account
	// is a property of the key, and the relationship it lost lives in an
	// operation, not in a name.
	//
	// So the logs are read back, for exactly the held accounts current state
	// could not place and no others: with nothing superseded on this machine, no
	// chain is walked at all.
	supersededRoles := map[string][]string{}
	want := map[string]bool{}
	for _, h := range order {
		if h.account == "" || strings.HasPrefix(h.account, loginClientAccountPrefix) {
			continue
		}
		if _, declared := declaredRoles[h.account]; declared {
			continue
		}
		// A void membership places the key too. Its roles are not what a rotation
		// retired, so reading the log for them would answer a question nobody
		// asked and overwrite a placement that is already correct.
		if _, void := voidRoles[h.account]; void {
			continue
		}
		want[h.account] = true
	}
	if len(want) > 0 {
		for _, chain := range chainByDID {
			for account, p := range placementsFromLog(chain, want) {
				supersededRoles[account] = p.roles
				if accountDID[account] == "" {
					accountDID[account] = p.did
					accountKeyID[account] = p.keyID
				}
			}
		}
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
			declaredRoles:   declaredRoles,
			voidRoles:       voidRoles,
			declaredPublic:  declaredPublic,
			supersededRoles: supersededRoles,
			mintedBy:        mintedBy,
			mintedPublic:    mintedPublic,
			accountDID:      accountDID,
			accountKeyID:    accountKeyID,
			mintedDID:       mintedDID,
			mintedKeyID:     mintedKeyID,
			knownDID:        knownDID,
			deletedDID:      deletedDID,
			basisByDID:      basisByDID,
			loginAccount:    loginAccount,
			loginDID:        loginDID,
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
				accounts = append(accounts, keyAccountsFor(chain.DID, k.ID, k.PublicKeyMultibase)...)
			}
		}
		// Void memberships name accounts too. This list is what a backend that
		// cannot enumerate itself gets probed against, so omitting them would make
		// a held void key INVISIBLE on such a backend — the one place the ledger's
		// honesty about voids would silently stop applying.
		for _, void := range chain.State.VoidKeys {
			accounts = append(accounts, keyAccountsFor(chain.DID, void.Key.ID, void.Key.PublicKeyMultibase)...)
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
	case statusCandidate:
		return 3
	case statusOrphan:
		return 4
	default:
		return 5
	}
}

// logPlacement is where one key sat in one identity's history: the identity, the
// id it was declared under there, and every role it ever held.
type logPlacement struct {
	did   string
	keyID string
	roles []string
}

// placementsFromLog reads an identity's operation log and reports, for each of
// the wanted accounts, the identity and every role that identity ever declared
// the key in. The role sets are full-state on each operation, so a key that
// appears in one and not the next was rotated out — but this asks only what it
// WAS, which no later operation can take back.
//
// A malformed or undecodable operation is skipped rather than fatal: the log
// was already verified when it was ingested, and a ledger that refuses to
// report because one historical operation reads oddly is worse than one that
// reports what the rest of the log says.
func placementsFromLog(chain *relay.StoredIdentityChain, want map[string]bool) map[string]logPlacement {
	roleFields := [...]struct{ field, role string }{
		{"controllerKeys", "controller"},
		{"authKeys", "auth"},
		{"assertKeys", "assert"},
	}
	held := map[string]map[string]bool{}
	keyIDFor := map[string]string{}
	for _, token := range chain.Log {
		_, payload, err := protocol.DecodeJWSUnsafe(token)
		if err != nil || payload == nil {
			continue
		}
		for _, rf := range roleFields {
			entries, ok := payload[rf.field].([]any)
			if !ok {
				continue
			}
			for _, raw := range entries {
				item, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				id, _ := item["id"].(string)
				if id == "" {
					continue
				}
				pub, _ := item["publicKeyMultibase"].(string)
				// The log carries the public key beside the id, so a retired key
				// is findable under either addressing without a second source.
				for _, account := range keyAccountsFor(chain.DID, id, pub) {
					if !want[account] {
						continue
					}
					if held[account] == nil {
						held[account] = map[string]bool{}
						keyIDFor[account] = id
					}
					held[account][rf.role] = true
				}
			}
		}
	}
	// Emitted in the same order the current-state fold emits declared roles, so
	// one key's roles read the same whichever side of a rotation it is on.
	out := make(map[string]logPlacement, len(held))
	for account, roles := range held {
		p := logPlacement{did: chain.DID, keyID: keyIDFor[account]}
		for _, rf := range roleFields {
			if roles[rf.role] {
				p.roles = append(p.roles, rf.role)
			}
		}
		out[account] = p
	}
	return out
}

type classifyInputs struct {
	declaredRoles map[string][]string
	// voidRoles are the `<role> (void)` markers for memberships a chain declares
	// and no proof admitted — kept apart from declaredRoles so "does this key
	// work anywhere" stays a question with a one-map answer.
	voidRoles      map[string][]string
	declaredPublic map[string]string
	// supersededRoles is what a retired key USED to be, read out of the log —
	// keyed by account, and populated only for accounts current state cannot
	// place.
	supersededRoles map[string][]string
	mintedBy        map[string]*keyVaultProvenance
	mintedPublic    map[string]string
	// accountDID and accountKeyID place a CONTENT-ADDRESSED account: the account
	// is a property of the key alone, so which identity declares it and under
	// which key id are looked up rather than parsed out of the name.
	accountDID   map[string]string
	accountKeyID map[string]string
	mintedDID    map[string]string
	mintedKeyID  map[string]string
	knownDID     map[string]bool
	deletedDID   map[string]bool
	// basisByDID is the head each declaring chain was read at. Only the negative
	// verdicts use it, and they use it to say so out loud.
	basisByDID   map[string]chainAsOf
	loginAccount string
	loginDID     string
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
	case strings.HasPrefix(account, keyAccountPrefix), didScopedAccount(account):
		// Two addressings, one classification. A DID-scoped account carries its
		// DID and key id in the name; a content-addressed one carries its public
		// key, and the DID and key id are whatever a chain or a provenance record
		// says. Everything after this point reads the same fields either way.
		//
		// The DID-scoped arm requires the FULL shape, not merely a '#'. Parsing a
		// DID out of an account this CLI never wrote invents an identity, and an
		// invented identity has no chain, and no chain is the orphan verdict prune
		// deletes on. See didScopedAccount.
		if pub, ok := publicKeyFromAccount(account); ok {
			entry.PublicKey = pub
			entry.DID = firstNonEmpty(in.accountDID[account], in.mintedDID[account])
			entry.KeyID = firstNonEmpty(in.accountKeyID[account], in.mintedKeyID[account])
		} else {
			entry.DID = didFromKid(account)
			entry.KeyID = account[strings.Index(account, "#")+1:]
		}
		entry.Identity = config.FindIdentityName(cfg, entry.DID)
		entry.Deleted = in.deletedDID[entry.DID]
		switch {
		case len(in.declaredRoles[account]) > 0 || len(in.voidRoles[account]) > 0:
			entry.Status = statusDeclared
			// Effective roles first, then the void ones. The order is the point:
			// what the key DOES comes before what a chain merely says about it.
			entry.Roles = append(append([]string{}, in.declaredRoles[account]...), in.voidRoles[account]...)
			entry.Void = len(in.declaredRoles[account]) == 0
			switch {
			case entry.Void:
				// The whole reason this branch exists. A key claimed by a chain
				// and effective nowhere in it is a real state with a real fix, and
				// a person who is not told will read the row as a working key.
				entry.Reason = "declared by " + entry.DID + " and never proved — the membership is VOID: it is not in " +
					"effective state, it never resolves, and it obligates nobody. A key becomes real by presenting its " +
					"own proof ('dfos keys add')"
			case entry.Deleted:
				entry.Reason = "declared by a DELETED identity's chain — deletion is not revocation, and 'identity restore' is real"
			case len(in.voidRoles[account]) > 0:
				entry.Reason = "some roles this chain declares for the key were never proved — those are void and confer nothing"
			}
		case entry.DID != "" && in.knownDID[entry.DID]:
			entry.Status = statusSuperseded
			entry.Roles = in.supersededRoles[account]
			// The verdict and its basis are written in one breath, because the
			// verdict without the basis is the sentence that misled: "no longer
			// names this key", stated at full confidence, off a chain that had been
			// forked locally while the identity's own relay served a newer head
			// naming the key live.
			stamp := ""
			if basis, ok := in.basisByDID[entry.DID]; ok {
				entry.AsOf = &chainAsOf{HeadCID: basis.HeadCID, LastCreatedAt: basis.LastCreatedAt}
				stamp = " (" + chainBasis(basis.HeadCID, basis.LastCreatedAt) + ")"
			}
			entry.Reason = "the chain for this DID is in the local relay and no longer names this key — a rotation left it behind" + stamp
			if len(entry.Roles) > 0 {
				entry.Reason = "the chain for this DID is in the local relay and no longer names this key — a rotation retired it from " +
					strings.Join(entry.Roles, ", ") + stamp
			}
		case entry.DID != "":
			entry.Status = statusOrphan
			entry.Reason = "no chain for " + entry.DID + " in the local relay"
		default:
			// A content-addressed key nothing places. Every chain in the local
			// relay was read to get here (see buildKeyLedger), so no identity
			// this machine holds declares it and no vault records minting it.
			entry.Status = statusOrphan
			entry.Reason = "no identity in the local relay declares this key, and no vault records minting it"
		}
	case strings.HasPrefix(account, pendingAccountPrefix):
		entry.Origin = originPending
		entry.KeyID = strings.TrimPrefix(account, pendingAccountPrefix)
		entry.Status = statusOrphan
		entry.Reason = "an 'identity create' that was interrupted before its DID existed — no chain can ever name it"
	case strings.HasPrefix(account, candidateAccountPrefix):
		// A candidate is a key 'keys prove' presented to a key-add ceremony. That
		// nothing here declares it is its normal state, not a leftover: the chain
		// that adopts it belongs to the ceremony operator, and this machine may
		// never hold that chain at all. Never an orphan, therefore never pruned.
		entry.Origin = originCandidate
		entry.Status = statusCandidate
		entry.Reason = "presented to a key-add ceremony — the chain that adopts it is not this machine's, so nothing here declares it"
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

	// The public key: from the account itself where the account IS the public key,
	// then from the chain, then from the vault's record, then — only when nothing
	// else can say — from the seed. Deriving it is also the proof that the backend
	// really holds a key here, which is why a failure downgrades the entry to
	// uncertain instead of being ignored.
	if entry.PublicKey == "" {
		entry.PublicKey = in.declaredPublic[account]
	}
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
	for _, status := range []string{statusDeclared, statusLoginClient, statusSuperseded, statusCandidate,
		statusOrphan, statusUnreadable, statusUnnamed, statusUnrecognized} {
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
			// Which role a rotation retired is half of what an operator wants
			// from this row, so it is on the row rather than one 'keys show' away.
			if len(e.Roles) > 0 {
				return identityLabel(e) + " — was " + strings.Join(e.Roles, ", ") + ", no longer current"
			}
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
		if declared := declaredKeyMiss(selector); declared != "" {
			return nil, fmt.Errorf("%s", declared)
		}
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

// declaredKeyMiss answers the other half of a miss. A selector that names no key
// this machine HOLDS may still name a key an identity here DECLARES, and "no key
// matching" sends the operator looking for a lost seed when the fact is that the
// private half was never on this machine — a normal state for a chain custodied
// on one device and read on another. Empty when the selector names nothing.
//
// Bounded by the identities this machine has a name for, one point lookup each,
// and never by the corpus — the same reason buildKeyLedger folds over held keys
// rather than over chains.
func declaredKeyMiss(selector string) string {
	lr, err := getRelay()
	if err != nil {
		return ""
	}
	for name, ic := range cfg.Identities {
		chain, err := lr.Relay.GetIdentity(ic.DID)
		if err != nil || chain == nil {
			continue
		}
		for _, k := range stateKeyRoles(chain.DID, chain.State) {
			// Every spelling findKeyEntry matches for a held key is a miss to
			// answer for an unheld one: the id, the public key, and both account
			// shapes. An operator who names a key the way the keystore files it
			// asked the same question as one who names it by id.
			if selector != k.Key.ID && selector != k.Key.PublicKeyMultibase &&
				!slices.Contains(keyAccountsFor(chain.DID, k.Key.ID, k.Key.PublicKeyMultibase), selector) {
				continue
			}
			return fmt.Sprintf("'%s' is declared by %s as %s and not held on this machine — "+
				"'dfos identity status %s' reports the full roster with possession",
				selector, name, joinComma(k.Roles), name)
		}
	}
	return ""
}

func printKeyEntry(e keyLedgerEntry) {
	printKeyFacts(e)
	switch {
	case e.Prunable:
		fmt.Printf("  Prune:     'dfos keys prune' would remove this key\n")
	case keyRemovalRefusal(e) == nil:
		// Removable, and prune will never be the thing that removes it. Saying
		// only "never" here is how an operator ends up at the OS keychain.
		fmt.Printf("  Prune:     never — 'dfos keys prune' removes only keys with status %s; "+
			"'dfos keys remove %s' removes this one by name\n", statusOrphan, keyLabel(e))
	default:
		fmt.Printf("  Prune:     never — 'dfos keys prune' removes only keys with status %s\n", statusOrphan)
	}
}

// printKeyFacts is everything `keys show` reports about one key EXCEPT what to
// do about it. `keys remove` prints the facts and then says what it is doing,
// which is not the same as pointing at itself.
func printKeyFacts(e keyLedgerEntry) {
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
		if e.Status == statusSuperseded {
			fmt.Printf("  Roles:     %s — held until a rotation retired this key, not current\n", strings.Join(e.Roles, ", "))
		} else {
			fmt.Printf("  Roles:     %s\n", strings.Join(e.Roles, ", "))
		}
	}
	if e.Deleted {
		fmt.Printf("  Note:      the identity is deleted — deletion is not revocation, and 'identity restore' is real\n")
	}
	if e.Reason != "" {
		fmt.Printf("  Why:       %s\n", e.Reason)
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

// --- remove ---

// `keys remove` is the BY-NAME counterpart to prune's by-status sweep, and it
// exists for the one class of key that sweep can never reach.
//
// A candidate is a key `keys prove` presented to a ceremony someone else
// custodies the chain for. Nothing here declares it, and that is its normal
// state rather than orphanhood, so prune retains it forever — correctly, and
// unchanged by this command. But an abandoned ceremony, or a second ceremony
// that supersedes the first, leaves a candidate whose only removal path was the
// OS keychain itself. That is the gap: not a missing sweep, a missing name.
//
// So this takes exactly one key, named, and only the two statuses where the
// keystore is the whole story — candidate and orphan. Everything else is
// refused out loud with the reason, because a key a chain declares is that
// chain's business, and a key whose status cannot be established is nobody's to
// judge.
func newKeysRemoveCmd() *cobra.Command {
	var armed bool
	cmd := &cobra.Command{
		Use:   "remove <key-id|public-key|account>",
		Short: "Remove one named key this machine holds (dry run by default)",
		Long: "Remove ONE key, named by its key id, its public key, or the account it is stored under. It " +
			"prints the key, why it is removable, and what removing it costs, and removes nothing until " +
			"--yes.\n\n" +
			"Only two statuses are removable: `candidate`, a key presented to a key-add ceremony that no " +
			"chain here declares by design, and `orphan`, a key nothing declares at all. A `declared` key is " +
			"rotated out of the chain that names it, not deleted out from under it. A `superseded` key is " +
			"kept because this machine's view of a chain can be behind the network's — the same reason " +
			"'keys prune' retains it. The sign-in client key is infrastructure. A key whose status cannot be " +
			"established cannot be judged, and is left alone. Each refusal names its reason.",
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
			return runKeysRemove(*entry, armed)
		},
	}
	cmd.Flags().BoolVar(&armed, "yes", false, "Actually remove the key (without it, nothing is deleted)")
	return cmd
}

// keyRemoval is one removal, decided and — when armed — done.
type keyRemoval struct {
	Armed   bool           `json:"armed"`
	Removed bool           `json:"removed"`
	Key     keyLedgerEntry `json:"key"`
	// Because is why this status is one remove acts on. The entry's own Reason
	// says what the key IS; this says why that makes it removable.
	Because     string `json:"because"`
	Recoverable bool   `json:"recoverableFromVault"`
	Vault       string `json:"vault,omitempty"`
}

// keyRemovalRefusal reports why `keys remove` will not touch a key, or nil when
// it will. It is the single place the removable set is decided, so the help
// text, the `keys show` hint, and the command itself cannot drift apart.
func keyRemovalRefusal(e keyLedgerEntry) error {
	switch e.Status {
	case statusCandidate, statusOrphan:
		return nil

	case statusDeclared:
		roles := ""
		if len(e.Roles) > 0 {
			roles = " in " + strings.Join(e.Roles, ", ")
		}
		return fmt.Errorf("%s is declared by %s%s — that is chain business, not keystore business.\n"+
			"A declared key is rotated out of the chain that names it, not deleted out from under it: "+
			"'dfos identity update --rotate-controller|--rotate-auth|--rotate-assert' is the operation that "+
			"retires a key, and it publishes the fact rather than leaving the chain naming a key this machine "+
			"no longer holds.", keyLabel(e), identityLabel(e), roles)

	case statusSuperseded:
		// The refusal already said the verdict is about this relay. The stamp
		// says WHICH state of this relay, which is the difference between a
		// caveat an operator reads past and a fact they can go check.
		basis := ""
		if e.AsOf != nil {
			basis = " That verdict is " + chainBasis(e.AsOf.HeadCID, e.AsOf.LastCreatedAt) + "."
		}
		return fmt.Errorf("%s is superseded: the chain for %s is in this local relay and no longer names it.\n"+
			"That is a statement about this relay, not about the world — this machine's view of a chain can be "+
			"behind the network's, and a rotation seen here may not be the last word. It is the same reason "+
			"'dfos keys prune' retains a superseded key.%s\n"+
			"'dfos identity status %s' compares this machine's chain against the identity's relay.",
			keyLabel(e), identityLabel(e), basis, firstNonEmpty(e.Identity, e.DID))

	case statusLoginClient:
		return fmt.Errorf("%s is this installation's sign-in client key: infrastructure, named by %s, and "+
			"declared by no identity of yours.\n"+
			"Deleting the seed under the file that names it leaves 'dfos login' holding a client identity it "+
			"cannot prove. Delete %s to mint a new login client identity instead — the authorize host asks for "+
			"consent again.", keyLabel(e), loginClientFileName, loginClientFileName)

	default:
		// Every uncertain status, and any status a later version adds without
		// deciding this question: not removable until something decides it is.
		return fmt.Errorf("%s has status %s, so what it is cannot be established from what this machine can "+
			"see: %s\n"+
			"Uncertainty is not a candidate and not an orphan. 'dfos keys remove' acts on status %s and %s "+
			"only, the same rule that makes 'dfos keys prune' skip this key rather than judge it.",
			keyLabel(e), e.Status, e.Reason, statusCandidate, statusOrphan)
	}
}

// removableBecause says why the status this key carries is one remove acts on.
func removableBecause(status string) string {
	if status == statusCandidate {
		return "a candidate is claimed by a chain this machine does not custody, so nothing here ever declares " +
			"it and 'dfos keys prune' never reaches it — removal is by name and deliberate"
	}
	return "nothing in the local relay declares it and nothing else claims it — 'dfos keys prune' sweeps the " +
		"whole class; this removes just this one"
}

func runKeysRemove(e keyLedgerEntry, armed bool) error {
	if err := keyRemovalRefusal(e); err != nil {
		return err
	}

	removal := keyRemoval{
		Armed:       armed,
		Key:         e,
		Because:     removableBecause(e.Status),
		Recoverable: e.Recoverable,
	}
	if e.Vault != nil {
		removal.Vault = e.Vault.Name
	}

	if armed {
		// The same three questions prune asks at the last possible moment: is
		// this a key at all, is it still there, and is it still the account we
		// judged. The ledger is a snapshot; the delete is the act.
		switch {
		case keystore.IsReservedAccount(e.Account):
			return fmt.Errorf("refusing to delete %s: reserved account — not a key seed", e.Account)
		case e.Account == "":
			return fmt.Errorf("no account to delete: %s holds this key under a reference it cannot name (%s)",
				e.Backend, e.Ref)
		case !keys.HasKey(e.Account):
			return fmt.Errorf("%s is no longer in the keystore — something removed it since this ledger was "+
				"built", e.Account)
		}
		if err := keys.DeleteKey(e.Account); err != nil {
			return fmt.Errorf("delete %s from %s: %w", e.Account, e.Backend, err)
		}
		removal.Removed = true
	}

	if jsonFlag {
		outputJSON(removal)
		return nil
	}
	printKeyRemoval(removal)
	return nil
}

func printKeyRemoval(r keyRemoval) {
	printKeyFacts(r.Key)
	fmt.Println()
	if r.Removed {
		fmt.Printf("Removed:   this key's seed is gone from the keystore\n")
	} else {
		fmt.Printf("Remove:    would delete this key's seed from the keystore\n")
	}
	fmt.Printf("Because:   %s\n", r.Because)
	fmt.Printf("Recovery:  %s\n", keyRemovalRecovery(r))
	if !r.Removed {
		fmt.Printf("\nNothing was removed. Re-run with --yes to remove it.\n")
	}
}

// keyRemovalRecovery is the cost line: what a person still has after the delete.
func keyRemovalRecovery(r keyRemoval) string {
	if r.Recoverable {
		path := ""
		if r.Key.Vault != nil {
			path = " at " + r.Key.Vault.Path
		}
		return fmt.Sprintf("derivable again from vault '%s' phrase%s", r.Vault, path)
	}
	if r.Removed {
		return "no vault record named this key — this keystore was its only copy, and the seed is gone for good"
	}
	return "no vault record names this key — this keystore is its only copy, and once removed the seed is gone for good"
}

// --- small helpers ---

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

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
