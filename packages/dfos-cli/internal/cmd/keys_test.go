package cmd

// `dfos keys` tests. Like the vault and multi-device tests these drive RunE
// against the package globals setupDevices wires, so they MUST NOT run with
// t.Parallel(). setupDevices points DFOS_CONFIG at a temp directory and sets
// DFOS_NO_KEYCHAIN, so nothing here can reach the developer's own keystore.

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/keystore"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/localrelay"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/vault"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
)

// createStandaloneIdentity mints an identity whose keys come from no vault.
func createStandaloneIdentity(t *testing.T, name string, store *keystore.MemoryStore) string {
	t.Helper()
	keys = store
	cmd := newIdentityCreateCmd()
	mustSetFlag(t, cmd, "name", name)
	mustSetFlag(t, cmd, "no-vault", "true")
	var res struct {
		DID string `json:"did"`
	}
	runJSON(t, cmd, nil, &res)
	return res.DID
}

// plantKey puts a key into the store under a raw account, which is how every
// leftover this ledger has to reason about got there.
func plantKey(t *testing.T, store *keystore.MemoryStore, account string) string {
	t.Helper()
	_, pub, err := store.GenerateKey(account)
	if err != nil {
		t.Fatalf("plant %s: %v", account, err)
	}
	return protocol.EncodeMultikey(pub)
}

func entryFor(t *testing.T, l *keyLedger, account string) keyLedgerEntry {
	t.Helper()
	for _, e := range l.Entries {
		if e.Account == account {
			return e
		}
	}
	t.Fatalf("no ledger entry for %q; ledger holds %s", account, ledgerAccounts(l))
	return keyLedgerEntry{}
}

func ledgerAccounts(l *keyLedger) string {
	var out []string
	for _, e := range l.Entries {
		out = append(out, e.Account+"="+e.Status)
	}
	return strings.Join(out, " ")
}

func runPrune(t *testing.T, armed bool) pruneResult {
	t.Helper()
	cmd := newKeysPruneCmd()
	if armed {
		mustSetFlag(t, cmd, "yes", "true")
	}
	var res pruneResult
	runJSON(t, cmd, nil, &res)
	return res
}

// The ledger is a fold over stores that already exist. This walks every origin
// class through it at once, because the classes are only meaningful relative to
// each other.
func TestKeyLedgerFoldsEveryOriginClass(t *testing.T) {
	storeA, _, _ := setupDevices(t)

	createVault(t, "personal")
	if cfg.DefaultVault != "personal" {
		t.Fatalf("expected the first vault to become default-vault, got %q", cfg.DefaultVault)
	}
	vaultDID := createIdentity(t, "alice", storeA)
	standaloneDID := createStandaloneIdentity(t, "bob", storeA)

	// A create interrupted between minting and renaming.
	plantKey(t, storeA, "pending:key_interrupted")
	// A key whose identity chain this relay does not have.
	plantKey(t, storeA, "did:dfos:notinthisrelay#key_gone")
	// This installation's sign-in client key.
	loginPub := plantKey(t, storeA, loginClientAccount("key_login"))
	writeLoginClientFile(t, "did:dfos:loginclient", "key_login")
	// A vault-minted key whose chain is gone: the case where a written-down
	// phrase still covers a key nothing declares.
	strandedPub := plantKey(t, storeA, "did:dfos:vanished#key_stranded")
	if err := getVaults().Record("personal", vault.MintedKey{
		Index: 9, DID: "did:dfos:vanished", KeyID: "key_stranded", Role: "auth", PublicKey: strandedPub,
	}); err != nil {
		t.Fatalf("record vault provenance: %v", err)
	}

	keys = storeA
	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("buildKeyLedger: %v", err)
	}
	if !ledger.Enumerated {
		t.Fatalf("a memory store enumerates itself; ledger reported a limit: %s", ledger.Limit)
	}

	// Vault-minted, declared, with provenance.
	chain, err := localRelayInstance.Relay.GetIdentity(vaultDID)
	if err != nil || chain == nil {
		t.Fatalf("get alice's chain: %v", err)
	}
	authAccount := keyAccount(chain.State.AuthKeys[0].PublicKeyMultibase)
	auth := entryFor(t, ledger, authAccount)
	if auth.Origin != originVault {
		t.Fatalf("a vault-minted key reported origin %q", auth.Origin)
	}
	if auth.Status != statusDeclared || auth.Prunable {
		t.Fatalf("a declared key came out %q (prunable=%v)", auth.Status, auth.Prunable)
	}
	if auth.Vault == nil || auth.Vault.Name != "personal" || auth.Vault.Path == "" {
		t.Fatalf("a vault-minted key carried no provenance: %+v", auth.Vault)
	}
	if !auth.Recoverable {
		t.Fatal("a key with a vault record is derivable from that vault's phrase")
	}
	if auth.Identity != "alice" || auth.PublicKey != chain.State.AuthKeys[0].PublicKeyMultibase {
		t.Fatalf("declared key resolved to %q / %q", auth.Identity, auth.PublicKey)
	}
	if len(auth.Roles) == 0 {
		t.Fatal("a declared key reported no role")
	}

	// Standalone, declared, no provenance.
	bobChain, _ := localRelayInstance.Relay.GetIdentity(standaloneDID)
	standalone := entryFor(t, ledger, keyAccount(bobChain.State.AuthKeys[0].PublicKeyMultibase))
	if standalone.Origin != originStandalone || standalone.Vault != nil || standalone.Recoverable {
		t.Fatalf("a standalone key came out %+v", standalone)
	}

	// Pending leftover.
	pending := entryFor(t, ledger, "pending:key_interrupted")
	if pending.Origin != originPending || pending.Status != statusOrphan || !pending.Prunable {
		t.Fatalf("a pending leftover came out %+v", pending)
	}
	if pending.PublicKey == "" {
		t.Fatal("a pending key's public key should be recovered from its own seed")
	}

	// Key of an identity this relay has never seen.
	gone := entryFor(t, ledger, "did:dfos:notinthisrelay#key_gone")
	if gone.Status != statusOrphan || !gone.Prunable || gone.Recoverable {
		t.Fatalf("a key with no local chain came out %+v", gone)
	}

	// Sign-in client key: infrastructure, never an orphan.
	login := entryFor(t, ledger, loginClientAccount("key_login"))
	if login.Origin != originLoginClient || login.Status != statusLoginClient || login.Prunable {
		t.Fatalf("the login client key came out %+v", login)
	}
	if login.PublicKey != loginPub {
		t.Fatalf("login client public key = %q, want %q", login.PublicKey, loginPub)
	}

	// Vault-minted orphan: prunable, and recoverable, and the report says so.
	stranded := entryFor(t, ledger, "did:dfos:vanished#key_stranded")
	if stranded.Status != statusOrphan || !stranded.Prunable {
		t.Fatalf("a key with no local chain came out %q", stranded.Status)
	}
	if !stranded.Recoverable || stranded.Vault == nil || stranded.Vault.Name != "personal" {
		t.Fatalf("a vault-minted orphan lost its provenance: %+v", stranded)
	}
}

// The local relay's own key lives in relay.db's relay_meta table, not in the
// keystore, so a fold over the keystore cannot see it. That is the exemption:
// by construction, not by filter.
func TestKeyLedgerCannotReachTheLocalRelaysOwnKey(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	createStandaloneIdentity(t, "alice", storeA)
	plantKey(t, storeA, "pending:key_interrupted")
	keys = storeA

	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("buildKeyLedger: %v", err)
	}
	for _, e := range ledger.Entries {
		if e.DID == lr.RelayDID || strings.Contains(e.Account, lr.RelayDID) {
			t.Fatalf("the local relay's own key reached the ledger: %+v", e)
		}
	}

	// And an armed prune leaves the relay signing.
	if res := runPrune(t, true); res.Removed != 1 {
		t.Fatalf("prune --yes removed %d, want 1", res.Removed)
	}
	if _, err := lr.Relay.GetIdentity(lr.RelayDID); err != nil {
		t.Fatalf("the local relay lost its own identity: %v", err)
	}
	chain, err := lr.Relay.GetIdentity(lr.RelayDID)
	if err != nil || chain == nil {
		t.Fatal("the local relay's identity chain is gone after prune")
	}
}

func TestPruneIsADryRunUntilArmed(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	plantKey(t, storeA, "pending:key_interrupted")
	plantKey(t, storeA, "did:dfos:notinthisrelay#key_gone")
	keys = storeA

	dry := runPrune(t, false)
	if dry.Armed {
		t.Fatal("prune armed itself")
	}
	if len(dry.Orphans) != 2 {
		t.Fatalf("dry run found %d orphans, want 2", len(dry.Orphans))
	}
	if dry.Removed != 0 {
		t.Fatalf("a dry run removed %d keys", dry.Removed)
	}
	for _, o := range dry.Orphans {
		if o.Removed {
			t.Fatalf("a dry run marked %s removed", o.Account)
		}
		if o.Reason == "" {
			t.Fatalf("orphan %s came with no reason", o.Account)
		}
		if !storeA.HasKey(o.Account) {
			t.Fatalf("a dry run deleted %s", o.Account)
		}
	}

	armed := runPrune(t, true)
	if armed.Removed != 2 || armed.Failed != 0 {
		t.Fatalf("armed prune removed %d, failed %d; want 2 and 0", armed.Removed, armed.Failed)
	}
	for _, account := range []string{"pending:key_interrupted", "did:dfos:notinthisrelay#key_gone"} {
		if storeA.HasKey(account) {
			t.Fatalf("armed prune left orphan %s behind", account)
		}
	}
	// The identity's own keys are untouched.
	chain, _ := localRelayInstance.Relay.GetIdentity(did)
	for _, k := range chain.State.AuthKeys {
		if !storeA.HasKey(keyAccount(k.PublicKeyMultibase)) {
			t.Fatalf("prune removed a declared key %s", k.ID)
		}
	}
	if again := runPrune(t, false); len(again.Orphans) != 0 {
		t.Fatalf("orphans remain after an armed prune: %+v", again.Orphans)
	}
}

// Deletion is not revocation: a deleted identity's chain stays in the relay and
// `identity restore` is real, so its keys are still declared.
func TestPruneKeepsADeletedIdentitysKeys(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	keys = storeA

	del := newIdentityDeleteCmd()
	identityFlag = "alice"
	if err := del.RunE(del, nil); err != nil {
		t.Fatalf("identity delete: %v", err)
	}
	chain, err := lr.Relay.GetIdentity(did)
	if err != nil || chain == nil || !chain.State.IsDeleted {
		t.Fatalf("test premise wrong: alice is not deleted (%v)", err)
	}

	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("buildKeyLedger: %v", err)
	}
	saw := 0
	for _, e := range ledger.Entries {
		if e.DID != did {
			continue
		}
		saw++
		if e.Status != statusDeclared || e.Prunable {
			t.Fatalf("a deleted identity's key came out %q (prunable=%v)", e.Status, e.Prunable)
		}
		if !e.Deleted {
			t.Fatal("the ledger did not report that the identity is deleted")
		}
	}
	if saw == 0 {
		t.Fatal("the deleted identity's keys vanished from the ledger")
	}
	if res := runPrune(t, true); res.Removed != 0 {
		t.Fatalf("prune removed %d keys of a deleted identity", res.Removed)
	}
}

// Rotation leaves the old key behind. It is not declared any more and it is not
// an orphan either: this relay's view of a chain can be behind the network's.
func TestRotatedOutKeysAreSupersededNotOrphans(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	keys = storeA

	before, _ := localRelayInstance.Relay.GetIdentity(did)
	oldAuth := keyAccount(before.State.AuthKeys[0].PublicKeyMultibase)

	// Every role, so the genesis key is left declared in none of them. Rotating
	// one role would leave it current in the other two — see
	// TestKeysListReportsWhatARotationRetired.
	identityFlag = "alice"
	update := newIdentityUpdateCmd()
	mustSetFlag(t, update, "rotate-auth", "true")
	mustSetFlag(t, update, "rotate-controller", "true")
	mustSetFlag(t, update, "rotate-assert", "true")
	if err := update.RunE(update, nil); err != nil {
		t.Fatalf("identity update --rotate-*: %v", err)
	}

	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("buildKeyLedger: %v", err)
	}
	old := entryFor(t, ledger, oldAuth)
	if old.Status != statusSuperseded || old.Prunable {
		t.Fatalf("a rotated-out key came out %q (prunable=%v)", old.Status, old.Prunable)
	}
	if res := runPrune(t, true); res.Removed != 0 {
		t.Fatalf("prune removed %d rotated-out keys", res.Removed)
	}
	if !storeA.HasKey(oldAuth) {
		t.Fatal("prune deleted a rotated-out key")
	}
}

// Uncertain is not an orphan, and it is not silence either.
func TestPruneSkipsUncertainKeysLoudly(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	createStandaloneIdentity(t, "alice", storeA)
	// An account in no shape this CLI writes: it cannot be classified, so it
	// cannot be judged.
	plantKey(t, storeA, "something-nobody-here-writes")
	keys = storeA

	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("buildKeyLedger: %v", err)
	}
	odd := entryFor(t, ledger, "something-nobody-here-writes")
	if odd.Status != statusUnrecognized || odd.Prunable {
		t.Fatalf("an unclassifiable key came out %q (prunable=%v)", odd.Status, odd.Prunable)
	}

	res := runPrune(t, true)
	if res.Removed != 0 || len(res.Orphans) != 0 {
		t.Fatalf("prune acted on an unclassifiable key: %+v", res)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Account != "something-nobody-here-writes" {
		t.Fatalf("prune did not report the skip: %+v", res.Skipped)
	}
	if res.Skipped[0].Reason == "" {
		t.Fatal("a skip with no reason is not loud")
	}
	if !storeA.HasKey("something-nobody-here-writes") {
		t.Fatal("prune deleted a key it could not classify")
	}
}

// A vault mnemonic is stored in the same OS keychain service as the seeds. It
// must never reach the ledger, and prune must refuse it even if one did.
func TestVaultMnemonicsAreNeitherListedNorPruned(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	createStandaloneIdentity(t, "alice", storeA)
	keys = storeA
	// The account internal/vault writes into the shared keychain service.
	plantKey(t, storeA, "vault:personal")

	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("buildKeyLedger: %v", err)
	}
	for _, e := range ledger.Entries {
		if strings.HasPrefix(e.Account, "vault:") {
			t.Fatalf("a vault mnemonic account reached the ledger: %+v", e)
		}
	}
	if res := runPrune(t, true); res.Removed != 0 {
		t.Fatalf("prune removed %d entries; it must not touch vault secrets", res.Removed)
	}
	if !storeA.HasKey("vault:personal") {
		t.Fatal("prune deleted a vault mnemonic")
	}
}

// A backend that cannot list itself yields a PARTIAL ledger, and has to say so.
func TestALedgerOnANonEnumeratingBackendSaysItIsPartial(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	plantKey(t, storeA, "pending:key_invisible")

	keys = &blindStore{MemoryStore: storeA}
	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("buildKeyLedger: %v", err)
	}
	if ledger.Enumerated {
		t.Fatal("a backend that cannot list itself reported a complete ledger")
	}
	if !strings.Contains(ledger.Limit, "cannot") {
		t.Fatalf("the limit was not stated: %q", ledger.Limit)
	}
	// The declared keys are all still found, by name, through the candidates.
	chain, _ := localRelayInstance.Relay.GetIdentity(did)
	entryFor(t, ledger, keyAccount(chain.State.AuthKeys[0].PublicKeyMultibase))
	for _, e := range ledger.Entries {
		if e.Account == "pending:key_invisible" {
			t.Fatal("a leftover nothing names cannot be found on a blind backend; the ledger invented it")
		}
	}
	if res := runPrune(t, true); res.Removed != 0 {
		t.Fatalf("prune removed %d keys it could not see: %+v", res.Removed, res.Orphans)
	}
	if !storeA.HasKey("pending:key_invisible") {
		t.Fatal("prune deleted a key on a backend it could not enumerate")
	}
}

// blindStore is a keystore that holds keys and refuses to list them — the
// secret-service and Windows backends, in a form a test can drive.
type blindStore struct {
	*keystore.MemoryStore
}

func (b *blindStore) Entries() ([]keystore.Entry, error) { return nil, keystore.ErrNoEnumeration }

// countingStore is a keystore that counts what is asked OF it. The ledger's
// cost has to be a function of the keys this machine holds; a count that moves
// when the local relay's corpus grows is the fold running the wrong way round.
type countingStore struct {
	*keystore.MemoryStore
	has int
	get int
}

func (c *countingStore) HasKey(account string) bool {
	c.has++
	return c.MemoryStore.HasKey(account)
}

func (c *countingStore) GetPrivateKey(account string) (ed25519.PrivateKey, error) {
	c.get++
	return c.MemoryStore.GetPrivateKey(account)
}

// syntheticChains is how many identities this machine holds no key for get
// pushed into the local relay. It is well under a real backfilled store (tens of
// thousands) and far past the point where an O(corpus) fold shows up.
const syntheticChains = 5000

// seedSyncedIdentities writes chains this machine holds no key for straight into
// the store — what syncing from a relay that has followed the network leaves
// behind. Each carries a log and three declared keys, so a fold over them pays
// the JSON decode a real one does.
func seedSyncedIdentities(t *testing.T, lr *localrelay.LocalRelay, n int) {
	t.Helper()
	if err := lr.Store.BeginWriteBatch(); err != nil {
		t.Fatalf("begin write batch: %v", err)
	}
	for i := 0; i < n; i++ {
		did := fmt.Sprintf("did:dfos:z%027d", i)
		key := func(role string) protocol.MultikeyPublicKey {
			return protocol.MultikeyPublicKey{
				ID:                 role + "_" + strconv.Itoa(i),
				Type:               "Multikey",
				PublicKeyMultibase: fmt.Sprintf("z6Mk%044d", i),
			}
		}
		log := make([]string, 0, 4)
		for op := 0; op < 4; op++ {
			log = append(log, strings.Repeat("x", 256))
		}
		chain := relay.StoredIdentityChain{
			DID:           did,
			Log:           log,
			HeadCID:       fmt.Sprintf("bafy%040d", i),
			LastCreatedAt: "2026-01-01T00:00:00.000Z",
			State: protocol.IdentityState{
				DID:            did,
				ControllerKeys: []protocol.MultikeyPublicKey{key("controller")},
				AuthKeys:       []protocol.MultikeyPublicKey{key("auth")},
				AssertKeys:     []protocol.MultikeyPublicKey{key("assert")},
			},
		}
		if err := lr.Store.PutIdentityChain(chain); err != nil {
			_ = lr.Store.RollbackWriteBatch()
			t.Fatalf("seed identity %d: %v", i, err)
		}
	}
	if err := lr.Store.CommitWriteBatch(); err != nil {
		t.Fatalf("commit seeded identities: %v", err)
	}
}

// The ledger answers a question about the keys THIS MACHINE HOLDS. A local relay
// that has synced the network holds tens of thousands of chains it holds no key
// for, and the price of the answer must not track them: a fold that walks every
// chain — and probes the keystore once per key any of them declares — turns a
// four-key report into minutes of work. The count is the proof; the clock is the
// symptom it was found by.
func TestTheLedgerCostsTheKeysHeldNotTheChainsSynced(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	createVault(t, "personal")
	createIdentity(t, "alice", storeA)
	createStandaloneIdentity(t, "bob", storeA)
	plantKey(t, storeA, "pending:key_interrupted")
	writeLoginClientFile(t, "did:dfos:loginclient", "key_login")
	plantKey(t, storeA, loginClientAccount("key_login"))

	counting := &countingStore{MemoryStore: storeA}
	keys = counting
	before, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("buildKeyLedger on an empty relay: %v", err)
	}
	baseHas, baseGet := counting.has, counting.get

	seedSyncedIdentities(t, lr, syntheticChains)

	counting.has, counting.get = 0, 0
	start := time.Now()
	after, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("buildKeyLedger on a synced relay: %v", err)
	}
	elapsed := time.Since(start)

	if counting.has != baseHas || counting.get != baseGet {
		t.Fatalf("the fold asked the keystore %d HasKey / %d GetPrivateKey with %d chains synced, "+
			"and %d / %d with none — its cost tracks the corpus, not the keys held",
			counting.has, counting.get, syntheticChains, baseHas, baseGet)
	}
	// A ceiling on the whole fold, not a benchmark: the shape this catches took
	// over a minute on a real store, so anything near this bound is the bug back.
	if elapsed > 2*time.Second {
		t.Fatalf("building the ledger over %d synced chains took %s", syntheticChains, elapsed)
	}

	// Same answer, cheaper. The chains this machine holds no key for change
	// nothing about what it holds.
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(after)
	if string(beforeJSON) != string(afterJSON) {
		t.Fatalf("the ledger changed when unrelated chains synced:\n before %s\n  after %s", beforeJSON, afterJSON)
	}
}

// The cheap path must not cost the fallback its reach: a backend that cannot
// list itself still finds every declared key by name, however many chains the
// relay has synced.
func TestABlindBackendStillFindsDeclaredKeysOnASyncedRelay(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	seedSyncedIdentities(t, lr, 200)

	keys = &blindStore{MemoryStore: storeA}
	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("buildKeyLedger: %v", err)
	}
	if ledger.Enumerated {
		t.Fatal("a backend that cannot list itself reported a complete ledger")
	}
	chain, _ := localRelayInstance.Relay.GetIdentity(did)
	entry := entryFor(t, ledger, keyAccount(chain.State.AuthKeys[0].PublicKeyMultibase))
	if entry.Status != statusDeclared {
		t.Fatalf("a declared key on a blind backend came back %q", entry.Status)
	}
}

func TestKeysShowReportsOneKeyAndNeverItsSeed(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	createVault(t, "personal")
	did := createIdentity(t, "alice", storeA)
	keys = storeA

	chain, _ := localRelayInstance.Relay.GetIdentity(did)
	keyID := chain.State.AuthKeys[0].ID
	publicKey := chain.State.AuthKeys[0].PublicKeyMultibase
	priv, err := storeA.GetPrivateKey(keyAccount(publicKey))
	if err != nil {
		t.Fatalf("get private key: %v", err)
	}

	for _, selector := range []string{keyID, keyAccount(publicKey), publicKey} {
		cmd := newKeysShowCmd()
		var entry keyLedgerEntry
		runJSON(t, cmd, []string{selector}, &entry)
		if entry.KeyID != keyID {
			t.Fatalf("show %q resolved to key %q", selector, entry.KeyID)
		}
		if entry.Vault == nil || entry.Vault.Name != "personal" {
			t.Fatalf("show lost the provenance for %q: %+v", selector, entry.Vault)
		}
		if entry.Status != statusDeclared || len(entry.Roles) == 0 {
			t.Fatalf("show reported %q with roles %v", entry.Status, entry.Roles)
		}
	}

	// No spelling of the private key is anywhere in either output.
	human, _, err := runCapturing(t, newKeysShowCmd(), []string{keyID})
	if err != nil {
		t.Fatalf("keys show: %v", err)
	}
	assertNoSeed(t, human, priv)
	listed, _, err := runCapturing(t, newKeysListCmd(), nil)
	if err != nil {
		t.Fatalf("keys list: %v", err)
	}
	assertNoSeed(t, listed, priv)
}

func assertNoSeed(t *testing.T, out string, priv []byte) {
	t.Helper()
	for _, spelling := range []string{
		hexOf(priv), hexOf(priv[:32]), string(priv),
	} {
		if spelling != "" && strings.Contains(out, spelling) {
			t.Fatal("private key material reached the output")
		}
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

// A superseded key's role is not in current state — that is what superseded
// means — but it is in the log that retired it. The ledger reports it, so
// "which role did that rotation retire" is answered by the list rather than by
// a second command.
func TestKeysListReportsWhatARotationRetired(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA

	create := newIdentityCreateCmd()
	mustSetFlag(t, create, "name", "alice")
	mustSetFlag(t, create, "no-vault", "true")
	var created struct {
		DID           string `json:"did"`
		Key           string `json:"key"`
		PublicKey     string `json:"publicKey"`
		ControllerKey string `json:"controllerKey"`
		AuthKey       string `json:"authKey"`
	}
	runJSON(t, create, nil, &created)
	identityFlag = "alice"

	// A genesis key is one key in three roles, so rotating ONE role does not
	// retire it: it is still the controller and the assert key, and the ledger
	// has to say so rather than report it as rotated out.
	genesisAccount := keyAccount(created.PublicKey)
	rotate := newIdentityUpdateCmd()
	mustSetFlag(t, rotate, "rotate-auth", "true")
	runJSON(t, rotate, nil, nil)

	partial, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("build ledger: %v", err)
	}
	stillHeld := entryFor(t, partial, genesisAccount)
	if stillHeld.Status != statusDeclared {
		t.Fatalf("after --rotate-auth the genesis key is %s, want %s", stillHeld.Status, statusDeclared)
	}
	if got := strings.Join(stillHeld.Roles, ","); got != "controller,assert" {
		t.Fatalf("roles after --rotate-auth = %q, want controller,assert", got)
	}

	// Rotating the roles it kept is what actually retires it.
	rest := newIdentityUpdateCmd()
	mustSetFlag(t, rest, "rotate-controller", "true")
	mustSetFlag(t, rest, "rotate-assert", "true")
	runJSON(t, rest, nil, nil)

	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("build ledger: %v", err)
	}

	retired := entryFor(t, ledger, genesisAccount)
	if retired.Status != statusSuperseded {
		t.Fatalf("the rotated-out key is %s, want %s", retired.Status, statusSuperseded)
	}
	if got := strings.Join(retired.Roles, ","); got != "controller,auth,assert" {
		t.Fatalf("superseded roles = %q, want everything the log ever declared it in", got)
	}
	if row := declaredBy(retired); !strings.Contains(row, "was controller") || !strings.Contains(row, "no longer current") {
		t.Fatalf("the table row does not say which roles were retired: %q", row)
	}

	// Every other status carries no roles at all — the field is present when a
	// chain says what the key is for, and absent when nothing does.
	orphan := "did:dfos:2222222222222222222222222222222#key_x"
	candidate := candidateAccountPrefix + "z6MkExampleCandidateKey"
	plantKey(t, storeA, orphan)
	plantKey(t, storeA, candidate)
	ledger, err = buildKeyLedger()
	if err != nil {
		t.Fatalf("rebuild ledger: %v", err)
	}
	for _, account := range []string{orphan, candidate} {
		if roles := entryFor(t, ledger, account).Roles; len(roles) != 0 {
			t.Fatalf("%s reported roles %v; only a declaring chain names a role", account, roles)
		}
	}
}

// runRemove drives `keys remove <selector>` and returns its report. It is the
// happy path only — a refusal is an error, and removeRefusal is how those are
// asserted on.
func runRemove(t *testing.T, selector string, armed bool) keyRemoval {
	t.Helper()
	cmd := newKeysRemoveCmd()
	if armed {
		mustSetFlag(t, cmd, "yes", "true")
	}
	var res keyRemoval
	runJSON(t, cmd, []string{selector}, &res)
	return res
}

// removeRefusal asserts that `keys remove --yes <selector>` refuses, and hands
// back the refusal. Armed on purpose: a key this command will not touch is one
// it will not touch with --yes either.
func removeRefusal(t *testing.T, selector string) error {
	t.Helper()
	cmd := newKeysRemoveCmd()
	mustSetFlag(t, cmd, "yes", "true")
	_, _, err := runCapturing(t, cmd, []string{selector})
	if err == nil {
		t.Fatalf("'keys remove --yes %s' was allowed", selector)
	}
	return err
}

// A candidate is the key prune can never reach — nothing here declares it, and
// that is its normal state rather than orphanhood. `remove` is the by-name path
// that reaches it, and it is a dry run until armed.
func TestKeysRemoveTakesACandidatePruneNeverReaches(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	createStandaloneIdentity(t, "alice", storeA)
	candidate := candidateAccountPrefix + "z6MkAbandonedCeremonyKey"
	publicKey := plantKey(t, storeA, candidate)
	keys = storeA

	// The premise: an armed prune leaves the candidate exactly where it is.
	if res := runPrune(t, true); res.Removed != 0 {
		t.Fatalf("prune removed %d key(s); a candidate is never pruned", res.Removed)
	}
	if !storeA.HasKey(candidate) {
		t.Fatal("prune deleted a candidate")
	}

	dry := runRemove(t, publicKey, false)
	if dry.Armed || dry.Removed {
		t.Fatalf("a dry run reported armed=%v removed=%v", dry.Armed, dry.Removed)
	}
	if dry.Key.Account != candidate || dry.Key.Status != statusCandidate {
		t.Fatalf("remove resolved the public key to %+v", dry.Key)
	}
	if dry.Because == "" {
		t.Fatal("a removal with no stated reason is not deliberate")
	}
	if dry.Recoverable {
		t.Fatal("a planted key no vault minted is not derivable from any phrase")
	}
	if !storeA.HasKey(candidate) {
		t.Fatal("a dry run deleted the candidate")
	}

	armed := runRemove(t, candidate, true)
	if !armed.Armed || !armed.Removed {
		t.Fatalf("'remove --yes' reported armed=%v removed=%v", armed.Armed, armed.Removed)
	}
	if storeA.HasKey(candidate) {
		t.Fatal("'remove --yes' left the candidate in the keystore")
	}
	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("buildKeyLedger: %v", err)
	}
	for _, e := range ledger.Entries {
		if e.Account == candidate {
			t.Fatalf("the removed candidate is still in the ledger: %+v", e)
		}
	}
}

// An orphan is removable too — one at a time, named, which is the difference
// between this and prune's sweep.
func TestKeysRemoveTakesOneOrphanAndLeavesTheOthers(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	plantKey(t, storeA, "pending:key_interrupted")
	plantKey(t, storeA, "did:dfos:notinthisrelay#key_gone")
	keys = storeA

	// Named by its key id, which is what an operator reads off `keys list`.
	res := runRemove(t, "key_interrupted", true)
	if !res.Removed || res.Key.Status != statusOrphan {
		t.Fatalf("removing an orphan reported %+v", res)
	}
	if storeA.HasKey("pending:key_interrupted") {
		t.Fatal("'remove --yes' left the named orphan behind")
	}
	if !storeA.HasKey("did:dfos:notinthisrelay#key_gone") {
		t.Fatal("remove took an orphan it was not named")
	}
	chain, _ := localRelayInstance.Relay.GetIdentity(did)
	if !storeA.HasKey(keyAccount(chain.State.AuthKeys[0].PublicKeyMultibase)) {
		t.Fatal("remove took a declared key")
	}
}

// Everything else is refused, out loud, with the reason — and refused with
// --yes, because a key this command will not touch is not one an arming flag
// unlocks.
func TestKeysRemoveRefusesEveryStatusThatIsNotItsToJudge(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	keys = storeA

	before, _ := localRelayInstance.Relay.GetIdentity(did)
	genesis := keyAccount(before.State.AuthKeys[0].PublicKeyMultibase)

	// Declared: chain business, and the refusal names the operation that is not
	// this one.
	if err := removeRefusal(t, genesis); !strings.Contains(err.Error(), "rotate") {
		t.Fatalf("the declared-key refusal does not point at rotation: %v", err)
	}
	if !storeA.HasKey(genesis) {
		t.Fatal("a refusal deleted a declared key")
	}

	// Rotate every role, and the same key becomes superseded — still refused,
	// for the reason prune retains it: this relay's view can trail the network.
	identityFlag = "alice"
	update := newIdentityUpdateCmd()
	mustSetFlag(t, update, "rotate-auth", "true")
	mustSetFlag(t, update, "rotate-controller", "true")
	mustSetFlag(t, update, "rotate-assert", "true")
	if err := update.RunE(update, nil); err != nil {
		t.Fatalf("identity update --rotate-*: %v", err)
	}
	if err := removeRefusal(t, genesis); !strings.Contains(err.Error(), statusSuperseded) {
		t.Fatalf("the superseded refusal does not name the status: %v", err)
	}
	if !storeA.HasKey(genesis) {
		t.Fatal("a refusal deleted a superseded key")
	}

	// The sign-in client key: infrastructure, and the refusal names the file
	// that is the real handle on it.
	writeLoginClientFile(t, "did:dfos:loginclient", "key_login")
	login := loginClientAccount("key_login")
	plantKey(t, storeA, login)
	if err := removeRefusal(t, login); !strings.Contains(err.Error(), loginClientFileName) {
		t.Fatalf("the login-client refusal does not name %s: %v", loginClientFileName, err)
	}
	if !storeA.HasKey(login) {
		t.Fatal("a refusal deleted the sign-in client key")
	}

	// Uncertain is neither a candidate nor an orphan.
	plantKey(t, storeA, "something-nobody-here-writes")
	if err := removeRefusal(t, "something-nobody-here-writes"); !strings.Contains(err.Error(), statusUnrecognized) {
		t.Fatalf("the uncertain refusal does not name the status: %v", err)
	}
	if !storeA.HasKey("something-nobody-here-writes") {
		t.Fatal("a refusal deleted a key it could not classify")
	}
}

func TestKeysRemoveOnAnUnknownSelectorRemovesNothing(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	createStandaloneIdentity(t, "alice", storeA)
	keys = storeA

	err := removeRefusal(t, "key_nothingherematchesthis")
	if !strings.Contains(err.Error(), "no key matching") {
		t.Fatalf("an unknown selector reported %v", err)
	}
	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("buildKeyLedger: %v", err)
	}
	if len(ledger.Entries) == 0 {
		t.Fatal("a failed selector emptied the keystore")
	}
}

// A superseded verdict is only as current as the chain behind it, and the
// incident this guards against is what happens when it does not say so: a LIVE
// key reported as "the chain for this DID is in the local relay and no longer
// names this key", at full confidence, off a chain that had been forked locally
// while the identity's own relay served a newer head naming the key live.
//
// So the verdict names its basis wherever it appears — in the ledger's reason,
// in `keys list --json` with the CID whole, and in the `keys remove` refusal,
// which additionally names the command that asks the relay.
func TestSupersededVerdictNamesTheChainHeadItWasReadFrom(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	keys = storeA

	before, _ := localRelayInstance.Relay.GetIdentity(did)
	genesis := keyAccount(before.State.AuthKeys[0].PublicKeyMultibase)

	identityFlag = "alice"
	update := newIdentityUpdateCmd()
	mustSetFlag(t, update, "rotate-controller", "true")
	mustSetFlag(t, update, "rotate-auth", "true")
	mustSetFlag(t, update, "rotate-assert", "true")
	if err := update.RunE(update, nil); err != nil {
		t.Fatalf("identity update --rotate-*: %v", err)
	}

	after, _ := localRelayInstance.Relay.GetIdentity(did)
	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("build ledger: %v", err)
	}

	retired := entryFor(t, ledger, genesis)
	if retired.Status != statusSuperseded {
		t.Fatalf("the rotated-out key is %s, want %s", retired.Status, statusSuperseded)
	}
	// The prose carries the head, its date, and the fact that no relay answered.
	for _, want := range []string{
		"as of local head", truncateMiddle(after.HeadCID, 16), after.LastCreatedAt,
		"the identity's relay was not consulted",
	} {
		if !strings.Contains(retired.Reason, want) {
			t.Fatalf("the superseded reason is missing %q:\n%s", want, retired.Reason)
		}
	}
	// The document carries the CID whole, so a caller can compare it against
	// what a relay serves rather than against a terminal-width abbreviation.
	if retired.AsOf == nil || retired.AsOf.HeadCID != after.HeadCID || retired.AsOf.LastCreatedAt != after.LastCreatedAt {
		t.Fatalf("asOf = %+v, want head %s at %s", retired.AsOf, after.HeadCID, after.LastCreatedAt)
	}

	// Only the negative verdict is stamped. A declared key's row is not a claim
	// about what some other relay might say, so it carries no basis at all.
	current := entryFor(t, ledger, keyAccount(after.State.AuthKeys[0].PublicKeyMultibase))
	if current.Status != statusDeclared {
		t.Fatalf("the rotated-in key is %s, want %s", current.Status, statusDeclared)
	}
	if current.AsOf != nil {
		t.Fatalf("a declared key carries a basis stamp: %+v", current.AsOf)
	}

	// The same two facts survive the JSON path.
	var listed keyLedger
	runJSON(t, newKeysListCmd(), nil, &listed)
	listedEntry := entryFor(t, &listed, genesis)
	if listedEntry.AsOf == nil || listedEntry.AsOf.HeadCID != after.HeadCID {
		t.Fatalf("'keys list --json' dropped the basis: %+v", listedEntry.AsOf)
	}

	// And the refusal, which is where an operator most needs to know that the
	// verdict keeping their key is one relay's — and how to check it.
	refusal := removeRefusal(t, genesis).Error()
	for _, want := range []string{
		"as of local head", truncateMiddle(after.HeadCID, 16),
		"the identity's relay was not consulted",
		"'dfos identity status alice' compares this machine's chain against the identity's relay",
	} {
		if !strings.Contains(refusal, want) {
			t.Fatalf("the superseded refusal is missing %q:\n%s", want, refusal)
		}
	}
}

func writeLoginClientFile(t *testing.T, did, keyID string) {
	t.Helper()
	body, err := json.Marshal(loginClient{DID: did, KeyID: keyID, Chain: []string{}})
	if err != nil {
		t.Fatalf("marshal login client: %v", err)
	}
	path := loginClientPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write login client: %v", err)
	}
}

// A key a chain DECLARES but no possession proof admitted is void: absent from
// effective state, absent from the index, conferring nothing. The ledger's job is
// to say that out loud.
//
// The failure this guards against is specific and was real: reading only
// effective state, a held key under a void declaration fell through every
// placement branch and came out an ORPHAN, reason "no identity in the local relay
// declares this key" — which is exactly backwards. A chain declares it. The
// declaration is simply empty, and `prune`'s whole contract rests on orphan
// meaning nothing claims a key.
func TestKeys_AVoidMembershipIsDeclaredAndVoidNeverAnOrphan(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)

	chain, err := lr.Relay.GetIdentity(did)
	if err != nil || chain == nil {
		t.Fatalf("get identity: chain=%v err=%v", chain, err)
	}
	signer, err := selectHeldKey(did, chain.State.ControllerKeys, "controller")
	if err != nil {
		t.Fatalf("held controller key: %v", err)
	}
	controllerPriv, err := keys.GetPrivateKey(signer.Account)
	if err != nil {
		t.Fatalf("read controller key: %v", err)
	}

	// A second key this machine holds, introduced to the chain WITHOUT a proof —
	// the shape another implementation can still author and a relay still
	// sequences, because an unproved introduction voids a membership rather than
	// invalidating an operation.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	unproved := protocol.EncodeMultikey(pub)
	keyID := protocol.DeriveKeyID(unproved)
	mk := protocol.NewMultikeyPublicKey(keyID, pub)
	account := keyAccount(unproved)
	if _, err := keys.PutKey(account, priv); err != nil {
		t.Fatalf("store the unproved key: %v", err)
	}

	head := chain.Log[len(chain.Log)-1]
	h, _, err := protocol.DecodeJWSUnsafe(head)
	if err != nil {
		t.Fatalf("decode head: %v", err)
	}
	jws := signUnprovedIdentityUpdate(t, unprovedUpdate{
		previousCID:    h.CID,
		after:          chain.LastCreatedAt,
		controllerKeys: chain.State.ControllerKeys,
		authKeys:       append(append([]protocol.MultikeyPublicKey{}, chain.State.AuthKeys...), mk),
		assertKeys:     chain.State.AssertKeys,
		kid:            signer.KID,
		privateKey:     controllerPriv,
	})
	if res := lr.Relay.Ingest([]string{jws}); len(res) > 0 && res[0].Status == "rejected" {
		t.Fatalf("the relay rejected an unproved introduction instead of voiding it: %s", res[0].Error)
	}

	after, err := lr.Relay.GetIdentity(did)
	if err != nil || after == nil {
		t.Fatalf("get identity after: chain=%v err=%v", after, err)
	}
	if len(after.State.VoidKeys) == 0 {
		t.Fatalf("the chain records no void membership: %+v", after.State)
	}

	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	entry := entryFor(t, ledger, account)
	if entry.Status == statusOrphan {
		t.Fatalf("a key its own chain declares reported as an orphan: %+v", entry)
	}
	if entry.Status != statusDeclared {
		t.Fatalf("status %q, want %q", entry.Status, statusDeclared)
	}
	if !entry.Void {
		t.Fatalf("a wholly-void key is not marked void: %+v", entry)
	}
	if entry.Prunable {
		t.Fatal("a void key is prunable — prune would delete a key its chain still names")
	}
	if !contains(entry.Roles, "auth (void)") {
		t.Fatalf("roles %v, want the void marker", entry.Roles)
	}
	if !strings.Contains(entry.Reason, "VOID") {
		t.Fatalf("the reason does not say the membership is void: %q", entry.Reason)
	}
}

// unprovedUpdate is one identity update authored WITHOUT a possession proof for
// the keys it introduces.
type unprovedUpdate struct {
	previousCID string
	// after is the createdAt of the operation this one extends. A chain requires
	// each operation to be strictly later than the last, and a test that builds
	// two operations back to back can land both inside the same millisecond — so
	// this timestamp is derived from the parent rather than read off the clock and
	// hoped about. Getting it from the clock produces a test that passes alone and
	// fails in a full run, which is the worst kind of test.
	after                                string
	controllerKeys, authKeys, assertKeys []protocol.MultikeyPublicKey
	kid                                  string
	privateKey                           ed25519.PrivateKey
}

// signUnprovedIdentityUpdate hand-rolls an identity update operation from the
// kit's LOWER-LEVEL primitives — the CID computation and the JWS constructor —
// rather than going through SignIdentityUpdate.
//
// WHY THIS IS NOT LAZINESS OR A BACK DOOR. The kit's writers refuse to author an
// introduction that carries no proof, which is correct: this CLI must never mint
// a void membership. But a void membership is still a state that ARRIVES — a
// different implementation can author one, and operations already on the network
// may carry them — and a relay sequences such an operation rather than rejecting
// it, because an unproved introduction voids a membership without invalidating
// the operation that made it. So the receiving path needs coverage, and coverage
// needs a fixture the writer door is designed to make unobtainable.
//
// This is therefore a deliberate HOSTILE-IMPLEMENTATION FIXTURE: it stands in for
// a peer that does not enforce what we enforce. It lives here, in a test, and
// nothing in the command path can reach it. Building it from the primitives
// rather than from an exported unsafe signer is the point — the kit exposes no
// way to mint an unproved introduction, and this does not ask it to.
//
// It mirrors SignIdentityUpdateWithServices's payload exactly (member set, member
// names, and the whole-second timestamp spelling). If that shape ever changes,
// this fixture stops producing a chain the relay will sequence, and the test that
// depends on it fails rather than silently testing nothing.
func signUnprovedIdentityUpdate(t *testing.T, in unprovedUpdate) string {
	t.Helper()

	empty := func(s []protocol.MultikeyPublicKey) []protocol.MultikeyPublicKey {
		if s == nil {
			return []protocol.MultikeyPublicKey{}
		}
		return s
	}
	payload := map[string]any{
		"version":              1,
		"type":                 "update",
		"previousOperationCID": in.previousCID,
		"authKeys":             empty(in.authKeys),
		"assertKeys":           empty(in.assertKeys),
		"controllerKeys":       empty(in.controllerKeys),
		"createdAt":            afterTimestamp(t, in.after),
	}

	_, _, cid, err := protocol.DagCborCID(payload)
	if err != nil {
		t.Fatalf("compute the operation CID: %v", err)
	}
	jws, err := protocol.CreateJWS(protocol.JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:identity-op",
		Kid: in.kid,
		CID: cid,
	}, payload, in.privateKey)
	if err != nil {
		t.Fatalf("sign the unproved update: %v", err)
	}
	return jws
}

// afterTimestamp returns a protocol timestamp strictly later than prior, and no
// further into the future than it has to be.
//
// A chain rejects an operation whose createdAt does not advance, and it also
// rejects one too far ahead of the verifier's clock — so this takes the later of
// "one second past the parent" and "now", which satisfies both ends without
// depending on how fast the test ran.
func afterTimestamp(t *testing.T, prior string) string {
	t.Helper()
	const layout = "2006-01-02T15:04:05.000Z"
	next := time.Now().UTC()
	if prior != "" {
		parsed, err := time.Parse(layout, prior)
		if err != nil {
			t.Fatalf("parse the parent operation's createdAt %q: %v", prior, err)
		}
		if bump := parsed.Add(time.Second); bump.After(next) {
			next = bump
		}
	}
	return next.Format(layout)
}
