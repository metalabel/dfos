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
	authAccount := vaultDID + "#" + chain.State.AuthKeys[0].ID
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
	standalone := entryFor(t, ledger, standaloneDID+"#"+bobChain.State.AuthKeys[0].ID)
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
		if !storeA.HasKey(did + "#" + k.ID) {
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
	oldAuth := did + "#" + before.State.AuthKeys[0].ID

	identityFlag = "alice"
	update := newIdentityUpdateCmd()
	mustSetFlag(t, update, "rotate-auth", "true")
	if err := update.RunE(update, nil); err != nil {
		t.Fatalf("identity update --rotate-auth: %v", err)
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
	entryFor(t, ledger, did+"#"+chain.State.AuthKeys[0].ID)
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
	entry := entryFor(t, ledger, did+"#"+chain.State.AuthKeys[0].ID)
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
	priv, err := storeA.GetPrivateKey(did + "#" + keyID)
	if err != nil {
		t.Fatalf("get private key: %v", err)
	}

	for _, selector := range []string{keyID, did + "#" + keyID, chain.State.AuthKeys[0].PublicKeyMultibase} {
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
		ControllerKey string `json:"controllerKey"`
		AuthKey       string `json:"authKey"`
	}
	runJSON(t, create, nil, &created)
	identityFlag = "alice"

	rotate := newIdentityUpdateCmd()
	mustSetFlag(t, rotate, "rotate-auth", "true")
	runJSON(t, rotate, nil, nil)

	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("build ledger: %v", err)
	}

	retired := entryFor(t, ledger, created.DID+"#"+created.AuthKey)
	if retired.Status != statusSuperseded {
		t.Fatalf("the rotated-out key is %s, want %s", retired.Status, statusSuperseded)
	}
	if len(retired.Roles) != 1 || retired.Roles[0] != "auth" {
		t.Fatalf("superseded roles = %v, want [auth]", retired.Roles)
	}
	if row := declaredBy(retired); !strings.Contains(row, "was auth") || !strings.Contains(row, "no longer current") {
		t.Fatalf("the table row does not say which role was retired: %q", row)
	}

	// The role a rotation did NOT touch still reads as current.
	held := entryFor(t, ledger, created.DID+"#"+created.ControllerKey)
	if held.Status != statusDeclared {
		t.Fatalf("the untouched controller key is %s, want %s", held.Status, statusDeclared)
	}
	if len(held.Roles) != 1 || held.Roles[0] != "controller" {
		t.Fatalf("declared roles = %v, want [controller]", held.Roles)
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
