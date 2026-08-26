package relay

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// ===================================================================
// store test doubles
//
// Both embed the Store INTERFACE (not *MemoryStore), so only Store's own
// methods are promoted. That keeps the doubles from accidentally satisfying
// SigningStore / RebuildableIndexStore and changing which relay code paths the
// test exercises.
// ===================================================================

var errInjectedStore = errors.New("injected store failure")

// failingCommitStore makes the ingestion batch's CommitWriteBatch fail, so a
// test can observe what the relay does with a batch it could not commit.
//
// NOTE: the wrapped store is a MemoryStore with no real transaction, so the
// rollback is SIMULATED — the underlying writes are not actually reverted.
// That is deliberate and sufficient: these tests pin the RELAY's contract on
// commit failure (do not gossip, do not report the batch as landed), not
// SQLite's transactional semantics, which are the store's own concern.
type failingCommitStore struct {
	Store
	begun      int
	committed  int
	rolledBack int
}

func (s *failingCommitStore) BeginWriteBatch() error {
	s.begun++
	return nil
}

func (s *failingCommitStore) CommitWriteBatch() error {
	s.committed++
	return errInjectedStore
}

func (s *failingCommitStore) RollbackWriteBatch() error {
	s.rolledBack++
	return nil
}

// erroringStore injects a read failure into the specific store lookups that
// back an authorization gate. Each injection is opt-in and individually
// toggleable so a test can build its fixture against a healthy store and only
// then break the one lookup under test.
type erroringStore struct {
	Store
	// failIdentityDID makes GetIdentityChain fail for exactly this DID, and by
	// default only for its FIRST call.
	//
	// Both narrowings matter, because GetIdentityChain backs two different
	// things: the deleted-identity GATE, and key resolution. The gate always
	// reads first. If the injection also hit the later key-resolution read, the
	// read would be denied by a failed key resolve no matter what the gate did —
	// so the test would pass against the pre-fix code too, and prove nothing.
	// Failing only the gate's own read leaves the rest of verification healthy,
	// which is what makes "denied" attributable to the gate.
	failIdentityDID string
	// failIdentityCalls is how many calls for failIdentityDID fail (0 means 1).
	// Set it high to fail every call.
	failIdentityCalls int
	failedIdentity    int
	// failRevocation makes every IsCredentialRevoked lookup fail.
	failRevocation bool
}

func (s *erroringStore) GetIdentityChain(did string) (*StoredIdentityChain, error) {
	if s.failIdentityDID != "" && did == s.failIdentityDID {
		budget := s.failIdentityCalls
		if budget == 0 {
			budget = 1
		}
		if s.failedIdentity < budget {
			s.failedIdentity++
			return nil, errInjectedStore
		}
	}
	return s.Store.GetIdentityChain(did)
}

func (s *erroringStore) IsCredentialRevoked(issuerDID, credentialCID string, asOfUnix int64) (bool, error) {
	if s.failRevocation {
		return false, errInjectedStore
	}
	return s.Store.IsCredentialRevoked(issuerDID, credentialCID, asOfUnix)
}

// assertRetryableStoreReadRejection asserts the fail-closed shape: the op was
// DENIED, and denied RETRYABLY (DependencyMissing), so the raw op stays pending
// for the sequencer instead of being permanently — and irrecoverably — dropped.
func assertRetryableStoreReadRejection(t *testing.T, result IngestionResult) {
	t.Helper()
	if result.Status != "rejected" {
		t.Fatalf("a store error at an authorization gate must DENY, got status %q", result.Status)
	}
	if !result.DependencyMissing {
		t.Fatal("a store error is transient — the rejection must be retryable, or MarkOpRejected deletes the raw op forever")
	}
	if !strings.Contains(result.Error, storeReadErrorPrefix) {
		t.Fatalf("error = %q, want it prefixed %q", result.Error, storeReadErrorPrefix)
	}
}

// ===================================================================
// 1. commit failure must not gossip and must not report the batch landed
// ===================================================================

// TestCommitFailureDoesNotGossipOrReportLanded pins the rollback contract.
//
// The defect: on CommitWriteBatch failure the relay logged, called
// RollbackWriteBatch, and then STILL gossiped the batch's ops to peers and
// STILL returned status:"new" to the HTTP caller — advertising and reporting
// chain state it no longer held. Local state and what the relay told the world
// diverged, permanently, on a single failed commit.
func TestCommitFailureDoesNotGossipOrReportLanded(t *testing.T) {
	peerStore := NewMemoryStore()
	mock := newMockPeerClient(peerStore, 0)
	store := &failingCommitStore{Store: NewMemoryStore()}
	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	id := createTestIdentity(t)
	results := relay.Ingest([]string{id.token})

	if store.rolledBack != 1 {
		t.Fatalf("expected exactly 1 rollback after the failed commit, got %d", store.rolledBack)
	}

	// The batch is not held, so it must not be advertised.
	if calls := mock.drainSubmits(100 * time.Millisecond); len(calls) != 0 {
		t.Fatalf("a rolled-back batch must not be gossiped, got %d gossip call(s)", len(calls))
	}

	// ...and it must not be reported to the caller as landed.
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status == "new" || results[0].Status == "duplicate" {
		t.Fatalf("a rolled-back op must not be reported as %q — the relay does not hold it", results[0].Status)
	}
	if results[0].Status != "rejected" || !results[0].DependencyMissing {
		t.Fatalf("expected a retryable rejection, got status=%q dependencyMissing=%v",
			results[0].Status, results[0].DependencyMissing)
	}
	if !strings.Contains(results[0].Error, persistErrorPrefix) {
		t.Fatalf("error = %q, want it prefixed %q", results[0].Error, persistErrorPrefix)
	}
	if results[0].CID == "" {
		t.Fatal("the rewritten result must keep its CID so the op can be located in the raw store")
	}
}

// TestSuccessfulCommitStillGossips is the control for the test above: the
// rewrite must fire ONLY on commit failure, never on the healthy path.
func TestSuccessfulCommitStillGossips(t *testing.T) {
	peerStore := NewMemoryStore()
	mock := newMockPeerClient(peerStore, 0)
	relay, err := NewRelay(RelayOptions{
		Store:      NewMemoryStore(),
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	id := createTestIdentity(t)
	results := relay.Ingest([]string{id.token})
	if results[0].Status != "new" {
		t.Fatalf("healthy path: expected new, got %s (%s)", results[0].Status, results[0].Error)
	}
	if calls := mock.drainSubmits(100 * time.Millisecond); len(calls) != 1 {
		t.Fatalf("healthy path: expected 1 gossip call, got %d", len(calls))
	}
}

// ===================================================================
// 2a. fail-closed: revocation check (ingest path)
// ===================================================================

// TestIngestCredentialDeniesWhenRevocationCheckFails covers the revocation-gate
// class. ingestPublicCredential asks "is this credential already revoked?"
// before admitting it as standing authorization. The lookup previously
// discarded its error, so a store failure read as "not revoked" and the
// credential was ADMITTED on no evidence.
func TestIngestCredentialDeniesWhenRevocationCheckFails(t *testing.T) {
	memory := NewMemoryStore()
	store := &erroringStore{Store: memory}
	relay, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}

	issuer := createTestIdentity(t)
	if result := relay.Ingest([]string{issuer.token})[0]; result.Status != "new" {
		t.Fatalf("seed issuer identity: %s (%s)", result.Status, result.Error)
	}
	credential, _ := mintDelegatedCredential(t,
		issuer.did, issuer.did+"#"+issuer.auth.keyID, issuer.auth.priv,
		"*", "chain:*", "read", nil, time.Hour)

	// Control: a healthy revocation lookup admits the credential.
	if result := relay.Ingest([]string{credential})[0]; result.Status != "new" {
		t.Fatalf("control: expected new, got %s (%s)", result.Status, result.Error)
	}

	// Now break the revocation lookup and re-admit the same credential from a
	// clean store. A gate that cannot be evaluated must deny.
	memory2 := NewMemoryStore()
	store2 := &erroringStore{Store: memory2}
	relay2, err := NewRelay(RelayOptions{Store: store2})
	if err != nil {
		t.Fatal(err)
	}
	if result := relay2.Ingest([]string{issuer.token})[0]; result.Status != "new" {
		t.Fatalf("seed issuer identity: %s (%s)", result.Status, result.Error)
	}
	store2.failRevocation = true
	assertRetryableStoreReadRejection(t, relay2.Ingest([]string{credential})[0])
}

// ===================================================================
// 2b. fail-closed: deleted-identity gate (ingest path)
// ===================================================================

// TestIngestContentDeniesWhenSignerDeletedLookupFails covers the
// deleted-identity gate class. ingestContentOp refuses content ops signed by a
// deleted identity; the lookup previously discarded its error, so a store
// failure read as "not deleted" and the write was ADMITTED.
func TestIngestContentDeniesWhenSignerDeletedLookupFails(t *testing.T) {
	memory := NewMemoryStore()
	store := &erroringStore{Store: memory}
	relay, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}

	id := createTestIdentity(t)
	if result := relay.Ingest([]string{id.token})[0]; result.Status != "new" {
		t.Fatalf("seed identity: %s (%s)", result.Status, result.Error)
	}
	contentToken, _, _ := createTestContent(t, id)

	// Break every lookup of the signer's identity. Unlike the read-path tests
	// below, the gate's read is not reliably the first call for this DID (the
	// ingest pipeline reads it earlier too), so scoping to one call is fragile
	// here. Discrimination comes instead from asserting the ERROR SHAPE: with
	// the gate swallowing its error, the op was admitted outright or rejected
	// later by key resolution ("unknown identity:") — never with the
	// storeReadErrorPrefix that assertRetryableStoreReadRejection requires.
	store.failIdentityDID = id.did
	store.failIdentityCalls = 1 << 30
	assertRetryableStoreReadRejection(t, relay.Ingest([]string{contentToken})[0])

	// Control: with the lookup healthy the same op is admitted, proving the
	// denial came from the injected failure and not from the fixture.
	store.failIdentityDID = ""
	if result := relay.Ingest([]string{contentToken})[0]; result.Status != "new" {
		t.Fatalf("control: expected new, got %s (%s)", result.Status, result.Error)
	}
}

// ===================================================================
// 2c. fail-closed: read path — leaf gates and the delegation walk
// ===================================================================

// readPathFixture seeds a creator, a delegate, and a delegated credential
// chain: creator A issues a root credential to delegate B, and B issues the
// leaf to the requester. The leaf therefore carries prf=[root], so verifying it
// EXERCISES THE DELEGATION WALK rather than short-circuiting at the root.
type readPathFixture struct {
	creator   testIdentity
	delegate  testIdentity
	requester testIdentity
	leafJWS   string
	resource  string
}

func newReadPathFixture(t *testing.T, relay *Relay) readPathFixture {
	t.Helper()
	creator := createTestIdentity(t)
	delegate := createTestIdentity(t)
	requester := createTestIdentity(t)
	for _, id := range []testIdentity{creator, delegate, requester} {
		if result := relay.Ingest([]string{id.token})[0]; result.Status != "new" {
			t.Fatalf("seed identity: %s (%s)", result.Status, result.Error)
		}
	}
	const resource = "chain:bafytestcontent"
	rootJWS, _ := mintDelegatedCredential(t,
		creator.did, creator.did+"#"+creator.auth.keyID, creator.auth.priv,
		delegate.did, resource, "read", nil, time.Hour)
	leafJWS, _ := mintDelegatedCredential(t,
		delegate.did, delegate.did+"#"+delegate.auth.keyID, delegate.auth.priv,
		requester.did, resource, "read", []string{rootJWS}, time.Hour)
	return readPathFixture{
		creator:   creator,
		delegate:  delegate,
		requester: requester,
		leafJWS:   leafJWS,
		resource:  resource,
	}
}

func (f readPathFixture) verify(store Store) error {
	return verifyCredentialForAccess(
		f.leafJWS, CreateKeyResolver(store), f.resource, "read",
		f.creator.did, f.requester.did, store, false,
	)
}

// TestReadPathDeniesWhenStoreErrorsAtAnAuthorizationGate covers every read-path
// gate class in one table. Each case breaks exactly one store lookup and
// asserts the read is DENIED — previously each of these swallowed its error and
// returned "not revoked" / "not deleted", authorizing the read on no evidence.
func TestReadPathDeniesWhenStoreErrorsAtAnAuthorizationGate(t *testing.T) {
	memory := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{Store: memory})
	if err != nil {
		t.Fatal(err)
	}
	fix := newReadPathFixture(t, relay)

	// Control first: the whole chain verifies against a healthy store. Without
	// this the denials below would prove nothing — a broken fixture also denies.
	if err := fix.verify(memory); err != nil {
		t.Fatalf("control: healthy store must grant access, got %v", err)
	}

	// Each case breaks ONLY the gate's own lookup (see erroringStore.failIdentityDID
	// on why the deleted-identity cases fail just the first call), leaving the
	// rest of verification healthy — so a denial is attributable to the gate and
	// not to some later step failing for its own reasons.
	cases := []struct {
		name   string
		break_ func(s *erroringStore)
		gate   string
	}{
		{
			name:   "leaf revocation check",
			break_: func(s *erroringStore) { s.failRevocation = true },
			gate:   "the leaf's own revocation lookup, and the delegation walk's isRevoked closure",
		},
		{
			name:   "leaf issuer deleted gate",
			break_: func(s *erroringStore) { s.failIdentityDID = fix.delegate.did },
			gate:   "the leaf issuer's deleted-identity lookup",
		},
		{
			name:   "delegation walk isDeleted closure",
			break_: func(s *erroringStore) { s.failIdentityDID = fix.creator.did },
			gate:   "the parent issuer's deleted-identity lookup, inside VerifyDelegationChain",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &erroringStore{Store: memory}
			tc.break_(store)
			if err := fix.verify(store); err == nil {
				t.Fatalf("a store failure at %s must DENY the read, but access was granted", tc.gate)
			}
		})
	}
}
