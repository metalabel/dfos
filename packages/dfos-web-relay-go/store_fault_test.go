package relay

import (
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// ===================================================================
// a store fault is never a verdict
//
// A permanent rejection DELETES the raw op (MarkOpRejected), which is
// unrecoverable. So the classification of "the store failed" is not a detail: an
// unmarked store error classified as permanent, and a momentary "database is
// locked" during signature verification durably destroyed a valid operation.
// These tests inject a failing store at each seam that reads one and assert the
// same two things every time — the op is DENIED, and NOTHING CHANGED.
// ===================================================================

// faultInjectingStore fails one named read, everywhere it is reached.
//
// Unlike erroringStore (fail_closed_test.go), which fails a gate's FIRST read so
// the rest of verification stays healthy, this one fails every call — the shape a
// genuinely unwell store has.
type faultInjectingStore struct {
	referenceStore
	failIdentityDID string
	failOperation   bool
	// rejected records every raw op the relay durably dropped. A store fault
	// must never put anything here.
	rejected []string
}

func (s *faultInjectingStore) GetIdentityChain(did string) (*StoredIdentityChain, error) {
	if s.failIdentityDID != "" && did == s.failIdentityDID {
		return nil, errInjectedStore
	}
	return s.referenceStore.GetIdentityChain(did)
}

func (s *faultInjectingStore) GetOperation(cid string) (*StoredOperation, error) {
	if s.failOperation {
		return nil, errInjectedStore
	}
	return s.referenceStore.GetOperation(cid)
}

func (s *faultInjectingStore) MarkOpRejected(cid string, reason string) error {
	s.rejected = append(s.rejected, cid)
	return s.referenceStore.MarkOpRejected(cid, reason)
}

// assertStoreFaultLeftTheOpAlone is the shared assertion: retryable, flagged,
// and never durably rejected. wantPending is how many raw ops must still be
// waiting for a healthier pass.
func assertStoreFaultLeftTheOpAlone(t *testing.T, store *faultInjectingStore, result IngestionResult, wantPending int) {
	t.Helper()
	if result.Status != "rejected" {
		t.Fatalf("a store fault must DENY, got status %q", result.Status)
	}
	if !result.StoreFault {
		t.Fatalf("a store fault must be flagged as one, got %+v", result)
	}
	if isPermanentRejection(result) {
		t.Fatal("a store fault classified as PERMANENT — MarkOpRejected deletes the raw op, so this destroys a valid operation")
	}
	if len(store.rejected) != 0 {
		t.Fatalf("a store fault durably rejected raw op(s) %v", store.rejected)
	}
	if n := pendingCount(t, store); n != wantPending {
		t.Fatalf("pending raw ops = %d, want %d", n, wantPending)
	}
}

// TestKeyResolverStoreFaultDoesNotDestroyTheOperation is the headline case. The
// key resolvers used to return the store's error unwrapped, so it reached the
// classifier carrying no marker at all: not a dependency miss, therefore
// permanent, therefore deleted. An artifact is the cleanest reproduction because
// its verification resolves the signer key BEFORE any gate runs.
func TestKeyResolverStoreFaultDoesNotDestroyTheOperation(t *testing.T) {
	backing := NewMemoryStore()
	seed, err := BootstrapRelayIdentity(backing)
	if err != nil {
		t.Fatal(err)
	}
	healthy, err := NewRelay(RelayOptions{Store: backing, Identity: seed})
	if err != nil {
		t.Fatal(err)
	}
	id := ingestIdentity(t, healthy)
	artifact, _, err := dfos.SignArtifact(id.did,
		map[string]any{"$schema": "test/v1", "title": "hi"},
		id.did+"#"+id.auth.keyID, id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	store := &faultInjectingStore{referenceStore: backing, failIdentityDID: id.did}
	r, err := NewRelay(RelayOptions{Store: store, Identity: seed})
	if err != nil {
		t.Fatal(err)
	}

	assertStoreFaultLeftTheOpAlone(t, store, r.Ingest([]string{artifact})[0], 1)

	// Healed, the same operation is admitted — which is the whole point of
	// keeping it.
	store.failIdentityDID = ""
	if result := r.RunSequencerAndGossip(); result.Sequenced != 1 {
		t.Fatalf("expected the retry to sequence the artifact, got %+v", result)
	}
}

// TestIdempotencyReadStoreFaultDoesNotTruncateAChain covers the other unmarked
// read. Two idempotency gates dropped their error outright, so one transient
// reader fault on a RESUBMITTED genesis made "have I got this?" answer no, re-ran
// the genesis branch, and rewrote an N-operation chain as a 1-operation chain —
// reviving rotated-out keys and undoing a delete, unrecoverably.
func TestIdempotencyReadStoreFaultDoesNotTruncateAChain(t *testing.T) {
	backing := NewMemoryStore()
	seed, err := BootstrapRelayIdentity(backing)
	if err != nil {
		t.Fatal(err)
	}
	healthy, err := NewRelay(RelayOptions{Store: backing, Identity: seed})
	if err != nil {
		t.Fatal(err)
	}
	id := ingestIdentity(t, healthy)
	rotateExistingTestIdentity(t, healthy, id)

	before, err := backing.GetIdentityChain(id.did)
	if err != nil || before == nil || len(before.Log) < 2 {
		t.Fatalf("fixture: expected a multi-operation chain, got %+v (%v)", before, err)
	}

	store := &faultInjectingStore{referenceStore: backing, failOperation: true}
	r, err := NewRelay(RelayOptions{Store: store, Identity: seed})
	if err != nil {
		t.Fatal(err)
	}

	// Resubmit the genesis against a store whose operation lookup is broken. Its
	// raw op was drained by the healthy pass that first admitted it, so what
	// matters here is that the resubmission decides nothing and changes nothing.
	assertStoreFaultLeftTheOpAlone(t, store, r.Ingest([]string{id.token})[0], 0)

	after, err := backing.GetIdentityChain(id.did)
	if err != nil || after == nil {
		t.Fatalf("read chain after the faulted resubmission: %v", err)
	}
	if len(after.Log) != len(before.Log) || after.HeadCID != before.HeadCID {
		t.Fatalf("a resubmitted genesis truncated the chain: %d ops → %d, head %s → %s",
			len(before.Log), len(after.Log), before.HeadCID, after.HeadCID)
	}
}

// TestGenesisNeverReplacesAnExistingChain is the independent guard behind the
// idempotency read: whatever the read answers, nothing legitimate replaces a
// chain with its own genesis, so the write path refuses it outright.
func TestGenesisNeverReplacesAnExistingChain(t *testing.T) {
	store := NewMemoryStore()
	r, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	id := ingestIdentity(t, r)
	rotateExistingTestIdentity(t, r, id)

	before, _ := store.GetIdentityChain(id.did)

	// Re-ingest the genesis with the operation row removed from under it, which
	// is exactly the state a swallowed idempotency read used to simulate.
	drained := &operationHidingStore{referenceStore: store, hide: computeOpCID(id.token)}
	r2, err := NewRelay(RelayOptions{Store: drained, Identity: &RelayIdentity{DID: r.DID(), ProfileArtifactJWS: r.ProfileArtifactJWS()}})
	if err != nil {
		t.Fatal(err)
	}
	result := r2.Ingest([]string{id.token})[0]
	if result.Status != "rejected" {
		t.Fatalf("a genesis for a DID that already has history must be refused, got %q", result.Status)
	}

	after, _ := store.GetIdentityChain(id.did)
	if len(after.Log) != len(before.Log) || after.HeadCID != before.HeadCID {
		t.Fatalf("the chain was replaced by its own genesis: %d ops → %d", len(before.Log), len(after.Log))
	}
}

// operationHidingStore answers "not held" for one operation CID while leaving
// every other read intact — the state a genesis resubmission sees when the
// operations table and the chain row disagree.
type operationHidingStore struct {
	referenceStore
	hide string
}

func (s *operationHidingStore) GetOperation(cid string) (*StoredOperation, error) {
	if cid == s.hide {
		return nil, nil
	}
	return s.referenceStore.GetOperation(cid)
}
