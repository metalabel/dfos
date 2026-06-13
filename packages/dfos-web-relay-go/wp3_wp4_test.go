package relay

import (
	"fmt"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// ===================================================================
// WP-3 — structured dependency discriminator
// ===================================================================

// corruptSignature flips one character of a JWS signature segment so
// verification fails while the header/payload (→ CID) stay intact.
func corruptSignature(jws string) string {
	parts := []rune(jws)
	// find the last '.' and flip the char after it
	last := -1
	for i, c := range parts {
		if c == '.' {
			last = i
		}
	}
	if last < 0 || last+1 >= len(parts) {
		return jws
	}
	if parts[last+1] == 'A' {
		parts[last+1] = 'B'
	} else {
		parts[last+1] = 'A'
	}
	return string(parts)
}

// TestCIDLessDurabilityBadSigGenesis verifies a bad-signature genesis identity
// op carries a CID on rejection (so it is durably rejectable, not skipped
// forever by the sequencer's `if res.CID == "" continue`) and is NOT classified
// as a missing dependency.
func TestCIDLessDurabilityBadSigGenesis(t *testing.T) {
	store := NewMemoryStore()
	id := createTestIdentity(t)
	corrupt := corruptSignature(id.token)

	results := IngestOperations([]string{corrupt}, store)
	if results[0].Status != "rejected" {
		t.Fatalf("expected rejected, got %s", results[0].Status)
	}
	if results[0].CID == "" {
		t.Fatal("expected the rejection to carry a CID (durably rejectable)")
	}
	if results[0].DependencyMissing {
		t.Fatal("a bad-sig identity genesis is permanent, not a missing dependency")
	}
}

// TestBadSigDurablyRejectedThroughSequencer verifies the bad-sig op is marked
// rejected by the sequencer and not re-verified on a subsequent tick.
func TestBadSigDurablyRejectedThroughSequencer(t *testing.T) {
	store := NewMemoryStore()
	id := createTestIdentity(t)
	corrupt := corruptSignature(id.token)
	cid := computeOpCID(corrupt)
	if cid == "" {
		t.Fatal("expected a decodable corrupt token")
	}
	store.PutRawOp(cid, corrupt)

	relay, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	_, result := relay.RunSequencer()
	if result.Rejected != 1 {
		t.Fatalf("expected 1 rejected, got %d (pending=%d)", result.Rejected, result.Pending)
	}

	// a second pass finds nothing pending — the op was durably rejected
	_, second := relay.RunSequencer()
	if second.Rejected != 0 || second.Pending != 0 {
		t.Fatalf("expected nothing to process on second pass, got rejected=%d pending=%d", second.Rejected, second.Pending)
	}
}

// TestDependencyConvergenceContentBeforeKey verifies a content op ingested
// before its signing identity stays pending (DependencyMissing) and sequences
// once the identity arrives.
func TestDependencyConvergenceContentBeforeKey(t *testing.T) {
	store := NewMemoryStore()
	id := createTestIdentity(t)
	contentToken, _, _ := createTestContent(t, id)

	// ingest content before the identity is resolvable
	pending := IngestOperations([]string{contentToken}, store)
	if pending[0].Status != "rejected" {
		t.Fatalf("expected rejected (pending), got %s", pending[0].Status)
	}
	if !pending[0].DependencyMissing {
		t.Fatalf("expected DependencyMissing=true, got error %q", pending[0].Error)
	}
	if pending[0].CID == "" {
		t.Fatal("expected the pending rejection to carry a CID")
	}

	// ingest the identity, then the content op sequences
	IngestOperations([]string{id.token}, store)
	resolved := IngestOperations([]string{contentToken}, store)
	if resolved[0].Status != "new" {
		t.Fatalf("expected content op to sequence, got %s (%s)", resolved[0].Status, resolved[0].Error)
	}
}

// TestForkPointPrefixMatchesTSConstant pins the shared fork-point prefix
// byte-for-byte against the TS twin's FORK_POINT_STATE_ERROR_PREFIX.
func TestForkPointPrefixMatchesTSConstant(t *testing.T) {
	if ForkPointStateErrorPrefix != "failed to compute state at fork point: " {
		t.Fatalf("fork-point prefix drift: %q", ForkPointStateErrorPrefix)
	}
}

// ===================================================================
// WP-4 — write-path leaf revocation (the security headline)
// ===================================================================

// signDelegatedUpdate signs a content update by `delegate` carrying an inline
// authorization credential.
func signDelegatedUpdate(t *testing.T, delegate testIdentity, previousCID, docCID, authorization string) (token, opCID string) {
	t.Helper()
	kid := delegate.did + "#" + delegate.auth.keyID
	token, opCID, err := dfos.SignContentUpdateWithOptions(delegate.did, previousCID, docCID, kid, delegate.auth.priv, dfos.ContentUpdateOptions{
		Authorization: authorization,
	})
	if err != nil {
		t.Fatal(err)
	}
	return token, opCID
}

func newDocCID(t *testing.T, title string) string {
	t.Helper()
	cid, _, err := dfos.DocumentCID(map[string]any{"type": "post", "title": title})
	if err != nil {
		t.Fatal(err)
	}
	return cid
}

// TestWritePathLeafRevocationBlocksWrite is the WP-4 security test: a delegated
// write authorized by a credential is accepted, then after the LEAF credential
// is revoked the next write under the same credential is REJECTED. Without the
// explicit leaf check (verifyDelegationChain covers parents only) this would
// pass-when-it-should-fail.
func TestWritePathLeafRevocationBlocksWrite(t *testing.T) {
	store := NewMemoryStore()

	creator := createTestIdentity(t)
	delegate := createTestIdentity(t)
	contentToken, contentID, contentOpCID := createTestContent(t, creator)
	IngestOperations([]string{creator.token, delegate.token, contentToken}, store)

	// creator issues a WRITE credential to the delegate
	creatorKid := creator.did + "#" + creator.auth.keyID
	credential, err := dfos.CreateCredential(creator.did, delegate.did, creatorKid, "chain:"+contentID, "write", time.Hour, creator.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	credHeader, _, err := dfos.DecodeJWSUnsafe(credential)
	if err != nil {
		t.Fatal(err)
	}
	credentialCID := credHeader.CID

	// first delegated write — accepted
	doc1 := newDocCID(t, "first")
	w1, w1CID := signDelegatedUpdate(t, delegate, contentOpCID, doc1, credential)
	r1 := IngestOperations([]string{w1}, store)
	if r1[0].Status != "new" {
		t.Fatalf("expected first delegated write to be accepted, got %s (%s)", r1[0].Status, r1[0].Error)
	}

	// revoke the LEAF credential
	revToken, _, err := dfos.SignRevocation(creator.did, credentialCID, creatorKid, creator.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	rev := IngestOperations([]string{revToken}, store)
	if rev[0].Status != "new" {
		t.Fatalf("expected revocation to be accepted, got %s (%s)", rev[0].Status, rev[0].Error)
	}

	// second delegated write under the NOW-REVOKED leaf — MUST be rejected
	doc2 := newDocCID(t, "second")
	w2, _ := signDelegatedUpdate(t, delegate, w1CID, doc2, credential)
	r2 := IngestOperations([]string{w2}, store)
	if r2[0].Status != "rejected" {
		t.Fatalf("SECURITY: expected write under revoked leaf to be REJECTED, got %s", r2[0].Status)
	}
}

// TestWritePathAcceptsWildcardAudInline verifies an aud:"*" write credential
// presented inline is accepted (Go now matches TS — was rejected before WP-4).
func TestWritePathAcceptsWildcardAudInline(t *testing.T) {
	store := NewMemoryStore()
	creator := createTestIdentity(t)
	delegate := createTestIdentity(t)
	contentToken, contentID, contentOpCID := createTestContent(t, creator)
	IngestOperations([]string{creator.token, delegate.token, contentToken}, store)

	creatorKid := creator.did + "#" + creator.auth.keyID
	credential, err := dfos.CreateCredential(creator.did, "*", creatorKid, "chain:"+contentID, "write", time.Hour, creator.auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	doc := newDocCID(t, "wild")
	w, _ := signDelegatedUpdate(t, delegate, contentOpCID, doc, credential)
	r := IngestOperations([]string{w}, store)
	if r[0].Status != "new" {
		t.Fatalf("expected aud:* inline write to be accepted, got %s (%s)", r[0].Status, r[0].Error)
	}
}

// TestWritePathRejectsDeletedIssuer verifies a credential from a deleted issuer
// no longer authorizes a write (Go now matches TS).
func TestWritePathRejectsDeletedIssuer(t *testing.T) {
	store := NewMemoryStore()
	creator := createTestIdentity(t)
	delegate := createTestIdentity(t)
	contentToken, contentID, contentOpCID := createTestContent(t, creator)
	IngestOperations([]string{creator.token, delegate.token, contentToken}, store)

	creatorKid := creator.did + "#" + creator.auth.keyID
	credential, err := dfos.CreateCredential(creator.did, delegate.did, creatorKid, "chain:"+contentID, "write", time.Hour, creator.auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	// delete the creator (issuer) identity — signed by the controller key
	controllerKid := creator.did + "#" + creator.controller.keyID
	delToken, _, err := dfos.SignIdentityDelete(creator.opCID, controllerKid, creator.controller.priv)
	if err != nil {
		t.Fatal(err)
	}
	if dr := IngestOperations([]string{delToken}, store); dr[0].Status != "new" {
		t.Fatalf("expected identity delete to be accepted, got %s (%s)", dr[0].Status, dr[0].Error)
	}

	doc := newDocCID(t, "afterdelete")
	w, _ := signDelegatedUpdate(t, delegate, contentOpCID, doc, credential)
	r := IngestOperations([]string{w}, store)
	if r[0].Status != "rejected" {
		t.Fatalf("expected write authorized by deleted issuer to be REJECTED, got %s", r[0].Status)
	}
}

// ===================================================================
// review finding: go-sync PutRawOp error must not drop ops
// ===================================================================

// putRawOpFaultStore fails PutRawOp on the Nth call after arming, to simulate a
// transient store write failure during peer sync.
type putRawOpFaultStore struct {
	*MemoryStore
	failOnCall int // 1-based; 0 = never fail
	calls      int
}

func (f *putRawOpFaultStore) PutRawOp(cid, jwsToken string) error {
	f.calls++
	if f.failOnCall != 0 && f.calls == f.failOnCall {
		return fmt.Errorf("injected raw-op write failure")
	}
	return f.MemoryStore.PutRawOp(cid, jwsToken)
}

// syncPageClient serves a fixed set of ops over multiple sync cycles. It tracks
// the cursor it was asked to resume from so the test can assert the cursor did
// not advance past a dropped op.
type syncPageClient struct {
	entries    []PeerLogEntry
	lastAfter  string
	callCount  int
	failHealed bool // when true, the fault is healed and all ops are served
}

func (s *syncPageClient) GetIdentityLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (s *syncPageClient) GetContentLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (s *syncPageClient) SubmitOperations(string, []string) error { return nil }

func (s *syncPageClient) GetOperationLog(_ string, after string, _ int) (*PeerLogPage, error) {
	s.callCount++
	s.lastAfter = after
	// resume from `after`
	start := 0
	if after != "" {
		for i, e := range s.entries {
			if e.CID == after {
				start = i + 1
				break
			}
		}
	}
	if start >= len(s.entries) {
		return &PeerLogPage{Entries: nil, Cursor: nil}, nil
	}
	// serve one op per page so the cursor advances entry-by-entry
	e := s.entries[start]
	return &PeerLogPage{Entries: []PeerLogEntry{e}, Cursor: nil}, nil
}

// TestSyncPutRawOpFailureDoesNotAdvanceCursor verifies that a PutRawOp failure
// during peer sync does NOT advance the peer cursor — otherwise the dropped op
// would be skipped forever on the next cycle. After the store heals, a
// subsequent cycle re-fetches and stores the dropped op.
func TestSyncPutRawOpFailureDoesNotAdvanceCursor(t *testing.T) {
	// two real identity ops to sync
	idA := createTestIdentity(t)
	idB := createTestIdentity(t)
	cidA := computeOpCID(idA.token)
	cidB := computeOpCID(idB.token)

	client := &syncPageClient{
		entries: []PeerLogEntry{
			{CID: cidA, JWSToken: idA.token},
			{CID: cidB, JWSToken: idB.token},
		},
	}

	store := &putRawOpFaultStore{MemoryStore: NewMemoryStore()}
	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: client,
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// bootstrap wrote the relay identity via PutRawOp? No — bootstrap uses
	// PutIdentityChain, not PutRawOp. Arm the fault to fail the FIRST sync
	// PutRawOp (the first synced op, cidA).
	store.failOnCall = store.calls + 1

	if err := relay.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}

	// cidA must NOT have been stored, and the cursor must NOT have advanced.
	if _, ok := store.rawOps[cidA]; ok {
		t.Fatal("expected the failed op to NOT be stored")
	}
	cursor, _ := store.GetPeerCursor("http://peer-a")
	if cursor == cidA || cursor == cidB {
		t.Fatalf("cursor advanced past the dropped op: %q (op must be re-fetched next cycle)", cursor)
	}

	// heal the store and run another sync cycle — the dropped op is recovered.
	store.failOnCall = 0
	if err := relay.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.rawOps[cidA]; !ok {
		t.Fatal("expected the dropped op to be re-fetched and stored after the store healed")
	}

	// and both identities ultimately ingest
	if chain, _ := store.GetIdentityChain(idA.did); chain == nil {
		t.Fatal("expected identity A to be ingested after recovery")
	}
}
