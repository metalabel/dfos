package relay

import (
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// ===================================================================
// Two-relay convergence harness
//
// relay-conformance is single-relay (no peer/sync/replay), so this builds the
// minimal two-relay primitive in-process on top of peering_test.go's mock peer
// client. Two relays r1/r2, each with its own MemoryStore; r2 syncs r1's full
// global log in one batch. The SAME primitive serves both the temporal-split
// revocation-after-rotation guard (the D3 oracle) and the
// countersign-before-target convergence test — built ONCE.
// ===================================================================

// newSyncedRelay returns a relay r2 whose peer client serves r1's global log,
// so r2.SyncFromPeers() replays r1's full log in cursor order. r1 must already
// be drained (its sequencer run) before r2 syncs.
func newSyncedRelay(t *testing.T, r1Store *MemoryStore) *Relay {
	t.Helper()
	mock := newMockPeerClient(r1Store, 0)
	r2, err := NewRelay(RelayOptions{
		Store:      NewMemoryStore(),
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://r1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r2
}

// mintDelegatedCredential builds a delegated child credential (att + prf) by
// hand — CreateCredential hardcodes single att + prf:[] and cannot mint a
// delegated child. Shared by the subtree-revocation oracle.
func mintDelegatedCredential(t *testing.T, issuerDID, issuerKid string, issuerPriv []byte, aud, resource, action string, prf []string, ttl time.Duration) (token, cid string) {
	t.Helper()
	now := time.Now().Unix()
	prfAny := make([]any, len(prf))
	for i, p := range prf {
		prfAny[i] = p
	}
	payload := map[string]any{
		"version": 1,
		"type":    "DFOSCredential",
		"iss":     issuerDID,
		"aud":     aud,
		"att":     []any{map[string]any{"resource": resource, "action": action}},
		"prf":     prfAny,
		"exp":     now + int64(ttl.Seconds()),
		"iat":     now,
	}
	_, _, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}
	header := dfos.JWSHeader{Alg: "EdDSA", Typ: "did:dfos:credential", Kid: issuerKid, CID: cidStr}
	token, err = dfos.CreateJWS(header, payload, issuerPriv)
	if err != nil {
		t.Fatalf("CreateJWS: %v", err)
	}
	return token, cidStr
}

// ===================================================================
// D3 guard: temporal-split revocation-after-rotation
// ===================================================================

// TestTwoRelayRevocationAfterRotationConvergesUnderHistorical is the D3 guard.
//
// r1 ingests {credential, revocation} LIVE (the revocation is signed by the
// issuer's CURRENT auth key), then ingests {rotation} (which rotates that auth
// key OUT). r2 then syncs r1's FULL log in one batch — the sequencer sorts
// identity ops (the rotation) BEFORE revocations, so r2 replays the rotation
// FIRST and only then sees the revocation, whose signing key is no longer in
// current state.
//
// Under the SHIPPED decision (OQ5 = revocation stays HISTORICAL — the D3
// revocation-current-state half was REVERSED and dropped), the historical
// resolver still verifies the revocation on r2, so BOTH relays converge on
// "credential revoked + its delegated subtree denied".
//
// DECISION-COUPLING: this asserts CONVERGENCE only because revocation is
// historical. If anyone reintroduces current-state revocation resolution, r2
// would leave the credential (and its subtree) LIVE forever while r1 denies it —
// this test MUST flip RED. The assertion is the acceptance gate for any future
// as-of-createdAt teeth; do not relax it to mask a regression.
func TestTwoRelayRevocationAfterRotationConvergesUnderHistorical(t *testing.T) {
	r1Store := NewMemoryStore()
	r1, err := NewRelay(RelayOptions{Store: r1Store})
	if err != nil {
		t.Fatal(err)
	}

	creator := createTestIdentity(t)
	delegate := createTestIdentity(t)
	subDelegate := createTestIdentity(t)
	contentToken, contentID, contentOpCID := createTestContent(t, creator)

	// seed identities + content on r1
	if r := r1.Ingest([]string{creator.token, delegate.token, subDelegate.token, contentToken}); len(r) == 0 {
		t.Fatal("seed ingest returned no results")
	}

	creatorKid := creator.did + "#" + creator.auth.keyID

	// ROOT credential: creator → delegate, write on the chain (single att, prf:[])
	rootCred, err := dfos.CreateCredential(creator.did, delegate.did, creatorKid, "chain:"+contentID, "write", time.Hour, creator.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	rootHeader, _, err := dfos.DecodeJWSUnsafe(rootCred)
	if err != nil {
		t.Fatal(err)
	}
	rootCredCID := rootHeader.CID

	// CHILD credential: delegate → subDelegate, write, with the root as proof.
	// This is the "delegated subtree" — revoking the ROOT must deny the CHILD too.
	delegateKid := delegate.did + "#" + delegate.auth.keyID
	childCred, _ := mintDelegatedCredential(t, delegate.did, delegateKid, delegate.auth.priv,
		subDelegate.did, "chain:"+contentID, "write", []string{rootCred}, 30*time.Minute)

	// a first delegated write by the delegate under the root credential — LIVE,
	// accepted on r1.
	doc1 := newDocCID(t, "first")
	w1, _ := signDelegatedUpdate(t, delegate, contentOpCID, doc1, rootCred)
	if r := r1.Ingest([]string{w1}); r[0].Status != "new" {
		t.Fatalf("expected first delegated write accepted on r1, got %s (%s)", r[0].Status, r[0].Error)
	}

	// REVOCATION of the root credential — signed by the creator's CURRENT auth key.
	revToken, _, err := dfos.SignRevocation(creator.did, rootCredCID, creatorKid, creator.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	if r := r1.Ingest([]string{revToken}); r[0].Status != "new" {
		t.Fatalf("expected revocation accepted on r1, got %s (%s)", r[0].Status, r[0].Error)
	}

	// ROTATION: creator rotates its auth key A0 → A1 (the revocation's signing key
	// is now rotated OUT of current state). Signed by the controller key.
	newAuth := newTestKeypair()
	rotationToken, _, err := dfos.SignIdentityUpdate(
		creator.opCID,
		[]dfos.MultikeyPublicKey{creator.controller.mk},
		[]dfos.MultikeyPublicKey{newAuth.mk}, // A0 rotated out
		[]dfos.MultikeyPublicKey{},
		creator.did+"#"+creator.controller.keyID,
		creator.controller.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	if r := r1.Ingest([]string{rotationToken}); r[0].Status != "new" {
		t.Fatalf("expected rotation accepted on r1, got %s (%s)", r[0].Status, r[0].Error)
	}
	r1.RunSequencerAndGossip()

	// --- r1 oracle: credential revoked + subtree denied ---
	assertRevokedAndSubtreeDenied(t, "r1", r1, r1Store, creator, delegate, subDelegate,
		rootCred, childCred, rootCredCID, w1)

	// --- r2 syncs r1's FULL log in one batch (rotation-first ordering) ---
	r2 := newSyncedRelay(t, r1Store)
	if err := r2.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	r2.RunSequencerAndGossip()
	r2Store := r2.store.(*MemoryStore)

	// --- r2 oracle: MUST converge — credential revoked + subtree denied ---
	assertRevokedAndSubtreeDenied(t, "r2", r2, r2Store, creator, delegate, subDelegate,
		rootCred, childCred, rootCredCID, w1)
}

// assertRevokedAndSubtreeDenied is the shared convergence oracle: the root
// credential is in the revocation set, a delegated write under the (now revoked)
// root is rejected, and the child credential delegating from the revoked root is
// also denied (cascading subtree).
func assertRevokedAndSubtreeDenied(t *testing.T, label string, r *Relay, store *MemoryStore, creator, delegate, subDelegate testIdentity, rootCred, childCred, rootCredCID, w1CID string) {
	t.Helper()

	// 1. the revocation converged into the store's revocation set
	revoked, _ := store.IsCredentialRevoked(creator.did, rootCredCID)
	if !revoked {
		t.Fatalf("[%s] expected root credential to be in the revocation set (convergence FAILED — current-state regression?)", label)
	}

	// 2. a delegated write by the delegate under the REVOKED root → rejected
	doc2 := newDocCID(t, "after-revoke-"+label)
	chain, _ := store.GetContentChain(contentIDFromCred(t, rootCred))
	if chain == nil {
		t.Fatalf("[%s] content chain missing", label)
	}
	w2, _ := signDelegatedUpdate(t, delegate, chain.State.HeadCID, doc2, rootCred)
	if res := r.Ingest([]string{w2}); res[0].Status != "rejected" {
		t.Fatalf("[%s] SECURITY: expected delegated write under REVOKED root to be REJECTED, got %s", label, res[0].Status)
	}

	// 3. a sub-delegated write by subDelegate under the CHILD credential (whose
	//    proof is the revoked root) → rejected (cascading subtree).
	doc3 := newDocCID(t, "subtree-"+label)
	chain2, _ := store.GetContentChain(contentIDFromCred(t, rootCred))
	w3, _ := signDelegatedUpdate(t, subDelegate, chain2.State.HeadCID, doc3, childCred)
	if res := r.Ingest([]string{w3}); res[0].Status != "rejected" {
		t.Fatalf("[%s] SECURITY: expected sub-delegated write under revoked subtree to be REJECTED, got %s", label, res[0].Status)
	}
}

// contentIDFromCred extracts the chain content ID from a credential's first att
// resource (chain:<id>).
func contentIDFromCred(t *testing.T, cred string) string {
	t.Helper()
	_, payload, err := dfos.DecodeJWSUnsafe(cred)
	if err != nil {
		t.Fatal(err)
	}
	att := dfos.ParseAtt(payload)
	if len(att) == 0 {
		t.Fatal("credential has no att")
	}
	_, id, ok := dfos.ParseResource(att[0].Resource)
	if !ok {
		t.Fatalf("bad resource %q", att[0].Resource)
	}
	return id
}

// ===================================================================
// countersign-before-target cross-relay convergence
// ===================================================================

// TestTwoRelayCountersignBeforeTargetConverges verifies that a countersignature
// ingested BEFORE its target operation (classified DependencyMissing → retryable)
// converges across relays: r1 ingests {target, countersign} in the unfavorable
// order, r2 syncs the full log and the DependencyMissing retry resolves the
// countersign once the target arrives. This is the cross-relay analogue of the
// Go unit-level dependency convergence test — it had no cross-relay coverage.
func TestTwoRelayCountersignBeforeTargetConverges(t *testing.T) {
	r1Store := NewMemoryStore()
	r1, err := NewRelay(RelayOptions{Store: r1Store})
	if err != nil {
		t.Fatal(err)
	}

	creator := createTestIdentity(t)
	witness := createTestIdentity(t)
	contentToken, _, contentOpCID := createTestContent(t, creator)

	// seed identities + content on r1, drain
	r1.Ingest([]string{creator.token, witness.token, contentToken})
	r1.RunSequencerAndGossip()

	// witness countersigns the content op
	witnessKid := witness.did + "#" + witness.auth.keyID
	csToken, csCID, err := dfos.SignCountersign(witness.did, contentOpCID, witnessKid, witness.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	if r := r1.Ingest([]string{csToken}); r[0].Status != "new" {
		t.Fatalf("expected countersign accepted on r1, got %s (%s)", r[0].Status, r[0].Error)
	}
	r1.RunSequencerAndGossip()

	// sanity: r1 has the countersignature recorded against the target
	cs, _ := r1Store.GetCountersignatures(contentOpCID)
	if len(cs) != 1 {
		t.Fatalf("expected 1 countersignature on r1, got %d", len(cs))
	}
	_ = csCID

	// r2 syncs r1's FULL log. The mock peer serves the global log in cursor
	// (acceptance) order; r2's sequencer must converge the countersign via the
	// DependencyMissing retry once the target content op has been sequenced.
	r2 := newSyncedRelay(t, r1Store)
	if err := r2.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	r2.RunSequencerAndGossip()
	r2Store := r2.store.(*MemoryStore)

	cs2, _ := r2Store.GetCountersignatures(contentOpCID)
	if len(cs2) != 1 {
		t.Fatalf("expected countersign to converge on r2 (1 countersignature), got %d", len(cs2))
	}

	// nothing stuck pending on r2
	pending, _ := r2Store.CountUnsequenced()
	if pending != 0 {
		t.Fatalf("expected 0 pending ops on r2 after convergence, got %d", pending)
	}
}
