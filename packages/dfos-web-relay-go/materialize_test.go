package relay

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// the document createTestContent commits — duplicated here so the test can build
// the matching blob bytes and know the committed documentCID.
func testContentDoc() map[string]any {
	return map[string]any{"type": "post", "title": "hello world", "body": "test content"}
}

// TestVerifyBlobBytes pins the content-addressing gate shared by handlePutBlob and
// the follower materializer: bytes are accepted iff they canonically hash to the
// committed documentCID.
func TestVerifyBlobBytes(t *testing.T) {
	doc := testContentDoc()
	docCID, _, err := dfos.DocumentCID(doc)
	if err != nil {
		t.Fatal(err)
	}
	bytes, _ := json.Marshal(doc)

	if err := verifyBlobBytes(bytes, docCID); err != nil {
		t.Fatalf("valid blob rejected: %v", err)
	}
	// Re-serialized (different key order / whitespace) must still verify — the CID
	// is over the canonical dag-cbor form, not the literal JSON bytes.
	reordered := []byte(`{"body":"test content","title":"hello world","type":"post"}`)
	if err := verifyBlobBytes(reordered, docCID); err != nil {
		t.Fatalf("re-serialized blob rejected: %v", err)
	}
	if err := verifyBlobBytes(bytes, "bafyWRONGcid"); err == nil {
		t.Fatal("blob with mismatched documentCID was accepted")
	}
	if err := verifyBlobBytes([]byte("not json"), docCID); err == nil {
		t.Fatal("non-JSON blob was accepted")
	}
}

// seedGrantedContentOrigin builds an origin MemoryStore holding a content chain,
// a self-issued public-read grant covering it, and the chain's document blob —
// the state a producing relay has. Returns the store plus the creator and the
// committed documentCID. The blob is stored on the origin but NOT carried by the
// op log (blobs never gossip), which is exactly the gap the materializer closes.
func seedGrantedContentOrigin(t *testing.T) (store *MemoryStore, creator testIdentity, contentID, docCID, credentialCID string) {
	t.Helper()
	store = NewMemoryStore()
	origin, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}

	creator = createTestIdentity(t)
	contentToken, cid, _ := createTestContent(t, creator)
	contentID = cid

	doc := testContentDoc()
	dCID, _, err := dfos.DocumentCID(doc)
	if err != nil {
		t.Fatal(err)
	}
	docCID = dCID

	// self-issued standing public-read grant (aud "*") over chain:<contentID>
	creatorKid := creator.did + "#" + creator.auth.keyID
	grant, err := dfos.CreateCredential(creator.did, "*", creatorKid, "chain:"+contentID, "read", 100*365*24*time.Hour, creator.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	grantHeader, _, err := dfos.DecodeJWSUnsafe(grant)
	if err != nil {
		t.Fatal(err)
	}
	credentialCID = grantHeader.CID

	origin.Ingest([]string{creator.token, contentToken, grant})
	origin.RunSequencerAndGossip()

	// the producer holds the bytes; the op log does not carry them
	blobBytes, _ := json.Marshal(doc)
	if err := store.PutBlob(BlobKey{CreatorDID: creator.did, DocumentCID: docCID}, blobBytes); err != nil {
		t.Fatal(err)
	}
	return store, creator, contentID, docCID, credentialCID
}

// newFollower builds a follower relay peered to originStore (via the mock peer
// client) with the given ContentFollow mode, then syncs + sequences the origin's
// full op log — so it holds the chain + grant but, crucially, NOT the blob bytes.
func newFollower(t *testing.T, originStore *MemoryStore, mode string) *Relay {
	t.Helper()
	mock := newMockPeerClient(originStore, 0)
	f, err := NewRelay(RelayOptions{
		Store:         NewMemoryStore(),
		PeerClient:    mock,
		Peers:         []PeerConfig{{URL: "http://origin"}},
		ContentFollow: mode,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.SyncFromPeers(); err != nil {
		t.Fatalf("follower sync: %v", err)
	}
	f.RunSequencerAndGossip()
	return f
}

// TestMaterializeFollowedContentPullsGrantedBlob is the end-to-end proof: a
// follower that synced a chain + its public-read grant (but not the bytes) pulls
// and verifies the document blob on a sweep, going from "authorized but
// not-yet-materialized" (200 + blob 404) to serving real content.
func TestMaterializeFollowedContentPullsGrantedBlob(t *testing.T) {
	originStore, creator, contentID, docCID, _ := seedGrantedContentOrigin(t)
	follower := newFollower(t, originStore, "eager")

	key := BlobKey{CreatorDID: creator.did, DocumentCID: docCID}

	// preconditions: grant synced (authorized) but blob absent.
	if !hasPublicStandingAuth(contentID, "read", follower.readStore) {
		t.Fatal("precondition: follower did not sync the public-read grant")
	}
	if b, _ := follower.readStore.GetBlob(key); b != nil {
		t.Fatal("precondition: blob present before materialize (op log should not carry bytes)")
	}

	follower.MaterializeFollowedContent()

	got, err := follower.readStore.GetBlob(key)
	if err != nil || got == nil {
		t.Fatalf("blob was not materialized (err=%v)", err)
	}
	if err := verifyBlobBytes(got, docCID); err != nil {
		t.Fatalf("materialized blob fails content-address verification: %v", err)
	}
}

// TestMaterializeIsNoOpWhenNotEager guards the parity-safe default: a follower
// holding the same grant but with ContentFollow unset (or "none") must NOT pull
// any bytes — byte-identical to a non-following node.
func TestMaterializeIsNoOpWhenNotEager(t *testing.T) {
	originStore, creator, _, docCID, _ := seedGrantedContentOrigin(t)
	key := BlobKey{CreatorDID: creator.did, DocumentCID: docCID}

	for _, mode := range []string{"", "none"} {
		follower := newFollower(t, originStore, mode)
		follower.MaterializeFollowedContent()
		if b, _ := follower.readStore.GetBlob(key); b != nil {
			t.Fatalf("mode %q: blob materialized despite content-follow being off", mode)
		}
	}
}

// TestMaterializeSkipsUngrantedChain guards the gate: an eager follower must NOT
// materialize a chain it holds no standing public-read grant for (the materialize
// gate is the serve gate).
func TestMaterializeSkipsUngrantedChain(t *testing.T) {
	store := NewMemoryStore()
	origin, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	creator := createTestIdentity(t)
	contentToken, contentID, _ := createTestContent(t, creator)
	origin.Ingest([]string{creator.token, contentToken}) // NO grant
	origin.RunSequencerAndGossip()

	doc := testContentDoc()
	docCID, _, _ := dfos.DocumentCID(doc)
	blobBytes, _ := json.Marshal(doc)
	store.PutBlob(BlobKey{CreatorDID: creator.did, DocumentCID: docCID}, blobBytes)

	follower := newFollower(t, store, "eager")
	if hasPublicStandingAuth(contentID, "read", follower.readStore) {
		t.Fatal("precondition: ungranted chain should not be publicly authorized")
	}
	follower.MaterializeFollowedContent()

	if b, _ := follower.readStore.GetBlob(BlobKey{CreatorDID: creator.did, DocumentCID: docCID}); b != nil {
		t.Fatal("materialized a chain with no standing public-read grant")
	}
}

// TestGCReclaimsRevokedContentBlob is the GC-on-revoke proof: a follower
// materializes a granted chain, the creator revokes the grant, the follower syncs
// the revocation, and the GC sweep reclaims the now-unreadable blob.
func TestGCReclaimsRevokedContentBlob(t *testing.T) {
	originStore, creator, contentID, docCID, credentialCID := seedGrantedContentOrigin(t)
	follower := newFollower(t, originStore, "eager")
	key := BlobKey{CreatorDID: creator.did, DocumentCID: docCID}

	// materialize the granted blob
	follower.MaterializeFollowedContent()
	if b, _ := follower.readStore.GetBlob(key); b == nil {
		t.Fatal("setup: blob was not materialized")
	}

	// the creator revokes the grant; propagate it onto the origin's log
	creatorKid := creator.did + "#" + creator.auth.keyID
	revToken, _, err := dfos.SignRevocation(creator.did, credentialCID, creatorKid, creator.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	origin2, err := NewRelay(RelayOptions{Store: originStore})
	if err != nil {
		t.Fatal(err)
	}
	if r := origin2.Ingest([]string{revToken}); r[0].Status != "new" {
		t.Fatalf("expected revocation accepted, got %s (%s)", r[0].Status, r[0].Error)
	}
	origin2.RunSequencerAndGossip()

	// follower syncs the revocation
	if err := follower.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	follower.RunSequencerAndGossip()
	if hasPublicStandingAuth(contentID, "read", follower.readStore) {
		t.Fatal("precondition: grant should be revoked on the follower")
	}

	// GC reclaims the now-unreadable blob; the materialize gate already made it
	// unreachable, so this is pure storage reclamation.
	follower.GCRevokedContent()
	if b, _ := follower.readStore.GetBlob(key); b != nil {
		t.Fatal("GC did not reclaim the revoked chain's blob")
	}
}

// TestMaterializeFastPathGatedOnDirty is the core proof of the event-driven
// rewrite: with an empty work queue the fast path does NOTHING (a steady-state
// follower must not re-scan the corpus or re-pull bytes — that was the 100%-CPU
// bug), while the convergent backstop (ReconcileFollowedContent) forces a full scan
// and still materializes. Together: idle when clean, convergent on demand.
func TestMaterializeFastPathGatedOnDirty(t *testing.T) {
	originStore, creator, _, docCID, _ := seedGrantedContentOrigin(t)
	follower := newFollower(t, originStore, "eager") // sync+sequence marks the queue
	key := BlobKey{CreatorDID: creator.did, DocumentCID: docCID}

	// Drain the queue WITHOUT acting on it, simulating steady state: the chain +
	// grant are present locally, but nothing is flagged for work.
	follower.materializeDirty.take()
	if !follower.materializeDirty.empty() {
		t.Fatal("queue should be empty after take")
	}

	// Empty-queue fast path must be a no-op — no blob pulled.
	follower.MaterializeFollowedContent()
	if b, _ := follower.readStore.GetBlob(key); b != nil {
		t.Fatal("empty-queue fast path materialized a blob — steady state must be idle")
	}

	// The backstop forces a full convergent scan and DOES materialize.
	follower.ReconcileFollowedContent()
	if b, _ := follower.readStore.GetBlob(key); b == nil {
		t.Fatal("full-scan backstop failed to materialize the granted blob")
	}
}

// TestMarkContentFollowDirtyRouting pins how newly-sequenced ops route into the
// work queues: a content-op flags its own contentID for a targeted materialize, a
// chain-scoped grant flags the chain it names, a wildcard grant escalates to a full
// scan, a revocation drives GC over the chains whose grant it revoked, and a
// non-eager relay marks nothing.
func TestMarkContentFollowDirtyRouting(t *testing.T) {
	r, err := NewRelay(RelayOptions{Store: NewMemoryStore(), ContentFollow: "eager"})
	if err != nil {
		t.Fatal(err)
	}

	r.markContentFollowDirty(IngestionResult{Status: "new", Kind: "content-op", ChainID: "contentX"}, "")
	ids, full := r.materializeDirty.take()
	if full || len(ids) != 1 || ids[0] != "contentX" {
		t.Fatalf("content-op should mark only its contentID dirty, got ids=%v full=%v", ids, full)
	}

	issuer := createTestIdentity(t)
	r.markContentFollowDirty(
		IngestionResult{Status: "new", Kind: "credential", ChainID: issuer.did},
		testGrant(t, issuer, "chain:contentY"),
	)
	ids, full = r.materializeDirty.take()
	if full || len(ids) != 1 || ids[0] != "contentY" {
		t.Fatalf("a chain-scoped grant should mark only its chain, got ids=%v full=%v", ids, full)
	}

	r.markContentFollowDirty(
		IngestionResult{Status: "new", Kind: "credential", ChainID: issuer.did},
		testGrant(t, issuer, "chain:*"),
	)
	if _, full := r.materializeDirty.take(); !full {
		t.Fatal("a chain:* grant should request a full materialize scan")
	}

	r.markContentFollowDirty(
		IngestionResult{Status: "new", Kind: "revocation", ChainID: issuer.did,
			RevokedGrant: &RevokedGrant{ContentIDs: []string{"contentZ"}}},
		"",
	)
	ids, full = r.gcDirty.take()
	if full || len(ids) != 1 || ids[0] != "contentZ" {
		t.Fatalf("a chain-scoped revocation should GC only its chain, got ids=%v full=%v", ids, full)
	}

	// A non-eager relay must never mark work — content following is off.
	off, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	off.markContentFollowDirty(IngestionResult{Status: "new", Kind: "content-op", ChainID: "c"}, "")
	if !off.materializeDirty.empty() {
		t.Fatal("a non-eager relay must not mark materialize work")
	}
}

// testGrant signs a standing public grant over one resource. Only the att is read
// by markContentFollowDirty (DecodeJWSUnsafe), but signing it properly keeps the
// fixture a real credential rather than a shape that could drift from one.
func testGrant(t *testing.T, issuer testIdentity, resource string) string {
	t.Helper()
	kid := issuer.did + "#" + issuer.auth.keyID
	token, err := dfos.CreateCredential(issuer.did, "*", kid, resource, "read", time.Hour, issuer.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// testGrantResources signs a standing public grant over several resources at once —
// the multi-`att` shape CreateCredential's single-resource helper can't build.
func testGrantResources(t *testing.T, issuer testIdentity, resources ...string) string {
	t.Helper()
	att := make([]map[string]string, 0, len(resources))
	for _, resource := range resources {
		att = append(att, map[string]string{"resource": resource, "action": "read"})
	}
	return testGrantPayload(t, issuer, map[string]any{
		"version": 1, "type": "DFOSCredential", "iss": issuer.did, "aud": "*",
		"att": att, "prf": []string{}, "exp": time.Now().Add(time.Hour).Unix(),
	})
}

// testGrantPayload signs an arbitrary credential payload, so a test can hand the
// marker a token whose att is unreadable.
func testGrantPayload(t *testing.T, issuer testIdentity, payload map[string]any) string {
	t.Helper()
	token, err := dfos.CreateJWS(dfos.JWSHeader{
		Alg: "EdDSA", Typ: "did:dfos:credential", Kid: issuer.did + "#" + issuer.auth.keyID,
	}, payload, issuer.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// TestCredentialFollowTriggerNarrowsToGrantedChains is the core of the narrowing:
// the v1 credential resource grammar is closed on this axis, so a grant that names
// chains marks exactly those chains and never the whole corpus. The escalation
// cases are the other half of the contract — chain:* is genuinely unbounded, and
// ANY token whose att we cannot read fails OPEN to the full scan rather than
// silently skipping the work.
func TestCredentialFollowTriggerNarrowsToGrantedChains(t *testing.T) {
	issuer := createTestIdentity(t)
	credential := IngestionResult{Status: "new", Kind: "credential", ChainID: issuer.did}

	narrow := []struct {
		name  string
		token string
		want  []string
	}{
		{"one chain", testGrant(t, issuer, "chain:contentA"), []string{"contentA"}},
		{"several chains", testGrantResources(t, issuer, "chain:contentA", "chain:contentB"), []string{"contentA", "contentB"}},
		// A grant over an additive non-chain resource form authorizes no content
		// chain, so it warrants no materialize work at all — escalating it would
		// reintroduce the full-scan-per-credential cost this narrowing removes.
		{"no chain resources", testGrantResources(t, issuer, "api:api.example.com", "mailbox:mbx1"), nil},
		{"chain resources beside a non-chain one", testGrantResources(t, issuer, "api:api.example.com", "chain:contentA"), []string{"contentA"}},
	}
	for _, tc := range narrow {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewRelay(RelayOptions{Store: NewMemoryStore(), ContentFollow: "eager"})
			if err != nil {
				t.Fatal(err)
			}
			r.markContentFollowDirty(credential, tc.token)
			ids, full := r.materializeDirty.take()
			if full {
				t.Fatalf("%s: requested a full scan; the whole point is that it should not", tc.name)
			}
			if !sameIDSet(ids, tc.want) {
				t.Fatalf("%s: marked %v, want %v", tc.name, ids, tc.want)
			}
		})
	}

	failOpen := []struct {
		name  string
		token string
	}{
		{"chain:* wildcard", testGrant(t, issuer, "chain:*")},
		{"wildcard beside a named chain", testGrantResources(t, issuer, "chain:contentA", "chain:*")},
		{"undecodable token", "not-a-jws"},
		{"att is not an array", testGrantPayload(t, issuer, map[string]any{"att": "chain:contentA"})},
		{"att entry is not an object", testGrantPayload(t, issuer, map[string]any{"att": []any{"chain:contentA"}})},
		{"att entry resource is not a string", testGrantPayload(t, issuer, map[string]any{
			"att": []any{map[string]any{"resource": 42, "action": "read"}}})},
	}
	for _, tc := range failOpen {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewRelay(RelayOptions{Store: NewMemoryStore(), ContentFollow: "eager"})
			if err != nil {
				t.Fatal(err)
			}
			r.markContentFollowDirty(credential, tc.token)
			if _, full := r.materializeDirty.take(); !full {
				t.Fatalf("%s: must fail OPEN to a full materialize scan", tc.name)
			}
		})
	}
}

// TestRevocationFollowTriggerNarrowsToRevokedChains is the GC-side twin: the
// revoked grant's scope was already resolved at ingest, so a chain-scoped
// revocation reclaims only the chains that grant named. A wildcard grant, and a
// revocation of a credential the relay does not hold (scope unknown), both fail
// open to the corpus pass.
func TestRevocationFollowTriggerNarrowsToRevokedChains(t *testing.T) {
	cases := []struct {
		name     string
		grant    *RevokedGrant
		wantFull bool
		wantIDs  []string
	}{
		{"one chain", &RevokedGrant{ContentIDs: []string{"contentA"}}, false, []string{"contentA"}},
		{"several chains", &RevokedGrant{ContentIDs: []string{"contentA", "contentB"}}, false, []string{"contentA", "contentB"}},
		{"wildcard grant", &RevokedGrant{Wildcard: true, ContentIDs: []string{"contentA"}}, true, nil},
		// Rarer than a credential op, so the fail-open margin is free here even
		// where the credential side declines to pay it: an unheld grant's scope is
		// genuinely unknown, and a held grant naming no chain still buys one scan.
		{"grant not held", nil, true, nil},
		{"grant names no chain", &RevokedGrant{ContentIDs: nil}, true, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewRelay(RelayOptions{Store: NewMemoryStore(), ContentFollow: "eager"})
			if err != nil {
				t.Fatal(err)
			}
			r.markContentFollowDirty(IngestionResult{
				Status: "new", Kind: "revocation", ChainID: "did:dfos:issuer", RevokedGrant: tc.grant,
			}, "")
			ids, full := r.gcDirty.take()
			if full != tc.wantFull {
				t.Fatalf("%s: full=%v, want %v", tc.name, full, tc.wantFull)
			}
			if !tc.wantFull && !sameIDSet(ids, tc.wantIDs) {
				t.Fatalf("%s: marked %v, want %v", tc.name, ids, tc.wantIDs)
			}
		})
	}
}

// sameIDSet compares two contentID sets order-independently (the dirty queue is a
// map, so its drain order is not stable).
func sameIDSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]struct{}{}
	for _, id := range got {
		seen[id] = struct{}{}
	}
	for _, id := range want {
		if _, ok := seen[id]; !ok {
			return false
		}
	}
	return true
}

// TestChainScopedGrantStillMaterializes is the end-to-end guard that the narrowing
// didn't break the actual follow: a follower syncing a chain plus its chain-scoped
// public-read grant marks only that chain — no full-corpus scan requested — and
// still ends up holding the verified bytes.
func TestChainScopedGrantStillMaterializes(t *testing.T) {
	originStore, creator, contentID, docCID, _ := seedGrantedContentOrigin(t)
	follower := newFollower(t, originStore, "eager") // sync + sequence marks the queue
	key := BlobKey{CreatorDID: creator.did, DocumentCID: docCID}

	// Inspect what the sync actually queued: the chain-scoped grant must have named
	// its chain, not escalated to the corpus scan.
	ids, full := follower.materializeDirty.take()
	if full {
		t.Fatal("a chain-scoped grant requested a full materialize scan — the trigger did not narrow")
	}
	if !sameIDSet(ids, []string{contentID}) {
		t.Fatalf("marked %v, want just the granted chain %q", ids, contentID)
	}

	// Put the marks back and run the fast path: narrow marks alone must materialize.
	for _, id := range ids {
		follower.materializeDirty.markID(id)
	}
	follower.MaterializeFollowedContent()

	got, err := follower.readStore.GetBlob(key)
	if err != nil || got == nil {
		t.Fatalf("narrow mark did not materialize the granted blob (err=%v)", err)
	}
	if err := verifyBlobBytes(got, docCID); err != nil {
		t.Fatalf("materialized blob fails content-address verification: %v", err)
	}
}

// TestGCReclaimsScopedRevokedContentBlob is the GC end-to-end twin of
// TestGCReclaimsRevokedContentBlob: the revocation of a chain-scoped grant must
// reclaim the blob through the NARROW path — no full-corpus mark — or the scoping
// would be decorative, marking ids a consumer ignores.
func TestGCReclaimsScopedRevokedContentBlob(t *testing.T) {
	originStore, creator, contentID, docCID, credentialCID := seedGrantedContentOrigin(t)
	follower := newFollower(t, originStore, "eager")
	key := BlobKey{CreatorDID: creator.did, DocumentCID: docCID}

	follower.ReconcileFollowedContent()
	if b, _ := follower.readStore.GetBlob(key); b == nil {
		t.Fatal("setup: blob was not materialized")
	}
	follower.gcDirty.take() // drain the reconcile's full mark — the revocation must stand alone

	creatorKid := creator.did + "#" + creator.auth.keyID
	revToken, _, err := dfos.SignRevocation(creator.did, credentialCID, creatorKid, creator.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	origin2, err := NewRelay(RelayOptions{Store: originStore})
	if err != nil {
		t.Fatal(err)
	}
	if r := origin2.Ingest([]string{revToken}); r[0].Status != "new" {
		t.Fatalf("expected revocation accepted, got %s (%s)", r[0].Status, r[0].Error)
	}
	origin2.RunSequencerAndGossip()

	if err := follower.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	follower.RunSequencerAndGossip()
	if hasPublicStandingAuth(contentID, "read", follower.readStore) {
		t.Fatal("precondition: grant should be revoked on the follower")
	}

	// What the revocation queued must be the named chain, not the corpus.
	ids, full := follower.gcDirty.take()
	if full {
		t.Fatal("a chain-scoped revocation requested a full GC scan — the trigger did not narrow")
	}
	if !sameIDSet(ids, []string{contentID}) {
		t.Fatalf("GC marked %v, want just the revoked chain %q", ids, contentID)
	}

	for _, id := range ids {
		follower.gcDirty.markID(id)
	}
	follower.GCRevokedContent()
	if b, _ := follower.readStore.GetBlob(key); b != nil {
		t.Fatal("the narrow GC path did not reclaim the revoked chain's blob")
	}
}

// TestGCGatedOnDirty guards GC's steady-state idle: with nothing revoked/deleted
// since the last pass, GCRevokedContent must NOT scan the corpus — even an
// out-of-band orphaned blob is left for the periodic backstop. A markFull (what a
// synced revocation does) then drives reclamation.
func TestGCGatedOnDirty(t *testing.T) {
	originStore, creator, _, docCID, _ := seedGrantedContentOrigin(t)
	follower := newFollower(t, originStore, "eager")
	key := BlobKey{CreatorDID: creator.did, DocumentCID: docCID}

	// Materialize the granted blob, then plant a state where the blob exists but the
	// grant is gone (drop the public credential out-of-band, no revocation synced →
	// gcDirty stays empty), modelling a missed mark.
	follower.ReconcileFollowedContent()
	if b, _ := follower.readStore.GetBlob(key); b == nil {
		t.Fatal("setup: blob was not materialized")
	}
	// drain anything the reconcile queued so gcDirty is genuinely empty
	follower.gcDirty.take()

	// GC with an empty queue is a no-op — it must not even scan, so the blob stays.
	follower.GCRevokedContent()
	if b, _ := follower.readStore.GetBlob(key); b == nil {
		t.Fatal("empty-queue GC reclaimed a blob — steady state must be idle")
	}
}

// TestIngestMarksContentFollowDirty is the regression guard for meshed
// propagation: ops that arrive via Ingest — a gossip-push from a peer, or a direct
// client write — are sequenced in Ingest's immediate batch, NOT the pull sequencer
// (which then sees them as duplicates). If Ingest doesn't mark content-follow work,
// a meshed eager follower only materializes gossip-delivered content on the slow
// reconcile backstop, so a write to one lark takes minutes to appear on another.
func TestIngestMarksContentFollowDirty(t *testing.T) {
	r, err := NewRelay(RelayOptions{Store: NewMemoryStore(), ContentFollow: "eager"})
	if err != nil {
		t.Fatal(err)
	}
	creator := createTestIdentity(t)
	contentToken, contentID, _ := createTestContent(t, creator)

	// Deliver via Ingest — the gossip-push / direct-write entry point — not a pull.
	r.Ingest([]string{creator.token, contentToken})

	ids, _ := r.materializeDirty.take()
	found := false
	for _, id := range ids {
		if id == contentID {
			found = true
		}
	}
	if !found {
		t.Fatalf("Ingest of a content-op did not mark its contentID dirty (got %v) — meshed gossip propagation would stall to the backstop", ids)
	}
}

// failingBlobPeerClient is a PeerClient whose GetBlob always returns a configured
// error — used to exercise the blob-source circuit breaker.
type failingBlobPeerClient struct{ err error }

func (f *failingBlobPeerClient) GetIdentityLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (f *failingBlobPeerClient) GetContentLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (f *failingBlobPeerClient) GetOperationLog(string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (f *failingBlobPeerClient) SubmitOperations(string, []string) error { return nil }
func (f *failingBlobPeerClient) GetBlob(string, string, string) ([]byte, error) {
	return nil, f.err
}

// TestBlobSourceCircuitBreaker pins the dead-source heuristic: a transport/5xx
// failure trips the breaker (so a dead origin isn't re-hit per chain every sweep),
// a 404 does NOT (the peer is reachable, just lacks that blob), and an elapsed
// cooldown self-clears.
func TestBlobSourceCircuitBreaker(t *testing.T) {
	key := BlobKey{CreatorDID: "did:dfos:x", DocumentCID: "bafyDoc"}

	// transport error → breaker trips
	down, err := NewRelay(RelayOptions{
		Store: NewMemoryStore(), ContentFollow: "eager",
		Peers:      []PeerConfig{{URL: "http://dead"}},
		PeerClient: &failingBlobPeerClient{err: errors.New("connection refused")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if down.blobSourceCoolingDown("http://dead") {
		t.Fatal("breaker should be closed initially")
	}
	down.pullAndStoreBlob("chainX", "opX", key)
	if !down.blobSourceCoolingDown("http://dead") {
		t.Fatal("a transport failure must trip the breaker")
	}
	// an elapsed deadline self-clears
	down.blobSourceCooldown.Store("http://dead", time.Now().Add(-time.Second).UnixNano())
	if down.blobSourceCoolingDown("http://dead") {
		t.Fatal("an elapsed cooldown must self-clear")
	}

	// a 404 must NOT trip the breaker
	missing, err := NewRelay(RelayOptions{
		Store: NewMemoryStore(), ContentFollow: "eager",
		Peers:      []PeerConfig{{URL: "http://up"}},
		PeerClient: &failingBlobPeerClient{err: ErrBlobNotFound},
	})
	if err != nil {
		t.Fatal(err)
	}
	missing.pullAndStoreBlob("chainX", "opX", key)
	if missing.blobSourceCoolingDown("http://up") {
		t.Fatal("a 404 must not trip the breaker (the peer is reachable)")
	}
}

// TestMaterializeConcurrentCallsAreSafe exercises the bounded-concurrency sweep and
// the TryLock coalescing under concurrent callers (timer sweep + trigger kick).
// Run under -race in CI; here it asserts the sweep still converges.
func TestMaterializeConcurrentCallsAreSafe(t *testing.T) {
	originStore, creator, _, docCID, _ := seedGrantedContentOrigin(t)
	follower := newFollower(t, originStore, "eager")

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			follower.MaterializeFollowedContent()
		}()
	}
	wg.Wait()

	if b, _ := follower.readStore.GetBlob(BlobKey{CreatorDID: creator.did, DocumentCID: docCID}); b == nil {
		t.Fatal("concurrent sweeps did not converge to a materialized blob")
	}
}
