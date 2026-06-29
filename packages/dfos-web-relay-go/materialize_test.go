package relay

import (
	"encoding/json"
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
func seedGrantedContentOrigin(t *testing.T) (store *MemoryStore, creator testIdentity, contentID, docCID string) {
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

	origin.Ingest([]string{creator.token, contentToken, grant})
	origin.RunSequencerAndGossip()

	// the producer holds the bytes; the op log does not carry them
	blobBytes, _ := json.Marshal(doc)
	if err := store.PutBlob(BlobKey{CreatorDID: creator.did, DocumentCID: docCID}, blobBytes); err != nil {
		t.Fatal(err)
	}
	return store, creator, contentID, docCID
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
	originStore, creator, contentID, docCID := seedGrantedContentOrigin(t)
	follower := newFollower(t, originStore, "eager")

	key := BlobKey{CreatorDID: creator.did, DocumentCID: docCID}

	// preconditions: grant synced (authorized) but blob absent.
	if !follower.hasPublicStandingAuth(contentID, "read") {
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
	originStore, creator, _, docCID := seedGrantedContentOrigin(t)
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
	if follower.hasPublicStandingAuth(contentID, "read") {
		t.Fatal("precondition: ungranted chain should not be publicly authorized")
	}
	follower.MaterializeFollowedContent()

	if b, _ := follower.readStore.GetBlob(BlobKey{CreatorDID: creator.did, DocumentCID: docCID}); b != nil {
		t.Fatal("materialized a chain with no standing public-read grant")
	}
}
