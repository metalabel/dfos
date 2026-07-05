package relay

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// TestContentFollowingOverHTTP is the real-wire conformance test for content
// following: two relays connected only by loopback HTTP. Unlike the mock-transport
// tests, this exercises the ACTUAL paths a deployed follower uses — HttpPeerClient
// pulling /proof/v1/log and /content/:id/blob/:ref from the origin, then a client
// reading /content/:id/blob from the follower — plus the full lifecycle:
// authorized-but-not-materialized (404) → materialized (200, real bytes) → revoked
// (gate denies, 401) → GC reclaimed. It runs in the race-tested in-package suite.
func TestContentFollowingOverHTTP(t *testing.T) {
	// --- ORIGIN: a real relay holding a public-granted chain + its document bytes,
	// served over HTTP.
	originStore := NewMemoryStore()
	origin, err := NewRelay(RelayOptions{Store: originStore})
	if err != nil {
		t.Fatal(err)
	}
	creator := createTestIdentity(t)
	contentToken, contentID, _ := createTestContent(t, creator)
	doc := testContentDoc()
	docCID, _, err := dfos.DocumentCID(doc)
	if err != nil {
		t.Fatal(err)
	}
	creatorKid := creator.did + "#" + creator.auth.keyID
	grant, err := dfos.CreateCredential(creator.did, "*", creatorKid, "chain:"+contentID, "read", 100*365*24*time.Hour, creator.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	grantHeader, _, err := dfos.DecodeJWSUnsafe(grant)
	if err != nil {
		t.Fatal(err)
	}
	credentialCID := grantHeader.CID
	origin.Ingest([]string{creator.token, contentToken, grant})
	origin.RunSequencerAndGossip()
	blobBytes, _ := json.Marshal(doc)
	if err := originStore.PutBlob(BlobKey{CreatorDID: creator.did, DocumentCID: docCID}, blobBytes); err != nil {
		t.Fatal(err)
	}

	originSrv := httptest.NewServer(origin.Handler())
	defer originSrv.Close()

	// --- FOLLOWER: a real HttpPeerClient pointed at the origin server, eager.
	follower, err := NewRelay(RelayOptions{
		Store:         NewMemoryStore(),
		PeerClient:    NewHttpPeerClient(),
		Peers:         []PeerConfig{{URL: originSrv.URL}},
		ContentFollow: "eager",
	})
	if err != nil {
		t.Fatal(err)
	}
	followerSrv := httptest.NewServer(follower.Handler())
	defer followerSrv.Close()

	blobURL := followerSrv.URL + "/content/" + contentID + "/blob/head"

	// sync the proof plane (grant + content op) over HTTP — bytes do not ride it.
	if err := follower.SyncFromPeers(); err != nil {
		t.Fatalf("follower sync: %v", err)
	}
	follower.RunSequencerAndGossip()

	// AUTHORIZED BUT NOT MATERIALIZED: the grant synced, so the chain is authorized,
	// but the bytes haven't been pulled yet → a client read of the follower is a 404
	// "blob not found" (NOT a 401 — the read is authorized; NOT a 200 — no bytes).
	if !hasPublicStandingAuth(contentID, "read", follower.readStore) {
		t.Fatal("grant did not sync over HTTP")
	}
	if code := httpGetStatus(t, blobURL); code != 404 {
		t.Fatalf("pre-materialize: expected 404 (authorized-but-not-materialized), got %d", code)
	}

	// MATERIALIZE over HTTP: the follower pulls the blob from the origin's content
	// route, verifies it against the committed documentCID, and stores it.
	follower.MaterializeFollowedContent()

	resp, err := http.Get(blobURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("post-materialize: expected 200 from the follower, got %d", resp.StatusCode)
	}
	served, _ := io.ReadAll(resp.Body)
	if err := verifyBlobBytes(served, docCID); err != nil {
		t.Fatalf("follower served bytes that fail content-address verification: %v", err)
	}

	// REVOKE → the gate denies immediately (correctness-free revoke). The creator
	// revokes the grant; the follower syncs the revocation over HTTP.
	revToken, _, err := dfos.SignRevocation(creator.did, credentialCID, creatorKid, creator.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	origin.Ingest([]string{revToken})
	origin.RunSequencerAndGossip()
	if err := follower.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	follower.RunSequencerAndGossip()
	if hasPublicStandingAuth(contentID, "read", follower.readStore) {
		t.Fatal("grant should be revoked on the follower")
	}
	// Even though the bytes are still cached, the serve gate now denies anonymous
	// access → 401, not 200. Revocation is enforced by the gate, not by deletion.
	if code := httpGetStatus(t, blobURL); code != 401 {
		t.Fatalf("post-revoke: follower must deny anonymous read (401), got %d", code)
	}

	// GC reclaims the now-orphaned bytes (pure storage reclamation).
	follower.GCRevokedContent()
	if b, _ := follower.readStore.GetBlob(BlobKey{CreatorDID: creator.did, DocumentCID: docCID}); b != nil {
		t.Fatal("GC did not reclaim the revoked chain's blob")
	}
}

// httpGetStatus does a GET and returns the status code, closing the body.
func httpGetStatus(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}
