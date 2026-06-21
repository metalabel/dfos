package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// liteRelay builds a write:false (LITE pull-only) relay over a fresh store.
func liteRelay(t *testing.T, store Store, peers []PeerConfig, pc PeerClient) *Relay {
	t.Helper()
	writeDisabled := false
	r, err := NewRelay(RelayOptions{
		Store:      store,
		Write:      &writeDisabled,
		Peers:      peers,
		PeerClient: pc,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// wellKnownCaps fetches /.well-known/dfos-relay and returns the capabilities map.
func wellKnownCaps(t *testing.T, srvURL string) map[string]any {
	t.Helper()
	resp, err := http.Get(srvURL + "/.well-known/dfos-relay")
	if err != nil {
		t.Fatalf("GET well-known: %v", err)
	}
	defer resp.Body.Close()
	var body struct {
		Capabilities map[string]any `json:"capabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode well-known: %v", err)
	}
	return body.Capabilities
}

// TestLiteNodeRejectsWrites — a pull-only node rejects POST /proof/v1/operations
// with 501. The gate fires before body parsing, so any body is rejected (this is
// the same endpoint peers gossip into, so gossip-in is refused too).
func TestLiteNodeRejectsWrites(t *testing.T) {
	srv := httptest.NewServer(liteRelay(t, NewMemoryStore(), nil, nil).Handler())
	defer srv.Close()

	id := createTestIdentity(t)
	body := `{"operations":["` + id.token + `"]}`
	resp, err := http.Post(srv.URL+"/proof/v1/operations", "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("POST /operations: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 501 {
		t.Fatalf("expected 501 on a pull-only node, got %d", resp.StatusCode)
	}
}

// TestLiteNodeAdvertisesWriteFalse — well-known advertises the role so clients
// and peers know not to write before trying.
func TestLiteNodeAdvertisesWriteFalse(t *testing.T) {
	srv := httptest.NewServer(liteRelay(t, NewMemoryStore(), nil, nil).Handler())
	defer srv.Close()

	caps := wellKnownCaps(t, srv.URL)
	if caps["write"] != false {
		t.Fatalf("expected capabilities.write=false, got %v", caps["write"])
	}
	// a lite node is still a full proof node for reads
	if caps["proof"] != true {
		t.Fatalf("expected capabilities.proof=true, got %v", caps["proof"])
	}
}

// TestDefaultRelayAdvertisesWriteTrue — the default (write-accepting) relay
// advertises write:true and does NOT 501 on POST.
func TestDefaultRelayAdvertisesWriteTrue(t *testing.T) {
	r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	if caps := wellKnownCaps(t, srv.URL); caps["write"] != true {
		t.Fatalf("expected capabilities.write=true by default, got %v", caps["write"])
	}

	id := createTestIdentity(t)
	body := `{"operations":["` + id.token + `"]}`
	resp, err := http.Post(srv.URL+"/proof/v1/operations", "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("POST /operations: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 501 {
		t.Fatal("a write-enabled relay must not 501 on POST /operations")
	}
}

// TestLiteNodeServesReads — reads route normally on a pull-only node: a missing
// chain returns 404 (route reached), never 501 (which is write-only).
func TestLiteNodeServesReads(t *testing.T) {
	srv := httptest.NewServer(liteRelay(t, NewMemoryStore(), nil, nil).Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/proof/v1/identities/did:dfos:unknown000000000000")
	if err != nil {
		t.Fatalf("GET identity: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 for unknown identity on a lite node, got %d", resp.StatusCode)
	}
}

// TestLiteNodeStillPullsFromPeers — the keystone of "pull-only": writes are
// refused at the front door, but the node still ingests by PULLING a peer's log
// via SyncFromPeers. A peer holds an identity chain; the lite node syncs and
// ends up with that chain locally despite accepting no writes.
func TestLiteNodeStillPullsFromPeers(t *testing.T) {
	peerStore := NewMemoryStore()
	id := createTestIdentity(t)
	IngestOperations([]string{id.token}, peerStore)

	store := NewMemoryStore()
	r := liteRelay(t, store, []PeerConfig{{URL: "http://peer-a"}}, newMockPeerClient(peerStore, 0))

	if err := r.SyncFromPeers(); err != nil {
		t.Fatalf("SyncFromPeers: %v", err)
	}

	chain, _ := store.GetIdentityChain(id.did)
	if chain == nil {
		t.Fatal("expected identity chain in local store after pull-sync on a lite node")
	}
	if chain.DID != id.did {
		t.Fatalf("expected DID %s, got %s", id.did, chain.DID)
	}
}
