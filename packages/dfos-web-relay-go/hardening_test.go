package relay

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ===================================================================
// WP-10: peer-sync CID-trust wedge
// ===================================================================

// mismatchedCIDPeerClient returns a single operation-log page whose entries
// carry a CID that does NOT match the locally-computed CID of the token. A
// relay that trusts the peer-claimed CID keys its raw_ops row under the bogus
// CID; the sequencer then loops forever (MarkOpsSequenced(realCID) matches no
// row, the re-verified op reports "duplicate" → counts as progress) at 100% CPU
// holding ingestMu. The fix computes the CID locally.
type mismatchedCIDPeerClient struct {
	token       string // a real, decodable JWS token
	claimedCID  string // the (wrong) CID the peer claims for it
	served      bool
	undecodable bool // if true, also serve a garbage token
}

func (m *mismatchedCIDPeerClient) GetIdentityLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (m *mismatchedCIDPeerClient) GetContentLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (m *mismatchedCIDPeerClient) SubmitOperations(string, []string) error { return nil }

func (m *mismatchedCIDPeerClient) GetOperationLog(_ string, _ string, _ int) (*PeerLogPage, error) {
	if m.served {
		return &PeerLogPage{Entries: nil, Cursor: nil}, nil
	}
	m.served = true
	entries := []PeerLogEntry{{CID: m.claimedCID, JWSToken: m.token}}
	if m.undecodable {
		entries = append(entries, PeerLogEntry{CID: "bafyGARBAGE", JWSToken: "not-a-jws-token"})
	}
	// Cursor nil → single page; SyncFromPeers stops after this page.
	return &PeerLogPage{Entries: entries, Cursor: nil}, nil
}

// TestSyncRejectsMismatchedPeerCID verifies that a peer returning a CID that
// does not match the token does NOT wedge the relay: sync completes in bounded
// time, the op is keyed and sequenced under its real (locally-computed) CID,
// and nothing is left stuck pending.
func TestSyncRejectsMismatchedPeerCID(t *testing.T) {
	id := createTestIdentity(t)
	realCID := computeOpCID(id.token)
	if realCID == "" {
		t.Fatal("expected a decodable token")
	}

	mock := &mismatchedCIDPeerClient{
		token:      id.token,
		claimedCID: "bafyBOGUSdoesnotmatch",
	}

	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Run sync with a hard deadline — a wedge would never return.
	done := make(chan struct{})
	go func() {
		_ = relay.SyncFromPeers()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SyncFromPeers wedged — did not return within 5s (CID-trust loop)")
	}

	// The raw op must be keyed under the REAL CID, not the peer-claimed one.
	if _, ok := store.rawOps[realCID]; !ok {
		t.Fatalf("expected raw op keyed under real CID %s", realCID)
	}
	if _, ok := store.rawOps["bafyBOGUSdoesnotmatch"]; ok {
		t.Fatal("raw op must NOT be keyed under the peer-claimed (bogus) CID")
	}

	// Nothing must be left pending (a wedge leaves the bogus row pending forever).
	pending, _ := store.CountUnsequenced()
	if pending != 0 {
		t.Fatalf("expected 0 pending ops after sync, got %d", pending)
	}

	// And the identity must have been ingested under its real CID.
	chain, _ := store.GetIdentityChain(id.did)
	if chain == nil {
		t.Fatal("expected identity chain ingested after sync despite bogus claimed CID")
	}
}

// TestSyncSkipsUndecodableToken verifies that an undecodable token from a peer
// is skipped (not stored under an empty CID) and does not wedge sync.
func TestSyncSkipsUndecodableToken(t *testing.T) {
	id := createTestIdentity(t)
	realCID := computeOpCID(id.token)

	mock := &mismatchedCIDPeerClient{
		token:       id.token,
		claimedCID:  realCID, // honest CID for the good op
		undecodable: true,    // plus a garbage entry
	}

	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := relay.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}

	// the garbage token must not have created a raw op under an empty key
	if _, ok := store.rawOps[""]; ok {
		t.Fatal("undecodable token must not be stored under an empty CID key")
	}
	if len(store.rawOps) != 1 {
		t.Fatalf("expected exactly 1 raw op (the good one), got %d", len(store.rawOps))
	}
	pending, _ := store.CountUnsequenced()
	if pending != 0 {
		t.Fatalf("expected 0 pending ops, got %d", pending)
	}
}

// ===================================================================
// WP-11(b): ignored store write errors
// ===================================================================

// faultyStore embeds a MemoryStore and injects a write failure on the first
// PutIdentityChain call. Used to verify that a persistence failure does not
// cause the relay to report "new", mark the op sequenced, or gossip it.
type faultyStore struct {
	*MemoryStore
	failPutIdentity bool
}

func (f *faultyStore) PutIdentityChain(chain StoredIdentityChain) error {
	if f.failPutIdentity {
		return fmt.Errorf("injected disk failure")
	}
	return f.MemoryStore.PutIdentityChain(chain)
}

// gossipRecorderPeerClient records SubmitOperations calls.
type gossipRecorderPeerClient struct {
	submits chan []string
}

func (g *gossipRecorderPeerClient) GetIdentityLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (g *gossipRecorderPeerClient) GetContentLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (g *gossipRecorderPeerClient) GetOperationLog(string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (g *gossipRecorderPeerClient) SubmitOperations(_ string, ops []string) error {
	g.submits <- ops
	return nil
}

// TestIngestPersistFailureDoesNotGossip verifies that when a state write fails
// during ingestion, the relay does NOT report "new", does NOT mark the op
// sequenced (it stays pending for retry), and does NOT gossip it.
func TestIngestPersistFailureDoesNotGossip(t *testing.T) {
	// Start healthy so relay bootstrap (which writes its own identity) succeeds,
	// then inject the fault before ingesting the test op.
	store := &faultyStore{MemoryStore: NewMemoryStore()}
	gossip := &gossipRecorderPeerClient{submits: make(chan []string, 16)}
	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: gossip,
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	store.failPutIdentity = true

	id := createTestIdentity(t)
	results := relay.Ingest([]string{id.token})

	// The op must NOT report "new" — the write failed.
	if results[0].Status == "new" {
		t.Fatalf("expected non-new status on persist failure, got %q", results[0].Status)
	}

	// It must stay pending for retry (raw op stored, not sequenced, not rejected).
	realCID := computeOpCID(id.token)
	entry, ok := store.rawOps[realCID]
	if !ok {
		t.Fatal("expected raw op to be stored for retry")
	}
	if entry.status != "pending" {
		t.Fatalf("expected raw op to remain pending after persist failure, got %q", entry.status)
	}

	// Nothing must have been gossiped.
	select {
	case ops := <-gossip.submits:
		t.Fatalf("expected no gossip on persist failure, got %v", ops)
	case <-time.After(150 * time.Millisecond):
		// good — no gossip
	}

	// Now heal the store and re-run the sequencer: the op recovers.
	store.failPutIdentity = false
	relay.RunSequencerAndGossip()

	chain, _ := store.GetIdentityChain(id.did)
	if chain == nil {
		t.Fatal("expected identity chain to recover after store heals")
	}
	healedEntry := store.rawOps[realCID]
	if healedEntry.status != "sequenced" {
		t.Fatalf("expected op sequenced after heal, got %q", healedEntry.status)
	}
}

// ===================================================================
// WP-11(c): gossip chunking
// ===================================================================

// chunkRecorderPeerClient records the size of each SubmitOperations batch.
type chunkRecorderPeerClient struct {
	batches chan int
}

func (c *chunkRecorderPeerClient) GetIdentityLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (c *chunkRecorderPeerClient) GetContentLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (c *chunkRecorderPeerClient) GetOperationLog(string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (c *chunkRecorderPeerClient) SubmitOperations(_ string, ops []string) error {
	c.batches <- len(ops)
	return nil
}

// TestGossipChunksLargeBatches verifies that gossip never sends a batch larger
// than the receiver's 100-op limit.
func TestGossipChunksLargeBatches(t *testing.T) {
	rec := &chunkRecorderPeerClient{batches: make(chan int, 32)}
	relay, err := NewRelay(RelayOptions{
		Store:      NewMemoryStore(),
		PeerClient: rec,
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 250 tokens → must split into 100 + 100 + 50.
	tokens := make([]string, 250)
	for i := range tokens {
		tokens[i] = fmt.Sprintf("token-%d", i)
	}
	relay.gossipOps(tokens)

	var sizes []int
	total := 0
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	for total < 250 {
		select {
		case n := <-rec.batches:
			sizes = append(sizes, n)
			total += n
		case <-timer.C:
			t.Fatalf("only %d/250 ops gossiped before timeout (sizes=%v)", total, sizes)
		}
	}
	for _, n := range sizes {
		if n > maxGossipBatch {
			t.Fatalf("gossip batch of %d exceeds max %d", n, maxGossipBatch)
		}
	}
	if total != 250 {
		t.Fatalf("expected 250 total ops gossiped, got %d", total)
	}
}

// ===================================================================
// CORS
// ===================================================================

// TestCORSHeadersOnProofPlane verifies the exact CORS policy is emitted on
// proof-plane responses and that OPTIONS preflight returns 204. The policy must
// stay byte-for-byte in sync with the TS relay.
func TestCORSHeadersOnProofPlane(t *testing.T) {
	id := createTestIdentity(t)
	store := NewMemoryStore()
	IngestOperations([]string{id.token}, store)
	relay, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(relay.Handler())
	defer srv.Close()

	const (
		wantOrigin  = "*"
		wantMethods = "GET, POST, PUT, OPTIONS"
		wantHeaders = "Content-Type, Authorization"
	)

	// GET on a proof-plane route carries CORS headers.
	resp, err := http.Get(srv.URL + "/identities/" + id.did)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != wantOrigin {
		t.Fatalf("Allow-Origin = %q, want %q", got, wantOrigin)
	}
	if got := resp.Header.Get("Access-Control-Allow-Methods"); got != wantMethods {
		t.Fatalf("Allow-Methods = %q, want %q", got, wantMethods)
	}
	if got := resp.Header.Get("Access-Control-Allow-Headers"); got != wantHeaders {
		t.Fatalf("Allow-Headers = %q, want %q", got, wantHeaders)
	}

	// OPTIONS preflight returns 204 with the same headers.
	req, _ := http.NewRequest(http.MethodOptions, srv.URL+"/operations", nil)
	preflight, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	preflight.Body.Close()
	if preflight.StatusCode != http.StatusNoContent {
		t.Fatalf("OPTIONS status = %d, want 204", preflight.StatusCode)
	}
	if got := preflight.Header.Get("Access-Control-Allow-Origin"); got != wantOrigin {
		t.Fatalf("preflight Allow-Origin = %q, want %q", got, wantOrigin)
	}
	if got := preflight.Header.Get("Access-Control-Allow-Methods"); got != wantMethods {
		t.Fatalf("preflight Allow-Methods = %q, want %q", got, wantMethods)
	}
}
