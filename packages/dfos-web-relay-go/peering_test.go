package relay

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// =========================================================================
// mock peer client
// =========================================================================

// submitCall records a single SubmitOperations invocation.
type submitCall struct {
	PeerURL    string
	Operations []string
}

// mockPeerClient implements PeerClient backed by a real MemoryStore. It reads
// chain data and global log from the backing store using the same pagination
// logic as the real HTTP endpoints. SubmitOperations calls are sent to a
// buffered channel for test assertion.
type mockPeerClient struct {
	backingStore *MemoryStore
	pageSize     int // 0 = use caller's limit
	submits      chan submitCall
}

func newMockPeerClient(store *MemoryStore, pageSize int) *mockPeerClient {
	return &mockPeerClient{
		backingStore: store,
		pageSize:     pageSize,
		submits:      make(chan submitCall, 100),
	}
}

func (m *mockPeerClient) GetIdentityLog(_ string, did string, after string, limit int) (*PeerLogPage, error) {
	chain, err := m.backingStore.GetIdentityChain(did)
	if err != nil || chain == nil {
		return nil, nil
	}
	return m.paginateChainLog(chain.Log, after, limit), nil
}

func (m *mockPeerClient) GetContentLog(_ string, contentID string, after string, limit int) (*PeerLogPage, error) {
	chain, err := m.backingStore.GetContentChain(contentID)
	if err != nil || chain == nil {
		return nil, nil
	}
	return m.paginateChainLog(chain.Log, after, limit), nil
}

func (m *mockPeerClient) GetOperationLog(_ string, after string, limit int) (*PeerLogPage, error) {
	effectiveLimit := m.pageSize
	if effectiveLimit == 0 {
		effectiveLimit = limit
	}
	entries, cursor, err := m.backingStore.ReadLog(after, effectiveLimit)
	if err != nil {
		return nil, err
	}
	peerEntries := make([]PeerLogEntry, len(entries))
	for i, e := range entries {
		peerEntries[i] = PeerLogEntry{CID: e.CID, JWSToken: e.JWSToken}
	}
	var cursorPtr *string
	if cursor != "" {
		cursorPtr = &cursor
	}
	return &PeerLogPage{Entries: peerEntries, Cursor: cursorPtr}, nil
}

func (m *mockPeerClient) SubmitOperations(peerURL string, operations []string) error {
	m.submits <- submitCall{PeerURL: peerURL, Operations: operations}
	return nil
}

func (m *mockPeerClient) paginateChainLog(log []string, after string, limit int) *PeerLogPage {
	effectiveLimit := m.pageSize
	if effectiveLimit == 0 {
		effectiveLimit = limit
	}

	entries := make([]PeerLogEntry, 0, len(log))
	for _, jws := range log {
		header, _, _ := dfos.DecodeJWSUnsafe(jws)
		cid := ""
		if header != nil {
			cid = header.CID
		}
		entries = append(entries, PeerLogEntry{CID: cid, JWSToken: jws})
	}

	startIdx := 0
	if after != "" {
		for i, e := range entries {
			if e.CID == after {
				startIdx = i + 1
				break
			}
		}
	}

	end := startIdx + effectiveLimit
	if end > len(entries) {
		end = len(entries)
	}
	page := entries[startIdx:end]

	var cursor *string
	if len(page) == effectiveLimit {
		c := page[len(page)-1].CID
		cursor = &c
	}

	return &PeerLogPage{Entries: page, Cursor: cursor}
}

// drainSubmits reads all pending submits from the channel with a short timeout.
func (m *mockPeerClient) drainSubmits(timeout time.Duration) []submitCall {
	var calls []submitCall
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case call := <-m.submits:
			calls = append(calls, call)
		case <-timer.C:
			return calls
		}
	}
}

// =========================================================================
// test helpers
// =========================================================================

type testIdentity struct {
	token string
	did   string
	opCID string
	ctrl  testKeypair
	auth  testKeypair
}

type testKeypair struct {
	mk    dfos.MultikeyPublicKey
	keyID string
	priv  []byte
}

func newTestKeypair() testKeypair {
	pub, priv, _ := ed25519.GenerateKey(nil)
	keyID := dfos.GenerateKeyID()
	mk := dfos.NewMultikeyPublicKey(keyID, pub)
	return testKeypair{mk: mk, keyID: keyID, priv: priv}
}

func createTestIdentity(t *testing.T) testIdentity {
	t.Helper()
	ctrl := newTestKeypair()
	auth := newTestKeypair()
	token, did, opCID, err := dfos.SignIdentityCreate(
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{auth.mk},
		[]dfos.MultikeyPublicKey{},
		ctrl.keyID,
		ctrl.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	return testIdentity{token: token, did: did, opCID: opCID, ctrl: ctrl, auth: auth}
}

func createTestContent(t *testing.T, id testIdentity) (token, contentID, opCID string) {
	t.Helper()
	doc := map[string]any{"type": "post", "title": "hello world", "body": "test content"}
	docCID, _, err := dfos.DocumentCID(doc)
	if err != nil {
		t.Fatal(err)
	}
	kid := id.did + "#" + id.auth.keyID
	token, contentID, opCID, err = dfos.SignContentCreate(id.did, docCID, kid, "", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	return token, contentID, opCID
}

func boolPtr(b bool) *bool { return &b }

// =========================================================================
// gossip tests
// =========================================================================

func TestGossipNewOps(t *testing.T) {
	peerStore := NewMemoryStore()
	mock := newMockPeerClient(peerStore, 0)
	store := NewMemoryStore()
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
	if results[0].Status != "new" {
		t.Fatalf("expected new, got %s", results[0].Status)
	}

	calls := mock.drainSubmits(100 * time.Millisecond)
	if len(calls) != 1 {
		t.Fatalf("expected 1 gossip call, got %d", len(calls))
	}
	if calls[0].PeerURL != "http://peer-a" {
		t.Fatalf("expected peer-a, got %s", calls[0].PeerURL)
	}
	if len(calls[0].Operations) != 1 || calls[0].Operations[0] != id.token {
		t.Fatal("gossip should contain the ingested token")
	}
}

func TestGossipDuplicateOps(t *testing.T) {
	peerStore := NewMemoryStore()
	mock := newMockPeerClient(peerStore, 0)
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	id := createTestIdentity(t)
	relay.Ingest([]string{id.token})
	// drain first gossip
	mock.drainSubmits(100 * time.Millisecond)

	// ingest again — duplicate, no gossip
	results := relay.Ingest([]string{id.token})
	if results[0].Status != "duplicate" {
		t.Fatalf("expected duplicate, got %s", results[0].Status)
	}

	calls := mock.drainSubmits(100 * time.Millisecond)
	if len(calls) != 0 {
		t.Fatalf("expected 0 gossip calls for duplicate, got %d", len(calls))
	}
}

func TestGossipDisabled(t *testing.T) {
	peerStore := NewMemoryStore()
	mock := newMockPeerClient(peerStore, 0)
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: mock,
		Peers: []PeerConfig{
			{URL: "http://peer-a", Gossip: boolPtr(true)},
			{URL: "http://peer-b", Gossip: boolPtr(false)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	id := createTestIdentity(t)
	relay.Ingest([]string{id.token})

	calls := mock.drainSubmits(100 * time.Millisecond)
	if len(calls) != 1 {
		t.Fatalf("expected 1 gossip call, got %d", len(calls))
	}
	if calls[0].PeerURL != "http://peer-a" {
		t.Fatalf("expected peer-a, got %s", calls[0].PeerURL)
	}
}

func TestGossipAllPeers(t *testing.T) {
	peerStore := NewMemoryStore()
	mock := newMockPeerClient(peerStore, 0)
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: mock,
		Peers: []PeerConfig{
			{URL: "http://peer-a"},
			{URL: "http://peer-b"},
			{URL: "http://peer-c"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	id := createTestIdentity(t)
	relay.Ingest([]string{id.token})

	calls := mock.drainSubmits(100 * time.Millisecond)
	if len(calls) != 3 {
		t.Fatalf("expected 3 gossip calls, got %d", len(calls))
	}
	urls := map[string]bool{}
	for _, c := range calls {
		urls[c.PeerURL] = true
	}
	for _, u := range []string{"http://peer-a", "http://peer-b", "http://peer-c"} {
		if !urls[u] {
			t.Fatalf("missing gossip to %s", u)
		}
	}
}

// =========================================================================
// read-through tests (via HTTP handlers)
// =========================================================================

func TestReadThroughIdentity(t *testing.T) {
	peerStore := NewMemoryStore()
	id := createTestIdentity(t)
	IngestOperations([]string{id.token}, peerStore)

	mock := newMockPeerClient(peerStore, 0)
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(relay.Handler())
	defer srv.Close()

	var body map[string]any
	resp := getJSONTest(t, srv.URL+"/identities/"+id.did, &body)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if body["did"] != id.did {
		t.Fatalf("expected DID %s, got %v", id.did, body["did"])
	}
}

func TestReadThroughIdentity404(t *testing.T) {
	peerStore := NewMemoryStore()
	mock := newMockPeerClient(peerStore, 0)
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(relay.Handler())
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/identities/did:dfos:nonexistent")
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestReadThroughIdentityMultiPage(t *testing.T) {
	peerStore := NewMemoryStore()
	id := createTestIdentity(t)

	// create identity update so chain has 2 ops
	updateToken, _, err := dfos.SignIdentityUpdate(
		id.opCID,
		[]dfos.MultikeyPublicKey{id.ctrl.mk},
		[]dfos.MultikeyPublicKey{id.auth.mk},
		[]dfos.MultikeyPublicKey{},
		id.did+"#"+id.ctrl.keyID,
		id.ctrl.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	IngestOperations([]string{id.token, updateToken}, peerStore)

	// verify peer has 2-op chain
	peerChain, _ := peerStore.GetIdentityChain(id.did)
	if peerChain == nil || len(peerChain.Log) != 2 {
		t.Fatalf("expected 2-op chain in peer, got %v", peerChain)
	}

	// pageSize=1 forces pagination
	mock := newMockPeerClient(peerStore, 1)
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(relay.Handler())
	defer srv.Close()

	var body map[string]any
	resp := getJSONTest(t, srv.URL+"/identities/"+id.did, &body)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// verify full chain ingested locally
	localChain, _ := store.GetIdentityChain(id.did)
	if localChain == nil {
		t.Fatal("expected chain in local store")
	}
	if len(localChain.Log) != 2 {
		t.Fatalf("expected 2-op chain, got %d", len(localChain.Log))
	}
}

func TestReadThroughContent(t *testing.T) {
	peerStore := NewMemoryStore()
	id := createTestIdentity(t)
	contentToken, contentID, _ := createTestContent(t, id)

	// seed peer with identity + content
	IngestOperations([]string{id.token, contentToken}, peerStore)

	mock := newMockPeerClient(peerStore, 0)
	store := NewMemoryStore()
	// ingest identity locally (needed to verify content ops)
	IngestOperations([]string{id.token}, store)

	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(relay.Handler())
	defer srv.Close()

	var body map[string]any
	resp := getJSONTest(t, srv.URL+"/content/"+contentID, &body)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if body["contentId"] != contentID {
		t.Fatalf("expected contentId %s, got %v", contentID, body["contentId"])
	}
}

func TestReadThroughDisabled(t *testing.T) {
	peerStore := NewMemoryStore()
	id := createTestIdentity(t)
	IngestOperations([]string{id.token}, peerStore)

	mock := newMockPeerClient(peerStore, 0)
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://peer-a", ReadThrough: boolPtr(false)}},
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(relay.Handler())
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/identities/" + id.did)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// =========================================================================
// sync tests
// =========================================================================

func TestSyncFromPeers(t *testing.T) {
	peerStore := NewMemoryStore()
	id := createTestIdentity(t)
	IngestOperations([]string{id.token}, peerStore)

	mock := newMockPeerClient(peerStore, 0)
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

	chain, _ := store.GetIdentityChain(id.did)
	if chain == nil {
		t.Fatal("expected identity chain in local store after sync")
	}
	if chain.DID != id.did {
		t.Fatalf("expected DID %s, got %s", id.did, chain.DID)
	}
}

func TestSyncCursorPersistence(t *testing.T) {
	peerStore := NewMemoryStore()
	id := createTestIdentity(t)
	results := IngestOperations([]string{id.token}, peerStore)
	opCID := results[0].CID

	mock := newMockPeerClient(peerStore, 0)
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	relay.SyncFromPeers()

	cursor, _ := store.GetPeerCursor("http://peer-a")
	if cursor != opCID {
		t.Fatalf("expected cursor %s, got %s", opCID, cursor)
	}
}

func TestSyncMultiPage(t *testing.T) {
	peerStore := NewMemoryStore()

	ids := make([]testIdentity, 3)
	for i := 0; i < 3; i++ {
		ids[i] = createTestIdentity(t)
		IngestOperations([]string{ids[i].token}, peerStore)
	}

	// pageSize=1 forces 3 pages
	mock := newMockPeerClient(peerStore, 1)
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	relay.SyncFromPeers()

	for _, id := range ids {
		chain, _ := store.GetIdentityChain(id.did)
		if chain == nil {
			t.Fatalf("expected identity %s in local store after multi-page sync", id.did)
		}
	}
}

func TestSyncResumesFromCursor(t *testing.T) {
	peerStore := NewMemoryStore()

	idA := createTestIdentity(t)
	idB := createTestIdentity(t)
	idC := createTestIdentity(t)
	IngestOperations([]string{idA.token}, peerStore)
	resultsB := IngestOperations([]string{idB.token}, peerStore)
	IngestOperations([]string{idC.token}, peerStore)

	mock := newMockPeerClient(peerStore, 0)
	store := NewMemoryStore()
	// pre-set cursor to B → sync should only fetch C
	store.SetPeerCursor("http://peer-a", resultsB[0].CID)

	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	relay.SyncFromPeers()

	// A and B should NOT be in local store
	chainA, _ := store.GetIdentityChain(idA.did)
	if chainA != nil {
		t.Fatal("identity A should not be in local store (skipped by cursor)")
	}
	chainB, _ := store.GetIdentityChain(idB.did)
	if chainB != nil {
		t.Fatal("identity B should not be in local store (skipped by cursor)")
	}

	// C should be synced
	chainC, _ := store.GetIdentityChain(idC.did)
	if chainC == nil {
		t.Fatal("expected identity C in local store after sync")
	}
}

func TestSyncDisabled(t *testing.T) {
	peerStore := NewMemoryStore()
	id := createTestIdentity(t)
	IngestOperations([]string{id.token}, peerStore)

	mock := newMockPeerClient(peerStore, 0)
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://peer-a", Sync: boolPtr(false)}},
	})
	if err != nil {
		t.Fatal(err)
	}

	relay.SyncFromPeers()

	chain, _ := store.GetIdentityChain(id.did)
	if chain != nil {
		t.Fatal("expected no identity when sync is disabled")
	}
}

func TestSyncEmptyPeer(t *testing.T) {
	peerStore := NewMemoryStore()
	mock := newMockPeerClient(peerStore, 0)
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	relay.SyncFromPeers()

	cursor, _ := store.GetPeerCursor("http://peer-a")
	if cursor != "" {
		t.Fatalf("expected empty cursor, got %s", cursor)
	}
}

// =========================================================================
// test HTTP helper
// =========================================================================

func getJSONTest(t *testing.T, url string, v any) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	if v != nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err := json.Unmarshal(body, v); err != nil {
			t.Fatalf("decode %s: %v (body: %s)", url, err, string(body))
		}
		resp.Body = io.NopCloser(strings.NewReader(string(body)))
	}
	return resp
}
