package relay

// The peer identity pin, in the relay library.
//
// Before this, PeerConfig had no DID at all: peer state was keyed purely by URL,
// so a relay whose peer re-keyed (or whose peer's address was taken over by
// someone else) went on syncing that peer's whole log, gossiping every sequenced
// operation to it, answering read-through misses out of it, and pulling document
// blobs from it, with no check anywhere in the loop. The CLI held a pin and
// checked it on the commands it owned; the embedded relay's own peer traffic
// carried none of that with it.
//
// Every test here counts the peer calls it is about, because "skipped the peer"
// and "asked the peer and it had nothing" are the same output otherwise.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	pinnedRelayDID = "did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar"
	otherRelayDID  = "did:dfos:cv7n8vkvr64cctf3294h9k4eanhff8z"
)

// identifyingMock is a mockPeerClient that also answers the identity question,
// so it satisfies IdentifyingPeerClient. It counts every peer touch the pin gate
// is supposed to prevent — the log pulls, the blob fetches, and the identity
// question itself.
//
// It EMBEDS the shared mock rather than replacing it, which is the point of
// IdentifyingPeerClient being optional: the plain mock is still a valid
// PeerClient and still gets no pin check at all.
type identifyingMock struct {
	*mockPeerClient
	did    string // what this peer serves at its well-known
	didErr error  // set to make the question unanswerable (an offline peer)

	didCalls         atomic.Int32
	operationLogHits atomic.Int32
	identityLogHits  atomic.Int32
	contentLogHits   atomic.Int32
	blobHits         atomic.Int32
}

func newIdentifyingMock(store *MemoryStore, did string) *identifyingMock {
	return &identifyingMock{mockPeerClient: newMockPeerClient(store, 0), did: did}
}

func (m *identifyingMock) GetPeerDID(string) (string, error) {
	m.didCalls.Add(1)
	if m.didErr != nil {
		return "", m.didErr
	}
	return m.did, nil
}

func (m *identifyingMock) GetOperationLog(peerURL, after string, limit int) (*PeerLogPage, error) {
	m.operationLogHits.Add(1)
	return m.mockPeerClient.GetOperationLog(peerURL, after, limit)
}

func (m *identifyingMock) GetIdentityLog(peerURL, did, after string, limit int) (*PeerLogPage, error) {
	m.identityLogHits.Add(1)
	return m.mockPeerClient.GetIdentityLog(peerURL, did, after, limit)
}

func (m *identifyingMock) GetContentLog(peerURL, contentID, after string, limit int) (*PeerLogPage, error) {
	m.contentLogHits.Add(1)
	return m.mockPeerClient.GetContentLog(peerURL, contentID, after, limit)
}

func (m *identifyingMock) GetBlob(peerURL, contentID, ref string) ([]byte, error) {
	m.blobHits.Add(1)
	return m.mockPeerClient.GetBlob(peerURL, contentID, ref)
}

// pinnedRelay builds a relay whose single peer carries pin, backed by a peer
// store the mock serves and a mock that answers as serves.
func pinnedRelay(t *testing.T, peerStore *MemoryStore, pin, serves string) (*Relay, *identifyingMock) {
	t.Helper()
	mock := newIdentifyingMock(peerStore, serves)
	r, err := NewRelay(RelayOptions{
		Store:      NewMemoryStore(),
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://peer-a", DID: pin}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r, mock
}

// TestPeerPinMismatchSkipsTheSyncPull is the unbounded direction: bulk sync
// takes the peer's WHOLE log, so a peer that is no longer the relay this node
// was configured against must not be pulled from at all.
func TestPeerPinMismatchSkipsTheSyncPull(t *testing.T) {
	peerStore := NewMemoryStore()
	id := createTestIdentity(t)
	IngestOperations([]string{id.token}, peerStore)

	r, mock := pinnedRelay(t, peerStore, otherRelayDID, pinnedRelayDID)
	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}

	if mock.operationLogHits.Load() != 0 {
		t.Errorf("a refused peer must not be pulled from, got %d log fetches", mock.operationLogHits.Load())
	}
	if chain, _ := r.store.GetIdentityChain(id.did); chain != nil {
		t.Error("nothing from a refused peer may land in the local store")
	}
	if cursor, _ := r.readStore.GetPeerCursor("http://peer-a"); cursor != "" {
		t.Errorf("a refused peer's cursor must not move, got %q", cursor)
	}
}

// TestPeerPinMismatchIsReportedOnTheSyncStatus: a skipped cycle is otherwise
// indistinguishable from a quiet one — it attempts nothing, receives nothing,
// and fails nothing — which is precisely the silence a moved pin must not hide
// in. The verdict rides on the same status the well-known serves.
func TestPeerPinMismatchIsReportedOnTheSyncStatus(t *testing.T) {
	r, _ := pinnedRelay(t, NewMemoryStore(), otherRelayDID, pinnedRelayDID)
	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}

	st := r.PeerSyncStatuses()["http://peer-a"]
	if st.PinMismatch == nil {
		t.Fatal("a skipped peer must report the mismatch, got nil")
	}
	for _, want := range []string{"http://peer-a", otherRelayDID, pinnedRelayDID} {
		if !strings.Contains(*st.PinMismatch, want) {
			t.Errorf("the reported mismatch must name %q, got %q", want, *st.PinMismatch)
		}
	}
}

// TestPeerPinMismatchSkipsGossip is the direction that PUBLISHES: everything
// this relay sequences would otherwise be pushed to whoever now answers at the
// peer's address.
func TestPeerPinMismatchSkipsGossip(t *testing.T) {
	r, mock := pinnedRelay(t, NewMemoryStore(), otherRelayDID, pinnedRelayDID)

	id := createTestIdentity(t)
	if results := r.Ingest([]string{id.token}); results[0].Status != "new" {
		t.Fatalf("expected the local ingest to succeed, got %s", results[0].Status)
	}

	if calls := mock.drainSubmits(200 * time.Millisecond); len(calls) != 0 {
		t.Fatalf("a refused peer must receive no gossip, got %d push(es)", len(calls))
	}
}

// TestPeerPinMismatchSkipsReadThrough: read-through serves a peer's answer as
// this relay's own AND ingests it, so a refused peer is not asked and the miss
// stays a 404.
func TestPeerPinMismatchSkipsReadThrough(t *testing.T) {
	peerStore := NewMemoryStore()
	id := createTestIdentity(t)
	contentToken, contentID, _ := createTestContent(t, id)
	IngestOperations([]string{id.token, contentToken}, peerStore)

	r, mock := pinnedRelay(t, peerStore, otherRelayDID, pinnedRelayDID)
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	for _, path := range []string{
		"/proof/v1/identities/" + id.did,
		"/1.0/identifiers/" + id.did,
		"/proof/v1/content/" + contentID,
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Errorf("GET %s through a refused peer must 404, got %d", path, resp.StatusCode)
		}
	}
	if mock.identityLogHits.Load() != 0 || mock.contentLogHits.Load() != 0 {
		t.Errorf("a refused peer must not be read through: %d identity, %d content fetches",
			mock.identityLogHits.Load(), mock.contentLogHits.Load())
	}
}

// TestPeerPinMismatchSkipsBlobMaterialization covers the content plane's pull.
// The bytes are content-address-verified on arrival, so a refused peer could not
// have slipped bad ones past that — but which relays this machine talks to is a
// posture the operator set, and a re-keyed peer is outside it whatever the
// hashes say.
func TestPeerPinMismatchSkipsBlobMaterialization(t *testing.T) {
	r, mock := pinnedRelay(t, NewMemoryStore(), otherRelayDID, pinnedRelayDID)

	r.pullAndStoreBlob("content-id", "op-cid", BlobKey{CreatorDID: "did:dfos:x", DocumentCID: "doc-cid"})
	if mock.blobHits.Load() != 0 {
		t.Errorf("a refused peer must not be asked for blobs, got %d fetches", mock.blobHits.Load())
	}
}

// TestPeerPinMatchingLetsTrafficThrough: the pin is not a tax on the normal
// case. A peer serving the DID it is pinned to behaves exactly as an unpinned
// one does.
func TestPeerPinMatchingLetsTrafficThrough(t *testing.T) {
	peerStore := NewMemoryStore()
	id := createTestIdentity(t)
	IngestOperations([]string{id.token}, peerStore)

	r, mock := pinnedRelay(t, peerStore, pinnedRelayDID, pinnedRelayDID)
	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	if chain, _ := r.store.GetIdentityChain(id.did); chain == nil {
		t.Fatal("a matching pin must not stop the sync pull")
	}
	if st := r.PeerSyncStatuses()["http://peer-a"]; st.PinMismatch != nil {
		t.Errorf("a matching pin must report no mismatch, got %q", *st.PinMismatch)
	}

	local := createTestIdentity(t)
	r.Ingest([]string{local.token})
	if calls := mock.drainSubmits(200 * time.Millisecond); len(calls) == 0 {
		t.Error("a matching pin must not stop gossip")
	}
}

// TestUnpinnedPeerIsNeverAsked is the compatibility contract: a peer named by
// URL alone makes no claim about identity, so the gate does not fetch, does not
// refuse, and costs nothing.
func TestUnpinnedPeerIsNeverAsked(t *testing.T) {
	peerStore := NewMemoryStore()
	id := createTestIdentity(t)
	IngestOperations([]string{id.token}, peerStore)

	r, mock := pinnedRelay(t, peerStore, "", pinnedRelayDID)
	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}

	if mock.didCalls.Load() != 0 {
		t.Errorf("an unpinned peer must never be asked for its DID, got %d calls", mock.didCalls.Load())
	}
	if chain, _ := r.store.GetIdentityChain(id.did); chain == nil {
		t.Fatal("an unpinned peer must sync exactly as before")
	}
}

// TestUnansweredPinIsNotAMismatch: unreachable, non-200, and undecodable are all
// "no evidence", never "a different identity". An offline peer is a reachability
// problem the operation reports in its own words — turning it into a pin refusal
// would stop replication over a fact nobody established.
func TestUnansweredPinIsNotAMismatch(t *testing.T) {
	peerStore := NewMemoryStore()
	id := createTestIdentity(t)
	IngestOperations([]string{id.token}, peerStore)

	r, mock := pinnedRelay(t, peerStore, otherRelayDID, "")
	mock.didErr = errors.New("dial tcp: connection refused")

	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	if chain, _ := r.store.GetIdentityChain(id.did); chain == nil {
		t.Fatal("an unanswered pin question must not stop the sync pull")
	}
	if st := r.PeerSyncStatuses()["http://peer-a"]; st.PinMismatch != nil {
		t.Errorf("an unreachable peer must not be reported as a moved pin, got %q", *st.PinMismatch)
	}
}

// TestPeerPinVerdictIsCached: the gate is hit on every sync tick, every gossip
// chunk, and every read-through miss. One well-known fetch per recheck window
// is what keeps that affordable.
func TestPeerPinVerdictIsCached(t *testing.T) {
	r, mock := pinnedRelay(t, NewMemoryStore(), pinnedRelayDID, pinnedRelayDID)

	for range 3 {
		if err := r.SyncFromPeers(); err != nil {
			t.Fatal(err)
		}
	}
	if got := mock.didCalls.Load(); got != 1 {
		t.Fatalf("the peer's DID was fetched %d times, want 1", got)
	}
}

// TestPeerPinVerdictExpires: the pin is checked before AND during. A verdict
// older than the recheck window is re-asked, so an identity that moves under a
// long-running `serve` is caught within a cycle or two rather than at restart.
func TestPeerPinVerdictExpires(t *testing.T) {
	peerStore := NewMemoryStore()
	id := createTestIdentity(t)
	IngestOperations([]string{id.token}, peerStore)

	r, mock := pinnedRelay(t, peerStore, pinnedRelayDID, pinnedRelayDID)
	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	if chain, _ := r.store.GetIdentityChain(id.did); chain == nil {
		t.Fatal("precondition: the matching pin must sync first")
	}

	// The peer re-keys, and the standing verdict is aged past its window.
	mock.did = otherRelayDID
	r.peerPinMu.Lock()
	r.peerPins["http://peer-a"] = peerPinVerdict{checkedAt: time.Now().Add(-2 * peerPinRecheck)}
	r.peerPinMu.Unlock()

	before := mock.operationLogHits.Load()
	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	if mock.operationLogHits.Load() != before {
		t.Error("a pin that moved mid-run must stop the next pull, not the one after a restart")
	}
	if st := r.PeerSyncStatuses()["http://peer-a"]; st.PinMismatch == nil {
		t.Error("the expired-and-re-asked verdict must be reported")
	}
}

// TestPinnedPeerOnAnUnidentifyingClientStillFlows: a PeerClient that cannot ask
// the question leaves the pin UNVERIFIABLE, which is not the same as violated.
// Every in-process mock in this package is such a client, which is why they all
// keep working unchanged.
func TestPinnedPeerOnAnUnidentifyingClientStillFlows(t *testing.T) {
	peerStore := NewMemoryStore()
	id := createTestIdentity(t)
	IngestOperations([]string{id.token}, peerStore)

	r, err := NewRelay(RelayOptions{
		Store:      NewMemoryStore(),
		PeerClient: newMockPeerClient(peerStore, 0), // no GetPeerDID
		Peers:      []PeerConfig{{URL: "http://peer-a", DID: otherRelayDID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	if chain, _ := r.store.GetIdentityChain(id.did); chain == nil {
		t.Fatal("a pin no transport can check must not stop traffic")
	}
}

// TestHttpPeerClientReadsThePinFromTheWellKnown covers the HTTP half: the DID
// comes from the `did` member of the relay descriptor at the root, and every
// unanswerable case is an error rather than a bare "" that would read as a
// mismatch against a real pin.
func TestHttpPeerClientReadsThePinFromTheWellKnown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/.well-known/dfos-relay" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"did":"` + pinnedRelayDID + `","protocol":"dfos-web-relay"}`))
	}))
	defer srv.Close()

	client := NewHttpPeerClient()
	// The trailing slash is the spelling a hand-written config carries; it must
	// not become "…//.well-known/dfos-relay".
	got, err := client.GetPeerDID(srv.URL + "/")
	if err != nil {
		t.Fatalf("GetPeerDID: %v", err)
	}
	if got != pinnedRelayDID {
		t.Fatalf("served DID = %q, want %q", got, pinnedRelayDID)
	}

	if _, err := client.GetPeerDID("http://127.0.0.1:1"); err == nil {
		t.Error("an unreachable peer must report an error, not an empty DID")
	}
}
