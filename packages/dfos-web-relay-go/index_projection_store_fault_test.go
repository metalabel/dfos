package relay

import (
	"net/http/httptest"
	"testing"
)

// blobFaultStore fails every blob read while failBlob is set. The projection
// reads a blob to derive docSchema/title, and the read route reads one to serve
// bytes — both must tell a fault apart from an absence.
type blobFaultStore struct {
	*MemoryStore
	failBlob bool
}

func (s *blobFaultStore) GetBlob(key BlobKey) ([]byte, error) {
	if s.failBlob {
		return nil, errInjectedStore
	}
	return s.MemoryStore.GetBlob(key)
}

// TestProjectionAbortsOnBlobStoreFault: a blob read that FAILED is not a
// document that is ABSENT. Persisting a null docSchema and advancing the cursor
// makes the outage permanent — the row is never revisited, because the worker
// believes it is caught up. The run must abort with the cursor where it was, and
// the row must be correct once the store recovers.
func TestProjectionAbortsOnBlobStoreFault(t *testing.T) {
	store := &blobFaultStore{MemoryStore: NewMemoryStore()}
	r, err := NewRelay(RelayOptions{
		Store:           store,
		Authority:       testAuthority,
		IndexProjection: IndexProjectionExternal,
	})
	if err != nil {
		t.Fatal(err)
	}

	creator := ingestIdentity(t, r)
	document := map[string]any{"$schema": testPostSchema, "title": "visible"}
	c := createIndexedContent(t, r, store.MemoryStore, creator, document, true)

	store.failBlob = true
	run := projectIndex(store, DefaultIndexProjectionBudget, r.logger)
	if run.CaughtUp {
		t.Fatal("a run that hit a store fault reported itself caught up — nothing will retry it")
	}
	rows, err := store.QueryIndexContent(IndexContentQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("an aborted run wrote %d content rows", len(rows))
	}
	cursor, err := store.GetIndexCursor()
	if err != nil {
		t.Fatal(err)
	}
	if cursor.LogCursor != "" {
		t.Fatalf("an aborted run advanced the cursor to %q", cursor.LogCursor)
	}

	// Recovery: the same work runs again and the row is right.
	store.failBlob = false
	if run := drainIndexProjection(store, DefaultIndexProjectionBudget, 0, r.logger); !run.CaughtUp {
		t.Fatal("the projection did not catch up after the store recovered")
	}
	rows, err = store.QueryIndexContent(IndexContentQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	var row *IndexContentRow
	for i := range rows {
		if rows[i].ContentID == c.contentID {
			row = &rows[i]
		}
	}
	if row == nil {
		t.Fatal("no content row after recovery")
	}
	if row.DocSchema == nil || *row.DocSchema != testPostSchema {
		t.Fatalf("docSchema = %v, want %q — the recovered run did not read the blob", row.DocSchema, testPostSchema)
	}
}

// TestBlobReadStoreFaultIs5xxNotNotFound: RELAY requires a store failure to be
// answered with a 5xx. A 404 tells the caller the blob is not there, which is a
// claim about the corpus this relay is in no position to make.
func TestBlobReadStoreFaultIs5xxNotNotFound(t *testing.T) {
	store := &blobFaultStore{MemoryStore: NewMemoryStore()}
	r, err := NewRelay(RelayOptions{Store: store, Authority: testAuthority})
	if err != nil {
		t.Fatal(err)
	}

	creator := ingestIdentity(t, r)
	document := map[string]any{"$schema": testPostSchema, "title": "visible"}
	c := createIndexedContent(t, r, store.MemoryStore, creator, document, true)
	addPublicRead(t, r, creator, c.contentID)

	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	store.failBlob = true
	status, _, _ := getJSONBody(t, srv.URL+"/content/"+c.contentID+"/blob/head")
	if status < 500 {
		t.Fatalf("status = %d, want 5xx — a store fault answered as an absence", status)
	}
}

// contentChainFaultStore fails GetContentChain once armed. Arming happens inside
// the peer walk, so the route's FIRST lookup is a healthy miss and only the
// reread that follows read-through faults.
type contentChainFaultStore struct {
	*MemoryStore
	armed bool
}

func (s *contentChainFaultStore) GetContentChain(contentID string) (*StoredContentChain, error) {
	if s.armed {
		return nil, errInjectedStore
	}
	return s.MemoryStore.GetContentChain(contentID)
}

// armingPeerClient answers the read-through walk and arms the store fault, so
// the fault lands exactly on the reread the route does afterwards.
type armingPeerClient struct {
	*mockPeerClient
	store *contentChainFaultStore
}

func (c *armingPeerClient) GetContentLog(peerURL, contentID, after string, limit int) (*PeerLogPage, error) {
	page, err := c.mockPeerClient.GetContentLog(peerURL, contentID, after, limit)
	c.store.armed = true
	return page, err
}

// TestPostReadThroughStoreFaultIs5xxNotNotFound: the reread that follows a
// read-through discarded its error, so a failed read answered 404 — the same
// answer as "no peer has it", from a relay that does not know either way.
func TestPostReadThroughStoreFaultIs5xxNotNotFound(t *testing.T) {
	peerStore := NewMemoryStore()
	id := createTestIdentity(t)
	_, contentID, _ := createTestContent(t, id)
	IngestOperations([]string{id.token}, peerStore)

	store := &contentChainFaultStore{MemoryStore: NewMemoryStore()}
	IngestOperations([]string{id.token}, store.MemoryStore)
	r, err := NewRelay(RelayOptions{
		Store:      store,
		Authority:  testAuthority,
		PeerClient: &armingPeerClient{mockPeerClient: newMockPeerClient(peerStore, 0), store: store},
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	status, _, _ := getJSONBody(t, srv.URL+"/proof/v1/content/"+contentID)
	if status < 500 {
		t.Fatalf("status = %d, want 5xx — a store fault answered as a miss", status)
	}
}
