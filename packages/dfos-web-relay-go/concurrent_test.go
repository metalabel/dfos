package relay

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ===================================================================
// SQLiteStore-backed concurrency (gives the -race CI job a real path)
//
// Every other Go relay test uses NewMemoryStore, which is RWMutex-guarded with
// no s.tx — it reproduces nothing under `go test -race`. This test drives
// concurrent Ingest + SyncFromPeers + RunSequencerAndGossip against a real
// FILE-backed SQLiteStore (NewRelay auto-derives the WAL readStore for it), so
// the shared two-pool writeDB(MaxOpenConns=1)/readDB(MaxOpenConns=4) and the
// ingestMu/s.tx aliasing have an actual concurrency surface for the race
// detector to inspect.
//
// :memory: is a TRAP here — NewSQLiteStore opens TWO connection pools, and an
// in-memory DB gives each pool a SEPARATE database, so the readDB never sees
// writeDB's writes. The test MUST use a mktemp FILE path.
// ===================================================================

func TestSQLiteConcurrentIngestSyncSequencer(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "concurrent.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// a peer backed by a MemoryStore seeded with a batch of identities — the
	// sync goroutine pulls these into the SQLite relay concurrently with ingest.
	peerStore := NewMemoryStore()
	peerIDs := make([]testIdentity, 20)
	for i := range peerIDs {
		peerIDs[i] = createTestIdentity(t)
		IngestOperations([]string{peerIDs[i].token}, peerStore)
	}
	mock := newMockPeerClient(peerStore, 0)

	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatalf("NewRelay: %v", err)
	}

	// independent identities to ingest concurrently on the local path
	localIDs := make([]testIdentity, 40)
	for i := range localIDs {
		localIDs[i] = createTestIdentity(t)
	}

	var wg sync.WaitGroup

	// N ingest goroutines, each ingesting a disjoint slice
	const ingestWorkers = 4
	per := len(localIDs) / ingestWorkers
	for w := 0; w < ingestWorkers; w++ {
		start := w * per
		end := start + per
		if w == ingestWorkers-1 {
			end = len(localIDs)
		}
		wg.Add(1)
		go func(ids []testIdentity) {
			defer wg.Done()
			for _, id := range ids {
				relay.Ingest([]string{id.token})
			}
		}(localIDs[start:end])
	}

	// concurrent sync from the peer
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			_ = relay.SyncFromPeers()
		}
	}()

	// concurrent sequencer ticks
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			relay.RunSequencerAndGossip()
			time.Sleep(time.Millisecond)
		}
	}()

	wg.Wait()

	// drain to a fixed point so every accepted op is materialized
	for i := 0; i < 5; i++ {
		relay.RunSequencerAndGossip()
	}

	// all local identities must have ingested
	for _, id := range localIDs {
		chain, err := store.GetIdentityChain(id.did)
		if err != nil {
			t.Fatalf("GetIdentityChain(%s): %v", id.did, err)
		}
		if chain == nil {
			t.Fatalf("expected local identity %s ingested after concurrent run", id.did)
		}
	}

	// all peer identities must have synced
	for _, id := range peerIDs {
		chain, _ := store.GetIdentityChain(id.did)
		if chain == nil {
			t.Fatalf("expected peer identity %s synced after concurrent run", id.did)
		}
	}

	// nothing left stuck pending
	pending, _ := store.CountUnsequenced()
	if pending != 0 {
		t.Fatalf("expected 0 pending ops after drain, got %d", pending)
	}
}
