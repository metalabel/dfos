package relay

import (
	"path/filepath"
	"testing"
)

// ===================================================================
// what feeds the projection, and what the capability block may claim
//
// The projection reads the operation log and is kicked by the relay. Both of
// those are load-bearing in ways that are invisible from the accepting path, and
// each one has a shape where /.well-known would advertise index: true over rows
// that can never move.
// ===================================================================

// TestProjectionAdvancesOnTheSequencerPath: an operation that arrives by PEER
// SYNC reaches the index.
//
// Peer-pulled ops are staged as raw ops and drained by the sequencer; they never
// enter Relay.Ingest. A relay that only kicked the projection from the accepting
// path would therefore serve an index frozen at boot on every pull-only node —
// including a --no-write LITE node, which has no accepting path at all and could
// never advance it.
func TestProjectionAdvancesOnTheSequencerPath(t *testing.T) {
	store := NewMemoryStore()
	r, err := NewRelay(RelayOptions{Store: store, Authority: testAuthority})
	if err != nil {
		t.Fatal(err)
	}

	id := createTestIdentity(t)
	if _, err := store.PutRawOp(computeOpCID(id.token), id.token, OpOriginPeer); err != nil {
		t.Fatal(err)
	}

	if result := r.RunSequencerAndGossip(); result.Sequenced != 1 {
		t.Fatalf("sequencer sequenced %d ops, want 1 (%+v)", result.Sequenced, result)
	}

	rows, err := store.QueryIndexIdentities(IndexIdentityQuery{DID: id.did, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("the sequencer path left the index at %d rows, want 1 — the projection is not kicked on the peer-sync path", len(rows))
	}
}

// TestIndexIsOffWhenTheLogIs: index: true beside log: false is a capability block
// that lies, because the projection has no other input than ReadLog.
//
// Defaulted, it derives off. Explicitly asked for, it is refused at construction
// — the same treatment an explicit signing ask gets on a store that cannot serve
// the mailbox.
func TestIndexIsOffWhenTheLogIs(t *testing.T) {
	off := false
	on := true

	r, err := NewRelay(RelayOptions{Store: NewMemoryStore(), Authority: testAuthority, Log: &off})
	if err != nil {
		t.Fatal(err)
	}
	if r.indexEnabled {
		t.Fatal("a relay with no operation log advertises an index the projection can never fill")
	}
	if r.projection != nil {
		t.Fatal("a disabled index must not carry a projection worker")
	}

	if _, err := NewRelay(RelayOptions{Store: NewMemoryStore(), Authority: testAuthority, Log: &off, Index: &on}); err == nil {
		t.Fatal("index: true with log: false must be refused at construction, not derived away silently")
	}
}

// storeWithoutWriterState is a store that can Commit but keeps no writer
// bookkeeping — the shape RelayWriteStore alone describes. Embedding the
// INTERFACE (not the concrete MemoryStore) is what drops the writer-state
// methods: only RelayWriteStore's own method set is promoted.
type storeWithoutWriterState struct {
	RelayWriteStore
}

// TestWriteCapabilityNeedsTheWriterState: ingestion needs raw-op and sequencer
// bookkeeping as well as Commit, so a store with only Commit must not advertise
// write: true — the endpoint it promises would reject 100% of submissions.
func TestWriteCapabilityNeedsTheWriterState(t *testing.T) {
	backing := NewMemoryStore()
	identity, err := BootstrapRelayIdentity(backing)
	if err != nil {
		t.Fatal(err)
	}

	r, err := NewRelay(RelayOptions{
		Store:     storeWithoutWriterState{RelayWriteStore: backing},
		Identity:  identity,
		Authority: testAuthority,
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.writeEnabled {
		t.Fatal("write: true on a store that cannot keep writer state promises an endpoint that rejects everything")
	}

	id := createTestIdentity(t)
	if res := r.Ingest([]string{id.token}); res[0].Status != "rejected" {
		t.Fatalf("ingest on a writer-state-less store = %q, want rejected", res[0].Status)
	}
}

// TestBuiltProjectionIsAdoptedRatherThanReplayed: a durable store stamped at the
// current projection version, with rows and no cursor, is the first boot after
// the cursor existed. Its rows were maintained by a process that did not keep
// one, so they are already correct and the log walk that would re-derive them is
// pure cost — and on a large public-read corpus every historical delete, restore,
// and chain:* grant in that replay is another full sweep.
func TestBuiltProjectionIsAdoptedRatherThanReplayed(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "adopt.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	r, err := NewRelay(RelayOptions{Store: store, Authority: testAuthority})
	if err != nil {
		t.Fatal(err)
	}
	ingestIdentity(t, r)
	ingestIdentity(t, r)

	tip, err := logTip(store)
	if err != nil {
		t.Fatal(err)
	}
	if tip == "" {
		t.Fatal("the fixture wrote no log entries")
	}

	// The pre-cursor state: rows built, version stamped, no cursor.
	if err := store.SetIndexCursor(IndexCursor{}); err != nil {
		t.Fatal(err)
	}
	if err := rebuildIndexProjection(store, r.logger); err != nil {
		t.Fatal(err)
	}
	cursor, err := store.GetIndexCursor()
	if err != nil {
		t.Fatal(err)
	}
	if cursor.LogCursor != tip {
		t.Fatalf("cursor = %q, want the log tip %q — a built projection must be adopted, not replayed", cursor.LogCursor, tip)
	}

	// The opposite case, which the populated check exists for: a rebuild clears
	// the rows and leaves the same zero cursor. Adopting there would discard the
	// rebuild permanently, so it must replay from the start.
	if err := store.ClearIndexProjection(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIndexCursor(IndexCursor{}); err != nil {
		t.Fatal(err)
	}
	if err := rebuildIndexProjection(store, r.logger); err != nil {
		t.Fatal(err)
	}
	cursor, err = store.GetIndexCursor()
	if err != nil {
		t.Fatal(err)
	}
	if cursor.LogCursor != "" {
		t.Fatalf("cursor = %q, want empty — an emptied projection has nothing to adopt", cursor.LogCursor)
	}
	if run := drainIndexProjection(store, DefaultIndexProjectionBudget, 0, r.logger); !run.CaughtUp {
		t.Fatal("the replay after a rebuild did not catch up")
	}
	rows, err := store.QueryIndexIdentities(IndexIdentityQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 {
		t.Fatalf("after the rebuild replay, identity rows = %d, want at least 2", len(rows))
	}
}
