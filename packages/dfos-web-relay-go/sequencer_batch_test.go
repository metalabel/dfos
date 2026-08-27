package relay

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// ===================================================================
// store test double
// ===================================================================

// faultyBatchStore wraps a REAL SQLiteStore so its transaction semantics are
// real: a rolled-back batch actually reverts. That is the whole point here —
// these tests are about what survives a failure mid-batch, which a store with a
// simulated rollback cannot answer.
//
// The Store interface is embedded (not *SQLiteStore) for the same reason
// fail_closed_test.go's doubles do it: only Store's own methods are promoted, so
// the double cannot accidentally satisfy an optional capability interface and
// change which relay code paths run. BatchableStore is then re-exposed
// explicitly, delegating to the wrapped store.
type faultyBatchStore struct {
	Store
	batch BatchableStore
	// failAppend makes AppendToLog fail — the last of the three writes an
	// accepted op performs, and therefore the crash window under test.
	failAppend bool
	// failCommit makes the batch fail to commit, with a real rollback behind it.
	failCommit bool
}

func newFaultyBatchStore(t *testing.T, name string) *faultyBatchStore {
	t.Helper()
	// File-backed, not :memory: — NewSQLiteStore opens separate reader and
	// writer pools, and :memory: would give each its own empty database.
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return &faultyBatchStore{Store: store, batch: store}
}

func (s *faultyBatchStore) AppendToLog(entry LogEntry) error {
	if s.failAppend {
		return errInjectedStore
	}
	return s.Store.AppendToLog(entry)
}

func (s *faultyBatchStore) BeginWriteBatch() error { return s.batch.BeginWriteBatch() }

func (s *faultyBatchStore) CommitWriteBatch() error {
	if s.failCommit {
		// Roll the real transaction back so the store is left usable, then
		// report the failure the relay must react to.
		_ = s.batch.RollbackWriteBatch()
		return errInjectedStore
	}
	return s.batch.CommitWriteBatch()
}

func (s *faultyBatchStore) RollbackWriteBatch() error { return s.batch.RollbackWriteBatch() }

// logHasCID reports whether the proof log carries an entry for cid.
func logHasCID(t *testing.T, store Store, cid string) bool {
	t.Helper()
	entries, _, err := store.ReadLog("", 1000)
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	for _, entry := range entries {
		if entry.CID == cid {
			return true
		}
	}
	return false
}

// stagePendingOp stages a token as a pending raw op, exactly as Ingest and
// SyncFromPeers do, without sequencing it.
func stagePendingOp(t *testing.T, store Store, token string) string {
	t.Helper()
	cid := computeOpCID(token)
	if cid == "" {
		t.Fatal("expected a decodable storage CID")
	}
	if _, err := store.PutRawOp(cid, token, OpOriginDirect); err != nil {
		t.Fatalf("PutRawOp: %v", err)
	}
	return cid
}

func pendingCount(t *testing.T, store Store) int {
	t.Helper()
	n, err := store.CountUnsequenced()
	if err != nil {
		t.Fatalf("CountUnsequenced: %v", err)
	}
	return n
}

// ===================================================================
// 1. the crash window: an op must never land without its log entry
// ===================================================================

// TestSequencerOpNeverLandsWithoutItsLogEntry is the regression for the defect
// this file exists for.
//
// Admitting an operation writes its chain state, its operation row, and its
// /proof/v1/log append. Run unbatched, each of those commits on its own, so a
// failure after the operation row but before the log append leaves the operation
// stored — and therefore served on every per-chain route — while the proof log
// has no record of it. It stays that way forever: the idempotency check at the
// top of each ingest path finds the stored operation and returns "duplicate"
// before the append is retried, so the log entry is never written. Nothing
// reports it, because opCount is derived from the log itself.
//
// The test drives exactly that sequence: fail the log append, then heal the
// store and re-run the sequencer. The op must end up in the log. Against the
// unbatched sequencer it does not — the second pass sees a "duplicate".
func TestSequencerOpNeverLandsWithoutItsLogEntry(t *testing.T) {
	store := newFaultyBatchStore(t, "crash-window.db")
	relay, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}

	token := createTestIdentity(t).token
	cid := stagePendingOp(t, store, token)

	// Pass 1: the log append fails partway through applying the op.
	store.failAppend = true
	relay.RunSequencer()

	if logHasCID(t, store, cid) {
		t.Fatal("the failed append must not have produced a log entry")
	}
	if n := pendingCount(t, store); n != 1 {
		t.Fatalf("the op must stay pending and re-ingestable, got %d pending raw op(s)", n)
	}
	if op, _ := store.GetOperation(cid); op != nil {
		t.Fatal("the operation row must have been rolled back with the failed append — " +
			"a stored operation makes every retry a no-op 'duplicate', stranding the log entry forever")
	}

	// Pass 2: the store is healthy again. The op must now land in full.
	store.failAppend = false
	relay.RunSequencer()

	if !logHasCID(t, store, cid) {
		t.Fatal("after the store recovered, the op is still missing from the proof log — " +
			"it landed on the chain routes without its log entry and no retry can repair it")
	}
	if op, _ := store.GetOperation(cid); op == nil {
		t.Fatal("expected the operation to be stored after the healthy pass")
	}
	if n := pendingCount(t, store); n != 0 {
		t.Fatalf("expected the raw op to drain after the healthy pass, got %d pending", n)
	}
}

// ===================================================================
// 2. the sequencer's half of the fail-closed contract
// ===================================================================

// TestSequencerCommitFailureDoesNotGossipOrStrand is the sequencer analog of
// TestCommitFailureDoesNotGossipOrReportLanded, which pins the same contract for
// the ingest path's batch: a batch that could not be committed is not held, so
// it must not be advertised — and, on this path, its raw ops must remain pending
// so the next pass can ingest them.
func TestSequencerCommitFailureDoesNotGossipOrStrand(t *testing.T) {
	store := newFaultyBatchStore(t, "commit-failure.db")
	mock := newMockPeerClient(NewMemoryStore(), 0)
	relay, err := NewRelay(RelayOptions{
		Store:      store,
		PeerClient: mock,
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	token := createTestIdentity(t).token
	cid := stagePendingOp(t, store, token)

	store.failCommit = true
	result := relay.RunSequencerAndGossip()

	if calls := mock.drainSubmits(100 * time.Millisecond); len(calls) != 0 {
		t.Fatalf("a rolled-back chunk must not be gossiped, got %d gossip call(s)", len(calls))
	}
	if result.Sequenced != 0 {
		t.Fatalf("a rolled-back chunk must not be reported as sequenced, got %d", result.Sequenced)
	}
	if op, _ := store.GetOperation(cid); op != nil {
		t.Fatal("the rolled-back chunk's writes must not survive the rollback")
	}
	if n := pendingCount(t, store); n != 1 {
		t.Fatalf("the rolled-back chunk's raw ops must stay pending, got %d", n)
	}

	// The next pass, against a healthy store, ingests them cleanly.
	store.failCommit = false
	result = relay.RunSequencerAndGossip()

	if result.Sequenced != 1 {
		t.Fatalf("expected the retry to sequence the op, got %d", result.Sequenced)
	}
	if !logHasCID(t, store, cid) {
		t.Fatal("expected the retried op in the proof log")
	}
	if n := pendingCount(t, store); n != 0 {
		t.Fatalf("expected the raw op to drain on the retry, got %d pending", n)
	}
	if calls := mock.drainSubmits(time.Second); len(calls) != 1 {
		t.Fatalf("expected the committed op to gossip once, got %d gossip call(s)", len(calls))
	}
}

// ===================================================================
// 3. the unique cid index: a double append cannot duplicate a log row
// ===================================================================

// TestAppendToLogIsIdempotentPerCID pins the structural half of the fix. The
// batch closes the window that produced double appends; the unique index makes
// the duplicate row impossible regardless of how the append is reached.
func TestAppendToLogIsIdempotentPerCID(t *testing.T) {
	for _, tc := range []struct {
		name  string
		store func(t *testing.T) Store
	}{
		{
			name: "sqlite",
			store: func(t *testing.T) Store {
				s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "append.db"))
				if err != nil {
					t.Fatalf("NewSQLiteStore: %v", err)
				}
				t.Cleanup(func() { s.Close() })
				return s
			},
		},
		{
			name:  "memory",
			store: func(t *testing.T) Store { return NewMemoryStore() },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.store(t)
			token := createTestIdentity(t).token
			entry := LogEntry{CID: computeOpCID(token), JWSToken: token, Kind: "identity-op", ChainID: "did:dfos:test"}

			for i := 0; i < 2; i++ {
				if err := store.AppendToLog(entry); err != nil {
					t.Fatalf("append %d: %v", i+1, err)
				}
			}

			entries, _, err := store.ReadLog("", 100)
			if err != nil {
				t.Fatalf("ReadLog: %v", err)
			}
			count := 0
			for _, e := range entries {
				if e.CID == entry.CID {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("a repeated append must leave exactly one log row, got %d", count)
			}
		})
	}
}

// TestOperationLogCIDIndexUpgrade covers the in-place upgrade path: a database
// created before the cid index was unique carries a non-unique index and may
// carry the duplicate rows it allowed. Opening it must dedupe (keeping the
// FIRST receipt) and convert the index, since CREATE UNIQUE INDEX IF NOT EXISTS
// leaves an index that already exists under that name alone.
func TestOperationLogCIDIndexUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	if _, err := legacy.Exec(`
		CREATE TABLE operation_log (
			seq INTEGER PRIMARY KEY AUTOINCREMENT,
			cid TEXT NOT NULL,
			jws_token TEXT NOT NULL,
			kind TEXT NOT NULL,
			chain_id TEXT NOT NULL,
			created_at TEXT,
			ingested_at TEXT
		);
		CREATE INDEX idx_operation_log_cid ON operation_log(cid);
	`); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	// Two rows for one cid — the double append the non-unique index permitted —
	// plus an unrelated row that must survive untouched.
	for _, row := range []struct{ cid, token string }{
		{"bafyduplicate", "first-receipt"},
		{"bafyduplicate", "second-receipt"},
		{"bafyunique", "only-receipt"},
	} {
		if _, err := legacy.Exec(
			"INSERT INTO operation_log (cid, jws_token, kind, chain_id, created_at, ingested_at) VALUES (?, ?, 'identity-op', 'did:dfos:test', '', '')",
			row.cid, row.token,
		); err != nil {
			t.Fatalf("seed legacy row: %v", err)
		}
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore (upgrade): %v", err)
	}
	defer store.Close()

	entries, _, err := store.ReadLog("", 100)
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected the duplicate to be collapsed to 2 rows, got %d (%+v)", len(entries), entries)
	}
	for _, entry := range entries {
		if entry.CID == "bafyduplicate" && entry.JWSToken != "first-receipt" {
			t.Fatalf("the surviving row must be the lowest seq (first receipt), got %q", entry.JWSToken)
		}
	}

	// And the index is now unique, so the duplicate cannot come back.
	if err := store.AppendToLog(LogEntry{CID: "bafyduplicate", JWSToken: "third-receipt", Kind: "identity-op", ChainID: "did:dfos:test"}); err != nil {
		t.Fatalf("AppendToLog after upgrade: %v", err)
	}
	entries, _, err = store.ReadLog("", 100)
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("the upgraded index must refuse a duplicate cid, got %d rows", len(entries))
	}
}
