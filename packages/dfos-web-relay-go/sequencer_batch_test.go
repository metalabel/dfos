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

// faultyCommitStore wraps a REAL SQLiteStore so its transaction semantics are
// real: a Commit that fails actually leaves nothing behind. That is the whole
// point here — these tests are about what survives a failed write, which a store
// with a simulated rollback cannot answer.
//
// The referenceStore INTERFACE is embedded (not *SQLiteStore) for the same
// reason fail_closed_test.go's doubles do it: only that interface's methods are
// promoted, so the double cannot accidentally satisfy an optional capability
// interface and change which relay code paths run.
type faultyCommitStore struct {
	referenceStore
	// failCommit makes every operation Commit fail.
	failCommit bool
	// failLogEntryCommit fails only a commit that carries a global-log append —
	// the crash window this file exists for, since the log append is the last of
	// the three writes an accepted operation performs.
	failLogEntryCommit bool
}

func newFaultyCommitStore(t *testing.T, name string) *faultyCommitStore {
	t.Helper()
	// File-backed, not :memory: — NewSQLiteStore opens separate reader and
	// writer pools, and :memory: would give each its own empty database.
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return &faultyCommitStore{referenceStore: store}
}

func (s *faultyCommitStore) Commit(batch CommitBatch) (CommitResult, error) {
	if s.failCommit {
		return "", errInjectedStore
	}
	if s.failLogEntryCommit && batch.Operation != nil && batch.Operation.LogEntry != nil {
		return "", errInjectedStore
	}
	return s.referenceStore.Commit(batch)
}

// logHasCID reports whether the proof log carries an entry for cid.
func logHasCID(t *testing.T, store RelayReadStore, cid string) bool {
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
func stagePendingOp(t *testing.T, store RelayWriterState, token string) string {
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

func pendingCount(t *testing.T, store RelayWriterState) int {
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
// /proof/v1/log append. Written independently, each of those commits on its own,
// so a failure after the operation row but before the log append leaves the
// operation stored — and therefore served on every per-chain route — while the
// proof log has no record of it. It stays that way forever: the idempotency
// check at the top of each ingest path finds the stored operation and returns
// "duplicate" before the append is retried, so the log entry is never written.
// Nothing reports it, because opCount is derived from the log itself.
//
// The test drives exactly that sequence: fail the commit that carries the log
// append, then heal the store and re-run the sequencer. The op must end up in
// the log, whole.
func TestSequencerOpNeverLandsWithoutItsLogEntry(t *testing.T) {
	store := newFaultyCommitStore(t, "crash-window.db")
	relay, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}

	token := createTestIdentity(t).token
	cid := stagePendingOp(t, store, token)

	// Pass 1: the write that carries the log append fails.
	store.failLogEntryCommit = true
	relay.RunSequencer()

	if logHasCID(t, store, cid) {
		t.Fatal("the failed commit must not have produced a log entry")
	}
	if n := pendingCount(t, store); n != 1 {
		t.Fatalf("the op must stay pending and re-ingestable, got %d pending raw op(s)", n)
	}
	if op, _ := store.GetOperation(cid); op != nil {
		t.Fatal("the operation row must not survive the failed commit — " +
			"a stored operation makes every retry a no-op 'duplicate', stranding the log entry forever")
	}

	// Pass 2: the store is healthy again. The op must now land in full.
	store.failLogEntryCommit = false
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
// TestCommitFailureDoesNotGossipOrReportLanded: an operation the store refused
// is not held, so it must not be advertised — and its raw op must remain pending
// so the next pass can ingest it.
func TestSequencerCommitFailureDoesNotGossipOrStrand(t *testing.T) {
	store := newFaultyCommitStore(t, "commit-failure.db")
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
		t.Fatalf("a refused op must not be gossiped, got %d gossip call(s)", len(calls))
	}
	if result.Sequenced != 0 {
		t.Fatalf("a refused op must not be reported as sequenced, got %d", result.Sequenced)
	}
	if op, _ := store.GetOperation(cid); op != nil {
		t.Fatal("a refused commit must leave nothing behind")
	}
	if n := pendingCount(t, store); n != 1 {
		t.Fatalf("a refused op's raw row must stay pending, got %d", n)
	}

	// The next pass, against a healthy store, ingests it cleanly.
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
// 3. the unique cid index: a double commit cannot duplicate a log row
// ===================================================================

// TestCommitIsIdempotentPerCID pins the structural half of the fix. Commit is
// the race backstop — a second commit of a held CID answers "duplicate" and
// writes nothing — and the unique index makes a duplicate log row impossible
// regardless of how the append is reached.
func TestCommitIsIdempotentPerCID(t *testing.T) {
	for _, tc := range []struct {
		name  string
		store func(t *testing.T) referenceStore
	}{
		{
			name: "sqlite",
			store: func(t *testing.T) referenceStore {
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
			store: func(t *testing.T) referenceStore { return NewMemoryStore() },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.store(t)
			token := createTestIdentity(t).token
			cid := computeOpCID(token)
			entry := LogEntry{CID: cid, JWSToken: token, Kind: "identity-op", ChainID: "did:dfos:test"}
			commit := CommitBatch{Operation: &OperationCommit{
				Operation: StoredOperation{CID: cid, JWSToken: token, ChainType: "identity", ChainID: "did:dfos:test"},
				LogEntry:  &entry,
			}}

			first, err := store.Commit(commit)
			if err != nil {
				t.Fatalf("first commit: %v", err)
			}
			if first != CommitNew {
				t.Fatalf("first commit: got %q, want %q", first, CommitNew)
			}
			second, err := store.Commit(commit)
			if err != nil {
				t.Fatalf("second commit: %v", err)
			}
			if second != CommitDuplicate {
				t.Fatalf("second commit of a held CID: got %q, want %q", second, CommitDuplicate)
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
				t.Fatalf("a repeated commit must leave exactly one log row, got %d", count)
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

	// And the index is now unique, so a second append for the same cid cannot
	// come back — reached here through a commit for a CID the operations table
	// does not hold, which is exactly the legacy shape.
	entry := LogEntry{CID: "bafyduplicate", JWSToken: "third-receipt", Kind: "identity-op", ChainID: "did:dfos:test"}
	if _, err := store.Commit(CommitBatch{Operation: &OperationCommit{
		Operation: StoredOperation{CID: "bafyduplicate", JWSToken: "third-receipt", ChainType: "identity", ChainID: "did:dfos:test"},
		LogEntry:  &entry,
	}}); err != nil {
		t.Fatalf("commit after upgrade: %v", err)
	}
	entries, _, err = store.ReadLog("", 100)
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("the upgraded index must refuse a duplicate cid, got %d rows", len(entries))
	}
}
