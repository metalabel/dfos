package relay

import (
	"path/filepath"
	"testing"
)

// rawOpPruneStore is the slice of the store surface the R4 prune test exercises.
type rawOpPruneStore interface {
	PutRawOp(cid, jwsToken string) error
	MarkOpRejected(cid, reason string) error
	CountUnsequenced() (int, error)
}

// TestMarkOpRejectedDeletesRawOpMemory and ...SQLite lock the R4 hardening: a
// permanent rejection must DELETE the raw op row, not flip its status. Keeping
// rejected rows let an unauthenticated submitter grow the content-addressed raw
// store without bound by mutating one byte per op to mint a fresh CID. The
// deletion is proven by re-putting the same CID afterward — PutRawOp is
// put-if-absent (INSERT OR IGNORE), so a pending row reappears only if the
// original was actually gone; a status flip would leave the row present and the
// re-put would be a no-op, keeping the count at 0.
func TestMarkOpRejectedDeletesRawOpMemory(t *testing.T) {
	assertPruneDeletes(t, NewMemoryStore())
}

func TestMarkOpRejectedDeletesRawOpSQLite(t *testing.T) {
	// File-backed (not :memory:) — NewSQLiteStore opens separate reader/writer
	// pools, and :memory: would give each its own database.
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "prune.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	assertPruneDeletes(t, store)
}

func assertPruneDeletes(t *testing.T, s rawOpPruneStore) {
	t.Helper()
	const cid = "bafyExampleRawOpPruneCID"

	if err := s.PutRawOp(cid, "jws-token-1"); err != nil {
		t.Fatalf("PutRawOp: %v", err)
	}
	if n, _ := s.CountUnsequenced(); n != 1 {
		t.Fatalf("after put: want 1 unsequenced, got %d", n)
	}

	if err := s.MarkOpRejected(cid, "permanent: bad signature"); err != nil {
		t.Fatalf("MarkOpRejected: %v", err)
	}
	if n, _ := s.CountUnsequenced(); n != 0 {
		t.Fatalf("after reject: want 0 unsequenced, got %d", n)
	}

	// Re-put the SAME CID — only re-creates a pending row if the reject deleted it.
	if err := s.PutRawOp(cid, "jws-token-2"); err != nil {
		t.Fatalf("re-PutRawOp: %v", err)
	}
	if n, _ := s.CountUnsequenced(); n != 1 {
		t.Fatalf("re-put after reject: want 1 unsequenced (row was deleted), got %d", n)
	}
}
