package relay

import (
	"errors"
	"path/filepath"
	"testing"
)

// TestReadLogCursorContract guards the shared list-envelope contract on the
// global log, for both store backends (parity-enforced twins):
//
//   - `next` only on a FULL page; a partial page means caught up and returns "".
//     The old behavior (resume cursor on any non-empty page) was an anti-entropy
//     optimization; it was retired when the envelope was unified because the
//     puller never fabricates cursors and retains its last persisted one on
//     null — re-fetching a single final partial page per cycle, deduped cheaply,
//     with the bounded reconcile scrubber as backstop. This matches how the
//     production relay has always paged (opaque cursor, null on final page).
//   - An unknown `after` returns ErrUnknownLogCursor (the route maps it to 400,
//     never a silently empty page) — log cursors are relay-local.
//   - Resuming from the last entry of a full page serves the remainder exactly
//     once; no entry is skipped or re-served.
func TestReadLogCursorContract(t *testing.T) {
	cases := []struct {
		name  string
		store func(t *testing.T) Store
	}{
		{"memory", func(t *testing.T) Store { return NewMemoryStore() }},
		{"sqlite", func(t *testing.T) Store {
			s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "readlog.db"))
			if err != nil {
				t.Fatalf("NewSQLiteStore: %v", err)
			}
			return s
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := c.store(t)
			r, err := NewRelay(RelayOptions{Store: store})
			if err != nil {
				t.Fatal(err)
			}

			const seeded = 5
			for i := 0; i < seeded; i++ {
				id := createTestIdentity(t)
				r.Ingest([]string{id.token})
			}

			// Partial (not-full) page → caught up → empty `next`.
			entries, next, err := store.ReadLog("", 1000)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) == 0 {
				t.Fatal("no entries seeded into the operation log")
			}
			if next != "" {
				t.Fatalf("partial page returned next=%q, want empty (caught up)", next)
			}

			// Full page → `next` = last entry's CID; resuming serves the remainder
			// exactly once.
			pageSize := len(entries) - 2
			firstPage, next, err := store.ReadLog("", pageSize)
			if err != nil {
				t.Fatal(err)
			}
			if len(firstPage) != pageSize {
				t.Fatalf("full page returned %d entries, want %d", len(firstPage), pageSize)
			}
			if next != firstPage[len(firstPage)-1].CID {
				t.Fatalf("full page next=%q, want last entry CID %q", next, firstPage[len(firstPage)-1].CID)
			}
			rest, restNext, err := store.ReadLog(next, 1000)
			if err != nil {
				t.Fatal(err)
			}
			if len(rest) != len(entries)-pageSize {
				t.Fatalf("resume served %d entries, want %d", len(rest), len(entries)-pageSize)
			}
			if restNext != "" {
				t.Fatalf("final partial page returned next=%q, want empty", restNext)
			}

			// Unknown cursor → ErrUnknownLogCursor, never a silently empty page.
			if _, _, err := store.ReadLog("bafynonexistentcursor", 1000); !errors.Is(err, ErrUnknownLogCursor) {
				t.Fatalf("unknown cursor returned err=%v, want ErrUnknownLogCursor", err)
			}
		})
	}
}
