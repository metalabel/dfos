package relay

import (
	"path/filepath"
	"testing"
)

// TestReadLogFinalPageReturnsResumeCursor is the anti-entropy-chatter regression
// guard. A caught-up puller must be able to advance PAST the final partial page;
// if ReadLog returns an empty cursor whenever the page isn't full, the puller
// resumes from the prior checkpoint and re-fetches the whole tail (up to a page)
// every sync cycle forever — re-decoding and re-hashing already-sequenced ops. The
// fix: return a resume cursor whenever the page has entries, so the next fetch from
// it (seq > last) returns an empty page and the puller stops. Verified for both
// store backends (they are parity-enforced twins).
func TestReadLogFinalPageReturnsResumeCursor(t *testing.T) {
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

			// Seed a handful of ops — fewer than the page limit, so the only page is
			// a partial final page.
			const seeded = 5
			for i := 0; i < seeded; i++ {
				id := createTestIdentity(t)
				r.Ingest([]string{id.token})
			}

			entries, cursor, err := store.ReadLog("", 1000)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) == 0 {
				t.Fatal("no entries seeded into the operation log")
			}
			if cursor == "" {
				t.Fatal("final partial page returned an empty cursor — a caught-up puller would re-fetch the tail every cycle (anti-entropy chatter)")
			}

			// Resuming from the final cursor must return an empty page (caught up) —
			// NOT re-serve the tail.
			next, _, err := store.ReadLog(cursor, 1000)
			if err != nil {
				t.Fatal(err)
			}
			if len(next) != 0 {
				t.Fatalf("resuming from the final cursor returned %d entries, want 0 — the puller would loop re-fetching them", len(next))
			}
		})
	}
}
