package relay

import (
	"path/filepath"
	"testing"
)

// TestInterruptedRebuildResumesRatherThanAdoptingItsPartialRows: rows and the
// cursor are two separate writes, so a rebuild that commits one batch of rows and
// stops before SetIndexCursor leaves populated rows beside a zero cursor — the
// same shape as a projection built without a cursor. Adopting there stamps the
// tip and skips every row the rebuild had not reached, permanently. The rebuild
// marker is what tells the two apart.
func TestInterruptedRebuildResumesRatherThanAdoptingItsPartialRows(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "rebuild.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	r, err := NewRelay(RelayOptions{Store: store, Authority: testAuthority})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		ingestIdentity(t, r)
	}

	// What a complete projection of this corpus says, before anything is cleared.
	before, err := store.QueryIndexIdentities(IndexIdentityQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(before) < 4 {
		t.Fatalf("the fixture projected %d identity rows, want at least 4", len(before))
	}

	// A rebuild starts: rows cleared, version stamped, backlog undrained.
	if err := store.SetIndexProjectionVersion(0); err != nil {
		t.Fatal(err)
	}
	if err := rebuildIndexProjection(store, r.logger); err != nil {
		t.Fatal(err)
	}
	started, err := store.GetIndexCursor()
	if err != nil {
		t.Fatal(err)
	}

	// One budgeted run commits its rows, then the process dies before the cursor
	// write lands — so the cursor is still exactly what the rebuild wrote.
	if run := projectIndex(store, 1, r.logger); run.Projected == 0 {
		t.Fatal("the fixture run projected nothing")
	}
	if err := store.SetIndexCursor(started); err != nil {
		t.Fatal(err)
	}
	populated, err := indexProjectionPopulated(store)
	if err != nil {
		t.Fatal(err)
	}
	if !populated {
		t.Fatal("the fixture left no rows — there is nothing to mistake for a built projection")
	}

	// Restart. The rebuild is resumed, not adopted.
	if err := rebuildIndexProjection(store, r.logger); err != nil {
		t.Fatal(err)
	}
	cursor, err := store.GetIndexCursor()
	if err != nil {
		t.Fatal(err)
	}
	if cursor.LogCursor != "" {
		t.Fatalf("cursor = %q, want empty — an unfinished rebuild must resume, not adopt the tip", cursor.LogCursor)
	}

	if run := drainIndexProjection(store, DefaultIndexProjectionBudget, 0, r.logger); !run.CaughtUp {
		t.Fatal("the resumed rebuild did not catch up")
	}
	rows, err := store.QueryIndexIdentities(IndexIdentityQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(before) {
		t.Fatalf("identity rows = %d, want %d — the rebuild skipped what it had not reached", len(rows), len(before))
	}

	// The marker is cleared by the run that finishes, so the next boot adopts
	// normally instead of replaying forever.
	cursor, err = store.GetIndexCursor()
	if err != nil {
		t.Fatal(err)
	}
	if cursor.Rebuilding {
		t.Fatal("a caught-up projection still reports a rebuild in progress")
	}
}
