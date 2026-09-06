package relay

import "testing"

// ===================================================================
// the projection is bounded, resumable, and off the accepting path
//
// This is the structural answer to issue #266. Two triggers fanned out over the
// corpus from inside the ingest mutex, and one of them — a revocation the relay
// could not resolve — was free to mint and reachable by an anonymous POST. What
// replaces it: a worker on a persisted log cursor with a per-run budget, where a
// fan-out becomes a sweep that drains across runs.
// ===================================================================

// externalProjectionRelay builds a relay whose projection the TEST drives, with a
// budget small enough that one run cannot finish the work.
func externalProjectionRelay(t *testing.T, budget int) (*Relay, *MemoryStore) {
	t.Helper()
	store := NewMemoryStore()
	r, err := NewRelay(RelayOptions{
		Store:                 store,
		Authority:             testAuthority,
		IndexProjection:       IndexProjectionExternal,
		IndexProjectionBudget: budget,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r, store
}

// TestProjectionDrainsALogBacklogAcrossBudgetedRuns: with the operator driving
// the worker, nothing is projected until they run it, and each run does at most a
// budget's worth of work. The cursor is what makes the next run resume rather
// than restart.
func TestProjectionDrainsALogBacklogAcrossBudgetedRuns(t *testing.T) {
	r, store := externalProjectionRelay(t, 2)
	creator := ingestIdentity(t, r)
	for i := 0; i < 4; i++ {
		createIndexedContent(t, r, store, creator, map[string]any{"$schema": testPostSchema, "title": "c"}, false)
	}

	// Nothing ran, so nothing is projected — the honest state of an index whose
	// worker has not been called.
	rows, err := store.QueryIndexContent(IndexContentQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("external projection must not run itself, got %d rows", len(rows))
	}

	runs := 0
	for {
		runs++
		if runs > 20 {
			t.Fatal("the projection never caught up")
		}
		result := projectIndex(store, 2, r.logger)
		if result.Projected > 2 {
			t.Fatalf("a run exceeded its budget: projected %d, budget 2", result.Projected)
		}
		if result.CaughtUp {
			break
		}
		if result.Projected == 0 && result.Swept == 0 {
			t.Fatal("the projection stalled without catching up")
		}
	}
	if runs < 2 {
		t.Fatalf("a backlog larger than the budget must take more than one run, took %d", runs)
	}

	rows, err = store.QueryIndexContent(IndexContentQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("after draining, content rows = %d, want 4", len(rows))
	}
}

// TestProjectionSweepResumesAcrossRuns: a chain:* grant reaches every content row
// without naming one, which is the fan-out that used to be an unbounded stall
// inside the ingest mutex. It is now a sweep carried on the cursor, capped per
// run, and it converges.
func TestProjectionSweepResumesAcrossRuns(t *testing.T) {
	r, store := externalProjectionRelay(t, 2)
	creator := ingestIdentity(t, r)
	contents := make([]testContent, 0, 4)
	for i := 0; i < 4; i++ {
		contents = append(contents, createIndexedContent(t, r, store, creator, map[string]any{"$schema": testPostSchema, "title": "c"}, false))
	}
	// Drain the content ops first, so the sweep below is the only outstanding work.
	drainIndexProjection(store, 2, 0, r.logger)

	addPublicReadResource(t, r, creator, "chain:*")

	// The grant is one log entry, and it triggers a sweep of every content row.
	// With a budget of 2 that cannot finish in one run.
	sawOutstandingSweep := false
	runs := 0
	for {
		runs++
		if runs > 20 {
			t.Fatal("the sweep never drained")
		}
		result := projectIndex(store, 2, r.logger)
		if result.Swept > 2 {
			t.Fatalf("a sweep run exceeded its budget: swept %d, budget 2", result.Swept)
		}
		cursor, err := store.GetIndexCursor()
		if err != nil {
			t.Fatal(err)
		}
		if cursor.Sweep != nil {
			sawOutstandingSweep = true
			if cursor.Sweep.Scope != IndexSweepAll {
				t.Fatalf("a chain:* grant must sweep every content row, got scope %q", cursor.Sweep.Scope)
			}
		}
		if result.CaughtUp {
			break
		}
		if result.Projected == 0 && result.Swept == 0 {
			t.Fatal("the sweep stalled without catching up")
		}
	}
	if !sawOutstandingSweep {
		t.Fatal("the sweep finished inside one run — the fixture no longer exercises resumption")
	}

	// Converged: every row is public, exactly as an unbounded single pass would
	// have left them.
	handler := r.Handler()
	for _, content := range contents {
		if indexContentRowByID(t, handler, content.contentID)["publicRead"] != true {
			t.Fatalf("content %s did not converge to public after the sweep drained", content.contentID)
		}
	}
	cursor, _ := store.GetIndexCursor()
	if cursor.Sweep != nil {
		t.Fatalf("a drained sweep must clear itself, got %+v", cursor.Sweep)
	}
}

// TestProjectionRestartsOnAnUnknownLogCursor: a wiped or rebuilt log leaves the
// persisted cursor naming an entry that no longer exists. The worker restarts
// from the beginning rather than stalling on it forever — safe because every
// recompute is convergent, so a replay costs work and changes nothing.
func TestProjectionRestartsOnAnUnknownLogCursor(t *testing.T) {
	r, store := externalProjectionRelay(t, 100)
	creator := ingestIdentity(t, r)
	content := createIndexedContent(t, r, store, creator, map[string]any{"$schema": testPostSchema, "title": "c"}, false)
	drainIndexProjection(store, 100, 0, r.logger)

	if err := store.SetIndexCursor(IndexCursor{LogCursor: "bafy-a-cursor-this-log-never-issued"}); err != nil {
		t.Fatal(err)
	}
	result := projectIndex(store, 100, r.logger)
	if result.Projected == 0 {
		t.Fatal("an unknown cursor must restart the walk, not stall it")
	}
	if !result.CaughtUp {
		t.Fatalf("the restarted walk did not catch up: %+v", result)
	}
	if indexContentRowByID(t, r.Handler(), content.contentID) == nil {
		t.Fatal("the replayed walk did not reproduce the content row")
	}
}
