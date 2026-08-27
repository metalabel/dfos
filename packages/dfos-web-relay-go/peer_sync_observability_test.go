package relay

import (
	"bytes"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// PutRawOp: inserted vs ignored
// ---------------------------------------------------------------------------

// rawOpInsertStore is the slice of the store surface the inserted-vs-ignored
// tests exercise.
type rawOpInsertStore interface {
	PutRawOp(cid, jwsToken string, origin ...OpOrigin) (bool, error)
	CountUnsequenced() (int, error)
}

// TestPutRawOpReportsInserted{Memory,SQLite} — put-if-absent has to say WHICH it
// did. Peer sync re-reads the same ops constantly (the final partial page comes
// back every cycle; the anti-entropy scrub re-walks the log on purpose), so a
// caller with only an error return cannot tell a corpus that is growing from one
// that is merely being re-served. A duplicate is not an error either way.
func TestPutRawOpReportsInsertedMemory(t *testing.T) {
	assertReportsInserted(t, NewMemoryStore())
}

func TestPutRawOpReportsInsertedSQLite(t *testing.T) {
	// File-backed (not :memory:) — NewSQLiteStore opens separate reader/writer
	// pools, and :memory: would give each its own database.
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "insert.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	assertReportsInserted(t, store)
}

func assertReportsInserted(t *testing.T, s rawOpInsertStore) {
	t.Helper()
	const cid = "bafyExampleRawOpInsertedCID"

	inserted, err := s.PutRawOp(cid, "jws-token-1")
	if err != nil {
		t.Fatalf("PutRawOp: %v", err)
	}
	if !inserted {
		t.Fatal("first put of a fresh CID reported inserted=false")
	}

	// Same CID again — the duplicate the dedup exists for.
	inserted, err = s.PutRawOp(cid, "jws-token-1")
	if err != nil {
		t.Fatalf("duplicate PutRawOp errored: %v", err)
	}
	if inserted {
		t.Fatal("duplicate put reported inserted=true")
	}

	// A different token under the same CID cannot happen in practice (the CID is
	// computed from the token) but must still read as a duplicate, never as an
	// overwrite that claims new work.
	inserted, err = s.PutRawOp(cid, "jws-token-2")
	if err != nil {
		t.Fatalf("duplicate PutRawOp with a different token errored: %v", err)
	}
	if inserted {
		t.Fatal("duplicate put with a different token reported inserted=true")
	}

	if n, _ := s.CountUnsequenced(); n != 1 {
		t.Fatalf("want 1 unsequenced row after three puts of one CID, got %d", n)
	}
}

// ---------------------------------------------------------------------------
// caught-up transition logging
// ---------------------------------------------------------------------------

// seqCursorPeerClient pages a monotonic sequence cursor and ALWAYS issues one,
// including on the page that empties the log — so a client that has consumed the
// whole log resumes at the tail and receives a genuinely empty page next cycle.
// (relay.dfos.com's log cursor is likewise a sequence integer, base64-encoded.)
// This is what makes the exact-multiple-of-the-cap tail reachable in a test: a
// peer that instead returns a null cursor on its final page hands back that same
// final page forever, so a cycle never receives zero.
type seqCursorPeerClient struct {
	entries  []PeerLogEntry
	pageSize int
}

func (c *seqCursorPeerClient) GetOperationLog(_ string, after string, limit int) (*PeerLogPage, error) {
	start := 0
	if after != "" {
		if _, err := fmt.Sscanf(after, "seq:%d", &start); err != nil {
			return nil, ErrPeerInvalidCursor
		}
	}
	if start > len(c.entries) {
		start = len(c.entries)
	}
	end := start + c.pageSize
	if end > len(c.entries) {
		end = len(c.entries)
	}
	tok := fmt.Sprintf("seq:%d", end)
	return &PeerLogPage{
		Entries: append([]PeerLogEntry{}, c.entries[start:end]...),
		Cursor:  &tok,
	}, nil
}

func (c *seqCursorPeerClient) GetIdentityLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (c *seqCursorPeerClient) GetContentLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (c *seqCursorPeerClient) SubmitOperations(string, []string) error { return nil }
func (c *seqCursorPeerClient) GetBlob(string, string, string) ([]byte, error) {
	return nil, nil
}

// TestCaughtUpIsLoggedOnExactMultipleTail pins the case the old fetched>0 guard
// could never reach: a backlog whose size is an exact multiple of the per-cycle
// op cap. The last cycle carrying ops receives a full cap's worth and therefore
// reports caughtUp:false; the next cycle receives nothing at all. Guarding the
// line on "received something" means such a relay NEVER says it caught up, and
// logging every quiet cycle instead would bury the mesh in noise — so the line
// is edge-triggered, and this test holds that edge.
func TestCaughtUpIsLoggedOnExactMultipleTail(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	a := createTestIdentity(t)
	b := createTestIdentity(t)
	peer := &seqCursorPeerClient{
		entries:  []PeerLogEntry{entryFor(a.token), entryFor(b.token)},
		pageSize: 1,
	}
	r, err := NewRelay(RelayOptions{
		Store:      NewMemoryStore(),
		Logger:     logger,
		Peers:      []PeerConfig{{URL: "http://peer"}},
		PeerClient: peer,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Cap == corpus size: the backlog ends exactly on a cycle boundary.
	r.maxOpsPerSyncCycle = len(peer.entries)

	// Cycle 1 — receives a full cap's worth, so it cannot know it is done.
	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	if st := r.PeerSyncStatuses()["http://peer"]; st.CaughtUp {
		t.Fatalf("caughtUp = true on a cycle that hit the op cap: %+v", st)
	}
	if n := strings.Count(logs.String(), "caughtUp=true"); n != 0 {
		t.Fatalf("caughtUp=true logged %d times on the capped cycle, want 0", n)
	}

	// Cycle 2 — receives nothing. This is the only cycle that can announce it.
	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	st := r.PeerSyncStatuses()["http://peer"]
	if !st.CaughtUp {
		t.Fatalf("caughtUp = false after draining the peer's log: %+v", st)
	}
	if st.LastReceived != 0 {
		t.Fatalf("lastReceived = %d on the tail cycle, want 0", st.LastReceived)
	}
	if n := strings.Count(logs.String(), "caughtUp=true"); n != 1 {
		t.Fatalf("caughtUp=true logged %d times after catching up, want exactly 1", n)
	}

	// Cycles 3 and 4 — steady state. The edge already fired; a caught-up relay
	// stays silent rather than emitting a line per tick forever.
	before := logs.Len()
	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(logs.String(), "caughtUp=true"); n != 1 {
		t.Fatalf("caughtUp=true logged %d times across quiet cycles, want exactly 1", n)
	}
	if strings.Contains(logs.String()[before:], "peer sync cycle") {
		t.Fatalf("quiet cycles logged a sync line:\n%s", logs.String()[before:])
	}
}

// TestSyncReportsInsertedSeparatelyFromReceived — the pre-fix counter added
// len(page.Entries), so a re-walk of an already-held corpus reported the full
// corpus as work done. received and inserted must diverge on a re-read.
func TestSyncReportsInsertedSeparatelyFromReceived(t *testing.T) {
	a := createTestIdentity(t)
	b := createTestIdentity(t)
	peer := &seqCursorPeerClient{
		entries:  []PeerLogEntry{entryFor(a.token), entryFor(b.token)},
		pageSize: 2,
	}
	r, err := NewRelay(RelayOptions{
		Store:      NewMemoryStore(),
		Peers:      []PeerConfig{{URL: "http://peer"}},
		PeerClient: peer,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	if st := r.PeerSyncStatuses()["http://peer"]; st.LastReceived != 2 || st.LastInserted != 2 {
		t.Fatalf("first sync received/inserted = %d/%d, want 2/2", st.LastReceived, st.LastInserted)
	}

	// Rewind the cursor and re-walk the same corpus — exactly what the scrub
	// sweep does on purpose, and what a peer that restarts our walk does by
	// accident. Every entry comes back; none of them is new.
	if err := r.ResetPeerCursors(); err != nil {
		t.Fatal(err)
	}
	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	st := r.PeerSyncStatuses()["http://peer"]
	if st.LastReceived != 2 {
		t.Fatalf("re-walk received = %d, want 2", st.LastReceived)
	}
	if st.LastInserted != 0 {
		t.Fatalf("re-walk inserted = %d, want 0 — duplicates counted as new work", st.LastInserted)
	}
}

// TestFailedCycleIsNotCaughtUp — a failing peer receives nothing, and so does a
// drained one. Reading a bare zero as "caught up" would paint a wedged peer
// green on the very endpoint an operator checks to find it.
func TestFailedCycleIsNotCaughtUp(t *testing.T) {
	r, err := NewRelay(RelayOptions{
		Store:      NewMemoryStore(),
		Peers:      []PeerConfig{{URL: "http://peer"}},
		PeerClient: &erroringPeerClient{},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		if err := r.SyncFromPeers(); err != nil {
			t.Fatal(err)
		}
		st := r.PeerSyncStatuses()["http://peer"]
		if st.CaughtUp {
			t.Fatalf("cycle %d: caughtUp = true on a failing peer: %+v", i, st)
		}
		if st.ConsecutiveFailures != i {
			t.Fatalf("cycle %d: consecutiveFailures = %d, want %d", i, st.ConsecutiveFailures, i)
		}
		if st.LastSuccessAt != nil {
			t.Fatalf("cycle %d: lastSuccessAt set for a peer that never answered", i)
		}
		if st.LastAttemptAt == nil {
			t.Fatalf("cycle %d: lastAttemptAt null despite an attempt", i)
		}
	}
}

// erroringPeerClient fails every log fetch — a peer that is down, unreachable,
// or serving errors.
type erroringPeerClient struct{}

func (c *erroringPeerClient) GetOperationLog(string, string, int) (*PeerLogPage, error) {
	return nil, fmt.Errorf("peer unreachable")
}
func (c *erroringPeerClient) GetIdentityLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (c *erroringPeerClient) GetContentLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (c *erroringPeerClient) SubmitOperations(string, []string) error { return nil }
func (c *erroringPeerClient) GetBlob(string, string, string) ([]byte, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// reconcile heartbeat
// ---------------------------------------------------------------------------

// TestReconcileSweepLogsEvenWhenItSweepsNothing — the scrubber is the mechanism
// that unwedges a stale forward cursor, and it ran silently unless it found
// something. A scrubber that has stopped and a scrubber walking a corpus with
// nothing new looked identical. It paces itself at one run per
// reconcileEveryCycles, so a line per sweep is a heartbeat, not spam.
func TestReconcileSweepLogsEvenWhenItSweepsNothing(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	r, err := NewRelay(RelayOptions{
		Store:      NewMemoryStore(),
		Logger:     logger,
		Peers:      []PeerConfig{{URL: "http://peer"}},
		PeerClient: &seqCursorPeerClient{entries: nil, pageSize: 10},
	})
	if err != nil {
		t.Fatal(err)
	}

	// The scrub fires on the reconcileEveryCycles-th cycle and not before.
	for i := 0; i < reconcileEveryCycles-1; i++ {
		if err := r.SyncFromPeers(); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(logs.String(), "peer reconcile sweep") {
		t.Fatal("scrub logged before its cadence was due")
	}
	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	if !strings.Contains(out, "peer reconcile sweep") {
		t.Fatalf("scrub swept nothing and said nothing — a wedged scrubber is indistinguishable:\n%s", out)
	}
	if !strings.Contains(out, "received=0") {
		t.Fatalf("scrub heartbeat omits its received count:\n%s", out)
	}
	if st := r.PeerSyncStatuses()["http://peer"]; st.LastReconcileAt == nil {
		t.Fatalf("stats.peerSync lastReconcileAt null after a sweep: %+v", st)
	}
}
