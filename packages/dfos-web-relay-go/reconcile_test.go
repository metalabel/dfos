package relay

import (
	"fmt"
	"testing"
)

// entryFor builds a peer log entry from a valid identity-create token, keyed by
// the locally-recomputed storage CID (what the relay stores under).
func entryFor(token string) PeerLogEntry {
	return PeerLogEntry{CID: computeOpCID(token), JWSToken: token}
}

// ---------------------------------------------------------------------------
// Cure: the forward pull must not fabricate a bare-CID cursor a peer can't
// resume from, and must keep converging against a peer that returns a null
// cursor on its final page (notably the production relay).
// ---------------------------------------------------------------------------

// nullFinalCursorPeerClient mimics the production relay's proof-log pagination:
// it issues its OWN opaque cursor tokens ("off:N") for full pages, returns a
// NULL cursor on the final page, and serves an EMPTY page for any `after` it did
// not issue (e.g. a bare CID). A client that fabricates a bare-CID resume cursor
// when the peer returns null therefore stalls forever; a client that retains the
// last peer-supplied token keeps converging.
type nullFinalCursorPeerClient struct {
	entries  []PeerLogEntry
	pageSize int
}

func (c *nullFinalCursorPeerClient) GetOperationLog(_ string, after string, limit int) (*PeerLogPage, error) {
	start := 0
	if after != "" {
		// Only our own "off:N" tokens are recognized. A bare CID (or any other
		// unrecognized cursor) returns empty — exactly how prod treats a cursor
		// format it didn't mint.
		if _, err := fmt.Sscanf(after, "off:%d", &start); err != nil {
			return &PeerLogPage{Entries: []PeerLogEntry{}}, nil
		}
	}
	if start > len(c.entries) {
		start = len(c.entries)
	}
	end := start + c.pageSize
	if end >= len(c.entries) {
		end = len(c.entries)
	}
	page := append([]PeerLogEntry{}, c.entries[start:end]...)
	var cursor *string
	if end < len(c.entries) { // more remain → issue an opaque resume token
		tok := fmt.Sprintf("off:%d", end)
		cursor = &tok
	}
	return &PeerLogPage{Entries: page, Cursor: cursor}, nil
}

func (c *nullFinalCursorPeerClient) GetIdentityLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (c *nullFinalCursorPeerClient) GetContentLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (c *nullFinalCursorPeerClient) SubmitOperations(string, []string) error { return nil }
func (c *nullFinalCursorPeerClient) GetBlob(string, string, string) ([]byte, error) {
	return nil, nil
}

// TestForwardPullSurvivesNullFinalCursor is the regression for the lark-vs-prod
// stall: against a peer that returns a null cursor on its final page and rejects
// unrecognized (bare-CID) cursors, the forward pull must NOT fabricate a
// bare-CID cursor and wedge. After catching up, a newly appended op must still
// be recovered by the ordinary forward pull alone (no scrubber, no reset).
func TestForwardPullSurvivesNullFinalCursor(t *testing.T) {
	store := NewMemoryStore()

	a := createTestIdentity(t)
	b := createTestIdentity(t)
	c := createTestIdentity(t)
	d := createTestIdentity(t) // appended AFTER catch-up

	// pageSize 2 forces multi-page catch-up so a real "off:N" token is retained
	// (the single-page corpus path is exercised implicitly: the final page is null).
	peer := &nullFinalCursorPeerClient{
		entries:  []PeerLogEntry{entryFor(a.token), entryFor(b.token), entryFor(c.token)},
		pageSize: 2,
	}

	r, err := NewRelay(RelayOptions{
		Store:      store,
		Peers:      []PeerConfig{{URL: "http://peer"}},
		PeerClient: peer,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	if op, _ := store.GetOperation(computeOpCID(c.token)); op == nil {
		t.Fatal("expected the relay to catch up to op c")
	}

	// Append a new op at the head. With the bare-CID-fabrication bug the relay
	// would have stored c's CID as its cursor; the peer rejects it → empty →
	// d is never pulled. With the cure the relay retains the last "off:N" token
	// (or re-scans), so a plain forward sync recovers d — well before the
	// reconcile scrubber is due.
	peer.entries = append(peer.entries, entryFor(d.token))
	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	if op, _ := store.GetOperation(computeOpCID(d.token)); op == nil {
		t.Fatal("forward pull stalled — newly appended op not recovered (cursor-fabrication regression)")
	}
}

// ---------------------------------------------------------------------------
// Defense-in-depth: the bounded scrubber recovers an op the forward pull's
// high-water cursor cannot reach (a wedged/stale cursor, or an op a peer places
// behind the high-water mark).
// ---------------------------------------------------------------------------

// cidCursorPeerClient pages by a bare-CID forward cursor and returns entries
// strictly AFTER it. An op placed behind an already-advanced cursor is invisible
// to forward pagination but is surfaced by a re-scan from the start (the
// reconcile scrubber lapping). pageSize forces multi-page catch-up so the relay
// advances its high-water cursor to a real op CID rather than holding "".
type cidCursorPeerClient struct {
	entries  []PeerLogEntry
	pageSize int
}

func (c *cidCursorPeerClient) indexOf(cid string) int {
	for i, e := range c.entries {
		if e.CID == cid {
			return i
		}
	}
	return -1
}

func (c *cidCursorPeerClient) GetOperationLog(_ string, after string, limit int) (*PeerLogPage, error) {
	start := 0
	if after != "" {
		idx := c.indexOf(after)
		if idx < 0 {
			return &PeerLogPage{Entries: []PeerLogEntry{}}, nil
		}
		start = idx + 1
	}
	end := start + c.pageSize
	if end > len(c.entries) {
		end = len(c.entries)
	}
	page := append([]PeerLogEntry{}, c.entries[start:end]...)
	var cursor *string
	if len(page) == c.pageSize { // full page → more may follow (bare-CID cursor)
		cid := page[len(page)-1].CID
		cursor = &cid
	}
	return &PeerLogPage{Entries: page, Cursor: cursor}, nil
}

func (c *cidCursorPeerClient) GetIdentityLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (c *cidCursorPeerClient) GetContentLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (c *cidCursorPeerClient) SubmitOperations(string, []string) error        { return nil }
func (c *cidCursorPeerClient) GetBlob(string, string, string) ([]byte, error) { return nil, nil }

// TestReconcileRecoversCursorInvisibleOp verifies the bounded anti-entropy
// scrubber recovers an op the forward pull can never reach: once the relay's
// high-water cursor has advanced past a position, an op the peer later serves
// behind that cursor is invisible to forward pagination. The scrubber, lapping a
// re-scan from the start, must surface it.
func TestReconcileRecoversCursorInvisibleOp(t *testing.T) {
	store := NewMemoryStore()

	a := createTestIdentity(t)
	b := createTestIdentity(t)
	c := createTestIdentity(t)
	d := createTestIdentity(t)
	hidden := createTestIdentity(t)

	// pageSize 2 → catch-up advances the high-water cursor to d's CID via full
	// pages (not the "" single-page path), so an op inserted behind it is truly
	// forward-invisible.
	peer := &cidCursorPeerClient{
		entries: []PeerLogEntry{
			entryFor(a.token), entryFor(b.token), entryFor(c.token), entryFor(d.token),
		},
		pageSize: 2,
	}

	r, err := NewRelay(RelayOptions{
		Store:      store,
		Peers:      []PeerConfig{{URL: "http://peer"}},
		PeerClient: peer,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Catch up: high-water cursor advances to d.
	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	if op, _ := store.GetOperation(computeOpCID(d.token)); op == nil {
		t.Fatal("expected the relay to be caught up to op d")
	}

	// The peer serves an op BEHIND the high-water cursor (between b and c).
	peer.entries = []PeerLogEntry{
		entryFor(a.token), entryFor(b.token),
		entryFor(hidden.token),
		entryFor(c.token), entryFor(d.token),
	}

	// Forward pull from the high-water cursor (at d) can never see it. Run up to
	// just under the scrub cadence (the catch-up sync counted as cycle 1) and
	// confirm the gap persists — and that we don't trip the scrubber early.
	for i := 0; i < reconcileEveryCycles-2; i++ {
		if err := r.SyncFromPeers(); err != nil {
			t.Fatal(err)
		}
	}
	if op, _ := store.GetOperation(computeOpCID(hidden.token)); op != nil {
		t.Fatal("forward pull should NOT have recovered the cursor-invisible op (scrubber not yet due)")
	}

	// One more cycle reaches reconcileEveryCycles → the scrubber re-scans from the
	// start and recovers the op.
	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	if op, _ := store.GetOperation(computeOpCID(hidden.token)); op == nil {
		t.Fatal("reconcile scrubber failed to recover the cursor-invisible op")
	}
}
