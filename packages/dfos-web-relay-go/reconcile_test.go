package relay

import (
	"testing"
)

// lossyForwardPeerClient simulates a peer (notably the production relay) whose
// proof log is ordered by op timestamp rather than ingest order and is paged by
// a forward cursor. An op inserted into the MIDDLE of the ordering — a
// "back-dated" op whose timestamp sorts behind an already-advanced cursor — is
// invisible to forward pagination from the high-water mark, but a re-scan from
// the start (the reconcile scrubber lapping) surfaces it. GetOperationLog
// returns entries strictly AFTER the cursor CID; an unknown cursor returns empty
// (mirrors prod's timestamp cursor running off the end).
type lossyForwardPeerClient struct {
	entries []PeerLogEntry
}

func (c *lossyForwardPeerClient) indexOf(cid string) int {
	for i, e := range c.entries {
		if e.CID == cid {
			return i
		}
	}
	return -1
}

func (c *lossyForwardPeerClient) GetOperationLog(_ string, after string, limit int) (*PeerLogPage, error) {
	start := 0
	if after != "" {
		idx := c.indexOf(after)
		if idx < 0 {
			return &PeerLogPage{Entries: []PeerLogEntry{}}, nil // unknown cursor → empty
		}
		start = idx + 1
	}
	end := start + limit
	if end > len(c.entries) {
		end = len(c.entries)
	}
	page := append([]PeerLogEntry{}, c.entries[start:end]...)
	var cursor *string
	if len(page) == limit { // full page → more may follow
		c := page[len(page)-1].CID
		cursor = &c
	}
	return &PeerLogPage{Entries: page, Cursor: cursor}, nil
}

func (c *lossyForwardPeerClient) GetIdentityLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (c *lossyForwardPeerClient) GetContentLog(string, string, string, int) (*PeerLogPage, error) {
	return nil, nil
}
func (c *lossyForwardPeerClient) SubmitOperations(string, []string) error { return nil }

// entryFor builds a peer log entry from a valid identity-create token, keyed by
// the locally-recomputed storage CID (what the relay stores under).
func entryFor(token string) PeerLogEntry {
	return PeerLogEntry{CID: computeOpCID(token), JWSToken: token}
}

// TestReconcileRecoversBackdatedOp is the regression for the lark-vs-prod drift:
// a relay caught up to a lossy-forward-cursor peer must still recover an op the
// peer later serves BEHIND the high-water cursor. The normal forward pull can
// never see it; the bounded anti-entropy scrubber must.
func TestReconcileRecoversBackdatedOp(t *testing.T) {
	store := NewMemoryStore()

	a := createTestIdentity(t)
	b := createTestIdentity(t)
	c := createTestIdentity(t)
	d := createTestIdentity(t)
	backdated := createTestIdentity(t)

	peer := &lossyForwardPeerClient{entries: []PeerLogEntry{
		entryFor(a.token), entryFor(b.token), entryFor(c.token), entryFor(d.token),
	}}

	r, err := NewRelay(RelayOptions{
		Store:      store,
		Peers:      []PeerConfig{{URL: "http://peer"}},
		PeerClient: peer,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Catch up: the relay pulls all four and advances its high-water cursor to d.
	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	if op, _ := store.GetOperation(computeOpCID(d.token)); op == nil {
		t.Fatal("expected the relay to be caught up to op d")
	}

	// The peer ingests a back-dated op INTO THE MIDDLE of its log — behind the
	// relay's high-water cursor (which sits at d, the last entry).
	peer.entries = []PeerLogEntry{
		entryFor(a.token), entryFor(b.token),
		entryFor(backdated.token), // sorts behind the cursor — forward pull can't reach it
		entryFor(c.token), entryFor(d.token),
	}

	// Normal forward sync can never surface it: the cursor is at d (still last),
	// so GetOperationLog(after=d) is empty. Run up to just under the scrub cadence
	// (the catch-up sync above already counted as cycle 1) to confirm the gap
	// persists and that we do NOT trip the scrubber before it is due.
	for i := 0; i < reconcileEveryCycles-2; i++ {
		if err := r.SyncFromPeers(); err != nil {
			t.Fatal(err)
		}
	}
	if op, _ := store.GetOperation(computeOpCID(backdated.token)); op != nil {
		t.Fatal("forward pull should NOT have recovered the back-dated op (scrubber not yet due)")
	}

	// One more cycle reaches reconcileEveryCycles → the scrubber re-scans from the
	// start and recovers the back-dated op.
	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	if op, _ := store.GetOperation(computeOpCID(backdated.token)); op == nil {
		t.Fatal("reconcile scrubber failed to recover the back-dated op")
	}
}
