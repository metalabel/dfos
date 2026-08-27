package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// wellKnownPendingOps fetches /.well-known/dfos-relay and returns stats.pendingOps.
func wellKnownPendingOps(t *testing.T, srvURL string) int {
	t.Helper()
	resp, err := http.Get(srvURL + "/.well-known/dfos-relay")
	if err != nil {
		t.Fatalf("GET well-known: %v", err)
	}
	defer resp.Body.Close()
	var body struct {
		Stats struct {
			PendingOps int `json:"pendingOps"`
		} `json:"stats"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode well-known: %v", err)
	}
	return body.Stats.PendingOps
}

// TestWellKnownReportsPendingOps — the status endpoint surfaces the raw_ops backlog
// so a wedged/backed-up relay is diagnosable over HTTP (no on-box sqlite3 needed).
func TestWellKnownReportsPendingOps(t *testing.T) {
	store := NewMemoryStore()

	// Stage an unsequenced raw op (handler-served relay runs no background
	// sequencer, so it stays pending).
	id := createTestIdentity(t)
	if _, err := store.PutRawOp(computeOpCID(id.token), id.token); err != nil {
		t.Fatal(err)
	}

	r, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	want, err := store.CountUnsequenced()
	if err != nil || want < 1 {
		t.Fatalf("expected >=1 pending raw op staged, got %d (err=%v)", want, err)
	}
	if got := wellKnownPendingOps(t, srv.URL); got != want {
		t.Fatalf("well-known stats.pendingOps=%d, want %d", got, want)
	}
}

func TestWellKnownReportsStatsAndPeers(t *testing.T) {
	store := NewMemoryStore()
	r, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}

	id := createTestIdentity(t)
	results := r.Ingest([]string{id.token})
	if len(results) != 1 || results[0].Status != "new" {
		t.Fatalf("expected identity ingest to be new, got %+v", results)
	}

	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/dfos-relay")
	if err != nil {
		t.Fatalf("GET well-known: %v", err)
	}
	defer resp.Body.Close()
	var body struct {
		Peers []struct {
			Endpoint string `json:"endpoint"`
		} `json:"peers"`
		Stats struct {
			OpCount      int            `json:"opCount"`
			CountsByKind map[string]int `json:"countsByKind"`
			OldestOpAt   *string        `json:"oldestOpAt"`
			HeadCID      *string        `json:"headCid"`
		} `json:"stats"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode well-known: %v", err)
	}

	if body.Peers == nil {
		t.Fatal("well-known peers must be an array, got null or missing")
	}
	if len(body.Peers) != 0 {
		t.Fatalf("well-known peers len=%d, want 0", len(body.Peers))
	}
	if body.Stats.OpCount < 1 {
		t.Fatalf("well-known stats.opCount=%d, want >=1", body.Stats.OpCount)
	}
	for _, key := range []string{"identity", "content", "artifact", "credential", "countersign", "revocation"} {
		if _, ok := body.Stats.CountsByKind[key]; !ok {
			t.Fatalf("well-known stats.countsByKind missing key %q", key)
		}
	}
	if body.Stats.HeadCID == nil || *body.Stats.HeadCID == "" {
		t.Fatal("well-known stats.headCid is empty")
	}
	if body.Stats.OldestOpAt == nil || *body.Stats.OldestOpAt == "" {
		t.Fatal("well-known stats.oldestOpAt is empty")
	}
	if _, present := decodeWellKnownStats(t, srv.URL)["peerSync"]; present {
		t.Fatal("well-known stats.peerSync present on a relay with no sync peers")
	}
}

// decodeWellKnownStats returns the raw stats object so a test can assert on
// OPTIONAL fields by presence, not just by zero value.
func decodeWellKnownStats(t *testing.T, srvURL string) map[string]json.RawMessage {
	t.Helper()
	resp, err := http.Get(srvURL + "/.well-known/dfos-relay")
	if err != nil {
		t.Fatalf("GET well-known: %v", err)
	}
	defer resp.Body.Close()
	var body struct {
		Stats map[string]json.RawMessage `json:"stats"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode well-known: %v", err)
	}
	return body.Stats
}

// wellKnownPeerSync fetches stats.peerSync, failing when the field is absent.
func wellKnownPeerSync(t *testing.T, srvURL string) map[string]PeerSyncStatus {
	t.Helper()
	raw, present := decodeWellKnownStats(t, srvURL)["peerSync"]
	if !present {
		t.Fatal("well-known stats.peerSync missing for a configured sync peer")
	}
	var out map[string]PeerSyncStatus
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode stats.peerSync: %v", err)
	}
	return out
}

// TestWellKnownReportsPeerSyncStatus — the global counters say what this relay
// HOLDS and say nothing about whether it is still pulling. A caught-up relay is
// silent in the logs by design, so without this field a live sync loop and a
// dead one look identical from outside the box.
func TestWellKnownReportsPeerSyncStatus(t *testing.T) {
	a := createTestIdentity(t)
	b := createTestIdentity(t)
	peer := &seqCursorPeerClient{
		entries:  []PeerLogEntry{entryFor(a.token), entryFor(b.token)},
		pageSize: 1,
	}
	r, err := NewRelay(RelayOptions{
		Store:      NewMemoryStore(),
		Peers:      []PeerConfig{{URL: "http://peer"}},
		PeerClient: peer,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	// Before the first cycle the peer already has a row with null timestamps —
	// "configured but never reached" is itself the diagnosis an operator needs,
	// and an absent key could not express it.
	seeded, ok := wellKnownPeerSync(t, srv.URL)["http://peer"]
	if !ok {
		t.Fatal("stats.peerSync has no row for the configured peer")
	}
	if seeded.LastAttemptAt != nil {
		t.Fatalf("stats.peerSync lastAttemptAt = %q before any cycle, want null", *seeded.LastAttemptAt)
	}

	if err := r.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}

	st := wellKnownPeerSync(t, srv.URL)["http://peer"]
	if st.LastAttemptAt == nil || st.LastSuccessAt == nil {
		t.Fatalf("stats.peerSync timestamps still null after a successful cycle: %+v", st)
	}
	if st.LastReceived != 2 || st.LastInserted != 2 {
		t.Fatalf("stats.peerSync lastReceived/lastInserted = %d/%d, want 2/2", st.LastReceived, st.LastInserted)
	}
	if !st.CaughtUp {
		t.Fatal("stats.peerSync caughtUp = false after pulling the peer's whole log")
	}
	if st.ConsecutiveFailures != 0 {
		t.Fatalf("stats.peerSync consecutiveFailures = %d, want 0", st.ConsecutiveFailures)
	}
}
