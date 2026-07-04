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
	if err := store.PutRawOp(computeOpCID(id.token), id.token); err != nil {
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
}
