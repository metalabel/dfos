package cmd

import "testing"

func TestStatusStoreWorksWithNothingResolved(t *testing.T) {
	_, _, lr := setupDevices(t)
	cmd := newStatusCmd()
	mustSetFlag(t, cmd, "store", "true")
	var got struct {
		Resolved bool `json:"resolved"`
		Store    struct {
			Path         string         `json:"path"`
			OpCount      int            `json:"opCount"`
			CountsByKind map[string]int `json:"countsByKind"`
			Unsequenced  int            `json:"unsequenced"`
		} `json:"store"`
	}
	runJSON(t, cmd, nil, &got)
	if got.Resolved {
		t.Fatal("empty config unexpectedly resolved a context")
	}
	if got.Store.Path != lr.DBPath() {
		t.Fatalf("store path = %q, want %q", got.Store.Path, lr.DBPath())
	}
	if got.Store.OpCount <= 0 || got.Store.Unsequenced != 0 || len(got.Store.CountsByKind) != 6 {
		t.Fatalf("store stats = %+v", got.Store)
	}
}

func TestRelayGCReportsDatabaseSizes(t *testing.T) {
	_, _, lr := setupDevices(t)
	var got relayGCResult
	runJSON(t, newRelayGCCmd(), nil, &got)
	if got.Path != lr.DBPath() {
		t.Fatalf("gc path = %q, want %q", got.Path, lr.DBPath())
	}
	if got.SizeBefore <= 0 || got.SizeAfter <= 0 {
		t.Fatalf("gc sizes = before %d, after %d", got.SizeBefore, got.SizeAfter)
	}
}
