package cmd

// The bulk-sync gate: which registered peers `dfos sync` pulls a whole
// operation log from, and which it refuses to.
//
// The bug these cover shipped in v0.40.0: a config.toml peer became a relay
// peer with library defaults for every switch, so nothing an operator could
// write in config.toml stopped the pull. A 352KB local store grew to 38MB
// against a peer the config said not to sync.
//
// Every test here counts the peer's /proof/v1/log hits, because "did not sync"
// and "synced and got nothing" are the same output otherwise.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/localrelay"
)

// fakePeer is a relay far enough along to be registered and polled: it serves a
// well-known and an empty operation log, and counts the log pulls.
type fakePeer struct {
	server   *httptest.Server
	logHits  atomic.Int32
	infoHits atomic.Int32
	// opsHits counts operations PUSHED to this peer — the gossip direction. A
	// local-only command must never move this. See gossip_posture_test.go.
	opsHits atomic.Int32
	// what the well-known advertises.
	did   string
	proof bool
	log   bool
}

func newFakePeer(t *testing.T) *fakePeer {
	t.Helper()
	p := &fakePeer{did: pinnedDID, proof: true, log: true}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/dfos-relay":
			p.infoHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"did":      p.did,
				"protocol": "dfos-web-relay",
				"version":  "test",
				"capabilities": map[string]any{
					"proof":   p.proof,
					"content": true,
					"log":     p.log,
					"write":   true,
				},
			})
		case "/proof/v1/log":
			p.logHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"entries": []any{}, "next": nil})
		case "/proof/v1/operations":
			// The gossip-out endpoint. Accepting here rather than 404ing matters:
			// the relay suppresses gossip to a peer that refuses a push, which
			// would mask a leak after the first attempt.
			p.opsHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(p.server.Close)
	return p
}

// runSync drives `dfos sync` (optionally with --peer) and returns the parsed
// JSON result. Unlike runJSON it hands back the error, since refusing is one of
// the behaviors under test.
func runSync(t *testing.T, peerName string) (syncResult, error) {
	t.Helper()
	cmd := newSyncCmd()
	if peerName != "" {
		mustSetFlag(t, cmd, "peer", peerName)
	}
	var got syncResult
	_, _, err := runCapturingJSON(t, cmd, nil, &got)
	// `sync --peer` opens its own relay; hand ownership back to the harness so
	// its cleanup closes the right one.
	if localRelayInstance != nil && localRelayInstance != syncHarnessRelay {
		localRelayInstance.Close()
		localRelayInstance = syncHarnessRelay
	}
	return got, err
}

type syncResult struct {
	Peers     int      `json:"peers"`
	Synced    []string `json:"synced"`
	Processed int      `json:"processed"`
	Status    string   `json:"status"`
	Skipped   []struct {
		Peer   string `json:"peer"`
		Reason string `json:"reason"`
	} `json:"skipped"`
}

// syncHarnessRelay is the relay setupDevices opened, so a test can tell it apart
// from one `sync --peer` opened for itself.
var syncHarnessRelay *localrelay.LocalRelay

func setupSync(t *testing.T) {
	t.Helper()
	_, _, lr := setupDevices(t)
	syncHarnessRelay = lr
	t.Cleanup(func() { syncHarnessRelay = nil })
}

// applyPeers registers peers and reopens the local relay against the resulting
// config. That order is the real invocation's: config.toml is loaded in
// PersistentPreRunE and the relay is opened lazily afterwards, so the peer set
// the relay runs on is the one the config named.
func applyPeers(t *testing.T, relays map[string]config.RelayConfig) {
	t.Helper()
	for name, r := range relays {
		cfg.Relays[name] = r
	}
	if localRelayInstance != nil {
		localRelayInstance.Close()
	}
	lr, err := localrelay.Open(cfg, &localrelay.Options{
		DBPath: t.TempDir() + "/relay.db",
		Logger: quietRelayLogger(),
	})
	if err != nil {
		t.Fatalf("reopen local relay: %v", err)
	}
	localRelayInstance, syncHarnessRelay = lr, lr
	t.Cleanup(func() { lr.Close() })
}

// TestSyncPullsAnUngatedPeer is the control: with nothing gating it, `dfos sync`
// does pull the peer's log. Without this the "no pull" assertions below could
// pass because the harness never pulls anything.
func TestSyncPullsAnUngatedPeer(t *testing.T) {
	setupSync(t)
	peer := newFakePeer(t)
	applyPeers(t, map[string]config.RelayConfig{"prod": {URL: peer.server.URL}})

	got, err := runSync(t, "")
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if got.Status != "complete" || got.Peers != 1 || len(got.Synced) != 1 || got.Synced[0] != "prod" {
		t.Fatalf("sync result = %+v", got)
	}
	if peer.logHits.Load() == 0 {
		t.Fatal("an ungated peer must be polled for its log")
	}
}

// TestSyncSkipsGatedPeers covers the three ways a peer is off, and pins that the
// skip is REPORTED — a silently skipped peer is indistinguishable from a peer
// that had nothing to send.
func TestSyncSkipsGatedPeers(t *testing.T) {
	off, on := false, true
	tests := []struct {
		name       string
		relay      func(url string) config.RelayConfig
		wantReason string
	}{
		{
			name:       "sync = false",
			relay:      func(u string) config.RelayConfig { return config.RelayConfig{URL: u, Sync: &off} },
			wantReason: "sync = false",
		},
		{
			// The live report: content and proof set false on the prod peer, and
			// the whole log arrived anyway.
			name: "proof = false",
			relay: func(u string) config.RelayConfig {
				return config.RelayConfig{URL: u, Content: &off, Proof: &off}
			},
			wantReason: "proof = false",
		},
		{
			name: "log = false",
			relay: func(u string) config.RelayConfig {
				return config.RelayConfig{URL: u, Proof: &on, Log: &off}
			},
			wantReason: "log = false",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setupSync(t)
			peer := newFakePeer(t)
			applyPeers(t, map[string]config.RelayConfig{"prod": tc.relay(peer.server.URL)})

			got, err := runSync(t, "")
			if err != nil {
				t.Fatalf("sync: %v", err)
			}
			if peer.logHits.Load() != 0 {
				t.Fatalf("a gated peer was polled %d time(s)", peer.logHits.Load())
			}
			if got.Status != "all_peers_skipped" || got.Peers != 0 {
				t.Fatalf("sync result = %+v", got)
			}
			if len(got.Skipped) != 1 || got.Skipped[0].Peer != "prod" {
				t.Fatalf("skipped = %+v, want one entry naming prod", got.Skipped)
			}
			if !strings.Contains(got.Skipped[0].Reason, tc.wantReason) {
				t.Fatalf("reason = %q, want it to name %q", got.Skipped[0].Reason, tc.wantReason)
			}
		})
	}
}

// TestSyncGatesOnePeerAndNotTheOther pins that the gate is per-peer: the mesh
// still syncs, minus the one peer the config took out.
func TestSyncGatesOnePeerAndNotTheOther(t *testing.T) {
	setupSync(t)
	off := false
	open, gated := newFakePeer(t), newFakePeer(t)
	applyPeers(t, map[string]config.RelayConfig{
		"open":  {URL: open.server.URL},
		"gated": {URL: gated.server.URL, Sync: &off},
	})

	got, err := runSync(t, "")
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if got.Peers != 1 || len(got.Synced) != 1 || got.Synced[0] != "open" {
		t.Fatalf("sync result = %+v, want the open peer alone", got)
	}
	if open.logHits.Load() == 0 {
		t.Error("the ungated peer must still be polled")
	}
	if gated.logHits.Load() != 0 {
		t.Error("the gated peer must not be polled")
	}
}

// TestSyncPeerFlagNarrowsToOnePeer covers `dfos sync --peer <name>`: the named
// peer is pulled and the other is not configured at all for that run.
func TestSyncPeerFlagNarrowsToOnePeer(t *testing.T) {
	setupSync(t)
	a, b := newFakePeer(t), newFakePeer(t)
	applyPeers(t, map[string]config.RelayConfig{
		"a": {URL: a.server.URL},
		"b": {URL: b.server.URL},
	})

	got, err := runSync(t, "a")
	if err != nil {
		t.Fatalf("sync --peer a: %v", err)
	}
	if got.Peers != 1 || len(got.Synced) != 1 || got.Synced[0] != "a" {
		t.Fatalf("sync result = %+v", got)
	}
	if a.logHits.Load() == 0 {
		t.Error("the named peer must be polled")
	}
	if b.logHits.Load() != 0 {
		t.Error("a peer not named must not be polled")
	}
}

// TestSyncPeerFlagRefusesAGatedPeer is the distinguishability rule: asking for a
// peer the config says never to pull is an error naming the switch and the file
// that holds it — not a silent no-op, and not a silent sync.
func TestSyncPeerFlagRefusesAGatedPeer(t *testing.T) {
	setupSync(t)
	off := false
	peer := newFakePeer(t)
	applyPeers(t, map[string]config.RelayConfig{"prod": {URL: peer.server.URL, Sync: &off}})

	_, err := runSync(t, "prod")
	if err == nil {
		t.Fatal("sync --peer against a sync = false peer must refuse")
	}
	for _, want := range []string{"prod", "sync = false", config.ConfigPath()} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must name %q", err, want)
		}
	}
	if peer.logHits.Load() != 0 {
		t.Error("a refused sync must not have pulled anything")
	}
}

func TestSyncPeerFlagRejectsAnUnknownPeer(t *testing.T) {
	setupSync(t)
	_, err := runSync(t, "nope")
	if err == nil || !strings.Contains(err.Error(), "unknown peer: nope") {
		t.Fatalf("error = %v, want an unknown-peer refusal", err)
	}
}

// TestPeerAddDoesNotPullTheLog is the second half of the live report: a fresh
// registration must not drag the peer's corpus onto the machine as a side
// effect of being named.
func TestPeerAddDoesNotPullTheLog(t *testing.T) {
	setupSync(t)
	peer := newFakePeer(t)

	var added struct {
		Name string `json:"name"`
		Log  bool   `json:"log"`
		Sync bool   `json:"sync"`
	}
	runJSON(t, newPeerAddCmd(), []string{"prod", peer.server.URL}, &added)

	if peer.logHits.Load() != 0 {
		t.Fatalf("peer add pulled the log %d time(s)", peer.logHits.Load())
	}
	if peer.infoHits.Load() == 0 {
		t.Error("peer add must fetch the well-known")
	}
	if !added.Sync || !added.Log {
		t.Errorf("a peer registered with no switches bulk-syncs: %+v", added)
	}
	if r := cfg.Relays["prod"]; r.Sync != nil {
		t.Errorf("no --no-sync means no sync key is written, got %v", *r.Sync)
	}
}

// TestPeerAddNoSyncRegistersWithoutBulkSync is the opt-in-only posture: register
// the peer for explicit flows, and never pull its log.
func TestPeerAddNoSyncRegistersWithoutBulkSync(t *testing.T) {
	setupSync(t)
	peer := newFakePeer(t)

	cmd := newPeerAddCmd()
	mustSetFlag(t, cmd, "no-sync", "true")
	var added struct {
		Sync bool `json:"sync"`
	}
	runJSON(t, cmd, []string{"prod", peer.server.URL}, &added)

	if added.Sync {
		t.Error("--no-sync must report the peer as not bulk-syncing")
	}
	r := cfg.Relays["prod"]
	if r.Sync == nil || *r.Sync {
		t.Fatalf("--no-sync must write sync = false, got %v", r.Sync)
	}

	// And the switch holds: a later `dfos sync` leaves the peer alone.
	if _, err := runSync(t, ""); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if peer.logHits.Load() != 0 {
		t.Fatalf("a --no-sync peer was polled %d time(s)", peer.logHits.Load())
	}
}

// TestPeerAddPreservesTheSwitchOnReRegistration: re-adding a peer refreshes its
// metadata. Silently turning bulk sync back on is exactly the surprise the
// switch exists to prevent.
func TestPeerAddPreservesTheSwitchOnReRegistration(t *testing.T) {
	setupSync(t)
	peer := newFakePeer(t)

	cmd := newPeerAddCmd()
	mustSetFlag(t, cmd, "no-sync", "true")
	runJSON(t, cmd, []string{"prod", peer.server.URL}, nil)

	runJSON(t, newPeerAddCmd(), []string{"prod", peer.server.URL}, nil)
	if r := cfg.Relays["prod"]; r.Sync == nil || *r.Sync {
		t.Fatalf("re-registering must keep sync = false, got %v", r.Sync)
	}

	// --no-sync=false is how it comes back on, explicitly.
	back := newPeerAddCmd()
	mustSetFlag(t, back, "no-sync", "false")
	runJSON(t, back, []string{"prod", peer.server.URL}, nil)
	if r := cfg.Relays["prod"]; r.Sync == nil || !*r.Sync {
		t.Fatalf("--no-sync=false must write sync = true, got %v", r.Sync)
	}
}

// TestPeerAddCachesTheLogCapability: a peer that serves no operation log is not
// polled for one, and the reason is recorded rather than rediscovered per cycle.
func TestPeerAddCachesTheLogCapability(t *testing.T) {
	setupSync(t)
	peer := newFakePeer(t)
	peer.log = false

	runJSON(t, newPeerAddCmd(), []string{"prod", peer.server.URL}, nil)
	r := cfg.Relays["prod"]
	if r.Log == nil || *r.Log {
		t.Fatalf("log capability = %v, want a cached false", r.Log)
	}
	if reason := config.BulkSyncDisabledReason(r); !strings.Contains(reason, "log = false") {
		t.Fatalf("reason = %q, want it to name the log capability", reason)
	}
}
