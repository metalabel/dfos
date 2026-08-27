package localrelay

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
)

func boolPtr(b bool) *bool { return &b }

func quietLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// peerByURL finds the merged entry for a URL, or fails the test.
func peerByURL(t *testing.T, peers []relay.PeerConfig, url string) relay.PeerConfig {
	t.Helper()
	for _, peer := range peers {
		if peer.URL == url {
			return peer
		}
	}
	t.Fatalf("no peer for %q in %+v", url, peers)
	return relay.PeerConfig{}
}

// TestMergePeerConfigsDedupes covers the merge Open performs between config.toml
// relays and explicitly supplied peers.
//
// The duplicate is not merely redundant: peer state — the sync cursor above all
// — is keyed by URL, so two entries for one relay pull against a shared cursor
// while every push, read-through, and reconcile tick for that relay happens
// twice.
func TestMergePeerConfigsDedupes(t *testing.T) {
	tests := []struct {
		name   string
		config []relay.PeerConfig
		extra  []relay.PeerConfig
		want   []relay.PeerConfig
	}{
		{
			name:   "distinct peers are all kept",
			config: []relay.PeerConfig{{URL: "https://relay-a.example"}},
			extra:  []relay.PeerConfig{{URL: "https://relay-b.example"}},
			want: []relay.PeerConfig{
				{URL: "https://relay-a.example"},
				{URL: "https://relay-b.example"},
			},
		},
		{
			// The exact misconfiguration: name a relay in config.toml, then name
			// it again on the command line to attach a flag to it. The explicit
			// entry must win, or the flags are silently dropped.
			name:   "explicit peer wins over the config entry",
			config: []relay.PeerConfig{{URL: "https://relay-a.example"}},
			extra:  []relay.PeerConfig{{URL: "https://relay-a.example", Gossip: boolPtr(false), Sync: boolPtr(true)}},
			want: []relay.PeerConfig{
				{URL: "https://relay-a.example", Gossip: boolPtr(false), Sync: boolPtr(true)},
			},
		},
		{
			// The two sources spell the same relay differently. --peers/PEERS
			// trims whitespace and trailing slashes; config.toml does not, so
			// the dedup key has to apply the same normalization to both sides.
			name:   "trailing slash and whitespace are the same peer",
			config: []relay.PeerConfig{{URL: "https://relay-a.example/"}},
			extra:  []relay.PeerConfig{{URL: "https://relay-a.example", ReadThrough: boolPtr(false)}},
			want: []relay.PeerConfig{
				{URL: "https://relay-a.example", ReadThrough: boolPtr(false)},
			},
		},
		{
			name:   "duplicates within one source collapse too",
			config: nil,
			extra: []relay.PeerConfig{
				{URL: "https://relay-a.example", Gossip: boolPtr(true)},
				{URL: "https://relay-a.example", Gossip: boolPtr(false)},
			},
			want: []relay.PeerConfig{{URL: "https://relay-a.example", Gossip: boolPtr(false)}},
		},
		{
			name:   "empty urls are dropped",
			config: []relay.PeerConfig{{URL: "https://relay-a.example"}},
			extra:  []relay.PeerConfig{{URL: ""}, {URL: "   "}},
			want:   []relay.PeerConfig{{URL: "https://relay-a.example"}},
		},
		{
			name:   "no peers at all",
			config: nil,
			extra:  nil,
			want:   nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mergePeerConfigs(tc.config, tc.extra, quietLogger())
			if len(got) != len(tc.want) {
				t.Fatalf("got %d peers, want %d (%+v)", len(got), len(tc.want), got)
			}
			for _, want := range tc.want {
				peer := peerByURL(t, got, want.URL)
				assertFlag(t, want.URL, "gossip", peer.Gossip, want.Gossip)
				assertFlag(t, want.URL, "readThrough", peer.ReadThrough, want.ReadThrough)
				assertFlag(t, want.URL, "sync", peer.Sync, want.Sync)
			}
		})
	}
}

// TestMergePeerConfigsFromConfigRelays runs the merge over the real
// config.toml-derived input, the way Open assembles it.
func TestMergePeerConfigsFromConfigRelays(t *testing.T) {
	cfg := &config.Config{
		Relays: map[string]config.RelayConfig{
			"local":  {URL: "http://127.0.0.1:4444"},
			"shared": {URL: "https://relay.example"},
		},
	}
	extra := []relay.PeerConfig{{URL: "https://relay.example", Sync: boolPtr(false)}}

	got := mergePeerConfigs(buildPeerConfigs(cfg), extra, quietLogger())
	if len(got) != 2 {
		t.Fatalf("got %d peers, want 2 (%+v)", len(got), got)
	}
	shared := peerByURL(t, got, "https://relay.example")
	if shared.Sync == nil || *shared.Sync {
		t.Errorf("the explicit peer's sync=false must survive the merge, got %v", shared.Sync)
	}
}

// TestMergePeerConfigsLogsTheDrop pins the loud line. A dropped duplicate is
// invisible otherwise — the relay simply behaves as if one of the two
// definitions was never written.
func TestMergePeerConfigsLogsTheDrop(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelWarn}))

	mergePeerConfigs(
		[]relay.PeerConfig{{URL: "https://relay-a.example/"}},
		[]relay.PeerConfig{{URL: "https://relay-a.example"}},
		logger,
	)

	line := out.String()
	if !strings.Contains(line, "duplicate peer URL") {
		t.Errorf("expected a warning about the duplicate, got %q", line)
	}
	if !strings.Contains(line, "https://relay-a.example") {
		t.Errorf("the warning must name the peer, got %q", line)
	}
}

func assertFlag(t *testing.T, url, name string, got, want *bool) {
	t.Helper()
	switch {
	case got == nil && want == nil:
	case got == nil || want == nil:
		t.Errorf("%s %s: got %v want %v", url, name, got, want)
	case *got != *want:
		t.Errorf("%s %s: got %v want %v", url, name, *got, *want)
	}
}
