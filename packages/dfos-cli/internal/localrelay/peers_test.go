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

	got := mergePeerConfigs(buildPeerConfigs(cfg, nil), extra, quietLogger())
	if len(got) != 2 {
		t.Fatalf("got %d peers, want 2 (%+v)", len(got), got)
	}
	shared := peerByURL(t, got, "https://relay.example")
	if shared.Sync == nil || *shared.Sync {
		t.Errorf("the explicit peer's sync=false must survive the merge, got %v", shared.Sync)
	}
}

// TestBuildPeerConfigsHonorsSwitches is the regression for the bulk-pull bug: a
// config.toml peer used to become a peer with library defaults for all three
// switches, so `sync = false` (and a peer that serves no proof plane or no log)
// still had its entire operation log pulled onto the machine.
func TestBuildPeerConfigsHonorsSwitches(t *testing.T) {
	tests := []struct {
		name  string
		relay config.RelayConfig
		want  relay.PeerConfig
	}{
		{
			// The compat case, and the common one: a config written before the
			// switches existed keeps every default.
			name:  "no switches and no capabilities leaves every default",
			relay: config.RelayConfig{URL: "https://relay.example"},
			want:  relay.PeerConfig{URL: "https://relay.example"},
		},
		{
			name:  "capabilities advertised true leave every default",
			relay: config.RelayConfig{URL: "https://relay.example", Content: boolPtr(true), Proof: boolPtr(true), Log: boolPtr(true)},
			want:  relay.PeerConfig{URL: "https://relay.example"},
		},
		{
			name:  "sync = false disables the pull",
			relay: config.RelayConfig{URL: "https://relay.example", Sync: boolPtr(false)},
			want:  relay.PeerConfig{URL: "https://relay.example", Sync: boolPtr(false)},
		},
		{
			// The live report: proof = false on the prod peer, and the whole
			// proof log arrived anyway.
			name:  "proof = false disables the pull",
			relay: config.RelayConfig{URL: "https://relay.example", Content: boolPtr(false), Proof: boolPtr(false)},
			want:  relay.PeerConfig{URL: "https://relay.example", Sync: boolPtr(false)},
		},
		{
			name:  "log = false disables the pull",
			relay: config.RelayConfig{URL: "https://relay.example", Proof: boolPtr(true), Log: boolPtr(false)},
			want:  relay.PeerConfig{URL: "https://relay.example", Sync: boolPtr(false)},
		},
		{
			// content is about the document plane. Bulk sync is the proof plane's
			// operation log, so content alone never gates it.
			name:  "content = false alone does not disable the pull",
			relay: config.RelayConfig{URL: "https://relay.example", Content: boolPtr(false), Proof: boolPtr(true)},
			want:  relay.PeerConfig{URL: "https://relay.example"},
		},
		{
			name:  "gossip and read-through carry through verbatim",
			relay: config.RelayConfig{URL: "https://relay.example", Gossip: boolPtr(false), ReadThrough: boolPtr(false), Sync: boolPtr(true)},
			want:  relay.PeerConfig{URL: "https://relay.example", Gossip: boolPtr(false), ReadThrough: boolPtr(false), Sync: boolPtr(true)},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Relays: map[string]config.RelayConfig{"peer": tc.relay}}
			got := buildPeerConfigs(cfg, nil)
			if len(got) != 1 {
				t.Fatalf("got %d peers, want 1 (%+v)", len(got), got)
			}
			assertFlag(t, tc.want.URL, "gossip", got[0].Gossip, tc.want.Gossip)
			assertFlag(t, tc.want.URL, "readThrough", got[0].ReadThrough, tc.want.ReadThrough)
			assertFlag(t, tc.want.URL, "sync", got[0].Sync, tc.want.Sync)
		})
	}
}

// TestBuildPeerConfigsOnlyPeers covers `dfos sync --peer <name>`: the run is
// narrowed to one registered peer, and the others are not configured at all —
// so nothing about them (cursor, gossip, read-through) moves either.
func TestBuildPeerConfigsOnlyPeers(t *testing.T) {
	cfg := &config.Config{
		Relays: map[string]config.RelayConfig{
			"local": {URL: "http://127.0.0.1:4444"},
			"prod":  {URL: "https://relay.example"},
		},
	}

	all := buildPeerConfigs(cfg, nil)
	if len(all) != 2 {
		t.Fatalf("nil filter must take every peer, got %+v", all)
	}
	// Sorted by name, so the peer list is the same on every run.
	if all[0].URL != "http://127.0.0.1:4444" || all[1].URL != "https://relay.example" {
		t.Errorf("peers must be built in sorted name order, got %+v", all)
	}

	one := buildPeerConfigs(cfg, []string{"prod"})
	if len(one) != 1 || one[0].URL != "https://relay.example" {
		t.Fatalf("only=[prod] must yield prod alone, got %+v", one)
	}

	none := buildPeerConfigs(cfg, []string{})
	if len(none) != 0 {
		t.Errorf("an empty (non-nil) filter selects nothing, got %+v", none)
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

// TestWithGossipOffOverridesEverySpelling pins the local-only posture at its
// mechanism. Options.Gossip == false — the zero value every one-shot command
// opens on — forces the switch off for every peer, whatever the peer entry said.
//
// It is an OVERRIDE rather than a default because the leak it closes came from a
// default: an absent `gossip` key means on, so a peer registered the ordinary
// way (`dfos peer add`, no switches) received every operation a local command
// sequenced. Making the CLI's default false would have left `gossip = true` and
// the object form of --peers still pushing.
func TestWithGossipOffOverridesEverySpelling(t *testing.T) {
	peers := withGossipOff([]relay.PeerConfig{
		{URL: "https://absent.example"},
		{URL: "https://on.example", Gossip: boolPtr(true)},
		{URL: "https://off.example", Gossip: boolPtr(false)},
		// The other two switches are pulls this machine initiates; only gossip
		// puts local state on a peer, so only gossip is touched.
		{URL: "https://pulls.example", ReadThrough: boolPtr(true), Sync: boolPtr(true)},
	})

	for _, peer := range peers {
		if peer.Gossip == nil || *peer.Gossip {
			t.Errorf("%s gossips: %v", peer.URL, peer.Gossip)
		}
	}
	pulls := peerByURL(t, peers, "https://pulls.example")
	assertFlag(t, pulls.URL, "readThrough", pulls.ReadThrough, boolPtr(true))
	assertFlag(t, pulls.URL, "sync", pulls.Sync, boolPtr(true))
}

// TestBuildPeerConfigsKeepsTheGossipSwitch is the serve half: the switch a peer
// entry carries survives untouched, so `serve` — which opens with gossip on —
// pushes to exactly the peers the config says to push to.
func TestBuildPeerConfigsKeepsTheGossipSwitch(t *testing.T) {
	cfg := &config.Config{Relays: map[string]config.RelayConfig{
		"absent": {URL: "https://absent.example"},
		"on":     {URL: "https://on.example", Gossip: boolPtr(true)},
		"off":    {URL: "https://off.example", Gossip: boolPtr(false)},
	}}
	peers := buildPeerConfigs(cfg, nil)

	assertFlag(t, "https://absent.example", "gossip", peerByURL(t, peers, "https://absent.example").Gossip, nil)
	assertFlag(t, "https://on.example", "gossip", peerByURL(t, peers, "https://on.example").Gossip, boolPtr(true))
	assertFlag(t, "https://off.example", "gossip", peerByURL(t, peers, "https://off.example").Gossip, boolPtr(false))
}

// TestPeerConfigForCarriesThePin is the gap that let `dfos serve` run its whole
// peer loop — sync, gossip, read-through, blob materialization — against a peer
// set identified by URL alone. config.toml held the pin the CLI's own commands
// refuse to cross, and the mapping into the relay library dropped it on the
// floor.
func TestPeerConfigForCarriesThePin(t *testing.T) {
	const pin = "did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar"

	pinned := PeerConfigFor(config.RelayConfig{URL: "https://relay.example", DID: pin})
	if pinned.DID != pin {
		t.Fatalf("the pin must reach the relay library, got %q", pinned.DID)
	}

	// A hand-written entry with only a url makes no claim about identity, and ""
	// is what the library reads as unchecked.
	unpinned := PeerConfigFor(config.RelayConfig{URL: "https://relay.example"})
	if unpinned.DID != "" {
		t.Errorf("an unpinned entry must stay unpinned, got %q", unpinned.DID)
	}

	// A peer this machine must not bulk-sync is still gossiped to and read
	// through, so the pin has to survive the sync override.
	off := PeerConfigFor(config.RelayConfig{URL: "https://relay.example", DID: pin, Sync: boolPtr(false)})
	if off.DID != pin {
		t.Errorf("forcing sync off must not drop the pin, got %q", off.DID)
	}
}

// TestMergePeerConfigsKeepsThePinTheRedefinitionOmits: naming a relay twice is
// how an operator attaches a flag to a config.toml peer, and the --peers object
// form has no obligation to restate an identity config.toml already recorded.
// Letting the redefinition win outright would turn "gossip off here" into "and
// stop checking who this is".
func TestMergePeerConfigsKeepsThePinTheRedefinitionOmits(t *testing.T) {
	const configured = "did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar"
	const explicit = "did:dfos:cv7n8vkvr64cctf3294h9k4eanhff8z"

	inherited := mergePeerConfigs(
		[]relay.PeerConfig{{URL: "https://relay.example", DID: configured}},
		[]relay.PeerConfig{{URL: "https://relay.example", Gossip: boolPtr(false)}},
		quietLogger(),
	)
	peer := peerByURL(t, inherited, "https://relay.example")
	if peer.DID != configured {
		t.Errorf("an omitted did must inherit the config pin, got %q", peer.DID)
	}
	assertFlag(t, peer.URL, "gossip", peer.Gossip, boolPtr(false))

	// An explicit one still wins outright: only an ABSENT pin inherits.
	stated := mergePeerConfigs(
		[]relay.PeerConfig{{URL: "https://relay.example", DID: configured}},
		[]relay.PeerConfig{{URL: "https://relay.example", DID: explicit}},
		quietLogger(),
	)
	if got := peerByURL(t, stated, "https://relay.example").DID; got != explicit {
		t.Errorf("an explicit did must win, got %q", got)
	}
}
