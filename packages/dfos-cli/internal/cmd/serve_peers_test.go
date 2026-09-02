package cmd

import (
	"testing"

	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
)

func boolPtr(b bool) *bool { return &b }

// TestParsePeersForms covers the three documented forms of --peers / PEERS.
func TestParsePeersForms(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []relay.PeerConfig
	}{
		{
			name:  "empty",
			input: "",
			want:  nil,
		},
		{
			// An explicit empty JSON array is a legitimate "no peers" — a
			// templated deployment renders it that way.
			name:  "empty json array",
			input: "[]",
			want:  nil,
		},
		{
			name:  "comma separated",
			input: "http://relay-b:8080, https://relay-c.example.com ",
			want: []relay.PeerConfig{
				{URL: "http://relay-b:8080"},
				{URL: "https://relay-c.example.com"},
			},
		},
		{
			name:  "json array of urls",
			input: `["http://relay-b:8080","https://relay-c.example.com"]`,
			want: []relay.PeerConfig{
				{URL: "http://relay-b:8080"},
				{URL: "https://relay-c.example.com"},
			},
		},
		{
			// The form the relay README documents. It used to fall through to
			// comma-splitting, producing peers like `[{"url":"https://x"` that
			// failed every sync tick forever.
			name:  "json array of objects",
			input: `[{"url":"http://relay-b:8080"},{"url":"http://relay-c:8080","gossip":false,"readThrough":false,"sync":true}]`,
			want: []relay.PeerConfig{
				{URL: "http://relay-b:8080"},
				{URL: "http://relay-c:8080", Gossip: boolPtr(false), ReadThrough: boolPtr(false), Sync: boolPtr(true)},
			},
		},
		{
			name:  "mixed urls and objects",
			input: `["http://relay-b:8080",{"url":"http://relay-c:8080","sync":false}]`,
			want: []relay.PeerConfig{
				{URL: "http://relay-b:8080"},
				{URL: "http://relay-c:8080", Sync: boolPtr(false)},
			},
		},
		{
			// The identity pin. Only the object form can carry one — the other two
			// spellings say nothing about a peer beyond its address — so a bare URL
			// beside a pinned object stays unpinned, and the relay library reads
			// that "" as unchecked rather than as a pin to nothing.
			name:  "object form carries the identity pin",
			input: `[{"url":"http://relay-b:8080","did":"did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar"},"http://relay-c:8080"]`,
			want: []relay.PeerConfig{
				{URL: "http://relay-b:8080", DID: "did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar"},
				{URL: "http://relay-c:8080"},
			},
		},
		{
			name:  "trailing slashes trimmed",
			input: "https://relay.example.com/",
			want:  []relay.PeerConfig{{URL: "https://relay.example.com"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePeers(tc.input)
			if err != nil {
				t.Fatalf("parsePeers(%q): unexpected error: %v", tc.input, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("parsePeers(%q): got %d peers, want %d (%+v)", tc.input, len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i].URL != tc.want[i].URL {
					t.Errorf("peer %d url: got %q want %q", i, got[i].URL, tc.want[i].URL)
				}
				if got[i].DID != tc.want[i].DID {
					t.Errorf("peer %d did: got %q want %q", i, got[i].DID, tc.want[i].DID)
				}
				assertFlag(t, i, "gossip", got[i].Gossip, tc.want[i].Gossip)
				assertFlag(t, i, "readThrough", got[i].ReadThrough, tc.want[i].ReadThrough)
				assertFlag(t, i, "sync", got[i].Sync, tc.want[i].Sync)
			}
		})
	}
}

// TestParsePeersRejects verifies a bad config fails at boot rather than becoming
// a permanent per-tick sync error.
func TestParsePeersRejects(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"malformed json array", `[{"url":"https://relay.example.com",]`},
		{"unknown per-peer field", `[{"url":"https://relay.example.com","gosip":false}]`},
		// `did` is a peerSpec member, so a misspelling of it must fail at boot
		// like any other — silently keeping the peer unpinned is exactly the
		// unchecked-identity condition the field exists to close.
		{"misspelled did field", `[{"url":"https://relay.example.com","dids":"did:dfos:x"}]`},
		{"object without url", `[{"gossip":false}]`},
		{"scheme-less url", "relay.example.com"},
		{"non-http scheme", "ftp://relay.example.com"},
		{"path only", "/proof/v1"},
		// A query or fragment swallows the path the peer client appends, so
		// every request would land on "/" — the same permanent error loop.
		{"query component", "https://relay.example.com?token=x"},
		{"bare query", "https://relay.example.com?"},
		{"fragment component", "https://relay.example.com#frag"},
		{"bare fragment", "https://relay.example.com#"},
		{"separators only", " , , "},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePeers(tc.input)
			if err == nil {
				t.Fatalf("parsePeers(%q): want error, got %+v", tc.input, got)
			}
		})
	}
}

// TestPeerFlagSuffix covers the boot banner's per-peer flag rendering.
func TestPeerFlagSuffix(t *testing.T) {
	if got := peerFlagSuffix(relay.PeerConfig{URL: "https://a.example"}); got != "" {
		t.Errorf("all-default peer: got %q want %q", got, "")
	}
	if got := peerFlagSuffix(relay.PeerConfig{URL: "https://a.example", Gossip: boolPtr(true)}); got != "" {
		t.Errorf("explicitly-enabled peer: got %q want %q", got, "")
	}
	want := " (disabled: gossip, sync)"
	if got := peerFlagSuffix(relay.PeerConfig{URL: "https://a.example", Gossip: boolPtr(false), Sync: boolPtr(false)}); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func assertFlag(t *testing.T, i int, name string, got, want *bool) {
	t.Helper()
	switch {
	case got == nil && want == nil:
	case got == nil || want == nil:
		t.Errorf("peer %d %s: got %v want %v", i, name, got, want)
	case *got != *want:
		t.Errorf("peer %d %s: got %v want %v", i, name, *got, *want)
	}
}
