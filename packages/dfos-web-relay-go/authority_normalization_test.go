package relay

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// AUTHORITY NORMALIZATION.
//
// API-AUTH is normative: a proof's `host` is the lowercase authority with the
// port OMITTED on the scheme default. The TS twin gets that for free from WHATWG
// URL.host; Go's url.URL.Host keeps whatever the operator wrote, so every Go
// signing site normalizes explicitly or the two stacks sign different hosts for
// the same peer URL — and the one that keeps ":443" 401s against a normally
// configured relay.

func TestNormalizeAuthority(t *testing.T) {
	cases := []struct{ scheme, hostport, want string }{
		{"https", "relay.example:443", "relay.example"},
		{"https", "relay.example:8443", "relay.example:8443"},
		{"http", "localhost:80", "localhost"},
		{"http", "localhost:8080", "localhost:8080"},
		{"https", "Relay.EXAMPLE", "relay.example"},
		{"https", "Relay.EXAMPLE:443", "relay.example"},
		// The default port is per scheme: http's 443 is an explicit port.
		{"http", "relay.example:443", "relay.example:443"},
		{"https", "relay.example:80", "relay.example:80"},
	}
	for _, c := range cases {
		if got := normalizeAuthority(c.scheme, c.hostport); got != c.want {
			t.Errorf("normalizeAuthority(%q, %q) = %q, want %q", c.scheme, c.hostport, got, c.want)
		}
	}
}

// roundTripperFunc answers a gossip push without a network, so the test observes
// what the signer was asked to bind rather than where the request went.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestGossipProofBindsTheNormalizedAuthority(t *testing.T) {
	client := &HttpPeerClient{client: &http.Client{
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
	}}

	for _, c := range []struct{ peerURL, want string }{
		{"https://relay.example:443", "relay.example"},
		{"https://relay.example:8443", "relay.example:8443"},
		{"http://localhost:80", "localhost"},
		{"https://Relay.EXAMPLE", "relay.example"},
	} {
		var signed string
		sign := func(_, host, _ string, _ []byte) (string, error) {
			signed = host
			return "", nil
		}
		if err := client.SubmitOperationsSigned(c.peerURL, []string{"op"}, sign); err != nil {
			t.Fatalf("push to %s: %v", c.peerURL, err)
		}
		if signed != c.want {
			t.Errorf("gossip to %s signed host %q, want %q", c.peerURL, signed, c.want)
		}
	}
}
