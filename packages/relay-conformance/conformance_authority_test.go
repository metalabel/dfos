package conformance

import "testing"

// AUTHORITY NORMALIZATION.
//
// API-AUTH is normative: a proof's `host` is the lowercase authority with the
// port OMITTED on the scheme default. A relay compares that member byte for byte
// against its own configured authority, and a relay behind https on 443 is
// configured for the bare host. A suite that signed "relay.example:443" would
// report a 401 as a conformance failure when the failure is the harness's.
//
// This case needs no live relay: it is about what the suite signs, so it runs
// even when RELAY_URL is unset and the rest of the package skips.

func TestRelayAuthorityNormalization(t *testing.T) {
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

// RELAY_AUTHORITY names the host a proxied or tunneled relay is configured for.
// It gets the same normalization, against the dialed URL's scheme — it names the
// same relay, so its default port is the same one the relay drops.
func TestRelayAuthorityEnvOverrideIsNormalized(t *testing.T) {
	t.Setenv("RELAY_AUTHORITY", "Relay.EXAMPLE:443")
	if got := relayAuthority(t, "https://127.0.0.1:8080"); got != "relay.example" {
		t.Fatalf("RELAY_AUTHORITY override = %q, want relay.example", got)
	}
}
