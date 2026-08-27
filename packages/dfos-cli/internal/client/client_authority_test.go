package client

import "testing"

// AUTHORITY NORMALIZATION.
//
// API-AUTH is normative: a proof's `host` is the lowercase authority with the
// port OMITTED on the scheme default. The TS twin gets that for free from WHATWG
// URL.host; Go's url.URL.Host keeps whatever the operator wrote, so a client
// that signed the raw host would bind "relay.example:443" against a relay
// configured — as every normally configured relay is — for "relay.example", and
// take a 401 on a URL spelling the operator is entitled to use.

func TestClientAuthorityNormalization(t *testing.T) {
	cases := []struct{ baseURL, want string }{
		{"https://relay.example:443", "relay.example"},
		{"https://relay.example:8443", "relay.example:8443"},
		{"http://localhost:80", "localhost"},
		{"http://localhost:8080", "localhost:8080"},
		{"https://Relay.EXAMPLE", "relay.example"},
		{"https://Relay.EXAMPLE:443", "relay.example"},
		// The default port is per scheme: http's 443 is an explicit port.
		{"http://relay.example:443", "relay.example:443"},
		{"https://relay.example:80", "relay.example:80"},
	}
	for _, c := range cases {
		got, err := New(c.baseURL).authority()
		if err != nil {
			t.Errorf("authority() for %q: %v", c.baseURL, err)
			continue
		}
		if got != c.want {
			t.Errorf("authority() for %q = %q, want %q", c.baseURL, got, c.want)
		}
	}

	if _, err := New("not-a-url").authority(); err == nil {
		t.Error("a URL with no authority did not error")
	}
}
