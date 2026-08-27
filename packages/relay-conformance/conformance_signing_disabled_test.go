package conformance

import (
	"bytes"
	"net/http"
	"testing"
)

// signingDisabledBase returns the relay URL only when capabilities.signing is
// false or absent. This mirrors contentDisabledBase exactly: enabled relays skip
// the disabled-capability assertions.
func signingDisabledBase(t *testing.T) string {
	t.Helper()
	base := relayURL(t)
	var meta struct {
		Capabilities struct {
			Signing bool `json:"signing"`
		} `json:"capabilities"`
	}
	resp := getJSON(t, base+"/.well-known/dfos-relay", &meta)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /.well-known/dfos-relay: status %d", resp.StatusCode)
	}
	if meta.Capabilities.Signing {
		t.Skip("relay advertises capabilities.signing: true — skipping signing-disabled conformance")
	}
	return base
}

func assertSigning501(t *testing.T, route string, resp *http.Response) {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		t.Fatalf("%s: returned 404 — a signing-disabled relay MUST return 501, not 404", route)
	}
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("%s: expected 501 Not Implemented, got %d", route, resp.StatusCode)
	}
}

func TestSigningDisabledRoutes501(t *testing.T) {
	base := signingDisabledBase(t)
	cid := "caaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	assertSigning501(t, "POST /signing/v0/requests", signingPost(t, base+"/signing/v0/requests", map[string]string{"request": "invalid"}))
	resp, err := http.Get(base + "/signing/v0/requests")
	if err != nil {
		t.Fatal(err)
	}
	assertSigning501(t, "GET /signing/v0/requests", resp)
	assertSigning501(t, "POST /signing/v0/requests/{cid}/response", signingPost(t, base+"/signing/v0/requests/"+cid+"/response", map[string]string{"response": "invalid"}))
	resp, err = http.Get(base + "/signing/v0/requests/" + cid + "/response")
	if err != nil {
		t.Fatal(err)
	}
	assertSigning501(t, "GET /signing/v0/requests/{cid}/response", resp)
	assertSigning501(t, "POST /signing/v0/requests/{cid}/decline", signingPost(t, base+"/signing/v0/requests/"+cid+"/decline", nil))
}

func TestSigningDisabledProofRoutesUnaffected(t *testing.T) {
	base := signingDisabledBase(t)
	req, _ := http.NewRequest(http.MethodPost, base+"/proof/v1/operations", bytes.NewBufferString(`{"operations":["invalid"]}`))
	req.Header.Set("content-type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotImplemented {
		t.Fatal("POST /proof/v1/operations returned 501 — signing gate leaked onto the proof plane")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /proof/v1/operations: expected 200 from adjacent proof plane, got %d", resp.StatusCode)
	}
}
