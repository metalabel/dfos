package conformance

import (
	"fmt"
	"net/http"
	"testing"
)

// Content-plane-disabled relay: when the well-known response advertises
// capabilities.content == false, every content-plane (document-gateway) route
// MUST return 501 Not Implemented — "capability not supported" — and NOT 404
// ("resource doesn't exist"). The distinction is a Tier-3 MUST in WEB-RELAY.md
// (§"all content plane routes return 501 Not Implemented — not 404"). The 501
// gate fires before any store lookup, so it holds regardless of whether the
// content id exists.
//
// This is a gated conformance check: it runs only against a relay deployed with
// the content plane OFF (dfos serve with content disabled). Against a normal
// content-enabled relay it self-skips, so it is safe to keep in the default
// `go test ./...` run. To exercise it, point RELAY_URL at a content-disabled
// relay.

// contentDisabledBase returns the relay URL only if the relay advertises
// capabilities.content == false; otherwise it skips. This keeps the 501
// assertions scoped to the deployment they describe — a content-enabled relay
// (the common case) legitimately returns 200/401/404 on these routes, not 501.
func contentDisabledBase(t *testing.T) string {
	t.Helper()
	base := relayURL(t)

	var meta struct {
		Capabilities struct {
			Content bool `json:"content"`
		} `json:"capabilities"`
	}
	resp := getJSON(t, base+"/.well-known/dfos-relay", &meta)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /.well-known/dfos-relay: status %d", resp.StatusCode)
	}
	if meta.Capabilities.Content {
		t.Skip("relay advertises capabilities.content: true — skipping content-disabled conformance")
	}
	return base
}

// assert501 issues a request and asserts a 501 Not Implemented — not a 404,
// 200, or anything else. The route under test is named for a legible failure.
func assert501(t *testing.T, route string, resp *http.Response) {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		t.Fatalf("%s: returned 404 — a content-disabled relay MUST return 501 (capability not supported), not 404 (resource missing)", route)
	}
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("%s: expected 501 Not Implemented, got %d", route, resp.StatusCode)
	}
}

// TestContentDisabledRoutes501 asserts every content-plane route returns 501 on
// a content-disabled relay. The three routes are the document-gateway sub-paths
// (GET/HEAD .../blob, GET .../blob/{ref}, PUT .../blob/{operationCID}).
// The bare proof-plane chain routes
// (GET /proof/v1/content/{id} and .../log) are deliberately NOT asserted here —
// those belong to the proof plane, are always served, and return 404 on a miss.
func TestContentDisabledRoutes501(t *testing.T) {
	base := contentDisabledBase(t)

	// An identity + auth token to present on the read/write routes. The 501 gate
	// fires before auth and before any store lookup, so a well-formed request is
	// not required — but using a real authed request proves the 501 is the gate
	// firing, not an auth (401) or routing (404) artifact masquerading as one.
	id := createIdentity(t, base)
	tok := authToken(t, base, id)

	// A syntactically valid 31-char content id that does not (and need not) exist
	// on the relay — the capability gate precedes existence checks.
	const contentID = "cv7n8vkvr64cctf3294h9k4eanhff8z"
	const opCID = "bafyreib4dsummyopcidforthe501gatetestxxxxxxxxxxxxxxxxx"

	t.Run("GET /content/{id}/blob (head)", func(t *testing.T) {
		resp := getBlob(t, base, contentID, tok)
		assert501(t, "GET /content/{id}/blob", resp)
	})

	t.Run("GET /content/{id}/blob/{ref}", func(t *testing.T) {
		resp := getBlob(t, base, contentID, tok, opCID)
		assert501(t, "GET /content/{id}/blob/{ref}", resp)
	})

	t.Run("PUT /content/{id}/blob/{operationCID}", func(t *testing.T) {
		resp := putBlob(t, base, contentID, opCID, tok, []byte("payload"))
		assert501(t, "PUT /content/{id}/blob/{operationCID}", resp)
	})
}

// TestContentDisabledProofRoutesUnaffected is the negative control: a
// content-disabled relay still serves the proof plane in full. The bare
// /proof/v1/content/{id} chain route is proof-plane, not content-plane, so it
// MUST NOT 501 — it returns 404 for a non-existent chain (route reached). This
// pins the boundary: 501 is scoped to the content (blob) plane only.
func TestContentDisabledProofRoutesUnaffected(t *testing.T) {
	base := contentDisabledBase(t)

	const contentID = "cv7n8vkvr64cctf3294h9k4eanhff8z"
	for _, path := range []string{
		"/proof/v1/content/" + contentID,
		"/proof/v1/content/" + contentID + "/log",
	} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotImplemented {
			t.Fatalf("GET %s: returned 501 — proof-plane chain routes are NOT content-plane and must never 501 (expected 404 for a missing chain)", path)
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s: expected 404 for a non-existent chain on a content-disabled relay, got %d", path, resp.StatusCode)
		}
	}
	_ = fmt.Sprint // keep fmt import stable if route list edited
}
