// Index-disabled relay conformance. When capabilities.index is explicitly
// false, every registered /index/v0 route returns 501 Not Implemented — never
// 404 — while the proof and content planes continue to operate normally.
package conformance

import (
	"encoding/json"
	"net/http"
	"testing"
)

// indexDisabledBase gates this suite on an explicit capabilities.index:false.
// An absent flag belongs to older relays and also means unsupported at the wire
// contract, but requiring explicit false keeps this deployment-mode suite from
// unexpectedly running against an unrelated legacy target.
func indexDisabledBase(t *testing.T) string {
	t.Helper()
	base := relayURL(t)

	var meta struct {
		Capabilities map[string]any `json:"capabilities"`
	}
	resp := getJSON(t, base+"/.well-known/dfos-relay", &meta)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /.well-known/dfos-relay: status %d, body: %s", resp.StatusCode, readBody(t, resp))
	}
	if meta.Capabilities["index"] != false {
		t.Skip("relay does not advertise capabilities.index: false — skipping index-disabled conformance")
	}
	return base
}

func assertIndex501(t *testing.T, route string, resp *http.Response) {
	t.Helper()
	body := readBody(t, resp)
	if resp.StatusCode == http.StatusNotFound {
		t.Fatalf("%s: returned 404 — an index-disabled relay MUST return 501 (capability not supported), body: %s", route, body)
	}
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("%s: expected 501 Not Implemented, got %d, body: %s", route, resp.StatusCode, body)
	}
}

// TestIndexDisabledRoutes501 covers every route currently registered under the
// /index/v0 family. The capability gate must precede parameter validation and
// store lookup, so these requests need no seeded index state.
func TestIndexDisabledRoutes501(t *testing.T) {
	base := indexDisabledBase(t)
	const did = "did:dfos:2222222222222222222222222222222"

	for _, route := range []string{
		"/index/v0/identities?limit=1",
		"/index/v0/content?limit=1",
		"/index/v0/credits?limit=1",
		"/index/v0/countersignatures?witness=" + did + "&limit=1",
		"/index/v0/credentials?issuer=" + did + "&limit=1",
	} {
		t.Run(route, func(t *testing.T) {
			resp, err := http.Get(base + route)
			if err != nil {
				t.Fatalf("GET %s: %v", route, err)
			}
			assertIndex501(t, "GET "+route, resp)
		})
	}
}

// TestIndexDisabledAdjacentSurfacesUnaffected proves index:false is scoped to
// the query projection: proof ingestion/reads and authenticated blob I/O remain
// live on an otherwise-default relay.
func TestIndexDisabledAdjacentSurfacesUnaffected(t *testing.T) {
	base := indexDisabledBase(t)
	creator := createIdentity(t, base)
	cc := createContent(t, base, creator)

	for _, route := range []string{
		"/proof/v1/identities/" + creator.did,
		"/proof/v1/content/" + cc.contentID,
	} {
		resp := getJSON(t, base+route, nil)
		body := readBody(t, resp)
		if resp.StatusCode == http.StatusNotImplemented {
			t.Fatalf("GET %s: returned 501 — the index capability gate leaked onto the proof plane, body: %s", route, body)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: expected 200 with index disabled, got %d, body: %s", route, resp.StatusCode, body)
		}
	}

	blobData, err := json.Marshal(cc.document)
	if err != nil {
		t.Fatalf("marshal content blob: %v", err)
	}
	upload := putBlob(t, base, cc.contentID, cc.genCID, signerFor(creator), blobData)
	if upload.StatusCode != http.StatusOK {
		t.Fatalf("PUT content blob with index disabled: status %d, body: %s", upload.StatusCode, readBody(t, upload))
	}
	upload.Body.Close()

	download := getBlob(t, base, cc.contentID, signerFor(creator))
	downloaded := readBody(t, download)
	if download.StatusCode != http.StatusOK {
		t.Fatalf("GET content blob with index disabled: status %d, body: %s", download.StatusCode, downloaded)
	}
	if string(downloaded) != string(blobData) {
		t.Fatal("content blob changed across index-disabled upload/download")
	}
}
