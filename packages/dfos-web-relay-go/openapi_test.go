package relay

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

const canonicalOpenAPIPath = "../dfos-web-relay/openapi.yaml"

// infoVersionLine matches the `info:` block's version line, the ONE line the
// copy is allowed to differ on: the release version-sync stamps the canonical
// document only, and the served document reports the running relay's Version
// anyway.
var infoVersionLine = regexp.MustCompile(`(?m)^  version: .*$`)

func openapiWithoutVersion(document []byte) string {
	return infoVersionLine.ReplaceAllString(string(document), "  version: <stamped>")
}

// The embedded document is a copy of the canonical description both reference
// relays serve. Nothing enforces that copy but this test — so when it fails, the
// fix is the one-liner in the message, never an edit to the embedded file.
func TestOpenAPIDocumentMatchesCanonical(t *testing.T) {
	canonical, err := os.ReadFile(canonicalOpenAPIPath)
	if err != nil {
		t.Fatalf("read canonical openapi.yaml: %v", err)
	}
	if openapiWithoutVersion(canonical) != openapiWithoutVersion(openapiYAML) {
		t.Fatalf("packages/dfos-web-relay-go/openapi.yaml has drifted from the canonical %s.\n"+
			"Re-copy it: cp packages/dfos-web-relay/openapi.yaml packages/dfos-web-relay-go/openapi.yaml",
			canonicalOpenAPIPath)
	}
}

// The route serves the document as JSON — the representation every OpenAPI
// consumer reads — and is ungated, like the well-known that advertises it.
func TestOpenAPIRouteServesJSONDocument(t *testing.T) {
	r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/openapi.json")
	if err != nil {
		t.Fatalf("GET /openapi.json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET /openapi.json = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	raw, _ := io.ReadAll(resp.Body)
	var document struct {
		OpenAPI string `json:"openapi"`
		Info    struct {
			Title   string `json:"title"`
			Version string `json:"version"`
		} `json:"info"`
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode /openapi.json: %v (body: %.200s)", err, raw)
	}
	if document.Info.Title != "DFOS Web Relay" {
		t.Fatalf("info.title = %q, want %q", document.Info.Title, "DFOS Web Relay")
	}
	// The served document reports THIS binary's version, not the copy's stamp.
	if document.Info.Version != Version {
		t.Fatalf("info.version = %q, want the relay's %q", document.Info.Version, Version)
	}
	if !strings.HasPrefix(document.OpenAPI, "3.") {
		t.Fatalf("openapi = %q, want a 3.x document", document.OpenAPI)
	}
	// Spot-check that the paths survived the YAML→JSON conversion intact.
	if _, ok := document.Paths["/.well-known/dfos-relay"]; !ok {
		t.Fatalf("paths missing /.well-known/dfos-relay: %v", keysOf(document.Paths))
	}
	if _, ok := document.Paths["/proof/v1/operations"]; !ok {
		t.Fatalf("paths missing /proof/v1/operations: %v", keysOf(document.Paths))
	}
}

func keysOf(m map[string]map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

// A relay that serves an OpenAPI document advertises its URL in the well-known's
// optional `openapi` field — and the advertised URL has to resolve.
func TestWellKnownAdvertisesOpenAPIDocument(t *testing.T) {
	r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/dfos-relay")
	if err != nil {
		t.Fatalf("GET well-known: %v", err)
	}
	defer resp.Body.Close()
	var body struct {
		OpenAPI string `json:"openapi"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode well-known: %v", err)
	}
	if body.OpenAPI != "/openapi.json" {
		t.Fatalf("well-known openapi = %q, want %q", body.OpenAPI, "/openapi.json")
	}

	advertised, err := http.Get(srv.URL + body.OpenAPI)
	if err != nil {
		t.Fatalf("GET the advertised %s: %v", body.OpenAPI, err)
	}
	defer advertised.Body.Close()
	if advertised.StatusCode != 200 {
		t.Fatalf("advertised %s = %d, want 200", body.OpenAPI, advertised.StatusCode)
	}
}
