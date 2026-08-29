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

	"gopkg.in/yaml.v3"
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

// THE SERVED DOCUMENT DESCRIBES THIS RELAY. A hardcoded host in the canonical
// document is wrong for every deployment but the one it names — a client that
// read `http://localhost:3000` out of a document fetched from a real relay would
// resolve every operation against localhost and reach nothing. The served copy's
// `servers` therefore names the relay's own configured authority.
func TestOpenAPIServersDescribesThisRelay(t *testing.T) {
	for _, tc := range []struct {
		authority string
		want      string
	}{
		{"relay.example.com", "https://relay.example.com"},
		{"Relay.Example.com:8443", "https://relay.example.com:8443"},
		// loopback is the one authority served in the clear
		{"localhost:3000", "http://localhost:3000"},
		{"127.0.0.1:3000", "http://127.0.0.1:3000"},
		{"[::1]:3000", "http://[::1]:3000"},
	} {
		t.Run(tc.authority, func(t *testing.T) {
			r, err := NewRelay(RelayOptions{Store: NewMemoryStore(), Authority: tc.authority})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := r.openapiDocument()
			if err != nil {
				t.Fatalf("render document: %v", err)
			}
			var document struct {
				Servers []struct {
					URL string `json:"url"`
				} `json:"servers"`
			}
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatalf("decode document: %v", err)
			}
			if len(document.Servers) != 1 || document.Servers[0].URL != tc.want {
				t.Fatalf("servers = %+v, want one entry %q", document.Servers, tc.want)
			}
		})
	}
}

// WITH NO AUTHORITY CONFIGURED there is nothing honest to write, and the member
// is absent rather than guessed — OpenAPI then resolves operations against the
// URL the document was retrieved from, which for a self-served document is this
// relay. Absent, never null and never an empty array: a `servers` present but
// empty is a document that describes no host at all.
func TestOpenAPIOmitsServersWithoutAuthority(t *testing.T) {
	r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := r.openapiDocument()
	if err != nil {
		t.Fatalf("render document: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode document: %v", err)
	}
	if _, present := document["servers"]; present {
		t.Fatalf("servers = %v, want the member absent", document["servers"])
	}
}

// The canonical document names no host — the absence the serve-time rewrite is
// written on top of. If a `servers` block ever comes back into openapi.yaml,
// every relay that cannot self-describe starts advertising it verbatim.
func TestCanonicalOpenAPIDeclaresNoServers(t *testing.T) {
	canonical, err := os.ReadFile(canonicalOpenAPIPath)
	if err != nil {
		t.Fatalf("read canonical openapi.yaml: %v", err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(canonical, &document); err != nil {
		t.Fatalf("parse canonical openapi.yaml: %v", err)
	}
	if _, present := document["servers"]; present {
		t.Fatalf("canonical openapi.yaml declares servers = %v; the document describes the "+
			"surface every relay serves, not the address of one — each relay writes its own",
			document["servers"])
	}
}

// The route serves what the document renderer produced, self-description
// included — the rewrite has to reach the wire, not just the cache.
func TestOpenAPIRouteServesTheSelfDescribedDocument(t *testing.T) {
	r, err := NewRelay(RelayOptions{Store: NewMemoryStore(), Authority: "relay.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + openapiPath)
	if err != nil {
		t.Fatalf("GET %s: %v", openapiPath, err)
	}
	defer resp.Body.Close()
	var document struct {
		Servers []struct {
			URL string `json:"url"`
		} `json:"servers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&document); err != nil {
		t.Fatalf("decode served document: %v", err)
	}
	if len(document.Servers) != 1 || document.Servers[0].URL != "https://relay.example.com" {
		t.Fatalf("served servers = %+v, want one entry %q", document.Servers, "https://relay.example.com")
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
