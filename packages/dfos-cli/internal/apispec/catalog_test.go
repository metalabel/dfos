package apispec

// The action catalog. What a document ADVERTISES is the union of two places
// that name action tokens under the same extension name — the scheme-level
// catalog map and each operation's requirement array — so the tests here pin
// the fold, the order, and the deduplication between them.

import (
	"strings"
	"testing"
)

// catalogDoc is a two-operation document whose scheme catalogs one token the
// operations never require and whose operations require two the catalog never
// lists — the general case, not the tidy one.
const catalogDoc = `openapi: 3.1.0
info:
  title: t
  version: "1"
servers:
  - url: https://api.example.test/v1
paths:
  /profile:
    get:
      operationId: getProfile
      x-dfos-actions: [read:profile, read:email]
      security:
        - popProof: []
          theGrant: []
  /posts:
    post:
      operationId: createPost
      x-dfos-actions: [[write:posts, read:profile]]
      security:
        - popProof: []
          theGrant: []
components:
  securitySchemes:
    popProof:
      type: http
      scheme: dfos
      x-dfos-typ: did:dfos:request-proof
      x-dfos-actions:
        read:profile: Read the granting user's own profile
        read:email: Read the granting user's account email address
        admin:everything: Do absolutely anything
    theGrant:
      type: apiKey
      in: header
      name: X-Credential
    bearerish:
      type: http
      scheme: bearer
      x-dfos-actions:
        not:ours: A stranger's vocabulary
`

func mustParse(t *testing.T, body string) *Doc {
	t.Helper()
	doc, err := Parse([]byte(body))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return doc
}

func catalogOf(t *testing.T, doc *Doc) []CatalogEntry {
	t.Helper()
	catalog, err := doc.ActionCatalog()
	if err != nil {
		t.Fatalf("ActionCatalog: %v", err)
	}
	return catalog
}

// The catalog's own order is kept, the operations' extras follow it sorted, and
// a token named in both places appears exactly once — with the description the
// catalog gave it.
func TestActionCatalogUnionsSchemeAndOperations(t *testing.T) {
	catalog := catalogOf(t, mustParse(t, catalogDoc))

	want := []CatalogEntry{
		{Action: "read:profile", Description: "Read the granting user's own profile", Advertised: true},
		{Action: "read:email", Description: "Read the granting user's account email address", Advertised: true},
		{Action: "admin:everything", Description: "Do absolutely anything", Advertised: true},
		{Action: "write:posts"},
	}
	if len(catalog) != len(want) {
		t.Fatalf("catalog = %+v, want %d entries", catalog, len(want))
	}
	for i := range want {
		if catalog[i] != want[i] {
			t.Fatalf("entry %d = %+v, want %+v", i, catalog[i], want[i])
		}
	}
}

// A scheme that is not one of this convention's proof schemes is left alone.
// Reading a stranger's `x-dfos-actions` would put a vocabulary that is not this
// host's in front of a person choosing what to grant.
func TestActionCatalogIgnoresForeignSchemes(t *testing.T) {
	for _, entry := range catalogOf(t, mustParse(t, catalogDoc)) {
		if entry.Action == "not:ours" {
			t.Fatalf("catalog took a token from a bearer scheme: %+v", entry)
		}
	}
}

// The unmarked `scheme: dfos` case — non-conforming, but the section that
// defines the fallback is the same one that defines the catalog, so its catalog
// is read too.
func TestActionCatalogReadsAnUnmarkedProofScheme(t *testing.T) {
	catalog := catalogOf(t, mustParse(t, `openapi: 3.1.0
info: {title: t, version: "1"}
paths: {}
components:
  securitySchemes:
    proof:
      type: http
      scheme: dfos
      x-dfos-actions:
        read:thing: Read the thing
`))
	if len(catalog) != 1 || catalog[0].Action != "read:thing" || catalog[0].Description != "Read the thing" {
		t.Fatalf("catalog = %+v", catalog)
	}
}

// A catalog written as a bare list still names the vocabulary; refusing it would
// hide actions a person could otherwise ask for.
func TestActionCatalogAcceptsASequenceCatalog(t *testing.T) {
	catalog := catalogOf(t, mustParse(t, `openapi: 3.1.0
info: {title: t, version: "1"}
paths: {}
components:
  securitySchemes:
    proof:
      type: http
      scheme: dfos
      x-dfos-typ: did:dfos:request-proof
      x-dfos-actions: [read:a, read:b]
`))
	if len(catalog) != 2 || catalog[0].Action != "read:a" || catalog[1].Action != "read:b" {
		t.Fatalf("catalog = %+v", catalog)
	}
	for _, entry := range catalog {
		if entry.Description != "" {
			t.Fatalf("a list catalog describes nothing, got %+v", entry)
		}
	}
}

func TestActionCatalogRefusesAnUnreadableCatalog(t *testing.T) {
	doc := mustParse(t, `openapi: 3.1.0
info: {title: t, version: "1"}
paths: {}
components:
  securitySchemes:
    proof:
      type: http
      scheme: dfos
      x-dfos-typ: did:dfos:request-proof
      x-dfos-actions: 17
`)
	_, err := doc.ActionCatalog()
	if err == nil || !strings.Contains(err.Error(), "proof") {
		t.Fatalf("want an error naming the scheme, got %v", err)
	}
}

// A document advertising nothing is empty, not an error: the caller decides
// what an empty catalog means, and here it means there is nothing to ask on.
func TestActionCatalogIsEmptyWhenNothingAdvertises(t *testing.T) {
	catalog := catalogOf(t, mustParse(t, `openapi: 3.1.0
info: {title: t, version: "1"}
paths:
  /open:
    get:
      operationId: getOpen
`))
	if len(catalog) != 0 {
		t.Fatalf("catalog = %+v, want empty", catalog)
	}
}

// ---------------------------------------------------------------------------
// authorities
// ---------------------------------------------------------------------------

func TestAuthoritiesFoldsTheDocumentsServers(t *testing.T) {
	authorities, _, err := mustParse(t, catalogDoc).Authorities(ServerPolicy{})
	if err != nil {
		t.Fatalf("Authorities: %v", err)
	}
	if len(authorities) != 1 || authorities[0] != "api.example.test" {
		t.Fatalf("authorities = %v", authorities)
	}
}

// The default port is dropped, matching the `host` a proof binds — a credential
// naming `api:host:443` is one no proof would ever match.
func TestAuthoritiesDropsTheDefaultPort(t *testing.T) {
	authorities, _, err := mustParse(t, `openapi: 3.1.0
info: {title: t, version: "1"}
servers: [{url: "https://API.Example.test:443/v1"}]
paths:
  /thing: {get: {operationId: getThing}}
`).Authorities(ServerPolicy{})
	if err != nil {
		t.Fatalf("Authorities: %v", err)
	}
	if len(authorities) != 1 || authorities[0] != "api.example.test" {
		t.Fatalf("authorities = %v", authorities)
	}
}

// A relative server URL resolves against the origin the document came from —
// what `"url": "/v1"` means. A per-operation server naming ANOTHER origin does
// NOT become a second authority: the fetch origin decides, so a document cannot
// widen the set of hosts a credential for it would be minted against.
func TestAuthoritiesRefusesToLetTheDocumentNameAnotherAuthority(t *testing.T) {
	doc := mustParse(t, `openapi: 3.1.0
info: {title: t, version: "1"}
servers: [{url: "/v1"}]
paths:
  /a: {get: {operationId: getA}}
  /b:
    get:
      operationId: getB
      servers: [{url: "https://other.example.test"}]
`)
	authorities, notes, err := doc.Authorities(ServerPolicy{FetchOrigin: "https://api.example.test"})
	if err != nil {
		t.Fatalf("Authorities: %v", err)
	}
	if len(authorities) != 1 || authorities[0] != "api.example.test" {
		t.Fatalf("authorities = %v — an off-origin servers entry must name no authority", authorities)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "other.example.test") {
		t.Fatalf("the ignored entry must be disclosed, got notes %v", notes)
	}

	// --trust-servers is the spelling that opts back in, and it is the only one.
	trusted, _, err := doc.Authorities(ServerPolicy{
		FetchOrigin: "https://api.example.test", TrustServers: true,
	})
	if err != nil {
		t.Fatalf("Authorities: %v", err)
	}
	if len(trusted) != 2 || trusted[1] != "other.example.test" {
		t.Fatalf("--trust-servers must honor the document's authority, got %v", trusted)
	}
}

// ---------------------------------------------------------------------------
// bundles — the structure a flat catalog loses
// ---------------------------------------------------------------------------

func TestActionBundlesKeepsTheANDAlternatives(t *testing.T) {
	bundles, err := mustParse(t, catalogDoc).ActionBundles()
	if err != nil {
		t.Fatalf("ActionBundles: %v", err)
	}
	// Only createPost's [[write:posts, read:profile]] is a combination;
	// getProfile's [read:profile, read:email] is an OR of single tokens and has
	// no structure to keep.
	if len(bundles) != 1 {
		t.Fatalf("bundles = %+v, want exactly the one AND-alternative", bundles)
	}
	if bundles[0].Label() != "write:posts AND read:profile" {
		t.Fatalf("bundle label = %q", bundles[0].Label())
	}
	if len(bundles[0].Operations) != 1 || bundles[0].Operations[0] != "createPost" {
		t.Fatalf("bundle must name the route requiring it: %+v", bundles[0].Operations)
	}
}

// The same combination on two routes is ONE bundle naming both: it is one
// choice to make, not two.
func TestActionBundlesDedupesAcrossOperations(t *testing.T) {
	bundles, err := mustParse(t, `openapi: 3.1.0
info: {title: t, version: "1"}
servers: [{url: "https://api.example.test"}]
paths:
  /a:
    get: {operationId: getA, x-dfos-actions: [[read:profile, read:email]]}
  /b:
    get: {operationId: getB, x-dfos-actions: [[read:profile, read:email]]}
`).ActionBundles()
	if err != nil {
		t.Fatalf("ActionBundles: %v", err)
	}
	if len(bundles) != 1 || len(bundles[0].Operations) != 2 {
		t.Fatalf("bundles = %+v", bundles)
	}
}
