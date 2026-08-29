package apispec

import (
	"strings"
	"testing"
)

const paramDoc = `openapi: 3.1.1
info: {title: t, version: "1"}
servers:
  - url: %SERVER%
paths:
  /spaces/{space}/posts:
    parameters:
      - name: space
        in: path
        required: true
        schema: {type: string}
    get:
      operationId: listPosts
      parameters:
        - name: limit
          in: query
          schema: {type: integer}
        - name: after
          in: query
          schema: {type: string}
  /profile:
    get:
      operationId: getProfile
`

func paramFixture(t *testing.T, server string) *Doc {
	t.Helper()
	doc, err := Parse([]byte(strings.ReplaceAll(paramDoc, "%SERVER%", server)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return doc
}

func TestJoinServerPathNormalizesTrailingSlash(t *testing.T) {
	cases := []struct{ server, path, want string }{
		{"https://api.dfos.com/v1", "/spaces", "https://api.dfos.com/v1/spaces"},
		{"https://api.dfos.com/v1/", "/spaces", "https://api.dfos.com/v1/spaces"},
		{"https://api.dfos.com/v1///", "/spaces", "https://api.dfos.com/v1/spaces"},
		{"https://api.dfos.com/", "/spaces", "https://api.dfos.com/spaces"},
	}
	for _, tc := range cases {
		got, err := JoinServerPath(tc.server, tc.path)
		if err != nil {
			t.Fatalf("JoinServerPath(%q, %q): %v", tc.server, tc.path, err)
		}
		if got != tc.want {
			t.Fatalf("JoinServerPath(%q, %q) = %q, want %q", tc.server, tc.path, got, tc.want)
		}
	}
	if _, err := JoinServerPath("https://api.dfos.com/v1", "spaces"); err == nil {
		t.Fatalf("a path that does not begin with / must be refused")
	}
}

// The trailing slash reaches the built request, not just the join helper: a
// document whose server URL carries one must still produce /v1/spaces.
func TestBuildRequestSurvivesATrailingSlashInTheServerURL(t *testing.T) {
	for _, server := range []string{"https://api.example.test/v1", "https://api.example.test/v1/"} {
		doc := paramFixture(t, server)
		op, err := doc.FindOperation("listPosts")
		if err != nil {
			t.Fatal(err)
		}
		choice, err := op.ResolveServer(ServerPolicy{})
		if err != nil {
			t.Fatal(err)
		}
		base := choice.Base
		req, err := op.BuildRequest(base, map[string]string{"space": "nce"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if req.Target != "/v1/spaces/nce/posts" {
			t.Fatalf("server %q produced target %q", server, req.Target)
		}
		if req.URL != "https://api.example.test/v1/spaces/nce/posts" {
			t.Fatalf("server %q produced URL %q", server, req.URL)
		}
		if req.Authority != "api.example.test" {
			t.Fatalf("authority = %q", req.Authority)
		}
	}
}

func TestBuildRequestParameters(t *testing.T) {
	doc := paramFixture(t, "https://api.example.test/v1")
	op, err := doc.FindOperation("listPosts")
	if err != nil {
		t.Fatal(err)
	}
	resolved, _ := op.ResolveServer(ServerPolicy{})
	base := resolved.Base

	t.Run("query parameters land in the target the proof binds", func(t *testing.T) {
		req, err := op.BuildRequest(base, map[string]string{"space": "nce", "limit": "2", "after": "a b"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if req.Target != "/v1/spaces/nce/posts?after=a+b&limit=2" {
			t.Fatalf("target = %q", req.Target)
		}
	})

	t.Run("a path parameter is percent-encoded", func(t *testing.T) {
		req, err := op.BuildRequest(base, map[string]string{"space": "a/b"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if req.Target != "/v1/spaces/a%2Fb/posts" {
			t.Fatalf("target = %q", req.Target)
		}
	})

	t.Run("a missing required parameter is named", func(t *testing.T) {
		_, err := op.BuildRequest(base, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "space (path)") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("an undeclared parameter is refused, not dropped", func(t *testing.T) {
		_, err := op.BuildRequest(base, map[string]string{"space": "nce", "nope": "1"}, nil)
		if err == nil || !strings.Contains(err.Error(), `declares no parameter "nope"`) {
			t.Fatalf("err = %v", err)
		}
	})
}

// A relative server URL — the `"url": "/v1"` spelling — resolves against the
// origin the document was fetched from.
func TestRelativeServerURLResolvesAgainstTheOrigin(t *testing.T) {
	doc := paramFixture(t, "/v1")
	op, err := doc.FindOperation("getProfile")
	if err != nil {
		t.Fatal(err)
	}
	choice, err := op.ResolveServer(ServerPolicy{FetchOrigin: "https://api.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if choice.Base != "https://api.example.test/v1" {
		t.Fatalf("server = %q", choice.Base)
	}
	// A relative server URL names no authority, so resolving one discloses
	// nothing: there was never anything here to distrust.
	if choice.Note != "" {
		t.Fatalf("a relative server URL needs no disclosure, got %q", choice.Note)
	}
	if _, err := op.ResolveServer(ServerPolicy{}); err == nil {
		t.Fatalf("a relative server URL with no known origin must be refused")
	}
}

func TestNormalizeAuthorityDropsTheDefaultPort(t *testing.T) {
	cases := []struct{ scheme, hostport, want string }{
		{"https", "API.dfos.com", "api.dfos.com"},
		{"https", "api.dfos.com:443", "api.dfos.com"},
		{"https", "api.example.org:8443", "api.example.org:8443"},
		{"http", "localhost:80", "localhost"},
		{"http", "localhost:8080", "localhost:8080"},
	}
	for _, tc := range cases {
		if got := NormalizeAuthority(tc.scheme, tc.hostport); got != tc.want {
			t.Fatalf("NormalizeAuthority(%q, %q) = %q, want %q", tc.scheme, tc.hostport, got, tc.want)
		}
	}
}

func TestFindRouteAndFindOperation(t *testing.T) {
	doc := paramFixture(t, "https://api.example.test/v1")
	if _, err := doc.FindRoute("get", "/profile"); err != nil {
		t.Fatalf("FindRoute is method-case-insensitive: %v", err)
	}
	if _, err := doc.FindRoute("GET", "/spaces/nce/posts"); err == nil {
		t.Fatalf("a concrete path must not match a template — the parameter segment is unknowable")
	}
	if _, err := doc.FindOperation("listPost"); err == nil {
		t.Fatalf("operationId matching must be exact")
	}
}

func TestParseRejectsNonOpenAPIDocuments(t *testing.T) {
	for _, body := range []string{
		``,
		`{"hello":"world"}`,
		`{"swagger":"2.0","info":{"title":"t","version":"1"},"paths":{}}`,
	} {
		if _, err := Parse([]byte(body)); err == nil {
			t.Fatalf("Parse(%q) must fail", body)
		}
	}
}
