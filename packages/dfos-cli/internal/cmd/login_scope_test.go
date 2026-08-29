package cmd

// The scope ask. Every rule that decides WHICH action tokens a login asks for —
// explicit beats ask, --all-scopes takes the union, no terminal chooses nothing
// — is exercised here as a pure fold against a reader the test itself supplies.
// Nothing reaches the network: the target tests drive the same registry and
// fetcher stubs `dfos api` tests use.

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/apispec"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// scopeDoc advertises a catalog of two described actions plus one an operation
// requires and the catalog never listed.
const scopeDoc = `{
  "openapi": "3.1.1",
  "info": {"title": "Scoped API", "version": "1"},
  "servers": [{"url": "https://api.example.test/v1"}],
  "paths": {
    "/posts": {
      "post": {
        "operationId": "createPost",
        "x-dfos-actions": ["write:posts"],
        "security": [{"popProof": [], "theGrant": []}]
      }
    }
  },
  "components": {
    "securitySchemes": {
      "popProof": {
        "type": "http", "scheme": "dfos", "x-dfos-typ": "did:dfos:request-proof",
        "x-dfos-actions": {
          "read:profile": "Read the granting user's own profile",
          "read:email": "Read the granting user's account email address"
        }
      },
      "theGrant": {"type": "apiKey", "in": "header", "name": "X-Credential"}
    }
  }
}`

func scopeTarget(t *testing.T) *loginTarget {
	t.Helper()
	doc, err := apispec.Parse([]byte(scopeDoc))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	catalog, err := doc.ActionCatalog()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	return &loginTarget{Name: "scoped", Authority: "api.example.test", Document: "memory", Catalog: catalog}
}

// A refusing reader proves the ask was never reached. A path that "happens not
// to read" and one that cannot read are different guarantees, and this is the
// one worth having.
type refusingReader struct{ t *testing.T }

func (r refusingReader) Read([]byte) (int, error) {
	r.t.Fatalf("the scope ask read stdin when it must not have")
	return 0, nil
}

// ---------------------------------------------------------------------------
// which scope a run asks for
// ---------------------------------------------------------------------------

// EXPLICIT BEATS ASK: a typed scope is an instruction, carried through
// unchanged and never widened, reordered, or checked against the catalog.
func TestResolveLoginScopeExplicitBeatsAsk(t *testing.T) {
	target := scopeTarget(t)
	var out bytes.Buffer
	// A token the document never advertises — the catalog is a menu, not a
	// vocabulary this client enforces.
	scope, err := resolveLoginScope(target, "read:email nothing:known", false, refusingReader{t}, &out, true)
	if err != nil {
		t.Fatalf("resolveLoginScope: %v", err)
	}
	if scope != "read:email nothing:known" {
		t.Fatalf("scope = %q", scope)
	}
	if out.Len() != 0 {
		t.Fatalf("an explicit scope printed a menu: %q", out.String())
	}
}

// --all-scopes takes the union in CATALOG order, with no prompt.
func TestResolveLoginScopeAllScopes(t *testing.T) {
	var out bytes.Buffer
	scope, err := resolveLoginScope(scopeTarget(t), "", true, refusingReader{t}, &out, true)
	if err != nil {
		t.Fatalf("resolveLoginScope: %v", err)
	}
	if scope != "read:profile read:email write:posts" {
		t.Fatalf("scope = %q", scope)
	}
}

// NO TERMINAL, NO EXPLICIT SCOPE: an error that names every choice and both
// ways to make one. Never a silent default — a scope picked on a person's
// behalf is a grant they never made.
func TestResolveLoginScopeRefusesToChooseWithoutATerminal(t *testing.T) {
	_, err := resolveLoginScope(scopeTarget(t), "", false, refusingReader{t}, &bytes.Buffer{}, false)
	if err == nil {
		t.Fatalf("a non-interactive run with no scope must error")
	}
	for _, want := range []string{"read:profile", "read:email", "write:posts", "--scope", "--all-scopes", "api.example.test"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error must name %q, got:\n%s", want, err)
		}
	}
}

// A document that advertises nothing has nothing to offer, and says so with the
// one way out rather than inventing a token.
func TestResolveLoginScopeEmptyCatalog(t *testing.T) {
	target := &loginTarget{Authority: "api.example.test"}
	_, err := resolveLoginScope(target, "", true, refusingReader{t}, &bytes.Buffer{}, true)
	if err == nil || !strings.Contains(err.Error(), "--scope") {
		t.Fatalf("want a pointer at --scope, got %v", err)
	}
	// ...and an explicit scope still works against such a document.
	scope, err := resolveLoginScope(target, "read:whatever", false, refusingReader{t}, &bytes.Buffer{}, true)
	if err != nil || scope != "read:whatever" {
		t.Fatalf("explicit scope over an empty catalog = %q, %v", scope, err)
	}
}

// ---------------------------------------------------------------------------
// reading a selection
// ---------------------------------------------------------------------------

func TestSelectCatalogActions(t *testing.T) {
	catalog := scopeTarget(t).Catalog
	all := "read:profile read:email write:posts"

	for _, tc := range []struct {
		answer string
		want   string
	}{
		{"\n", all},
		{"   \n", all},
		{"all\n", all},
		{"ALL\n", all},
		{"1\n", "read:profile"},
		{"1,3\n", "read:profile write:posts"},
		{"3 1\n", "read:profile write:posts"},         // catalog order, not typed order
		{"read:email\n", "read:email"},                // by token
		{"2,write:posts\n", "read:email write:posts"}, // mixed
		{"1,1,1\n", "read:profile"},                   // a set, not a list
	} {
		got, err := selectCatalogActions(catalog, tc.answer)
		if err != nil {
			t.Fatalf("select(%q): %v", tc.answer, err)
		}
		if strings.Join(got, " ") != tc.want {
			t.Fatalf("select(%q) = %v, want %q", tc.answer, got, tc.want)
		}
	}
}

func TestSelectCatalogActionsRejections(t *testing.T) {
	catalog := scopeTarget(t).Catalog
	for _, tc := range []struct{ answer, want string }{
		{"9\n", "not one of the 3 actions"},
		{"0\n", "not one of the 3 actions"},
		{"read:nothing\n", "neither a number in the list nor an advertised action token"},
	} {
		_, err := selectCatalogActions(catalog, tc.answer)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("select(%q) = %v, want an error containing %q", tc.answer, err, tc.want)
		}
	}
}

// The menu shows every token, the descriptions the catalog wrote, and the
// answer becomes the scope.
func TestAskForScopesPresentsTheCatalogAndFoldsTheAnswer(t *testing.T) {
	var out bytes.Buffer
	scope, err := askForScopes(scopeTarget(t), strings.NewReader("1,3\n"), &out)
	if err != nil {
		t.Fatalf("askForScopes: %v", err)
	}
	if scope != "read:profile write:posts" {
		t.Fatalf("scope = %q", scope)
	}
	menu := out.String()
	for _, want := range []string{
		"read:profile", "Read the granting user's own profile",
		"read:email", "Read the granting user's account email address",
		"write:posts", "Asking for: read:profile write:posts",
	} {
		if !strings.Contains(menu, want) {
			t.Fatalf("menu must contain %q, got:\n%s", want, menu)
		}
	}
}

// ---------------------------------------------------------------------------
// which API a login is scoped to
// ---------------------------------------------------------------------------

func TestResolveLoginTargetPrefersARegisteredName(t *testing.T) {
	setupDevices(t)
	setupAPIRegistry(t)

	add := newAPIAddCmd()
	mustSetFlag(t, add, "file", writeTempDoc(t, scopeDoc))
	runJSON(t, add, []string{"scoped"}, nil)

	// The fetcher fails every call, so a resolution that reached the network
	// would fail rather than pass quietly.
	target, err := resolveLoginTarget("scoped", refusingReader{t}, &bytes.Buffer{}, false)
	if err != nil {
		t.Fatalf("resolveLoginTarget: %v", err)
	}
	if target.Name != "scoped" || target.Authority != "api.example.test" {
		t.Fatalf("target = %+v", target)
	}
	if target.Resource() != "api:api.example.test" {
		t.Fatalf("resource = %q", target.Resource())
	}
	if len(target.Catalog) != 3 {
		t.Fatalf("catalog = %+v", target.Catalog)
	}
}

// A bare host runs the SAME discovery `api add` runs, and offers to keep what
// it found under a local name.
func TestResolveLoginTargetDiscoversAndOffersToRegister(t *testing.T) {
	setupDevices(t)
	setupAPIRegistry(t)
	withFetcher(t, map[string]string{
		"https://api.example.test/.well-known/dfos-relay": `{"openapi": "https://api.example.test/openapi.json"}`,
		"https://api.example.test/openapi.json":           scopeDoc,
	})

	var out bytes.Buffer
	target, err := resolveLoginTarget("api.example.test", strings.NewReader("\n"), &out, true)
	if err != nil {
		t.Fatalf("resolveLoginTarget: %v", err)
	}
	if target.Authority != "api.example.test" || target.Name != "api.example.test" {
		t.Fatalf("target = %+v", target)
	}
	registrations, err := apiStore().List()
	if err != nil || len(registrations) != 1 || registrations[0].Name != "api.example.test" {
		t.Fatalf("registry = %+v (%v)", registrations, err)
	}

	// Declining is a first-class answer: the credential lands either way.
	setupAPIRegistry(t)
	withFetcher(t, map[string]string{
		"https://api.example.test/.well-known/dfos-relay": `{"openapi": "https://api.example.test/openapi.json"}`,
		"https://api.example.test/openapi.json":           scopeDoc,
	})
	target, err = resolveLoginTarget("api.example.test", strings.NewReader("-\n"), &out, true)
	if err != nil {
		t.Fatalf("resolveLoginTarget (declined): %v", err)
	}
	if target.Name != "" || target.Authority != "api.example.test" {
		t.Fatalf("declined target = %+v", target)
	}
	if registrations, _ := apiStore().List(); len(registrations) != 0 {
		t.Fatalf("declining registered anyway: %+v", registrations)
	}
}

// A document spanning two authorities is two grants. Picking one for the
// operator would hand them a credential for a host they did not name.
func TestDocumentAuthorityRefusesMoreThanOne(t *testing.T) {
	doc, err := apispec.Parse([]byte(`{
	  "openapi": "3.1.1",
	  "info": {"title": "t", "version": "1"},
	  "servers": [{"url": "https://one.example.test"}],
	  "paths": {
	    "/a": {"get": {"operationId": "getA"}},
	    "/b": {"get": {"operationId": "getB", "servers": [{"url": "https://two.example.test"}]}}
	  }
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err = documentAuthority(doc, "", "spread")
	if err == nil || !strings.Contains(err.Error(), "one.example.test") || !strings.Contains(err.Error(), "two.example.test") {
		t.Fatalf("want an error naming both authorities, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// what came back
// ---------------------------------------------------------------------------

// credentialWithResources mints a credential shaped the way an authorize host
// returns one: `aud` is the login client, and the HOST lives in the attenuation.
func credentialWithResources(t *testing.T, resources ...string) string {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	att := make([]any, 0, len(resources))
	for _, resource := range resources {
		att = append(att, map[string]any{"resource": resource, "action": "read:profile"})
	}
	token, err := protocol.CreateJWS(protocol.JWSHeader{
		Alg: "EdDSA", Typ: credentialJWSTyp, Kid: testLoginSubject + "#key_test",
	}, map[string]any{"iss": testLoginSubject, "aud": testLoginOther, "att": att}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// THE HOST IS IN THE ATTENUATION, not in `aud`. `aud` is this installation's
// login client in every case, so it says nothing about which host a grant is
// for; `api call` selects on `att[].resource`, and so does this.
func TestCredentialNamesResourceReadsTheAttenuation(t *testing.T) {
	token := credentialWithResources(t, "api:api.example.test", "content:abc")

	found, resources := credentialNamesResource(token, "api:api.example.test")
	if !found {
		t.Fatalf("the attenuation names the resource but it was not found (%v)", resources)
	}
	if len(resources) != 2 || resources[0] != "api:api.example.test" || resources[1] != "content:abc" {
		t.Fatalf("resources = %v", resources)
	}
	// The audience is never the host, and must never be read as one.
	if found, _ := credentialNamesResource(token, "api:"+testLoginOther); found {
		t.Fatalf("the audience was read as a host")
	}
	if found, _ := credentialNamesResource(token, "api:other.example.test"); found {
		t.Fatalf("a resource the credential never names matched")
	}
	if found, _ := credentialNamesResource("not-a-jws", "api:api.example.test"); found {
		t.Fatalf("an undecodable credential matched")
	}
}

// A credential that does not name the host is stored and SAID OUT LOUD: `api
// call` selects by that resource, so discovering the gap three commands later
// is the papercut the warning exists to prevent.
func TestWarnCredentialHostMismatch(t *testing.T) {
	target := &loginTarget{Authority: "api.example.test"}

	var quiet bytes.Buffer
	warnCredentialHostMismatch(credentialWithResources(t, "api:api.example.test"), target, &quiet)
	if quiet.Len() != 0 {
		t.Fatalf("a matching credential warned: %q", quiet.String())
	}

	var loud bytes.Buffer
	warnCredentialHostMismatch(credentialWithResources(t, "api:other.example.test"), target, &loud)
	for _, want := range []string{"api:api.example.test", "api:other.example.test", "dfos api call"} {
		if !strings.Contains(loud.String(), want) {
			t.Fatalf("warning must name %q, got:\n%s", want, loud.String())
		}
	}

	// No --host means no host to check against, and nothing to say.
	var none bytes.Buffer
	warnCredentialHostMismatch(credentialWithResources(t, "api:other.example.test"), nil, &none)
	if none.Len() != 0 {
		t.Fatalf("a login with no --host warned: %q", none.String())
	}
}

// ---------------------------------------------------------------------------
// flag combinations
// ---------------------------------------------------------------------------

// The flag gates are refused BEFORE anything resolves an identity, opens a
// listener, or reaches the network, so an unusable combination costs one line
// of output rather than a browser window.
func TestLoginScopeFlagCombinations(t *testing.T) {
	setupDevices(t)

	for _, tc := range []struct {
		name  string
		flags map[string]string
		want  string
	}{
		{"all-scopes needs a host", map[string]string{"all-scopes": "true"}, "--all-scopes needs --host"},
		{"scope and all-scopes disagree",
			map[string]string{"all-scopes": "true", "scope": "read:profile", "host": "api.example.test"},
			"pass --scope or --all-scopes, not both"},
		{"an empty scope is not a scope", map[string]string{"scope": ""}, "--scope must be non-empty"},
		{"a bad timeout is still a bad timeout", map[string]string{"timeout": "soon"}, "invalid --timeout"},
	} {
		cmd := newLoginCmd()
		for name, value := range tc.flags {
			mustSetFlag(t, cmd, name, value)
		}
		err := cmd.RunE(cmd, nil)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want one containing %q", tc.name, err, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// the pointer `api call` hands back
// ---------------------------------------------------------------------------

// The corrective text names the flag that now exists. Before --host there was
// no way to say "sign in for THIS host", so the pointer asked for a scope the
// operator had no way to look up.
func TestCredentialSelectionPointsAtLoginHost(t *testing.T) {
	setupDevices(t)

	_, err := selectCredentialForHost("api.example.test")
	if err == nil {
		t.Fatalf("an empty credential store must refuse")
	}
	for _, want := range []string{
		"no stored credential covers api:api.example.test",
		"dfos login --host api.example.test --as <name|did>",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error must contain %q, got:\n%s", want, err)
		}
	}
	if strings.Contains(err.Error(), "--scope <scope>") {
		t.Fatalf("the pre---host spelling survived:\n%s", err)
	}
}
