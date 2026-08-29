package cmd

// `dfos api` tests — the registry verbs, the staleness disclosure, and the
// profile the client actually signs for each requirement combination.
//
// These drive RunE against the package globals setupDevices wires, so they MUST
// NOT run with t.Parallel(). setupDevices points DFOS_CONFIG at a temp directory
// and sets DFOS_NO_KEYCHAIN, so nothing here reaches the developer's own state;
// setupAPIRegistry does the same for the API registry.

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/apispec"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/keystore"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// setupAPIRegistry points the registry at a temp directory and refuses every
// network fetch by default — a test that means to fetch says so with withFetcher.
func setupAPIRegistry(t *testing.T) *apispec.Store {
	t.Helper()
	prevStore, prevFetch := apiStoreForTests, apiFetcherForTests
	apiStoreForTests = apispec.NewStoreIn(t.TempDir())
	apiFetcherForTests = func(rawURL string) ([]byte, error) {
		t.Errorf("unexpected network fetch of %s", rawURL)
		return nil, fmt.Errorf("no network in tests")
	}
	t.Cleanup(func() { apiStoreForTests, apiFetcherForTests = prevStore, prevFetch })
	return apiStoreForTests
}

func withFetcher(t *testing.T, responses map[string]string) {
	t.Helper()
	apiFetcherForTests = func(rawURL string) ([]byte, error) {
		if body, ok := responses[rawURL]; ok {
			return []byte(body), nil
		}
		return nil, fmt.Errorf("HTTP 404")
	}
}

// capture runs fn with stdout and stderr swapped for pipes.
func capture(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout, os.Stderr = wOut, wErr
	fn()
	wOut.Close()
	wErr.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	out, _ := io.ReadAll(rOut)
	errOut, _ := io.ReadAll(rErr)
	return string(out), string(errOut)
}

// ---------------------------------------------------------------------------
// the registry verbs
// ---------------------------------------------------------------------------

const registryDoc = `{
  "openapi": "3.1.1",
  "info": {"title": "Test API", "version": "9.9"},
  "servers": [{"url": "https://api.example.test/v1"}],
  "paths": {"/thing": {"get": {"operationId": "getThing"}}}
}`

func TestAPIRegistryVerbs(t *testing.T) {
	setupDevices(t)
	setupAPIRegistry(t)

	add := newAPIAddCmd()
	mustSetFlag(t, add, "file", writeTempDoc(t, registryDoc))
	var registered apispec.Registration
	runJSON(t, add, []string{"test"}, &registered)
	if registered.Kind != apispec.KindFile || registered.Operations != 1 || registered.OpenAPI != "3.1.1" {
		t.Fatalf("registration = %+v", registered)
	}
	if registered.Title != "Test API" || registered.Version != "9.9" {
		t.Fatalf("registration lost the document's self-description: %+v", registered)
	}

	var listed []apiListItem
	runJSON(t, newAPIListCmd(), nil, &listed)
	if len(listed) != 1 || listed[0].Name != "test" || listed[0].Stale {
		t.Fatalf("list = %+v", listed)
	}

	// A second name may point at the same document; names are local labels.
	add2 := newAPIAddCmd()
	mustSetFlag(t, add2, "file", writeTempDoc(t, registryDoc))
	runJSON(t, add2, []string{"other"}, nil)
	runJSON(t, newAPIListCmd(), nil, &listed)
	if len(listed) != 2 || listed[0].Name != "other" || listed[1].Name != "test" {
		t.Fatalf("list must be name-ordered: %+v", listed)
	}

	runJSON(t, newAPIRemoveCmd(), []string{"test"}, nil)
	runJSON(t, newAPIListCmd(), nil, &listed)
	if len(listed) != 1 || listed[0].Name != "other" {
		t.Fatalf("after rm: %+v", listed)
	}

	rm := newAPIRemoveCmd()
	if err := rm.RunE(rm, []string{"test"}); err == nil {
		t.Fatalf("removing an unregistered name must be an error")
	}
	call := newAPICallCmd()
	if err := call.RunE(call, []string{"test", "getThing"}); err == nil ||
		!strings.Contains(err.Error(), "dfos api add test") {
		t.Fatalf("calling an unregistered API must say how to register it, got %v", err)
	}
}

func TestAPIAddDiscoversAndRefreshRerunsDiscovery(t *testing.T) {
	setupDevices(t)
	setupAPIRegistry(t)

	withFetcher(t, map[string]string{
		"https://api.example.test/.well-known/dfos-relay": `{"openapi":"/spec.json"}`,
		"https://api.example.test/spec.json":              registryDoc,
	})
	var registered apispec.Registration
	runJSON(t, newAPIAddCmd(), []string{"test", "api.example.test"}, &registered)
	if registered.Kind != apispec.KindWellKnown || registered.Document != "https://api.example.test/spec.json" {
		t.Fatalf("registration = %+v", registered)
	}
	if registered.Source != "api.example.test" {
		t.Fatalf("the source recorded must be what the user typed, got %q", registered.Source)
	}

	// The host moves its document. Refresh re-runs resolution from the SOURCE,
	// so it follows — a cached document URL is never treated as an address.
	withFetcher(t, map[string]string{
		"https://api.example.test/.well-known/dfos-relay": `{"openapi":"/v2/spec.json"}`,
		"https://api.example.test/v2/spec.json":           registryDoc,
	})
	var refreshed apispec.Registration
	runJSON(t, newAPIRefreshCmd(), []string{"test"}, &refreshed)
	if refreshed.Document != "https://api.example.test/v2/spec.json" {
		t.Fatalf("refresh did not follow the moved document: %+v", refreshed)
	}
}

// ---------------------------------------------------------------------------
// a loopback API that speaks the convention
// ---------------------------------------------------------------------------

// callDoc is the document under test. The server URL carries a TRAILING SLASH
// on purpose: literal concatenation would produce /v1//thing.
const callDoc = `{
  "openapi": "3.1.1",
  "info": {"title": "Test API", "version": "1"},
  "servers": [{"url": "%SERVER%/v1/"}],
  "security": [],
  "components": {
    "securitySchemes": {
      "whoIsAsking":  {"type": "http", "scheme": "dfos", "x-dfos-typ": "did:dfos:identity-proof"},
      "popProof":     {"type": "http", "scheme": "dfos", "x-dfos-typ": "did:dfos:request-proof"},
      "theGrant":     {"type": "apiKey", "in": "header", "name": "X-Credential"}
    }
  },
  "paths": {
    "/open":      {"get": {"operationId": "open"}},
    "/me":        {"get": {"operationId": "me", "security": [{"whoIsAsking": []}]}},
    "/profile":   {"get": {"operationId": "profile",
                    "security": [{"popProof": [], "theGrant": []}],
                    "x-dfos-actions": ["read:profile", "read:email"]}},
    "/anything":  {"get": {"operationId": "anything",
                    "security": [{"popProof": [], "theGrant": []}]}}
  }
}`

// received is what the loopback server saw.
type received struct {
	method        string
	target        string
	authorization string
	credential    string
}

func startAPIServer(t *testing.T, handler func(*received, http.ResponseWriter)) (*httptest.Server, *received) {
	t.Helper()
	last := &received{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*last = received{
			method:        r.Method,
			target:        r.URL.RequestURI(),
			authorization: r.Header.Get("Authorization"),
			credential:    r.Header.Get("X-Credential"),
		}
		handler(last, w)
	}))
	t.Cleanup(srv.Close)
	return srv, last
}

func okJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// registerCallDoc registers callDoc against srv under the name "test".
func registerCallDoc(t *testing.T, store *apispec.Store, srv *httptest.Server, fetchedAt time.Time) {
	t.Helper()
	body := strings.ReplaceAll(callDoc, "%SERVER%", srv.URL)
	if _, err := apispec.Parse([]byte(body)); err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}
	registration := apispec.Registration{
		Name: "test", Source: srv.URL, Document: srv.URL + "/openapi.json",
		Kind: apispec.KindConventional, Origin: srv.URL, FetchedAt: fetchedAt, Operations: 4,
	}
	if err := store.Put(registration, []byte(body)); err != nil {
		t.Fatalf("put: %v", err)
	}
}

func runCall(t *testing.T, args []string, set map[string]string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := newAPICallCmd()
	for name, value := range set {
		mustSetFlag(t, cmd, name, value)
	}
	stdout, stderr = capture(t, func() { err = cmd.RunE(cmd, args) })
	return stdout, stderr, err
}

func TestAPICallAnonymousNormalizesTheServerTrailingSlash(t *testing.T) {
	setupDevices(t)
	store := setupAPIRegistry(t)
	srv, last := startAPIServer(t, func(_ *received, w http.ResponseWriter) { okJSON(w) })
	registerCallDoc(t, store, srv, time.Now())

	stdout, stderr, err := runCall(t, []string{"test", "open"}, nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if last.target != "/v1/open" {
		t.Fatalf("request target = %q, want /v1/open (a trailing slash in the server URL must not double up)", last.target)
	}
	if last.authorization != "" {
		t.Fatalf("an anonymous route must carry no Authorization header, got %q", last.authorization)
	}
	if !strings.Contains(stdout, `"ok": true`) {
		t.Fatalf("stdout = %q", stdout)
	}
	if stderr != "" {
		t.Fatalf("a fresh document must print nothing extra, got stderr %q", stderr)
	}

	// The same route by METHOD + path template.
	if _, _, err := runCall(t, []string{"test", "GET", "/open"}, nil); err != nil {
		t.Fatalf("METHOD path spelling: %v", err)
	}
}

// A stale document says so ON STDERR, proceeds, and never refetches: stdout
// stays exactly the response document.
func TestAPICallDisclosesStalenessWithoutRefetching(t *testing.T) {
	setupDevices(t)
	store := setupAPIRegistry(t)
	srv, _ := startAPIServer(t, func(_ *received, w http.ResponseWriter) { okJSON(w) })
	registerCallDoc(t, store, srv, time.Now().Add(-3*24*time.Hour))

	// apiFetcherForTests fails the test if it is called at all — the assertion
	// that a call never surprise-networks beyond the call itself.
	stdout, stderr, err := runCall(t, []string{"test", "open"}, nil)
	if err != nil {
		t.Fatalf("a stale document must still make the call: %v", err)
	}
	if !strings.Contains(stderr, "spec for test is 3d old") || !strings.Contains(stderr, "dfos api refresh test") {
		t.Fatalf("stderr = %q", stderr)
	}
	if !strings.Contains(stdout, `"ok": true`) || strings.Contains(stdout, "spec for test") {
		t.Fatalf("the staleness line must not reach stdout: %q", stdout)
	}
}

// ---------------------------------------------------------------------------
// the artifacts each profile signs
// ---------------------------------------------------------------------------

// plantCredential stores a credential for subject, issued to a freshly minted
// login client, granting action on api:<authority>.
func plantCredential(t *testing.T, store *keystore.MemoryStore, subject, authority, action string) string {
	t.Helper()
	keys = store
	client, clientPriv, err := ensureLoginClient()
	if err != nil {
		t.Fatalf("mint login client: %v", err)
	}
	credential, err := protocol.CreateCredential(subject, client.DID, subject+"#key_issuer",
		"api:"+authority, action, time.Hour, clientPriv)
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}
	if _, err := storeLoginCredential(subject, client, credential); err != nil {
		t.Fatalf("store credential: %v", err)
	}
	return credential
}

// resolverFor answers the verifier's key lookups from the identity chain in the
// local relay, plus the login client's own key.
func resolverFor(t *testing.T, extra map[string]ed25519.PublicKey) protocol.KeyResolver {
	t.Helper()
	return func(kid string) (ed25519.PublicKey, error) {
		if pub, ok := extra[kid]; ok {
			return pub, nil
		}
		did, keyID, _ := strings.Cut(kid, "#")
		lr, err := getRelay()
		if err != nil {
			return nil, err
		}
		chain, err := lr.Relay.GetIdentity(did)
		if err != nil || chain == nil {
			return nil, fmt.Errorf("unknown DID %s", did)
		}
		for _, k := range chain.State.AuthKeys {
			if k.ID == keyID {
				raw, err := protocol.DecodeMultikey(k.PublicKeyMultibase)
				if err != nil {
					return nil, err
				}
				return ed25519.PublicKey(raw), nil
			}
		}
		return nil, fmt.Errorf("no key %s on %s", keyID, did)
	}
}

func TestAPICallSignsTheArtifactTheCombinationNames(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	store := setupAPIRegistry(t)

	srv, last := startAPIServer(t, func(r *received, w http.ResponseWriter) { okJSON(w) })
	registerCallDoc(t, store, srv, time.Now())
	authority := apispec.NormalizeAuthority("http", strings.TrimPrefix(srv.URL, "http://"))

	subject := createIdentity(t, "alice", storeA)
	credential := plantCredential(t, storeA, subject, authority, "read:profile")
	client, clientPriv, err := ensureLoginClient()
	if err != nil {
		t.Fatal(err)
	}
	resolve := resolverFor(t, map[string]ed25519.PublicKey{
		client.DID + "#" + client.KeyID: clientPriv.Public().(ed25519.PublicKey),
	})

	t.Run("the identity-proof combination signs an identity proof and no credential", func(t *testing.T) {
		if _, _, err := runCall(t, []string{"test", "me"}, nil); err != nil {
			t.Fatalf("call: %v", err)
		}
		if last.credential != "" {
			t.Fatalf("an identity-proof-only route must carry no X-Credential, got %q", last.credential)
		}
		token := protocol.ParseDFOSAuthorization(last.authorization)
		if token == "" {
			t.Fatalf("Authorization = %q", last.authorization)
		}
		verified, err := protocol.VerifyIdentityProof(token, protocol.IdentityProofExpectations{
			Method: "GET", Host: authority, Path: "/v1/me",
		}, resolve, time.Now())
		if err != nil {
			t.Fatalf("the signed identity proof does not verify against the spec: %v", err)
		}
		if verified.PresenterDID != subject {
			t.Fatalf("presenter = %s, want the resolved identity %s", verified.PresenterDID, subject)
		}
		// A request proof presented where an identity proof is required MUST be
		// rejected at the header gate — the typ scoping is what keeps the two
		// claims distinct, and this asserts the client picked the right one.
		if _, err := protocol.VerifyRequestProof(token, protocol.RequestProofExpectations{
			Method: "GET", Host: authority, Path: "/v1/me",
		}, resolve, time.Now()); err == nil {
			t.Fatalf("an identity proof passed a request-proof gate")
		}
	})

	t.Run("the delegated combination signs a request proof bound to the credential", func(t *testing.T) {
		if _, _, err := runCall(t, []string{"test", "profile"}, nil); err != nil {
			t.Fatalf("call: %v", err)
		}
		if last.credential != credential {
			t.Fatalf("X-Credential = %q, want the stored credential", last.credential)
		}
		token := protocol.ParseDFOSAuthorization(last.authorization)
		verified, err := protocol.VerifyRequestProof(token, protocol.RequestProofExpectations{
			Method: "GET", Host: authority, Path: "/v1/profile",
		}, resolve, time.Now())
		if err != nil {
			t.Fatalf("the signed request proof does not verify against the spec: %v", err)
		}
		// kid names the credential's audience — that equality IS the possession
		// being proven — and credentialCID is read from the credential's own header.
		if verified.PresenterDID != client.DID {
			t.Fatalf("presenter = %s, want the credential's audience %s", verified.PresenterDID, client.DID)
		}
		header, _, err := protocol.DecodeJWSUnsafe(credential)
		if err != nil {
			t.Fatal(err)
		}
		if verified.Payload.CredentialCID != header.CID {
			t.Fatalf("credentialCID = %q, want the credential's own cid header %q",
				verified.Payload.CredentialCID, header.CID)
		}
		if _, err := protocol.VerifyIdentityProof(token, protocol.IdentityProofExpectations{
			Method: "GET", Host: authority, Path: "/v1/profile",
		}, resolve, time.Now()); err == nil {
			t.Fatalf("a request proof passed an identity-proof gate")
		}
	})

	t.Run("presentation-suffices — a delegated route with no x-dfos-actions still calls", func(t *testing.T) {
		// The stored credential grants read:profile and the route requires no
		// particular token. A credential may always describe itself.
		if _, _, err := runCall(t, []string{"test", "anything"}, nil); err != nil {
			t.Fatalf("call: %v", err)
		}
		if last.credential == "" {
			t.Fatalf("the delegated combination must present a credential even with no actions declared")
		}
	})

	t.Run("--anon forces the anonymous profile over the document", func(t *testing.T) {
		if _, _, err := runCall(t, []string{"test", "profile"}, map[string]string{"anon": "true"}); err != nil {
			t.Fatalf("call: %v", err)
		}
		if last.authorization != "" || last.credential != "" {
			t.Fatalf("--anon must sign nothing, got %q / %q", last.authorization, last.credential)
		}
	})
}

func TestAPICallDelegatedRefusesWithoutACredential(t *testing.T) {
	setupDevices(t)
	store := setupAPIRegistry(t)
	srv, _ := startAPIServer(t, func(_ *received, w http.ResponseWriter) { okJSON(w) })
	registerCallDoc(t, store, srv, time.Now())

	_, _, err := runCall(t, []string{"test", "profile"}, nil)
	if err == nil {
		t.Fatalf("a delegated route with nothing stored must refuse")
	}
	if !strings.Contains(err.Error(), "no stored credential covers api:") ||
		!strings.Contains(err.Error(), "dfos login") {
		t.Fatalf("err = %v — it must name the resource and how to obtain a grant", err)
	}
}

// 401 and 403 mean different things and must read differently: the proof layer
// versus the credential layer. Action tokens are echoed VERBATIM in the 403,
// because this client never interprets one.
func TestAPICallRendersAuthAndScopeFailuresDistinguishably(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	store := setupAPIRegistry(t)

	status := http.StatusUnauthorized
	srv, _ := startAPIServer(t, func(_ *received, w http.ResponseWriter) {
		if status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", "DFOS")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"message":"nope"}`))
	})
	registerCallDoc(t, store, srv, time.Now())
	authority := apispec.NormalizeAuthority("http", strings.TrimPrefix(srv.URL, "http://"))

	subject := createIdentity(t, "alice", storeA)
	plantCredential(t, storeA, subject, authority, "read:memberships")

	_, _, err := runCall(t, []string{"test", "profile"}, nil)
	if err == nil {
		t.Fatal("expected a 401")
	}
	for _, want := range []string{"HTTP 401", "the proof layer refused", "challenge: DFOS", "Nothing was retried"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("401 error missing %q:\n%v", want, err)
		}
	}

	status = http.StatusForbidden
	_, _, err = runCall(t, []string{"test", "profile"}, nil)
	if err == nil {
		t.Fatal("expected a 403")
	}
	for _, want := range []string{
		"HTTP 403", "the credential layer refused",
		"requires: read:profile OR read:email",
		"grants on api:" + authority + ": read:memberships",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("403 error missing %q:\n%v", want, err)
		}
	}
	if strings.Contains(err.Error(), "the proof layer") {
		t.Fatalf("a 403 must not read as an auth failure:\n%v", err)
	}

	status = http.StatusServiceUnavailable
	_, _, err = runCall(t, []string{"test", "profile"}, nil)
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") ||
		!strings.Contains(err.Error(), "not a verdict on the request") {
		t.Fatalf("503 must read as the host's condition:\n%v", err)
	}
}

func TestAPICallOperationResolutionErrors(t *testing.T) {
	setupDevices(t)
	store := setupAPIRegistry(t)
	srv, _ := startAPIServer(t, func(_ *received, w http.ResponseWriter) { okJSON(w) })
	registerCallDoc(t, store, srv, time.Now())

	if _, _, err := runCall(t, []string{"test", "nope"}, nil); err == nil ||
		!strings.Contains(err.Error(), `operationId "nope"`) {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := runCall(t, []string{"test", "GET"}, nil); err == nil ||
		!strings.Contains(err.Error(), "is an HTTP method, not an operationId") {
		t.Fatalf("a bare method must be named as such, got %v", err)
	}
	if _, _, err := runCall(t, []string{"test", "GET", "/nope"}, nil); err == nil ||
		!strings.Contains(err.Error(), "no GET /nope") {
		t.Fatalf("err = %v", err)
	}
}

// Signing a proof for a plaintext request to a non-loopback host is refused
// BEFORE the signature: a proof sent in the clear replays for its whole
// freshness window.
func TestAPICallRefusesToSignPlaintextToARealHost(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	store := setupAPIRegistry(t)

	body := strings.ReplaceAll(callDoc, "%SERVER%", "http://api.example.test")
	if err := store.Put(apispec.Registration{
		Name: "plain", Source: "http://api.example.test", Document: "x",
		Kind: apispec.KindDirect, Origin: "http://api.example.test", FetchedAt: time.Now(),
	}, []byte(body)); err != nil {
		t.Fatal(err)
	}
	createIdentity(t, "alice", storeA)

	_, _, err := runCall(t, []string{"plain", "me"}, nil)
	if err == nil || !strings.Contains(err.Error(), "refusing to sign a http:// request") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseKeyValues(t *testing.T) {
	got, err := parseKeyValues([]string{"a=1", "b=x=y", "c="}, "--param")
	if err != nil {
		t.Fatal(err)
	}
	if got["a"] != "1" || got["b"] != "x=y" || got["c"] != "" {
		t.Fatalf("got %v", got)
	}
	if _, err := parseKeyValues([]string{"noequals"}, "--param"); err == nil {
		t.Fatalf("a value with no '=' must be refused")
	}
}

func TestHumanAge(t *testing.T) {
	cases := map[time.Duration]string{
		30 * time.Second: "just now",
		90 * time.Minute: "1h",
		50 * time.Hour:   "2d",
	}
	for d, want := range cases {
		if got := humanAge(d); got != want {
			t.Fatalf("humanAge(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestAPIListJSONShapeIsRoundTrippable(t *testing.T) {
	setupDevices(t)
	store := setupAPIRegistry(t)
	if err := store.Put(apispec.Registration{
		Name: "test", Source: "s", Document: "d", Kind: apispec.KindDirect,
		FetchedAt: time.Now().Add(-2 * time.Hour),
	}, []byte(registryDoc)); err != nil {
		t.Fatal(err)
	}
	var raw []map[string]any
	runJSON(t, newAPIListCmd(), nil, &raw)
	if len(raw) != 1 {
		t.Fatalf("raw = %v", raw)
	}
	for _, key := range []string{"name", "source", "document", "kind", "fetchedAt", "ageSeconds", "stale"} {
		if _, ok := raw[0][key]; !ok {
			t.Fatalf("list --json is missing %q: %v", key, raw[0])
		}
	}
	if _, err := json.Marshal(raw); err != nil {
		t.Fatal(err)
	}
}

// apispecRegistrationForTest is a minimal registration for tests that only need
// `api list` to have something to print.
func apispecRegistrationForTest() apispec.Registration {
	return apispec.Registration{
		Name: "test", Source: "s", Document: "d",
		Kind: apispec.KindDirect, FetchedAt: time.Now(),
	}
}
