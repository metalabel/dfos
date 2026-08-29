package cmd

// Login tests. Every rule the CLI enforces on its own — the callback split, the
// store-of-size-one replay check, the DfosAuthorizationServer discovery fold,
// the wire artifacts, and the signature gates — is exercised here as a pure
// fold or against a loopback socket the test itself binds. Nothing reaches the
// network: the only listener is the one under test, on 127.0.0.1.
//
// The client-identity tests mutate the package-global `keys`, so as with the
// multi-device tests they MUST NOT run with t.Parallel().

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/keystore"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

const (
	testLoginSubject = "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae"
	testLoginOther   = "did:dfos:cv7n8vkvr64cctf3294h9k4eanhff8z"
)

func testChallenge(subject string) protocol.SiwdChallenge {
	did := subject
	return protocol.SiwdChallenge{
		Domain:    loopbackHost,
		Nonce:     "login-nonce-01",
		Timestamp: "2026-08-10T12:34:56.000Z",
		DID:       &did,
	}
}

// signSiwdChallenge produces a subject's sign-in artifact the way an authorize
// host would: the canonical challenge bytes as the payload segment, under the
// sign-in typ.
func signSiwdChallenge(t *testing.T, challenge protocol.SiwdChallenge, kid string, priv ed25519.PrivateKey) string {
	t.Helper()
	return signSiwdChallengeTyp(t, challenge, kid, priv, protocol.SiwdJWSTyp)
}

func signSiwdChallengeTyp(t *testing.T, challenge protocol.SiwdChallenge, kid string, priv ed25519.PrivateKey, typ string) string {
	t.Helper()
	payload, err := protocol.SiwdSigningInput(challenge)
	if err != nil {
		t.Fatalf("signing input: %v", err)
	}
	header, err := json.Marshal(protocol.JWSHeader{Alg: "EdDSA", Typ: typ, Kid: kid})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	signingInput := protocol.Base64urlEncode(header) + "." + protocol.Base64urlEncode(payload)
	return signingInput + "." + protocol.Base64urlEncode(ed25519.Sign(priv, []byte(signingInput)))
}

// newTestLoginClient mints a real one-operation client identity, exactly as the
// command does, without touching the keystore or the config dir.
func newTestLoginClient(t *testing.T) (*loginClient, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyID := protocol.GenerateKeyID()
	key := protocol.NewMultikeyPublicKey(keyID, pub)
	jwsToken, did, _, err := protocol.SignIdentityCreate(
		[]protocol.MultikeyPublicKey{key},
		[]protocol.MultikeyPublicKey{key},
		[]protocol.MultikeyPublicKey{key},
		keyID, priv,
	)
	if err != nil {
		t.Fatalf("sign genesis: %v", err)
	}
	return &loginClient{DID: did, KeyID: keyID, Chain: []string{jwsToken}}, priv
}

// ---------------------------------------------------------------------------
// callback parsing
// ---------------------------------------------------------------------------

func TestParseLoginCallbackSuccess(t *testing.T) {
	raw := "http://127.0.0.1:51234/callback?jws=header.payload.sig&did=" + testLoginSubject +
		"#credential=cred.header.sig"
	got, err := parseLoginCallback(raw)
	if err != nil {
		t.Fatalf("parseLoginCallback: %v", err)
	}
	if got.JWS != "header.payload.sig" || got.DID != testLoginSubject {
		t.Fatalf("query half: %+v", got)
	}
	if got.Credential != "cred.header.sig" {
		t.Fatalf("credential lifted from fragment = %q", got.Credential)
	}
}

// The fragment is read from the bytes the browser sent, not from a
// percent-decoded view of them: the host serializes it with URLSearchParams, so
// it is parsed with the same grammar. A value carrying %2B or %26 must come back
// with a literal + and & rather than being split into extra parameters or
// having its plus eaten.
func TestParseLoginCallbackDecodesFragmentEscapes(t *testing.T) {
	raw := "http://127.0.0.1:51234/callback?jws=a.b.c&did=" + testLoginSubject +
		"#credential=head%2Bmid%26tail.body.sig"
	got, err := parseLoginCallback(raw)
	if err != nil {
		t.Fatalf("parseLoginCallback: %v", err)
	}
	if want := "head+mid&tail.body.sig"; got.Credential != want {
		t.Fatalf("credential = %q, want %q", got.Credential, want)
	}
	if got.JWS != "a.b.c" || got.DID != testLoginSubject {
		t.Fatalf("the query half was disturbed by the fragment: %+v", got)
	}
}

func TestParseLoginCallbackSuccessWithoutFragment(t *testing.T) {
	raw := "http://127.0.0.1:51234/callback?jws=a.b.c&did=" + testLoginSubject
	got, err := parseLoginCallback(raw)
	if err != nil {
		t.Fatalf("parseLoginCallback: %v", err)
	}
	if got.Credential != "" {
		t.Fatalf("credential = %q, want empty when there is no fragment", got.Credential)
	}
}

func TestParseLoginCallbackRejections(t *testing.T) {
	base := "http://127.0.0.1:51234/callback"
	cases := map[string]struct {
		raw  string
		want string
	}{
		"denial":                         {base + "?error=access_denied", "declined"},
		"denial outranks stray fragment": {base + "?error=access_denied#credential=cred", "declined"},
		"missing did":                    {base + "?jws=a.b.c", "missing did"},
		"missing jws":                    {base + "?did=" + testLoginSubject, "missing jws"},
		"empty jws is absent":            {base + "?jws=&did=" + testLoginSubject, "missing jws"},
		"empty did is absent":            {base + "?jws=a.b.c&did=", "missing did"},
		"nothing at all":                 {base, "no jws, did, or error"},
		"bare fragment only":             {base + "#credential=cred", "no jws, did, or error"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := parseLoginCallback(tc.raw)
			if err == nil {
				t.Fatalf("accepted %q as %+v", tc.raw, got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// the store of size one
// ---------------------------------------------------------------------------

func TestChallengeExpectationConsumesExactlyOnce(t *testing.T) {
	expect := &challengeExpectation{encoded: "Zm9v"}
	if err := expect.consume("Zm9v"); err != nil {
		t.Fatalf("first presentation rejected: %v", err)
	}
	if err := expect.consume("Zm9v"); err == nil {
		t.Fatal("the same challenge was accepted twice — the store is not consumed")
	}
}

func TestChallengeExpectationSpendsOnAFailedComparison(t *testing.T) {
	expect := &challengeExpectation{encoded: "Zm9v"}
	if err := expect.consume("YmFy"); err == nil {
		t.Fatal("a foreign challenge was accepted")
	}
	// Spent pass OR fail: an expectation that survived a wrong answer would
	// admit a second presentation.
	if err := expect.consume("Zm9v"); err == nil {
		t.Fatal("the expectation survived a failed comparison")
	}
}

// TestChallengeIsConsumedLast pins the ORDERING SIWD.md §Replay prevention
// requires: consumption is the final verification step, so an artifact that
// fails an earlier gate must never reach the expectation at all. It is asserted
// functionally — run the command's own sequence and check the expectation is
// still unspent after each failure that precedes it.
func TestChallengeIsConsumedLast(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	challenge := testChallenge(testLoginSubject)
	encoded := mustEncodeChallenge(t, challenge)
	kid := testLoginSubject + "#key_abc"
	state := protocol.IdentityState{
		DID:      testLoginSubject,
		AuthKeys: []protocol.MultikeyPublicKey{protocol.NewMultikeyPublicKey("key_abc", pub)},
	}

	// A callback that fails the signature gate: correct challenge bytes, but
	// signed by a key the chain does not publish.
	_, impostorPriv, _ := ed25519.GenerateKey(nil)
	forged := signSiwdChallenge(t, challenge, kid, impostorPriv)

	expect := &challengeExpectation{encoded: encoded}
	signerDID, keyID, segment, err := signerFromLoginJWS(forged, testLoginSubject)
	if err != nil {
		t.Fatalf("signerFromLoginJWS: %v", err)
	}
	if err := assertSignerBinding(signerDID, testLoginSubject); err != nil {
		t.Fatalf("assertSignerBinding: %v", err)
	}
	if err := verifyLoginSignature(forged, keyID, state); err == nil {
		t.Fatal("a forged signature verified")
	}
	if expect.spent {
		t.Fatal("a forged callback spent the expectation — consumption is not the final gate")
	}

	// And a subject-binding failure, likewise, never reaches it.
	if err := assertSignerBinding(signerDID, testLoginOther); err == nil {
		t.Fatal("a signer other than the bound subject was accepted")
	}
	if expect.spent {
		t.Fatal("a binding failure spent the expectation")
	}

	// The real artifact clears every gate and then spends it, once.
	genuine := signSiwdChallenge(t, challenge, kid, priv)
	_, keyID, segment, err = signerFromLoginJWS(genuine, testLoginSubject)
	if err != nil {
		t.Fatalf("signerFromLoginJWS: %v", err)
	}
	if err := verifyLoginSignature(genuine, keyID, state); err != nil {
		t.Fatalf("verifyLoginSignature: %v", err)
	}
	if err := expect.consume(segment); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := expect.consume(segment); err == nil {
		t.Fatal("the expectation admitted a second presentation")
	}
}

// TestWrongChallengeSpendsOnlyAtTheFinalGate: a well-formed, correctly-signed
// callback carrying a challenge this run did not mint passes every earlier gate
// and is caught by the consume — which is where the store of size one is meant
// to catch it.
func TestWrongChallengeSpendsOnlyAtTheFinalGate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	kid := testLoginSubject + "#key_abc"
	state := protocol.IdentityState{
		DID:      testLoginSubject,
		AuthKeys: []protocol.MultikeyPublicKey{protocol.NewMultikeyPublicKey("key_abc", pub)},
	}
	foreign := testChallenge(testLoginSubject)
	foreign.Nonce = "a-nonce-this-run-never-minted"
	jws := signSiwdChallenge(t, foreign, kid, priv)

	expect := &challengeExpectation{encoded: mustEncodeChallenge(t, testChallenge(testLoginSubject))}
	signerDID, keyID, segment, err := signerFromLoginJWS(jws, testLoginSubject)
	if err != nil {
		t.Fatalf("signerFromLoginJWS: %v", err)
	}
	if err := assertSignerBinding(signerDID, testLoginSubject); err != nil {
		t.Fatalf("assertSignerBinding: %v", err)
	}
	if err := verifyLoginSignature(jws, keyID, state); err != nil {
		t.Fatalf("verifyLoginSignature: %v", err)
	}
	if expect.spent {
		t.Fatal("the expectation was spent before the final gate")
	}
	if err := expect.consume(segment); err == nil {
		t.Fatal("a challenge this run never minted was accepted")
	} else if !strings.Contains(err.Error(), "this run's challenge") {
		t.Fatalf("error %q does not name the mismatch", err)
	}
}

func TestAssertSignerBinding(t *testing.T) {
	if err := assertSignerBinding(testLoginSubject, testLoginSubject); err != nil {
		t.Fatalf("the bound subject was refused: %v", err)
	}
	err := assertSignerBinding(testLoginOther, testLoginSubject)
	if err == nil {
		t.Fatal("a signature by a DID the challenge did not name was accepted")
	}
	// Both DIDs belong in the message: which was asked for, and which answered.
	if !strings.Contains(err.Error(), testLoginSubject) || !strings.Contains(err.Error(), testLoginOther) {
		t.Fatalf("error %q does not name both DIDs", err)
	}
}

// ---------------------------------------------------------------------------
// discovery — one entry, or none
// ---------------------------------------------------------------------------

func authServerEntry(id, endpoint string) protocol.ServiceEntry {
	return protocol.ServiceEntry{"id": id, "type": authorizationServerType, "endpoint": endpoint}
}

func TestAuthorizeEndpointOneEntryWins(t *testing.T) {
	services := []protocol.ServiceEntry{
		{"id": "relay", "type": "DfosRelay", "endpoint": "https://relay.example"},
		authServerEntry("auth", "https://app.example.com"),
	}
	endpoint, reason := authorizeEndpoint(services)
	if endpoint != "https://app.example.com/authorize" {
		t.Fatalf("endpoint = %q (reason %q)", endpoint, reason)
	}
}

// The /authorize surface is joined onto the PARSED path, so one endpoint
// spelling cannot become two authorize URLs and a base path is extended rather
// than replaced.
func TestAuthorizeEndpointJoinsThePath(t *testing.T) {
	cases := map[string]string{
		"https://app.example.com":       "https://app.example.com/authorize",
		"https://app.example.com/":      "https://app.example.com/authorize",
		"https://app.example.com///":    "https://app.example.com/authorize",
		"https://app.example.com/base":  "https://app.example.com/base/authorize",
		"https://app.example.com/base/": "https://app.example.com/base/authorize",
		"http://app.example.com:8443":   "http://app.example.com:8443/authorize",
	}
	for in, want := range cases {
		endpoint, reason := authorizeEndpoint([]protocol.ServiceEntry{authServerEntry("auth", in)})
		if endpoint != want {
			t.Errorf("endpoint for %q = %q (reason %q), want %q", in, endpoint, reason, want)
		}
	}
}

func TestAuthorizeEndpointFallsBack(t *testing.T) {
	cases := map[string]struct {
		services []protocol.ServiceEntry
		reason   string
	}{
		"no entry": {
			[]protocol.ServiceEntry{{"id": "relay", "type": "DfosRelay", "endpoint": "https://relay.example"}},
			"no " + authorizationServerType,
		},
		"empty services": {nil, "no " + authorizationServerType},
		"two entries — ambiguity degrades to the fallback, never to a choice": {
			[]protocol.ServiceEntry{
				authServerEntry("a", "https://app.example.com"),
				authServerEntry("b", "https://other.example.com"),
			},
			"ambiguous",
		},
		"empty endpoint": {
			[]protocol.ServiceEntry{authServerEntry("auth", "")},
			"names nothing",
		},
		"missing endpoint member": {
			[]protocol.ServiceEntry{{"id": "auth", "type": authorizationServerType}},
			"names nothing",
		},
		"relative endpoint": {
			[]protocol.ServiceEntry{authServerEntry("auth", "/authorize")},
			"names nothing",
		},
		"non-http scheme": {
			[]protocol.ServiceEntry{authServerEntry("auth", "ftp://app.example.com")},
			"names nothing",
		},
		// SIWD.md calls the member the canonical authorize ORIGIN url. These are
		// not origins, and appending a path to one would send the user somewhere
		// the identity never published.
		"endpoint carrying a query": {
			[]protocol.ServiceEntry{authServerEntry("auth", "https://app.example.com?tenant=a")},
			"names nothing",
		},
		"endpoint carrying a path and a query": {
			[]protocol.ServiceEntry{authServerEntry("auth", "https://app.example.com/base?tenant=a")},
			"names nothing",
		},
		"endpoint carrying a fragment": {
			[]protocol.ServiceEntry{authServerEntry("auth", "https://app.example.com#frag")},
			"names nothing",
		},
		"endpoint carrying userinfo": {
			[]protocol.ServiceEntry{authServerEntry("auth", "https://user:pw@app.example.com")},
			"names nothing",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			endpoint, reason := authorizeEndpoint(tc.services)
			if endpoint != "" {
				t.Fatalf("endpoint = %q, want the fallback", endpoint)
			}
			if !strings.Contains(reason, tc.reason) {
				t.Fatalf("reason %q does not mention %q", reason, tc.reason)
			}
		})
	}
}

func TestNormalizeAuthorizeURL(t *testing.T) {
	accepts := map[string]string{
		"https://app.example.com":           "https://app.example.com/authorize",
		"https://app.example.com/":          "https://app.example.com/authorize",
		"https://app.example.com/authorize": "https://app.example.com/authorize",
		"http://localhost:3000":             "http://localhost:3000/authorize",
		"https://app.example.com/siwd/go":   "https://app.example.com/siwd/go",
		// A query the user typed into the flag is carried, unlike a chain entry's:
		// this is an instruction, not discovery vocabulary.
		"https://app.example.com/authorize?tenant=a": "https://app.example.com/authorize?tenant=a",
	}
	for in, want := range accepts {
		got, err := normalizeAuthorizeURL(in)
		if err != nil {
			t.Fatalf("normalizeAuthorizeURL(%q) = error %v", in, err)
		}
		if got != want {
			t.Fatalf("normalizeAuthorizeURL(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"", "app.example.com", "ftp://app.example.com", "/authorize"} {
		if got, err := normalizeAuthorizeURL(in); err == nil {
			t.Fatalf("normalizeAuthorizeURL(%q) = %q, want an error", in, got)
		}
	}
}

// ---------------------------------------------------------------------------
// the authorize request
// ---------------------------------------------------------------------------

func TestBuildAuthorizeURLCarriesTheWireParams(t *testing.T) {
	lc, priv := newTestLoginClient(t)
	challenge := testChallenge(testLoginSubject)

	// A query the endpoint already carries must survive rather than be clobbered.
	request, encoded, err := buildAuthorizeURL(
		"https://app.example.com/authorize?ui=compact", challenge,
		"http://127.0.0.1:51234/callback", "identity read:profile", lc, priv,
	)
	if err != nil {
		t.Fatalf("buildAuthorizeURL: %v", err)
	}
	parsed, err := url.Parse(request)
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}
	query := parsed.Query()
	if query.Get("ui") != "compact" {
		t.Fatal("the endpoint's own query was clobbered")
	}
	if query.Get("challenge") != encoded {
		t.Fatalf("challenge param %q != returned encoding %q", query.Get("challenge"), encoded)
	}
	if query.Get("redirect_uri") != "http://127.0.0.1:51234/callback" {
		t.Fatalf("redirect_uri = %q", query.Get("redirect_uri"))
	}
	// Scope rides through verbatim, several tokens and all.
	if query.Get("scope") != "identity read:profile" {
		t.Fatalf("scope = %q, want the raw string", query.Get("scope"))
	}
	if query.Get("client_did") != lc.DID {
		t.Fatalf("client_did = %q, want %q", query.Get("client_did"), lc.DID)
	}

	// THE BYTE CONTRACT: the ask proof's payload segment and the challenge param
	// are the same bytes. The host compares them by string equality.
	proof := query.Get("client_proof")
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("client_proof is not a three-part JWS: %q", proof)
	}
	if parts[1] != encoded {
		t.Fatalf("ask proof payload segment %q != challenge param %q", parts[1], encoded)
	}
	header, _, err := protocol.DecodeJWSUnsafe(proof)
	if err != nil {
		t.Fatalf("decode client_proof: %v", err)
	}
	if header.Typ != protocol.SiwdAskJWSTyp {
		t.Fatalf("client_proof typ = %q, want %q", header.Typ, protocol.SiwdAskJWSTyp)
	}
	if header.Kid != lc.DID+"#"+lc.KeyID {
		t.Fatalf("client_proof kid = %q", header.Kid)
	}
	if _, _, err := protocol.VerifyJWS(proof, priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("client_proof does not verify: %v", err)
	}

	// The carriage is the verbatim log, genesis first.
	carriage, err := protocol.Base64urlDecode(query.Get("client_chain"))
	if err != nil {
		t.Fatalf("decode client_chain: %v", err)
	}
	var carried []string
	if err := json.Unmarshal(carriage, &carried); err != nil {
		t.Fatalf("client_chain is not a JSON array of strings: %v", err)
	}
	if len(carried) != 1 || carried[0] != lc.Chain[0] {
		t.Fatalf("client_chain = %v, want the verbatim log", carried)
	}
	verified, err := protocol.VerifyIdentityChain(carried)
	if err != nil || verified.State.DID != lc.DID {
		t.Fatalf("carried chain does not derive client_did: state=%+v err=%v", verified, err)
	}
}

func TestBuildAuthorizeURLRejectsANonCanonicalChallenge(t *testing.T) {
	lc, priv := newTestLoginClient(t)
	challenge := testChallenge(testLoginSubject)
	challenge.Timestamp = "2026-08-10T12:34:56.123Z"
	if request, _, err := buildAuthorizeURL("https://app.example.com/authorize", challenge,
		"http://127.0.0.1:1/callback", "identity", lc, priv); err == nil {
		t.Fatalf("built a request over a non-canonical challenge: %s", request)
	}
}

func TestEncodeClientChainBounds(t *testing.T) {
	if _, err := encodeClientChain(nil); err == nil {
		t.Fatal("an empty log was accepted for carriage")
	}
	oversized := make([]string, siwdCarriageCap+1)
	for i := range oversized {
		oversized[i] = "op"
	}
	if _, err := encodeClientChain(oversized); err == nil {
		t.Fatalf("a %d-operation log was accepted past the %d-operation cap", len(oversized), siwdCarriageCap)
	}
}

// ---------------------------------------------------------------------------
// the loopback relay
// ---------------------------------------------------------------------------

// testListenerHost is the literal authority the mux under test was "reached at".
const testListenerHost = "127.0.0.1:51234"

// loopbackRequest builds a request carrying the expected Host, which every
// request to this listener must. httptest.NewRequest defaults Host to
// example.com — precisely the shape the guard exists to refuse.
func loopbackRequest(method, path string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, path, body)
	r.Host = testListenerHost
	return r
}

func TestLoginCallbackPageRelaysTheFragment(t *testing.T) {
	mux := newLoginMux(make(chan string, collectBuffer), testListenerHost)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, loopbackRequest(http.MethodGet, "/callback", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /callback = %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, want := range []string{"location.href", `fetch("/collect"`, "you can close this tab"} {
		if !strings.Contains(body, want) {
			t.Fatalf("the relay page does not contain %q", want)
		}
	}
	// The signed challenge and the credential sit in the address bar and in
	// history until the page replaces them.
	if !strings.Contains(body, "history.replaceState") {
		t.Fatal("the relay page never scrubs the callback URL from the address bar")
	}
	// No external assets: the page must render with the network unavailable.
	for _, forbidden := range []string{"http://", "https://"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("the relay page references an external asset (%q)", forbidden)
		}
	}
}

func TestLoginCollectRoundTripsTheURL(t *testing.T) {
	urls := make(chan string, collectBuffer)
	mux := newLoginMux(urls, testListenerHost)

	want := "http://127.0.0.1:51234/callback?jws=a.b.c&did=" + testLoginSubject + "#credential=cred"
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, loopbackRequest(http.MethodPost, "/collect", strings.NewReader(want)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST /collect = %d", recorder.Code)
	}
	select {
	case got := <-urls:
		if got != want {
			t.Fatalf("collected %q, want %q", got, want)
		}
	default:
		t.Fatal("POST /collect delivered nothing to the waiting flow")
	}

	// A GET on /collect is not a callback.
	recorder = httptest.NewRecorder()
	mux.ServeHTTP(recorder, loopbackRequest(http.MethodGet, "/collect", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /collect = %d, want 405", recorder.Code)
	}
}

// A page reaching this port through a rebound DNS name carries that name in
// Host, never the literal loopback authority the redirect_uri named. Refusing on
// Host is what keeps a rebound origin from driving the listener.
func TestLoginListenerRefusesAForeignHost(t *testing.T) {
	urls := make(chan string, collectBuffer)
	mux := newLoginMux(urls, testListenerHost)

	for _, host := range []string{
		"evil.example.com",       // a rebound name
		"evil.example.com:51234", // …on the right port
		"localhost:51234",        // a loopback NAME is not the literal authority
		"127.0.0.1",              // right host, no port
		"127.0.0.1:51235",        // right host, wrong port
		"",                       // absent
	} {
		for _, route := range []struct {
			method, path string
		}{{http.MethodGet, "/callback"}, {http.MethodPost, "/collect"}} {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(route.method, route.path, strings.NewReader("http://x/callback?jws=a.b.c&did=d"))
			request.Host = host
			mux.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusForbidden {
				t.Errorf("%s %s with Host %q = %d, want 403", route.method, route.path, host, recorder.Code)
			}
		}
	}
	select {
	case got := <-urls:
		t.Fatalf("a foreign-Host POST delivered %q to the waiting flow", got)
	default:
	}
}

// An over-cap body is REFUSED, not silently truncated. A truncated callback URL
// parses fine and yields a credential that is bytes, not a credential — and
// delegation-chain credentials are legitimately large, which is why the cap is
// 1 MiB and why crossing it has to be detected rather than clipped.
func TestLoginCollectRefusesAnOversizedBody(t *testing.T) {
	urls := make(chan string, collectBuffer)
	mux := newLoginMux(urls, testListenerHost)

	oversized := "http://127.0.0.1:51234/callback?jws=a.b.c&did=" + testLoginSubject +
		"#credential=" + strings.Repeat("x", maxCollectBody)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, loopbackRequest(http.MethodPost, "/collect", strings.NewReader(oversized)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("an oversized POST /collect = %d, want a refusal", recorder.Code)
	}
	select {
	case got := <-urls:
		t.Fatalf("an oversized body was delivered anyway (%d bytes)", len(got))
	default:
	}

	// A body at the cap is still a callback.
	padding := maxCollectBody - len("http://127.0.0.1:51234/callback?jws=a.b.c&did="+testLoginSubject+"#credential=")
	atCap := "http://127.0.0.1:51234/callback?jws=a.b.c&did=" + testLoginSubject +
		"#credential=" + strings.Repeat("x", padding)
	recorder = httptest.NewRecorder()
	mux.ServeHTTP(recorder, loopbackRequest(http.MethodPost, "/collect", strings.NewReader(atCap)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("a %d-byte POST /collect = %d, want 200", len(atCap), recorder.Code)
	}
	select {
	case got := <-urls:
		if got != atCap {
			t.Fatalf("a body at the cap was delivered altered (%d bytes, want %d)", len(got), len(atCap))
		}
	default:
		t.Fatal("a body at the cap delivered nothing")
	}
}

// ---------------------------------------------------------------------------
// the wait loop
// ---------------------------------------------------------------------------

// Anyone on this machine can POST to a loopback port, so junk must not cancel a
// sign-in the user is halfway through.
func TestAwaitLoginCallbackSkipsGarbageAndKeepsWaiting(t *testing.T) {
	urls := make(chan string, 8)
	urls <- "not a url at all"
	urls <- ""
	urls <- "http://127.0.0.1:51234/callback"
	urls <- "{\"json\":\"probe\"}"
	want := "http://127.0.0.1:51234/callback?jws=a.b.c&did=" + testLoginSubject + "#credential=cred"
	urls <- want

	var warnings strings.Builder
	callback, err := awaitLoginCallback(urls, 5*time.Second, &warnings)
	if err != nil {
		t.Fatalf("awaitLoginCallback: %v", err)
	}
	if callback.JWS != "a.b.c" || callback.Credential != "cred" {
		t.Fatalf("callback = %+v, want the valid POST that followed the garbage", callback)
	}
	if got := strings.Count(warnings.String(), "\n"); got != 4 {
		t.Fatalf("logged %d warnings, want one per skipped body:\n%s", got, warnings.String())
	}
}

// A well-formed callback that says no is the host's ANSWER, not noise: it ends
// the wait rather than being skipped, or the flow would hang on a sign-in that
// is already over.
func TestAwaitLoginCallbackStopsOnAWellFormedRefusal(t *testing.T) {
	for name, raw := range map[string]string{
		"denial":        "http://127.0.0.1:51234/callback?error=access_denied",
		"half-callback": "http://127.0.0.1:51234/callback?jws=a.b.c",
		"missing jws":   "http://127.0.0.1:51234/callback?did=" + testLoginSubject,
	} {
		t.Run(name, func(t *testing.T) {
			urls := make(chan string, 1)
			urls <- raw
			// A long timeout: if this were skipped as garbage the test would block
			// rather than return, so a prompt error is the assertion.
			if _, err := awaitLoginCallback(urls, time.Minute, io.Discard); err == nil {
				t.Fatal("a well-formed refusal was treated as noise")
			}
		})
	}
}

// Skipping garbage buys no extra time: the deadline is computed once, so a
// flood delays nothing past the timeout the user asked for.
func TestAwaitLoginCallbackHonorsTheDeadline(t *testing.T) {
	urls := make(chan string, 1)
	urls <- "garbage"
	start := time.Now()
	_, err := awaitLoginCallback(urls, 80*time.Millisecond, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("the deadline was extended by the skipped body (waited %s)", elapsed)
	}
}

func TestLoginListenerBindsLoopbackAndCollects(t *testing.T) {
	listener, err := startLoginListener()
	if err != nil {
		t.Fatalf("startLoginListener: %v", err)
	}
	defer listener.close()
	if listener.port == 0 {
		t.Fatal("listener reported no port")
	}
	base := "http://" + loopbackHost + ":" + strconv.Itoa(listener.port)

	page, err := http.Get(base + "/callback")
	if err != nil {
		t.Fatalf("GET /callback: %v", err)
	}
	body, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if page.StatusCode != http.StatusOK || !strings.Contains(string(body), "/collect") {
		t.Fatalf("GET /callback = %d, body %q", page.StatusCode, body)
	}

	want := base + "/callback?jws=a.b.c&did=" + testLoginSubject
	posted, err := http.Post(base+"/collect", "text/plain", strings.NewReader(want))
	if err != nil {
		t.Fatalf("POST /collect: %v", err)
	}
	posted.Body.Close()

	select {
	case got := <-listener.urls:
		if got != want {
			t.Fatalf("collected %q, want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the listener never delivered the collected URL")
	}

	// close is idempotent: the command shuts down on collection and defers again.
	listener.close()
	listener.close()
}

// ---------------------------------------------------------------------------
// verifying what came back
// ---------------------------------------------------------------------------

func TestSignerFromLoginJWSHappyPath(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	challenge := testChallenge(testLoginSubject)
	encoded := mustEncodeChallenge(t, challenge)
	jws := signSiwdChallenge(t, challenge, testLoginSubject+"#key_abc", priv)

	did, keyID, segment, err := signerFromLoginJWS(jws, testLoginSubject)
	if err != nil {
		t.Fatalf("signerFromLoginJWS: %v", err)
	}
	if did != testLoginSubject || keyID != "key_abc" {
		t.Fatalf("signer = %s#%s", did, keyID)
	}
	// The payload SEGMENT is handed back verbatim for the caller to consume as
	// the final gate — not compared here, and not re-serialized.
	if segment != encoded {
		t.Fatalf("segment = %q, want the payload segment %q", segment, encoded)
	}
}

func TestSignerFromLoginJWSRejections(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	challenge := testChallenge(testLoginSubject)
	kid := testLoginSubject + "#key_abc"

	// An ASK PROOF covers the very same canonical bytes. Only the typ gate keeps
	// it from presenting here as the subject's sign-in.
	askProof, err := protocol.SignSiwdAskProof(challenge, kid, priv)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		jws     string
		courier string
		want    string
	}{
		"ask proof presented as a sign-in":  {askProof, testLoginSubject, "expected typ"},
		"not a compact JWS":                 {"nope", testLoginSubject, "three-part"},
		"kid without a key id":              {signSiwdChallenge(t, challenge, testLoginSubject+"#", priv), testLoginSubject, "kid must be a DID URL"},
		"kid without a did":                 {signSiwdChallenge(t, challenge, "#key_abc", priv), testLoginSubject, "kid must be a DID URL"},
		"courier did disagrees with signer": {signSiwdChallenge(t, challenge, kid, priv), testLoginOther, "signed the challenge"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if did, keyID, _, err := signerFromLoginJWS(tc.jws, tc.courier); err == nil {
				t.Fatalf("accepted, returning %s#%s", did, keyID)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func mustEncodeChallenge(t *testing.T, challenge protocol.SiwdChallenge) string {
	t.Helper()
	bytes, err := protocol.SiwdSigningInput(challenge)
	if err != nil {
		t.Fatalf("signing input: %v", err)
	}
	return protocol.Base64urlEncode(bytes)
}

func TestVerifyLoginSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	rotatedPub, _, _ := ed25519.GenerateKey(nil)
	challenge := testChallenge(testLoginSubject)
	jws := signSiwdChallenge(t, challenge, testLoginSubject+"#key_abc", priv)

	current := protocol.IdentityState{
		DID:      testLoginSubject,
		AuthKeys: []protocol.MultikeyPublicKey{protocol.NewMultikeyPublicKey("key_abc", pub)},
	}
	if err := verifyLoginSignature(jws, "key_abc", current); err != nil {
		t.Fatalf("a current auth key failed to verify: %v", err)
	}

	// A key that is in the chain but NOT in the auth set proves nothing here.
	assertOnly := protocol.IdentityState{
		DID:        testLoginSubject,
		AssertKeys: []protocol.MultikeyPublicKey{protocol.NewMultikeyPublicKey("key_abc", pub)},
	}
	if err := verifyLoginSignature(jws, "key_abc", assertOnly); err == nil {
		t.Fatal("a non-authentication key verified a sign-in")
	}

	// Rotated out: the id is still current, the key material is not.
	rotated := protocol.IdentityState{
		DID:      testLoginSubject,
		AuthKeys: []protocol.MultikeyPublicKey{protocol.NewMultikeyPublicKey("key_abc", rotatedPub)},
	}
	if err := verifyLoginSignature(jws, "key_abc", rotated); err == nil {
		t.Fatal("a signature verified against a rotated-out key")
	}

	deleted := current
	deleted.IsDeleted = true
	if err := verifyLoginSignature(jws, "key_abc", deleted); err == nil {
		t.Fatal("a deleted identity authenticated")
	}
}

// ---------------------------------------------------------------------------
// the per-install client identity
// ---------------------------------------------------------------------------

// setupLoginClientEnv points ConfigDir() at a temp dir and swaps in a memory
// keystore, restoring the package globals afterward.
func setupLoginClientEnv(t *testing.T) *keystore.MemoryStore {
	t.Helper()
	t.Setenv("DFOS_CONFIG", t.TempDir()+"/config.toml")
	store := keystore.NewMemoryStore()
	prev := keys
	keys = store
	t.Cleanup(func() { keys = prev })
	return store
}

func TestLoginClientIsStableAcrossLogins(t *testing.T) {
	setupLoginClientEnv(t)

	first, firstPriv, err := ensureLoginClient()
	if err != nil {
		t.Fatalf("first login: %v", err)
	}
	if err := protocol.ValidateDID(first.DID); err != nil {
		t.Fatalf("minted client DID: %v", err)
	}

	// The whole point of persisting: the same DID asks again, so the consent the
	// user already gave still names this party.
	second, secondPriv, err := ensureLoginClient()
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	if second.DID != first.DID || second.KeyID != first.KeyID {
		t.Fatalf("client identity changed between logins: %s#%s then %s#%s",
			first.DID, first.KeyID, second.DID, second.KeyID)
	}
	if !firstPriv.Equal(secondPriv) {
		t.Fatal("the reloaded client key differs from the minted one")
	}

	info, err := os.Stat(loginClientPath())
	if err != nil {
		t.Fatalf("stat %s: %v", loginClientPath(), err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("%s mode = %o, want 600", loginClientPath(), perm)
	}
}

func TestLoginClientRefusesToSilentlyReMint(t *testing.T) {
	store := setupLoginClientEnv(t)
	minted, _, err := ensureLoginClient()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// The record survives but the key is gone: re-minting here would discard
	// every consent and credential the old DID earned without saying so.
	store.DeleteKey(loginClientAccount(minted.KeyID))
	if _, _, err := ensureLoginClient(); err == nil {
		t.Fatal("a missing client key silently re-minted the identity")
	} else if !strings.Contains(err.Error(), "delete") {
		t.Fatalf("error %q does not hint at how to re-mint", err)
	}
}

func TestLoginClientRejectsAnEditedRecord(t *testing.T) {
	setupLoginClientEnv(t)
	minted, _, err := ensureLoginClient()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	tampered, err := json.Marshal(loginClient{DID: testLoginOther, KeyID: minted.KeyID, Chain: minted.Chain})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(loginClientPath(), tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureLoginClient(); err == nil {
		t.Fatal("a record naming a DID its own chain does not derive was accepted")
	}
}

// ---------------------------------------------------------------------------
// storing and reading back the credential
// ---------------------------------------------------------------------------

func TestCredentialFileName(t *testing.T) {
	got := credentialFileName(testLoginSubject, "")
	if strings.Contains(got, ":") {
		t.Fatalf("credential filename %q keeps a colon", got)
	}
	if !strings.HasSuffix(got, ".json") {
		t.Fatalf("credential filename %q is not a .json file", got)
	}
}

// A credential issued to anyone but this installation's client identity is
// inert here — audience-bound and unspendable without that DID's key — so
// storing it under a success line would misreport what the user now holds.
func TestAssertCredentialForClient(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	lc, _ := newTestLoginClient(t)

	mine, err := protocol.CreateCredential(
		testLoginSubject, lc.DID, testLoginSubject+"#key_abc",
		"chain:cv7n8vkvr64cctf3294h9k4eanhff8z", "read", time.Hour, priv,
	)
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}
	if err := assertCredentialForClient(mine, lc.DID); err != nil {
		t.Fatalf("a credential issued to this client was refused: %v", err)
	}

	// Issued to a different audience: the sign-in stands, the artifact does not.
	theirs, err := protocol.CreateCredential(
		testLoginSubject, testLoginOther, testLoginSubject+"#key_abc",
		"chain:cv7n8vkvr64cctf3294h9k4eanhff8z", "read", time.Hour, priv,
	)
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}
	err = assertCredentialForClient(theirs, lc.DID)
	if err == nil {
		t.Fatal("a credential issued to another DID was accepted")
	}
	if !strings.Contains(err.Error(), testLoginOther) || !strings.Contains(err.Error(), lc.DID) {
		t.Fatalf("error %q does not name both the actual and expected audience", err)
	}

	// iss is deliberately NOT gated: a space-owned resource legitimately issues
	// from the space's own DID rather than from the subject who signed in.
	fromElsewhere, err := protocol.CreateCredential(
		testLoginOther, lc.DID, testLoginOther+"#key_abc",
		"chain:cv7n8vkvr64cctf3294h9k4eanhff8z", "read", time.Hour, priv,
	)
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}
	if err := assertCredentialForClient(fromElsewhere, lc.DID); err != nil {
		t.Fatalf("a credential issued by another DID was refused: %v", err)
	}

	// Wrong typ, and undecodable bytes.
	notACredential := signSiwdChallengeTyp(t, testChallenge(testLoginSubject), testLoginSubject+"#key_abc", priv, protocol.SiwdJWSTyp)
	if err := assertCredentialForClient(notACredential, lc.DID); err == nil {
		t.Fatal("a sign-in artifact was accepted as a credential")
	}
	if err := assertCredentialForClient("nonsense", lc.DID); err == nil {
		t.Fatal("undecodable bytes were accepted as a credential")
	}
}

func TestStoreLoginCredential(t *testing.T) {
	setupLoginClientEnv(t)
	lc, _ := newTestLoginClient(t)

	path, err := storeLoginCredential(testLoginSubject, lc, "cred.header.sig", "")
	if err != nil {
		t.Fatalf("storeLoginCredential: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("%s mode = %o, want 600", path, perm)
	}
	dir, err := os.Stat(strings.TrimSuffix(path, "/"+credentialFileName(testLoginSubject, "")))
	if err != nil {
		t.Fatalf("stat credentials dir: %v", err)
	}
	if perm := dir.Mode().Perm(); perm != 0o700 {
		t.Fatalf("credentials dir mode = %o, want 700", perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record storedLoginCredential
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("stored record is not JSON: %v", err)
	}
	if record.SubjectDID != testLoginSubject || record.ClientDID != lc.DID ||
		record.ClientKeyID != lc.KeyID || record.Credential != "cred.header.sig" {
		t.Fatalf("stored record = %+v", record)
	}
	if _, err := time.Parse(loginTimestampLayout, record.ObtainedAt); err != nil {
		t.Fatalf("obtainedAt %q is not a protocol timestamp: %v", record.ObtainedAt, err)
	}
}

// The record is written through a temp file and renamed, so a re-login replaces
// the target rather than opening it — which means a symlink dropped at the path
// is discarded instead of followed into whatever it points at.
func TestStoreLoginCredentialReplacesRatherThanFollows(t *testing.T) {
	setupLoginClientEnv(t)
	lc, _ := newTestLoginClient(t)

	dir := filepath.Join(config.ConfigDir(), "credentials")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(elsewhere, []byte("untouched\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, credentialFileName(testLoginSubject, ""))
	if err := os.Symlink(elsewhere, target); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	path, err := storeLoginCredential(testLoginSubject, lc, "cred.header.sig", "")
	if err != nil {
		t.Fatalf("storeLoginCredential: %v", err)
	}
	if body, err := os.ReadFile(elsewhere); err != nil || string(body) != "untouched\n" {
		t.Fatalf("the symlink was followed: %q (%v)", body, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("the target is still a symlink")
	}

	// A second login overwrites in place, leaving no temp files behind.
	if _, err := storeLoginCredential(testLoginSubject, lc, "second.header.sig", ""); err != nil {
		t.Fatalf("second store: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != credentialFileName(testLoginSubject, "") {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("credentials dir holds %v, want only the record", names)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record storedLoginCredential
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("stored record is not JSON: %v", err)
	}
	if record.Credential != "second.header.sig" {
		t.Fatalf("credential = %q, want the newer one", record.Credential)
	}
}

func TestSummarizeCredentialDecodesLocally(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	token, err := protocol.CreateCredential(
		testLoginSubject, testLoginOther, testLoginSubject+"#key_abc",
		"chain:cv7n8vkvr64cctf3294h9k4eanhff8z", "read", time.Hour, priv,
	)
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}
	summary, err := summarizeCredential(token)
	if err != nil {
		t.Fatalf("summarizeCredential: %v", err)
	}
	if summary.Issuer != testLoginSubject || summary.Audience != testLoginOther {
		t.Fatalf("summary = %+v", summary)
	}
	if len(summary.Att) != 1 || summary.Att[0].Action != "read" ||
		summary.Att[0].Resource != "chain:cv7n8vkvr64cctf3294h9k4eanhff8z" {
		t.Fatalf("attenuations = %+v", summary.Att)
	}
	if summary.expiryText() == "unknown" {
		t.Fatalf("expiry did not decode: %+v", summary)
	}
}
