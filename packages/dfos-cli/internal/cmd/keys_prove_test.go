package cmd

// `dfos keys add` (alias `keys prove`) tests, of the PRESENTATION leg: the
// carriage, the resolution, the disclosure, the linkage check, the envelope, and
// the one attempt that puts it on the wire. What happens after the presentation
// — the status poll, the stale re-sign, and the six terminal states — is
// keys_prove_wait_test.go's.
//
// Like the vault, keys, and recover tests these drive
// RunE against the package globals setupDevices wires, so they MUST NOT run with
// t.Parallel().
//
// The ceremony operator is a loopback server rather than a mock: every failure
// this command has to distinguish is HTTP-shaped — a 404 for an expired code, a
// resolution that points off-authority, a refusal with a sentence in it, a host
// that does not answer at all — and a hand-written fake cannot get them wrong
// the way a real operator does.
//
// Nothing here reaches a real host. The stub is http on loopback, which is the
// one cleartext exemption checkCeremonyScheme makes.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/apispec"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/keystore"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/spf13/cobra"
)

// --- the stub ceremony operator ---

const (
	stubCode        = "ABCD2345"
	stubNonce       = "n0nce-64-bits-of-nothing"
	stubDID         = "did:dfos:z6MkadoptadoptadoptadoptadoptA"
	stubHandle      = "alice"
	stubDisplayName = "Alice Example"
	stubRoleSet     = "auth,assert"
	stubPrevCID     = "bafyreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy"
	stubExpiresAt   = "2026-08-30T12:00:00.000Z"
	stubPresentPath = "/keys/present"
)

type stubCeremony struct {
	server *httptest.Server

	// knobs — the resolution
	resolveStatus   int      // non-zero: answer the well-known with this status
	resolveBody     string   // non-empty: answer the well-known with this body
	resolveOmit     []string // members dropped from the resolution ("adopts.did" reaches inside)
	resolveAudience string   // non-empty: the audience answered instead of this authority
	resolvePresent  string   // non-empty: the presentation endpoint answered instead of the real one
	resolvePurpose  string   // non-empty: the purpose answered instead of key-add
	resolveRoleSet  string   // non-empty: the role set answered instead of the canonical one
	resolveRelay    string   // non-empty: the optional `relay` member of the resolution

	// knobs — the presentation
	presentStatus int    // non-zero: answer the presentation with this status
	presentBody   string // non-empty: the presentation body
	presentHangup bool   // drop the connection mid-request, so the POST gets no answer at all
	answerDID     string // non-empty: the identity the operator says already adopted the key

	// knobs — the status poll, which is the epilogue's operator half
	// (keys_prove_wait_test.go drives all of these)
	statusSequence  []map[string]any // answers handed out in order; the last one repeats
	statusStatus    int              // non-zero: answer the status route with this status
	statusBody      string           // the body that goes with statusStatus
	statusHangup    bool             // drop the connection, so a poll gets no answer at all
	statusFailFirst int              // answer this many polls with a 502 before behaving
	// staleUntil answers `presented` with `stale: true` until this many
	// presentations have arrived — the chain moving under a live ceremony, which
	// is an invitation to replace the envelope rather than a refusal of anything.
	staleUntil int
	// freshPrevCID is the head a RE-resolution answers. A stale ceremony that
	// re-resolved to the same head would be a stale ceremony forever.
	freshPrevCID string
	// freshDID and freshRoleSet move the POSITION on a re-resolution — the thing
	// a re-sign must refuse, because the position is what the human consented to.
	freshDID     string
	freshRoleSet string

	// observations
	wellKnownHits int
	presentHits   int
	statusHits    int
	lastCode      string
	lastStatusFor string
	lastPresented map[string]string
	lastEnvelopes []string
	lastQuery     url.Values
}

func newStubCeremony(t *testing.T) *stubCeremony {
	t.Helper()
	s := &stubCeremony{}
	s.server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.server.Close)
	return s
}

func (s *stubCeremony) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == keyProofWellKnownPath:
		s.wellKnownHits++
		s.lastCode = r.URL.Query().Get("code")
		if s.resolveStatus != 0 {
			w.WriteHeader(s.resolveStatus)
			_, _ = w.Write([]byte(s.resolveBody))
			return
		}
		if s.lastCode != stubCode {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"unknown or expired code"}`))
			return
		}
		writeJSON(w, s.resolution())

	case r.URL.Path == stubPresentPath && r.Method == http.MethodPost:
		s.presentHits++
		s.lastQuery = r.URL.Query()
		s.lastPresented = map[string]string{}
		_ = json.NewDecoder(r.Body).Decode(&s.lastPresented)
		if envelope := s.lastPresented["envelope"]; envelope != "" {
			s.lastEnvelopes = append(s.lastEnvelopes, envelope)
		}
		// The partition case: the request arrived and the answer never did. It is
		// the one presentation failure that is not a refusal, and the CLI has to
		// say so differently.
		if s.presentHangup {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		if s.presentStatus != 0 {
			w.WriteHeader(s.presentStatus)
			_, _ = w.Write([]byte(s.presentBody))
			return
		}
		// The ordinary answer names no key id and no DID: presenting stores the
		// proof and stops, and a chain row appears only once a human approves it.
		answer := map[string]any{"status": "presented"}
		if s.answerDID != "" {
			answer["did"] = s.answerDID
			answer["keyId"] = "key_ceremony"
		}
		writeJSON(w, answer)

	// The poll leg. Its URL is not answered anywhere: the CLI derives it from the
	// presentation endpoint's origin, so this route only ever gets asked at this
	// authority, with the ceremony's code and nothing else.
	case r.URL.Path == keyProofStatusPath:
		s.statusHits++
		s.lastStatusFor = r.URL.Query().Get("code")
		if s.statusHangup {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		// A surface that is restarting: unusable answers, then the ceremony. It is
		// a knob rather than a test's own goroutine so the flip happens where every
		// other answer is decided, in the handler.
		if s.statusHits <= s.statusFailFirst {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"upstream restarting"}`))
			return
		}
		if s.statusStatus != 0 {
			w.WriteHeader(s.statusStatus)
			_, _ = w.Write([]byte(s.statusBody))
			return
		}
		// The chain moved under the ceremony and the stored envelope names a head
		// that is no longer the head. It clears when a replacement arrives.
		if s.presentHits < s.staleUntil {
			writeJSON(w, map[string]any{"status": "presented", "stale": true})
			return
		}
		writeJSON(w, s.nextStatus())

	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"no route"}`))
	}
}

// nextStatus hands out the arranged answers in order and repeats the last one,
// which is how a real ceremony behaves: a status is a state, and a state that
// has been reached is the answer to every later ask.
func (s *stubCeremony) nextStatus() map[string]any {
	switch {
	case len(s.statusSequence) == 0:
		return map[string]any{"status": "presented"}
	case len(s.statusSequence) == 1:
		return s.statusSequence[0]
	}
	next := s.statusSequence[0]
	s.statusSequence = s.statusSequence[1:]
	return next
}

// resolution is the full signing context a live code answers with: everything
// the payload binds, and everything render-before-sign displays.
func (s *stubCeremony) resolution() map[string]any {
	adopts := map[string]any{"did": stubDID, "handle": stubHandle, "displayName": stubDisplayName}
	answer := map[string]any{
		"present":   s.presentURL(),
		"nonce":     stubNonce,
		"audience":  s.authority(),
		"purpose":   protocol.KeyAddJWSTyp,
		"adopts":    adopts,
		"roleSet":   stubRoleSet,
		"prevCID":   stubPrevCID,
		"expiresAt": stubExpiresAt,
	}
	if s.resolveAudience != "" {
		answer["audience"] = s.resolveAudience
	}
	if s.resolvePresent != "" {
		answer["present"] = s.resolvePresent
	}
	if s.resolvePurpose != "" {
		answer["purpose"] = s.resolvePurpose
	}
	if s.resolveRoleSet != "" {
		answer["roleSet"] = s.resolveRoleSet
	}
	if s.resolveRelay != "" {
		answer["relay"] = s.resolveRelay
	}
	// A re-resolution — the stale-head recovery's first step — answers the same
	// nonce against the CURRENT head. The position moves here only when a test is
	// asserting that a re-sign refuses to follow it.
	if s.wellKnownHits > 1 {
		if s.freshPrevCID != "" {
			answer["prevCID"] = s.freshPrevCID
		}
		if s.freshDID != "" {
			adopts["did"] = s.freshDID
		}
		if s.freshRoleSet != "" {
			answer["roleSet"] = s.freshRoleSet
		}
	}
	for _, member := range s.resolveOmit {
		if inner, ok := strings.CutPrefix(member, "adopts."); ok {
			delete(adopts, inner)
			continue
		}
		delete(answer, member)
	}
	return answer
}

func (s *stubCeremony) presentURL() string {
	return s.server.URL + stubPresentPath
}

// carriageURI is the QR form: a URL naming this operator's resolution with its
// code. It carries no signing context — that is the whole point of the shape.
func (s *stubCeremony) carriageURI() string {
	return s.server.URL + keyProofWellKnownPath + "?code=" + url.QueryEscape(stubCode)
}

// shortCode is what the operator's settings screen displays. A real one carries
// no scheme and resolves over https; this stub is loopback http, which is the
// one cleartext exemption, so the scheme is spelled out.
func (s *stubCeremony) shortCode() string {
	return "http://" + s.authority() + "/" + stubCode
}

func (s *stubCeremony) authority() string {
	u, _ := url.Parse(s.server.URL)
	return apispec.NormalizeAuthority(u.Scheme, u.Host)
}

// --- helpers ---

// runProve drives one `keys add` invocation. Stdin is not a terminal under
// `go test`, so every run that expects to complete passes --yes; the run that
// does not is asserting exactly that gate.
//
// IT PASSES --no-wait UNLESS THE CALLER SAYS OTHERWISE. Everything in this file
// is about the presentation leg — the carriage, the disclosure, the linkage
// check, the envelope, the one attempt — and the epilogue that follows a
// presentation has its own operator, its own clock, and its own file
// (keys_prove_wait_test.go). A test that wants the wait sets "no-wait" itself.
func runProve(t *testing.T, input string, flags map[string]string, out any) (stdout, stderr string, err error) {
	t.Helper()
	return runCapturingJSON(t, proveCmd(t, flags), []string{input}, out)
}

// runProveHuman is runProve without --json, for the assertions about what a
// person reads off the terminal on the way out.
func runProveHuman(t *testing.T, input string, flags map[string]string) (stdout, stderr string, err error) {
	t.Helper()
	return runCapturing(t, proveCmd(t, flags), []string{input})
}

func proveCmd(t *testing.T, flags map[string]string) *cobra.Command {
	t.Helper()
	cmd := newKeysProveCmd()
	cmd.SetIn(strings.NewReader(""))
	if _, waits := flags["no-wait"]; !waits {
		mustSetFlag(t, cmd, "no-wait", "true")
	}
	for name, value := range flags {
		mustSetFlag(t, cmd, name, value)
	}
	return cmd
}

// plantCandidate puts a key in the store under a candidate account, which is
// where a key a ceremony did not adopt lives.
func plantCandidate(t *testing.T, store *keystore.MemoryStore) string {
	t.Helper()
	_, pub, err := store.GenerateKey("plant:tmp")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	mb := protocol.EncodeMultikey(pub)
	if err := store.RenameKey("plant:tmp", candidateAccountPrefix+mb); err != nil {
		t.Fatalf("rename: %v", err)
	}
	return mb
}

// wireOracle points the resolution stack at an oracle that answers the
// has-ever-PROVED question, which is what the linkage refusal turns on. An
// unproved declaration on some other chain is not a link and not a burn — it is
// void, it never indexes, and it never obligates the true holder.
func wireOracle(t *testing.T) *fakeOracle {
	t.Helper()
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	relayFlag = "oracle"
	return oracle
}

// --- parsing ---

// A carriage is TWO values, whichever form carried it: the authority to ask, and
// the code to ask about. Nothing else in the URL is a value.
func TestKeysProve_ACarriageIsAnAuthorityAndACode(t *testing.T) {
	for _, tc := range []struct {
		name, input, wantHost, wantCode, wantVia string
	}{
		{"the URI form", "https://ceremony.example/.well-known/dfos-key-proof?code=xyz789",
			"ceremony.example", "xyz789", "carriage URI"},
		{"a deep link is the same two values", "https://ceremony.example/join?code=xyz789&tenant=t1",
			"ceremony.example", "xyz789", "carriage URI"},
		{"the short form", "ceremony.example/ABCD2345",
			"ceremony.example", "ABCD2345", "short code at ceremony.example"},
		{"a non-default port rides along", "https://ceremony.example:8443/ABCD2345",
			"ceremony.example:8443", "ABCD2345", "short code at ceremony.example:8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			car, err := parseCarriage(tc.input)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.input, err)
			}
			if car.Authority() != tc.wantHost || car.Code != tc.wantCode || car.Via != tc.wantVia {
				t.Fatalf("parsed %+v, want authority %q code %q via %q", car, tc.wantHost, tc.wantCode, tc.wantVia)
			}
		})
	}
}

func TestKeysProve_RejectsMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
	}{
		{"confusable glyph", "host.example/ABCD2I45", "not a ceremony code"},
		{"wrong length", "host.example/ABCD234", "not a ceremony code"},
		{"lowercase alphabet is normalized, not the length", "host.example/abcd234", "not a ceremony code"},
		{"two path segments", "host.example/a/ABCD2345", "neither carriage form"},
		{"no host", "ABCD2345", "neither carriage form"},
		{"an empty code member", "https://host.example/c?code=", "'code' member is empty"},
		{"a code that is not a token", "https://host.example/c?code=" + url.QueryEscape("a b/c"), "not a ceremony code"},
		{"duplicated code member", "https://h.example/c?code=a&code=b", "carries 'code' 2 times"},
		{"userinfo", "https://user:pw@h.example/c?code=abc", "userinfo"},
		{"cleartext off loopback", "http://host.example/c?code=abc", "refusing a cleartext ceremony"},
		{"not http at all", "ftp://host.example/c?code=abc", "refusing scheme 'ftp'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCarriage(tc.input)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("input %q: want error containing %q, got %v", tc.input, tc.want, err)
			}
		})
	}
}

// A URL carrying the signing context instead of a code is refused, and refused
// by name. There is no self-contained carriage: a context nobody resolved is a
// context somebody else chose, and reading one would skip the step that binds
// the ceremony to the authority the human typed.
func TestKeysProve_RefusesACarriageThatCarriesItsOwnContext(t *testing.T) {
	for _, input := range []string{
		"https://h.example/c?ceremony=cer_1&nonce=abc",
		"https://h.example/c?nonce=abc",
		"https://h.example/c?ceremony=cer_1&nonce=abc&did=did:dfos:z6Mk&roleSet=auth,assert",
	} {
		_, err := parseCarriage(input)
		if err == nil || !strings.Contains(err.Error(), "rather than a code") {
			t.Fatalf("input %q: want the context-carriage refusal, got %v", input, err)
		}
		if err != nil && !strings.Contains(err.Error(), "resolving that code at that authority") {
			t.Fatalf("the refusal does not say where context comes from: %v", err)
		}
	}
}

func TestKeysProve_ShortCodeIsCaseNormalized(t *testing.T) {
	stub := newStubCeremony(t)
	car, err := resolveCeremony("http://" + stub.authority() + "/" + strings.ToLower(stubCode))
	if err != nil {
		t.Fatalf("resolve lower-case code: %v", err)
	}
	if stub.lastCode != stubCode {
		t.Fatalf("resolved with %q, want %q", stub.lastCode, stubCode)
	}
	if car.Nonce != stubNonce || car.Code != stubCode {
		t.Fatalf("ceremony: %+v", car)
	}
	if car.Via != "short code at "+stub.authority() {
		t.Fatalf("via: %q", car.Via)
	}
}

// The whole signing context comes out of the resolution, and both carriage forms
// land on the same one. What the carriage carried was an authority and a code.
func TestKeysProve_ResolutionCarriesTheWholeSigningContext(t *testing.T) {
	for _, form := range []string{"short code", "carriage URI"} {
		t.Run(form, func(t *testing.T) {
			stub := newStubCeremony(t)
			input := stub.shortCode()
			if form == "carriage URI" {
				input = stub.carriageURI()
			}

			cer, err := resolveCeremony(input)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if cer.DID != stubDID || cer.Handle != stubHandle || cer.DisplayName != stubDisplayName {
				t.Fatalf("adopts: %+v", cer)
			}
			if cer.RoleSet != stubRoleSet || cer.PrevCID != stubPrevCID {
				t.Fatalf("position: %+v", cer)
			}
			if cer.Nonce != stubNonce || cer.Audience != stub.authority() {
				t.Fatalf("challenge: %+v", cer)
			}
			if cer.Present != stub.presentURL() || cer.Code != stubCode {
				t.Fatalf("presentation: %+v", cer)
			}
			if cer.ExpiresAt != stubExpiresAt {
				t.Fatalf("expiresAt: %q", cer.ExpiresAt)
			}
		})
	}
}

// A holder MUST NOT sign on a resolution that omits the identity, the roles, or
// the head — those are what the payload binds and what the human is shown, and a
// partial position is consent to something nobody saw. Every missing member is
// named at once, so a person is not made to re-run a ceremony to find the next.
func TestKeysProve_RefusesAResolutionMissingThePosition(t *testing.T) {
	for _, member := range []string{
		"present", "nonce", "audience", "adopts.did", "adopts.handle", "adopts.displayName", "roleSet", "prevCID",
	} {
		t.Run(member, func(t *testing.T) {
			stub := newStubCeremony(t)
			stub.resolveOmit = []string{member}

			_, err := resolveCeremony(stub.shortCode())
			if err == nil || !strings.Contains(err.Error(), "missing "+member) {
				t.Fatalf("omitting %q: want a refusal naming it, got %v", member, err)
			}
			if !strings.Contains(err.Error(), "nothing was signed") {
				t.Fatalf("the refusal does not say nothing was signed: %v", err)
			}
		})
	}

	// All at once, named in one sentence rather than one per run.
	stub := newStubCeremony(t)
	stub.resolveOmit = []string{"adopts.did", "roleSet", "prevCID"}
	_, err := resolveCeremony(stub.shortCode())
	if err == nil {
		t.Fatal("a resolution missing the whole position was accepted")
	}
	for _, want := range []string{"adopts.did", "roleSet", "prevCID"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal names only some of what is missing (%q absent): %v", want, err)
		}
	}
}

// A role set outside its one canonical spelling names a set no envelope can
// carry. Catching it at resolution means the refusal lands before a key is
// minted, rather than coming back out of the signer.
func TestKeysProve_RefusesANonCanonicalRoleSet(t *testing.T) {
	for _, roleSet := range []string{"assert,auth", "auth, assert", "auth,auth", "auth,owner", "owner", " auth"} {
		t.Run(roleSet, func(t *testing.T) {
			stub := newStubCeremony(t)
			stub.resolveRoleSet = roleSet

			_, err := resolveCeremony(stub.shortCode())
			if err == nil || !strings.Contains(err.Error(), "role set this envelope cannot carry") {
				t.Fatalf("role set %q: want a refusal, got %v", roleSet, err)
			}
			if !strings.Contains(err.Error(), "Nothing was signed") {
				t.Fatalf("the refusal does not say nothing was signed: %v", err)
			}
		})
	}
}

// A resolution naming some OTHER ceremony purpose is not this command's to
// complete. An absent purpose is tolerated — silence is not a claim about
// another ceremony — but a different one is.
func TestKeysProve_RefusesAForeignPurpose(t *testing.T) {
	stub := newStubCeremony(t)
	stub.resolvePurpose = "did:dfos:something-else"

	_, err := resolveCeremony(stub.shortCode())
	if err == nil || !strings.Contains(err.Error(), "did:dfos:something-else") ||
		!strings.Contains(err.Error(), protocol.KeyAddJWSTyp) {
		t.Fatalf("want a purpose refusal naming both, got %v", err)
	}

	absent := newStubCeremony(t)
	absent.resolveOmit = []string{"purpose"}
	if _, err := resolveCeremony(absent.shortCode()); err != nil {
		t.Fatalf("an absent purpose failed the ceremony: %v", err)
	}
}

// A code is displayed grouped so a person can read it, and it is retyped the way
// it was read. The separators are not in the alphabet, so dropping them decides
// nothing.
func TestKeysProve_ACodeSurvivesTheSpacingItWasDisplayedWith(t *testing.T) {
	for _, raw := range []string{"ABCD2345", "abcd2345", "ABCD-2345", "ABCD 2345", "AB CD-23 45", " ABCD2345 "} {
		code, ok := normalizeDeviceCode(raw)
		if !ok || code != stubCode {
			t.Fatalf("normalizeDeviceCode(%q) = %q, %v — want %q", raw, code, ok, stubCode)
		}
	}
	// What the tolerance is NOT: a separator never counts as a character, and
	// nothing outside the alphabet is dropped to make a code fit.
	for _, raw := range []string{"ABCD-234", "ABCD-234I", "ABCD_2345", "ABCD.2345"} {
		if code, ok := normalizeDeviceCode(raw); ok {
			t.Fatalf("normalizeDeviceCode(%q) accepted %q", raw, code)
		}
	}
}

func TestKeysProve_ResolvesACodeTypedWithSeparators(t *testing.T) {
	stub := newStubCeremony(t)
	car, err := resolveCeremony("http://" + stub.authority() + "/ABCD-23 45")
	if err != nil {
		t.Fatalf("resolve a grouped code: %v", err)
	}
	if stub.lastCode != stubCode {
		t.Fatalf("resolved with %q, want %q", stub.lastCode, stubCode)
	}
	if car.Nonce != stubNonce {
		t.Fatalf("ceremony: %+v", car)
	}
}

// The resolution's `relay` member is a courtesy: usable when it is one, absent
// when it is not, and never a reason to fail a ceremony.
func TestKeysProve_ReadsTheResolutionsOptionalRelay(t *testing.T) {
	for _, tc := range []struct {
		name, answered, want string
	}{
		{"absent", "", ""},
		{"https", "https://relay.example", "https://relay.example"},
		{"trailing slash trimmed", "https://relay.example/", "https://relay.example"},
		{"a path is a base too", "https://relay.example/dfos/", "https://relay.example/dfos"},
		{"http on loopback, as everywhere else here", "http://127.0.0.1:9999", "http://127.0.0.1:9999"},
		{"cleartext off loopback is ignored, not refused", "http://relay.example", ""},
		{"not a URL at all", "nonsense", ""},
		{"blank", "   ", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := newStubCeremony(t)
			stub.resolveRelay = tc.answered

			car, err := resolveCeremony(stub.shortCode())
			if err != nil {
				t.Fatalf("a %q relay member failed the ceremony: %v", tc.answered, err)
			}
			if car.Relay != tc.want {
				t.Fatalf("relay: %q, want %q", car.Relay, tc.want)
			}
		})
	}
}

// A carriage is an authority and a code. A `relay` query member on one is not an
// oracle — only a resolution names one — and it is not carried anywhere, because
// nothing but the code is read off the URL.
func TestKeysProve_ACarriageURIsQueryIsNotAnOracle(t *testing.T) {
	car, err := parseCarriage("https://ceremony.example/c?code=abc&relay=https%3A%2F%2Frelay.example")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if car.Code != "abc" || car.Authority() != "ceremony.example" {
		t.Fatalf("parsed: %+v", car)
	}
}

// The rule that makes both carriage forms safe: a code typed at one host can
// never resolve to a ceremony that lands anywhere else. Two members carry the
// authority, and either one moving is the same refusal.
func TestKeysProve_RefusesAnOffAuthorityResolution(t *testing.T) {
	t.Run("the audience moved", func(t *testing.T) {
		stub := newStubCeremony(t)
		stub.resolveAudience = "elsewhere.example"

		_, err := resolveCeremony(stub.shortCode())
		if err == nil || !strings.Contains(err.Error(), "REFUSING") ||
			!strings.Contains(err.Error(), "elsewhere.example") {
			t.Fatalf("want an off-authority refusal, got %v", err)
		}
		if stub.wellKnownHits != 1 {
			t.Fatalf("asked the well-known %d times, want exactly 1", stub.wellKnownHits)
		}
	})

	t.Run("the presentation endpoint moved", func(t *testing.T) {
		stub := newStubCeremony(t)
		stub.resolvePresent = "https://elsewhere.example/keys/present"

		_, err := resolveCeremony(stub.shortCode())
		if err == nil || !strings.Contains(err.Error(), "REFUSING") ||
			!strings.Contains(err.Error(), "elsewhere.example") {
			t.Fatalf("want an off-authority refusal, got %v", err)
		}
	})

	// An audience that byte-equals the authority does not license a presentation
	// endpoint that does not: both are checked, independently.
	t.Run("a matching audience does not cover a moved endpoint", func(t *testing.T) {
		stub := newStubCeremony(t)
		stub.resolvePresent = "https://elsewhere.example/keys/present"
		stub.resolveAudience = stub.authority()

		if _, err := resolveCeremony(stub.shortCode()); err == nil {
			t.Fatal("a moved presentation endpoint rode in behind a matching audience")
		}
	})
}

// A code that does not resolve is not retried and not polled: the route is rate
// limited, and a ceremony lives ten minutes.
func TestKeysProve_UnknownCodeIsAskedOnce(t *testing.T) {
	stub := newStubCeremony(t)

	_, err := resolveCeremony("http://" + stub.authority() + "/ZZZZ9999")
	if err == nil || !strings.Contains(err.Error(), "unknown or expired code") ||
		!strings.Contains(err.Error(), "Mint a fresh one") {
		t.Fatalf("want the expired-code guidance, got %v", err)
	}
	if stub.wellKnownHits != 1 {
		t.Fatalf("asked the well-known %d times, want exactly 1", stub.wellKnownHits)
	}
}

func TestKeysProve_AResolutionFailureIsNotAnExpiredCode(t *testing.T) {
	stub := newStubCeremony(t)
	stub.resolveStatus = http.StatusInternalServerError
	stub.resolveBody = `{"error":"the ceremony store is down"}`

	_, err := resolveCeremony(stub.shortCode())
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") ||
		!strings.Contains(err.Error(), "the ceremony store is down") {
		t.Fatalf("want the operator's own sentence, got %v", err)
	}
	if stub.wellKnownHits != 1 {
		t.Fatalf("asked the well-known %d times, want exactly 1", stub.wellKnownHits)
	}
}

// --- the ceremony, end to end ---

func TestKeysProve_HappyPath(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	oracle := wireOracle(t)
	stub := newStubCeremony(t)

	var result proveResult
	_, stderr, err := runProve(t, stub.shortCode(), map[string]string{"yes": "true"}, &result)
	if err != nil {
		t.Fatalf("keys prove: %v", err)
	}

	// The disclosure a human is owed, before anything was signed: the audience,
	// the identity being joined, and the roles being consented to.
	for _, want := range []string{
		"Audience:", stub.authority(), protocol.KeyAddJWSTyp,
		"Adds to:", stubDID, stubDisplayName, "@" + stubHandle,
		"Roles:", "auth — sign in and act as this identity", "assert — publish and attest as this identity",
		"Builds on:", stubPrevCID,
		"no identity has ever proved this key",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("disclosure missing %q:\n%s", want, stderr)
		}
	}
	// A ceremony that grants auth and assert does not mention controller. The
	// role lines are the human's only warning that one is being asked for.
	if strings.Contains(stderr, "controller") {
		t.Fatalf("the disclosure named a role this ceremony does not grant:\n%s", stderr)
	}

	if result.Status != "presented" {
		t.Fatalf("result: %+v", result)
	}
	if result.Audience != stub.authority() || result.Code != stubCode {
		t.Fatalf("result carriage: %+v", result)
	}
	if result.Adopts != stubDID || result.RoleSet != stubRoleSet || result.PrevCID != stubPrevCID {
		t.Fatalf("result position: %+v", result)
	}
	if !result.Linkage.Checked || len(result.Linkage.Declaring) != 0 {
		t.Fatalf("linkage: %+v", result.Linkage)
	}

	// The presentation body's shape, and what does NOT ride in it: the code and
	// the description travel beside the envelope, and the nonce rides only inside
	// the signed payload.
	if got := stub.lastPresented["code"]; got != stubCode {
		t.Fatalf("presented code: %q", got)
	}
	envelope := stub.lastPresented["envelope"]
	if envelope == "" {
		t.Fatal("the presentation carried no envelope")
	}
	// A machine that can name neither its user nor itself sends no description at
	// all, so the member count follows the default rather than assuming it.
	wantMembers := 2
	if want := defaultKeyDescription(); want != "" {
		wantMembers = 3
		if got := stub.lastPresented["description"]; got != want {
			t.Fatalf("presented description: %q, want %q", got, want)
		}
	}
	if len(stub.lastPresented) != wantMembers {
		t.Fatalf("the presentation body has extra members: %v", stub.lastPresented)
	}
	if stub.lastQuery.Get("code") != "" || stub.lastQuery.Get("nonce") != "" {
		t.Fatalf("the presentation POST carried the context in its query: %v", stub.lastQuery)
	}

	// The envelope itself, through the kit's own verifier, against EVERY arm a
	// real operator checks: the typ, the audience, the three positional members,
	// freshness, and the signature against the payload's OWN public key.
	verified, err := protocol.VerifyKeyProof(envelope, protocol.KeyProofExpectations{
		Typ: protocol.KeyAddJWSTyp, Audience: stub.authority(),
		DID: stubDID, RoleSet: stubRoleSet, PrevCID: stubPrevCID,
	}, time.Now())
	if err != nil {
		t.Fatalf("verify the envelope: %v", err)
	}
	if verified.Payload.Nonce != stubNonce {
		t.Fatalf("nonce: %q", verified.Payload.Nonce)
	}
	if verified.Payload.PublicKeyMultibase != result.PublicKey {
		t.Fatalf("the envelope names %s, the run reported %s", verified.Payload.PublicKeyMultibase, result.PublicKey)
	}
	if strings.Contains(stderr, "PRIVATE") || strings.Contains(envelope, result.PublicKey[:0]+"seed") {
		t.Fatal("private material surfaced")
	}

	// The key is held, under a candidate account. That is the NORMAL resting
	// place: presenting stores the proof, and a chain row appears only once a
	// human approves it on the operator's own surface.
	if result.Account != candidateAccountPrefix+result.PublicKey {
		t.Fatalf("account: %q", result.Account)
	}
	if !keys.HasKey(result.Account) {
		t.Fatalf("the candidate key is not in the keystore under %q", result.Account)
	}
	if oracle.indexQueries < 2 {
		t.Fatalf("the oracle was asked %d times — the sentinel probe and the key both", oracle.indexQueries)
	}
}

// A completion that names the identity that adopted the key moves the key out of
// the candidate namespace and into its ordinary address — its own public key —
// and writes the vault provenance the DID and key id make possible.
func TestKeysProve_AdoptedKeyIsFiledUnderItsIdentity(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	wireOracle(t)
	stub := newStubCeremony(t)
	stub.answerDID = stubDID

	var result proveResult
	if _, _, err := runProve(t, stub.shortCode(), map[string]string{"yes": "true"}, &result); err != nil {
		t.Fatalf("keys prove: %v", err)
	}
	want := keyAccount(result.PublicKey)
	if result.Account != want {
		t.Fatalf("account: %q, want %q", result.Account, want)
	}
	if !keys.HasKey(want) {
		t.Fatalf("no key under %q", want)
	}
	if keys.HasKey(candidateAccountPrefix + result.PublicKey) {
		t.Fatal("the candidate account was left behind after adoption")
	}
	// The vault now records the provenance, so the phrase covers the key.
	meta, err := getVaults().Load("personal")
	if err != nil {
		t.Fatalf("load vault: %v", err)
	}
	if len(meta.Minted) != 1 || meta.Minted[0].DID != stub.answerDID || meta.Minted[0].PublicKey != result.PublicKey {
		t.Fatalf("vault records: %+v", meta.Minted)
	}
}

// The candidate key is held, and a `prune` run leaves it exactly where it is.
func TestKeysProve_CandidateKeyIsListedAndNeverPruned(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	wireOracle(t)
	stub := newStubCeremony(t)

	var result proveResult
	if _, _, err := runProve(t, stub.shortCode(), map[string]string{"yes": "true"}, &result); err != nil {
		t.Fatalf("keys prove: %v", err)
	}

	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	entry := entryFor(t, ledger, result.Account)
	if entry.Status != statusCandidate || entry.Origin != originCandidate {
		t.Fatalf("entry: %+v", entry)
	}
	if entry.Prunable {
		t.Fatal("a candidate key is prunable")
	}
	if entry.PublicKey != result.PublicKey {
		t.Fatalf("entry public key %q, want %q", entry.PublicKey, result.PublicKey)
	}

	pruned := runPrune(t, true)
	for _, o := range pruned.Orphans {
		if o.Account == result.Account {
			t.Fatalf("prune removed the candidate key: %+v", o)
		}
	}
	if !keys.HasKey(result.Account) {
		t.Fatal("prune removed the candidate key")
	}
}

// --- one key, one DID ---

func TestKeysProve_RefusesAKeyAnIdentityHasDeclared(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	oracle := wireOracle(t)
	stub := newStubCeremony(t)

	held := plantCandidate(t, storeA)
	oracle.declare(held, "did:dfos:z6MkotherotherotherotherotherA", false, "")

	_, _, err := runProve(t, stub.carriageURI(), map[string]string{"yes": "true", "key": held}, nil)
	if err == nil || !strings.Contains(err.Error(), "REFUSING") ||
		!strings.Contains(err.Error(), "HAS-EVER-PROVED") {
		t.Fatalf("want a linkage refusal, got %v", err)
	}
	if stub.presentHits != 0 {
		t.Fatal("a refused ceremony was completed anyway")
	}

	// --force-linked is the human saying they mean to publish the link.
	var result proveResult
	if _, stderr, err := runProve(t, stub.carriageURI(),
		map[string]string{"yes": "true", "key": held, "force-linked": "true"}, &result); err != nil {
		t.Fatalf("--force-linked: %v", err)
	} else if !strings.Contains(stderr, "has already proved this key") {
		t.Fatalf("the forced run did not say what it was overriding:\n%s", stderr)
	}
	if result.Status != "presented" || !result.Forced {
		t.Fatalf("result: %+v", result)
	}
}

// A local chain that already names the key is a certainty, and certainty gets
// the earlier refusal — before any relay is asked.
func TestKeysProve_RefusesAKeyTheLocalRelayDeclares(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createIdentity(t, "alice", storeA)
	wireOracle(t)
	stub := newStubCeremony(t)

	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	var declared string
	for _, e := range ledger.Entries {
		if e.Status == statusDeclared {
			declared = e.PublicKey
		}
	}
	if declared == "" {
		t.Fatalf("no declared key for %s in the ledger", did)
	}

	_, _, err = runProve(t, stub.carriageURI(), map[string]string{"yes": "true", "key": declared}, nil)
	if err == nil || !strings.Contains(err.Error(), "already proved into "+did) {
		t.Fatalf("want a local linkage refusal, got %v", err)
	}
	if stub.presentHits != 0 {
		t.Fatal("a refused ceremony was completed anyway")
	}
}

// A key already filed under an identity's account stays there. An operator's
// answer files a CANDIDATE; it never moves a key something else is using.
func TestKeysProve_AnAdoptedAnswerNeverMovesAnExistingAccount(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createIdentity(t, "alice", storeA)
	wireOracle(t)
	stub := newStubCeremony(t)
	stub.answerDID = stubDID

	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	var declared keyLedgerEntry
	for _, e := range ledger.Entries {
		if e.Status == statusDeclared {
			declared = e
		}
	}
	if declared.Account == "" {
		t.Fatalf("no declared key for %s", did)
	}

	var result proveResult
	if _, _, err := runProve(t, stub.carriageURI(),
		map[string]string{"yes": "true", "force-linked": "true", "key": declared.PublicKey}, &result); err != nil {
		t.Fatalf("--force-linked: %v", err)
	}
	if result.Account != declared.Account {
		t.Fatalf("the key moved: %q, want %q", result.Account, declared.Account)
	}
	if !keys.HasKey(declared.Account) {
		t.Fatalf("%s no longer holds the key", declared.Account)
	}
	if keys.HasKey(stub.answerDID + "#key_ceremony") {
		t.Fatal("the operator's answer filed the key under its own identity")
	}
}

// An oracle that cannot answer is never read as "nothing declares this key".
func TestKeysProve_UnanswerableCheckRequiresAcknowledgment(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arrange func(*fakeOracle)
		want    string
	}{
		{"does not serve the index", func(o *fakeOracle) { o.indexStatus = http.StatusNotImplemented }, "501"},
		{"predates the key filter", func(o *fakeOracle) {
			o.ignoresKeyParam = true
			o.declare("z6MkirrelevantirrelevantirrelevantA", "did:dfos:z6Mksomeone", false, "")
		}, "ignored the 'key=' parameter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storeA, _, _ := setupDevices(t)
			keys = storeA
			createVault(t, "personal")
			oracle := wireOracle(t)
			tc.arrange(oracle)
			stub := newStubCeremony(t)

			_, _, err := runProve(t, stub.carriageURI(), map[string]string{"yes": "true"}, nil)
			if err == nil || !strings.Contains(err.Error(), "could not run") ||
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an unanswerable-check refusal mentioning %q, got %v", tc.want, err)
			}
			if !strings.Contains(err.Error(), "NOT 'no identity declares this key'") {
				t.Fatalf("the refusal read silence as an answer: %v", err)
			}
			if stub.presentHits != 0 {
				t.Fatal("signed anyway")
			}

			var result proveResult
			if _, stderr, err := runProve(t, stub.carriageURI(),
				map[string]string{"yes": "true", "force-linked": "true"}, &result); err != nil {
				t.Fatalf("--force-linked: %v", err)
			} else if !strings.Contains(stderr, "NOT CHECKED") {
				t.Fatalf("the forced run did not disclose the unchecked linkage:\n%s", stderr)
			}
			if result.Linkage.Checked || result.Status != "presented" {
				t.Fatalf("result: %+v", result)
			}
		})
	}
}

// No peer at all is the same class of failure as a peer that cannot answer —
// and the refusal names both halves, because a machine with no peer whose
// ceremony named no relay cannot fix the second half from here.
func TestKeysProve_NoOracleConfiguredRequiresAcknowledgment(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	stub := newStubCeremony(t)

	_, _, err := runProve(t, stub.carriageURI(), map[string]string{"yes": "true"}, nil)
	if err == nil || !strings.Contains(err.Error(), "could not run") ||
		!strings.Contains(err.Error(), "no peer to talk to") {
		t.Fatalf("want the no-oracle refusal, got %v", err)
	}
	if !strings.Contains(err.Error(), "Nor did this ceremony name one") {
		t.Fatalf("the refusal did not say the ceremony offered no relay either: %v", err)
	}
	if stub.presentHits != 0 {
		t.Fatal("signed anyway")
	}
}

// A machine that has no relay of its own takes the one the resolution named —
// for this one check. Nothing about it is written down.
func TestKeysProve_FallsBackToTheRelayTheResolutionNamed(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	// Deliberately NOT registerAsPeer: this machine knows no relay at all.
	oracle := newFakeOracle(t)
	stub := newStubCeremony(t)
	stub.resolveRelay = oracle.server.URL

	var result proveResult
	_, stderr, err := runProve(t, stub.shortCode(), map[string]string{"yes": "true"}, &result)
	if err != nil {
		t.Fatalf("keys prove: %v", err)
	}
	if !result.Linkage.Checked || result.Linkage.OracleVia != oracleViaResolution {
		t.Fatalf("linkage: %+v", result.Linkage)
	}
	if result.Linkage.OracleURL != oracle.server.URL {
		t.Fatalf("oracle URL: %q, want %q", result.Linkage.OracleURL, oracle.server.URL)
	}
	// The same discipline as a configured oracle: the sentinel probe, then the key.
	if oracle.indexQueries < 2 {
		t.Fatalf("the fallback oracle was asked %d times — the sentinel probe and the key both", oracle.indexQueries)
	}
	// The human is told whose oracle answered, because that is trust they are
	// extending at the moment they consent.
	if !strings.Contains(stderr, "named by the ceremony resolution") {
		t.Fatalf("the disclosure did not name the oracle's provenance:\n%s", stderr)
	}
	// And it is not a peer. A ceremony configures nothing.
	if len(cfg.Relays) != 0 {
		t.Fatalf("the ceremony's relay was registered: %v", cfg.Relays)
	}
	if cfg.DefaultPeer != "" {
		t.Fatalf("the ceremony's relay became a default: %q", cfg.DefaultPeer)
	}
}

// This machine's own peer always wins, and the relay the operator named is not
// even asked.
func TestKeysProve_AConfiguredPeerOutranksTheResolutionsRelay(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	mine := wireOracle(t)
	theirs := newFakeOracle(t)
	stub := newStubCeremony(t)
	stub.resolveRelay = theirs.server.URL

	var result proveResult
	_, stderr, err := runProve(t, stub.shortCode(), map[string]string{"yes": "true"}, &result)
	if err != nil {
		t.Fatalf("keys prove: %v", err)
	}
	if result.Linkage.OracleVia != oracleViaPeer || result.Linkage.Oracle != "oracle" {
		t.Fatalf("linkage: %+v", result.Linkage)
	}
	if theirs.indexQueries != 0 {
		t.Fatalf("the ceremony's relay was asked %d times despite a configured peer", theirs.indexQueries)
	}
	if mine.indexQueries < 2 {
		t.Fatalf("the configured oracle was asked %d times", mine.indexQueries)
	}
	if strings.Contains(stderr, "named by the ceremony resolution") {
		t.Fatalf("a configured peer was reported as the ceremony's:\n%s", stderr)
	}
}

// The fallback is for a holder that brought NO oracle — not for one whose
// oracle this machine found something wrong with.
//
// An unknown --relay is a relay the operator named and this machine cannot
// resolve. A moved DID pin is worse: the relay at that URL is not the one the
// config pinned, which is either a re-key or a different relay answering, and
// the CLI cannot tell those apart. Reaching past either for the relay the
// CEREMONY named would hand the oracle question to the party running the
// ceremony at exactly the moment this machine had reason to distrust the one it
// was told to use.
func TestKeysProve_ANamedOracleThatFailsIsNotReplacedByTheCeremonys(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arrange func(*testing.T)
		want    string
	}{
		{
			name: "the pin has moved",
			arrange: func(t *testing.T) {
				peer := newFakePeer(t) // serves pinnedDID
				cfg.Relays["prod"] = config.RelayConfig{URL: peer.server.URL, DID: otherDID}
				relayFlag = "prod"
			},
			// The alarm keeps its own words: both DIDs and the one command that
			// resolves it.
			want: "peer repin prod",
		},
		{
			name: "the relay is not one this machine knows",
			arrange: func(t *testing.T) {
				relayFlag = "not-registered"
			},
			want: "not-registered",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storeA, _, _ := setupDevices(t)
			keys = storeA
			createVault(t, "personal")
			theirs := newFakeOracle(t)
			stub := newStubCeremony(t)
			stub.resolveRelay = theirs.server.URL
			tc.arrange(t)

			_, _, err := runProve(t, stub.shortCode(), map[string]string{"yes": "true"}, nil)
			if err == nil || !strings.Contains(err.Error(), "could not run") {
				t.Fatalf("want an unanswerable-check refusal, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the refusal must carry %q:\n%v", tc.want, err)
			}
			if theirs.indexQueries != 0 {
				t.Fatalf("the ceremony's relay answered %d times for a machine that named its own", theirs.indexQueries)
			}
			if stub.presentHits != 0 {
				t.Fatal("signed anyway")
			}
			// A relay WAS offered by the ceremony, so the refusal must not claim
			// there was nothing to fall back to.
			if strings.Contains(err.Error(), "Nor did this ceremony name one") {
				t.Fatalf("the refusal reported no ceremony relay when one was offered: %v", err)
			}
		})
	}
}

// A fallback oracle answers under the same discipline it would as a peer: a
// relay that cannot answer the question refuses the ceremony rather than
// answering it with silence.
func TestKeysProve_AFallbackOracleThatCannotAnswerStillRefuses(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arrange func(*fakeOracle)
		want    string
	}{
		{"does not serve the index", func(o *fakeOracle) { o.indexStatus = http.StatusNotImplemented }, "501"},
		{"predates the key filter", func(o *fakeOracle) {
			o.ignoresKeyParam = true
			o.declare("z6MkirrelevantirrelevantirrelevantA", "did:dfos:z6Mksomeone", false, "")
		}, "ignored the 'key=' parameter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storeA, _, _ := setupDevices(t)
			keys = storeA
			createVault(t, "personal")
			oracle := newFakeOracle(t)
			tc.arrange(oracle)
			stub := newStubCeremony(t)
			stub.resolveRelay = oracle.server.URL

			_, _, err := runProve(t, stub.shortCode(), map[string]string{"yes": "true"}, nil)
			if err == nil || !strings.Contains(err.Error(), "could not run") ||
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an unanswerable-check refusal mentioning %q, got %v", tc.want, err)
			}
			// A relay WAS named — the refusal is about what it said, not about
			// there being nothing to ask.
			if strings.Contains(err.Error(), "Nor did this ceremony name one") {
				t.Fatalf("the refusal reported no relay when one answered: %v", err)
			}
			if stub.presentHits != 0 {
				t.Fatal("signed anyway")
			}
		})
	}
}

// --- the confirmation gate ---

func TestKeysProve_NonInteractiveWithoutYesSignsNothing(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	wireOracle(t)
	stub := newStubCeremony(t)

	_, stderr, err := runProve(t, stub.carriageURI(), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "nothing was signed") {
		t.Fatalf("want the confirmation gate, got %v", err)
	}
	if !strings.Contains(stderr, "Audience:") {
		t.Fatalf("the audience was not disclosed before the refusal:\n%s", stderr)
	}
	if stub.presentHits != 0 {
		t.Fatal("completed without a confirmation")
	}
	// The minted key is not lost — it is named in the refusal and held.
	if !strings.Contains(err.Error(), candidateAccountPrefix) {
		t.Fatalf("the refusal did not name the held candidate: %v", err)
	}
}

// --- completion failures ---

func TestKeysProve_ARefusedCompletionIsBurnedAndNotRetried(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	wireOracle(t)
	stub := newStubCeremony(t)
	stub.presentStatus = http.StatusBadRequest
	stub.presentBody = `{"error":"nonce already consumed"}`

	_, _, err := runProve(t, stub.carriageURI(), map[string]string{"yes": "true"}, nil)
	if err == nil {
		t.Fatal("a refused completion succeeded")
	}
	for _, want := range []string{"refused the proof (HTTP 400)", "nonce already consumed",
		"Treat this ceremony as spent", "Mint a fresh code", "--key "} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("failure message missing %q:\n%v", want, err)
		}
	}
	if stub.presentHits != 1 {
		t.Fatalf("presented %d times — a burned ceremony is never retried", stub.presentHits)
	}
}

// A presentation that got no answer is NOT a refusal, and the failure has to
// distinguish them: a refusal is something the operator said, and a partition is
// not. Here the resolution succeeds and the POST is what goes unanswered.
func TestKeysProve_AnUnreachableOperatorReadsAsUnreachable(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	wireOracle(t)
	stub := newStubCeremony(t)
	stub.presentHangup = true

	_, _, err := runProve(t, stub.carriageURI(), map[string]string{"yes": "true"}, nil)
	if err == nil || !strings.Contains(err.Error(), "could not reach the ceremony operator") {
		t.Fatalf("want an unreachable-operator failure, got %v", err)
	}
	// It is still spent as far as this machine knows, and it still is not retried.
	if !strings.Contains(err.Error(), "If the request arrived, the proof was presented") {
		t.Fatalf("the failure did not state the ambiguity: %v", err)
	}
	if stub.presentHits != 1 {
		t.Fatalf("presented %d times — an unanswered presentation is not retried either", stub.presentHits)
	}
}

// A host that cannot be reached AT ALL fails at the resolution, before any key
// material is touched — a different sentence, because nothing was signed and the
// code is still live.
func TestKeysProve_AnUnreachableResolutionCostsNothing(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	wireOracle(t)
	stub := newStubCeremony(t)
	uri := stub.carriageURI()
	stub.server.Close() // the operator is gone before the code is resolved

	_, _, err := runProve(t, uri, map[string]string{"yes": "true"}, nil)
	if err == nil || !strings.Contains(err.Error(), "to resolve the code") {
		t.Fatalf("want a resolution failure, got %v", err)
	}
	if !strings.Contains(err.Error(), "Nothing was signed and nothing was sent") {
		t.Fatalf("the failure did not say the ceremony survived: %v", err)
	}
}

func TestKeysProve_A200ThatDoesNotCompleteIsAFailure(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	wireOracle(t)
	stub := newStubCeremony(t)
	stub.presentStatus = http.StatusOK
	stub.presentBody = `{"status":"pending","message":"awaiting operator approval"}`

	_, _, err := runProve(t, stub.carriageURI(), map[string]string{"yes": "true"}, nil)
	if err == nil || !strings.Contains(err.Error(), "without accepting the proof") ||
		!strings.Contains(err.Error(), "awaiting operator approval") {
		t.Fatalf("want an incomplete-answer failure, got %v", err)
	}
}

// --- flags ---

func TestKeysProve_KeyAndVaultAreMutuallyExclusive(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	_, _, err := runProve(t, "https://h.example/c?ceremony=x&nonce=y",
		map[string]string{"key": "z6Mk", "vault": "personal"}, nil)
	if err == nil || !strings.Contains(err.Error(), "--key names a key this machine already holds") {
		t.Fatalf("want the mutual-exclusion error, got %v", err)
	}
}

// The virgin machine: a code pasted before this machine has ever held a seed.
// Every other failure in this command spends the ceremony, so this one has to
// say out loud that it did not — the same code is still good.
func TestKeysProve_WithNoVaultSelectedSaysSo(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	wireOracle(t)
	stub := newStubCeremony(t)

	_, _, err := runProve(t, stub.carriageURI(), map[string]string{"yes": "true"}, nil)
	if err == nil {
		t.Fatal("a machine with no vault minted a candidate anyway")
	}
	for _, want := range []string{
		"no vault to mint the candidate key from",
		"nothing was signed",
		"THE CEREMONY IS NOT SPENT",
		"dfos vault create <name>",
		"dfos config set default-vault <name>",
		"the same paste",
		"--no-vault",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the no-vault refusal is missing %q:\n%v", want, err)
		}
	}
	// No seed is created on a ceremony's behalf, and no key is left behind.
	if vaults, listErr := getVaults().List(); listErr != nil || len(vaults) != 0 {
		t.Fatalf("vaults after the refusal: %v (%v)", vaults, listErr)
	}
	if stub.presentHits != 0 {
		t.Fatal("signed anyway")
	}
}

// The description is a label for the operator's own list of keys. It rides
// beside the envelope, never inside it, and the human sees it before it goes.
func TestKeysProve_TheCompletionCarriesAKeyDescription(t *testing.T) {
	t.Run("this machine names itself by default", func(t *testing.T) {
		storeA, _, _ := setupDevices(t)
		keys = storeA
		createVault(t, "personal")
		wireOracle(t)
		stub := newStubCeremony(t)

		var result proveResult
		_, stderr, err := runProve(t, stub.shortCode(), map[string]string{"yes": "true"}, &result)
		if err != nil {
			t.Fatalf("keys prove: %v", err)
		}
		want := defaultKeyDescription()
		if result.Description != want || stub.lastPresented["description"] != want {
			t.Fatalf("description: result %q, wire %q, want %q",
				result.Description, stub.lastPresented["description"], want)
		}
		if want != "" && !strings.Contains(stderr, want) {
			t.Fatalf("the disclosure did not show the label being sent:\n%s", stderr)
		}
	})

	t.Run("--name is what the operator files it under", func(t *testing.T) {
		storeA, _, _ := setupDevices(t)
		keys = storeA
		createVault(t, "personal")
		wireOracle(t)
		stub := newStubCeremony(t)

		var result proveResult
		_, stderr, err := runProve(t, stub.shortCode(),
			map[string]string{"yes": "true", "name": "work laptop"}, &result)
		if err != nil {
			t.Fatalf("keys prove: %v", err)
		}
		if stub.lastPresented["description"] != "work laptop" || result.Description != "work laptop" {
			t.Fatalf("description: result %q, wire %q", result.Description, stub.lastPresented["description"])
		}
		if !strings.Contains(stderr, "work laptop") {
			t.Fatalf("the disclosure did not show the label being sent:\n%s", stderr)
		}
		// It is a label beside the proof, and nothing about the signed bytes.
		envelope := stub.lastPresented["envelope"]
		verified, err := protocol.VerifyKeyProof(envelope, protocol.KeyProofExpectations{
			Typ: protocol.KeyAddJWSTyp, Audience: stub.authority(),
			DID: stubDID, RoleSet: stubRoleSet, PrevCID: stubPrevCID,
		}, time.Now())
		if err != nil {
			t.Fatalf("verify the envelope: %v", err)
		}
		if verified.Payload.PublicKeyMultibase != result.PublicKey {
			t.Fatalf("the envelope names %s", verified.Payload.PublicKeyMultibase)
		}
		if strings.Contains(envelope, "work") {
			t.Fatal("the label reached the signed bytes")
		}
	})

	t.Run("an empty --name sends no member at all", func(t *testing.T) {
		storeA, _, _ := setupDevices(t)
		keys = storeA
		createVault(t, "personal")
		wireOracle(t)
		stub := newStubCeremony(t)

		var result proveResult
		if _, _, err := runProve(t, stub.shortCode(),
			map[string]string{"yes": "true", "name": ""}, &result); err != nil {
			t.Fatalf("keys prove: %v", err)
		}
		if _, present := stub.lastPresented["description"]; present {
			t.Fatalf("--name '' still sent a description: %v", stub.lastPresented)
		}
		if result.Description != "" {
			t.Fatalf("description: %q", result.Description)
		}
	})
}

// What a person is left holding: the key in full, the key shortened the way they
// will compare it against the other screen, and where to look it up in public.
func TestKeysProve_TheReceiptPointsAtTheKeyInPublic(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	wireOracle(t)
	stub := newStubCeremony(t)
	stub.answerDID = stubDID

	stdout, _, err := runProveHuman(t, stub.shortCode(), map[string]string{"yes": "true"})
	if err != nil {
		t.Fatalf("keys prove: %v", err)
	}
	publicKey := receiptField(t, stdout, "Key:")
	if publicKey == "" {
		t.Fatalf("the receipt names no key:\n%s", stdout)
	}

	// The explorer link carries the WHOLE key: a shortened one addresses nothing.
	if want := explorerKeyBase + publicKey; !strings.Contains(stdout, want) {
		t.Fatalf("the receipt is missing %q:\n%s", want, stdout)
	}
	if got := receiptField(t, stdout, "Key id:"); got != "key_ceremony ("+truncateKey(publicKey)+")" {
		t.Fatalf("key id line: %q", got)
	}
	if !strings.Contains(stdout, "Settings → Signing keys") {
		t.Fatalf("the receipt does not say where the name can be changed:\n%s", stdout)
	}

	// An operator that has not adopted the key yet — the ORDINARY answer — has no
	// settings screen to point at, and the receipt says what is actually true:
	// presented, awaiting approval, held here as a candidate.
	bare := newStubCeremony(t)
	stdout, _, err = runProveHuman(t, bare.shortCode(), map[string]string{"yes": "true"})
	if err != nil {
		t.Fatalf("keys prove: %v", err)
	}
	if strings.Contains(stdout, "Settings → Signing keys") {
		t.Fatalf("a candidate key was offered a rename it has no home for:\n%s", stdout)
	}
	if !strings.Contains(stdout, explorerKeyBase) {
		t.Fatalf("a candidate key got no explorer link:\n%s", stdout)
	}
	// The receipt reports PRESENTED and never claims the key was added.
	for _, want := range []string{
		"Presented:", stubDID, stubDisplayName, stubRoleSet,
		"Nothing is added to the chain until you approve it there",
		"held here as a candidate",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("the receipt is missing %q:\n%s", want, stdout)
		}
	}
	// The fingerprint a person compares against the operator's dialog.
	key := receiptField(t, stdout, "Key:")
	if !strings.Contains(stdout, truncateKey(key)) {
		t.Fatalf("the receipt gives no fingerprint to compare:\n%s", stdout)
	}
}

// An operator that answers with an identity OTHER than the one the human
// consented to files nothing. The key stays a candidate and no provenance is
// written against a chain nobody was shown.
func TestKeysProve_AnAdoptionNamingAnotherIdentityFilesNothing(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	wireOracle(t)
	stub := newStubCeremony(t)
	stub.answerDID = "did:dfos:z6MksomeoneelseentirelyentirelyA"

	var result proveResult
	if _, _, err := runProve(t, stub.shortCode(), map[string]string{"yes": "true"}, &result); err != nil {
		t.Fatalf("keys prove: %v", err)
	}
	if result.Account != candidateAccountPrefix+result.PublicKey {
		t.Fatalf("the key was filed against an identity the human never saw: %q", result.Account)
	}
	meta, err := getVaults().Load("personal")
	if err != nil {
		t.Fatalf("load vault: %v", err)
	}
	if len(meta.Minted) != 0 {
		t.Fatalf("provenance was written for an unconsented identity: %+v", meta.Minted)
	}
}

// receiptField reads one "  Label:  value" line out of the receipt.
func receiptField(t *testing.T, stdout, label string) string {
	t.Helper()
	for _, line := range strings.Split(stdout, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), label); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

func TestKeysProve_NoVaultMintsStandalone(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	wireOracle(t)
	stub := newStubCeremony(t)

	var result proveResult
	if _, _, err := runProve(t, stub.carriageURI(),
		map[string]string{"yes": "true", "no-vault": "true"}, &result); err != nil {
		t.Fatalf("--no-vault: %v", err)
	}
	if result.Vault != "" || !strings.Contains(result.KeyOrigin, "standalone") {
		t.Fatalf("result: %+v", result)
	}
	if !keys.HasKey(result.Account) {
		t.Fatal("the standalone candidate is not held")
	}
}

// compile-time guard: the command is registered under `keys`.
var _ = func() *cobra.Command { return newKeysProveCmd() }
