package cmd

// `dfos keys prove` tests. Like the vault, keys, and recover tests these drive
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
	"github.com/metalabel/dfos/packages/dfos-cli/internal/keystore"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/spf13/cobra"
)

// --- the stub ceremony operator ---

const (
	stubCode       = "ABCD2345"
	stubCeremonyID = "cer_01HQ"
	stubNonce      = "n0nce-64-bits-of-nothing"
)

type stubCeremony struct {
	server *httptest.Server

	// knobs
	resolveStatus  int    // non-zero: answer the well-known with this status
	resolveBody    string // non-empty: answer the well-known with this body
	resolveURI     string // non-empty: the carriage URI answered instead of the real one
	resolveRelay   string // non-empty: the optional `relay` member of the resolution
	completeStatus int    // non-zero: answer the completion with this status
	completeBody   string // non-empty: the completion body
	answerDID      string // non-empty: the identity the operator says adopted the key

	// observations
	wellKnownHits  int
	completeHits   int
	lastCode       string
	lastCompletion map[string]string
	lastQuery      url.Values
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
		answer := map[string]any{"uri": s.carriageURI()}
		if s.resolveRelay != "" {
			answer["relay"] = s.resolveRelay
		}
		writeJSON(w, answer)

	case r.URL.Path == "/keys/complete" && r.Method == http.MethodPost:
		s.completeHits++
		s.lastQuery = r.URL.Query()
		s.lastCompletion = map[string]string{}
		_ = json.NewDecoder(r.Body).Decode(&s.lastCompletion)
		if s.completeStatus != 0 {
			w.WriteHeader(s.completeStatus)
			_, _ = w.Write([]byte(s.completeBody))
			return
		}
		answer := map[string]any{"status": "completed", "keyId": "key_ceremony"}
		if s.answerDID != "" {
			answer["did"] = s.answerDID
		}
		writeJSON(w, answer)

	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"no route"}`))
	}
}

// carriageURI is what the short code resolves to: the completion endpoint plus
// the ceremony and the nonce, and no identity.
func (s *stubCeremony) carriageURI() string {
	if s.resolveURI != "" {
		return s.resolveURI
	}
	return s.server.URL + "/keys/complete?ceremony=" + stubCeremonyID + "&nonce=" + url.QueryEscape(stubNonce)
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

// proveFlags drives one `keys prove` invocation. Stdin is not a terminal under
// `go test`, so every run that expects to complete passes --yes; the run that
// does not is asserting exactly that gate.
func runProve(t *testing.T, input string, flags map[string]string, out any) (stdout, stderr string, err error) {
	t.Helper()
	cmd := newKeysProveCmd()
	cmd.SetIn(strings.NewReader(""))
	for name, value := range flags {
		mustSetFlag(t, cmd, name, value)
	}
	return runCapturingJSON(t, cmd, []string{input}, out)
}

// runProveHuman is runProve without --json, for the assertions about what a
// person reads off the terminal on the way out.
func runProveHuman(t *testing.T, input string, flags map[string]string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := newKeysProveCmd()
	cmd.SetIn(strings.NewReader(""))
	for name, value := range flags {
		mustSetFlag(t, cmd, name, value)
	}
	return runCapturing(t, cmd, []string{input})
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
// has-ever-declared question, which is what the linkage refusal turns on.
func wireOracle(t *testing.T) *fakeOracle {
	t.Helper()
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	relayFlag = "oracle"
	return oracle
}

// --- parsing ---

func TestKeysProve_ParsesTheCarriageURIForm(t *testing.T) {
	car, err := resolveCeremony("https://ceremony.example/keys/complete?ceremony=cer_1&nonce=abc&tenant=t1")
	if err != nil {
		t.Fatalf("parse carriage URI: %v", err)
	}
	if car.Ceremony != "cer_1" || car.Nonce != "abc" {
		t.Fatalf("triple: %+v", car)
	}
	if car.Audience != "ceremony.example" {
		t.Fatalf("audience: %q", car.Audience)
	}
	// The endpoint drops ceremony and nonce, and ONLY those: another member is
	// the operator's own routing and posting without it is posting elsewhere.
	if car.Endpoint != "https://ceremony.example/keys/complete?tenant=t1" {
		t.Fatalf("endpoint: %q", car.Endpoint)
	}
}

func TestKeysProve_AudienceCarriesANonDefaultPort(t *testing.T) {
	car, err := resolveCeremony("https://ceremony.example:8443/c?ceremony=x&nonce=y")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if car.Audience != "ceremony.example:8443" {
		t.Fatalf("audience: %q", car.Audience)
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
		{"carriage URI missing the nonce", "https://host.example/c?ceremony=x", "no 'nonce' member"},
		{"carriage URI missing the ceremony", "https://host.example/c?nonce=y", "no 'ceremony' member"},
		{"duplicated ceremony member", "https://h.example/c?ceremony=a&ceremony=b&nonce=y", "carries 'ceremony' 2 times"},
		{"cleartext off loopback", "http://host.example/c?ceremony=x&nonce=y", "refusing a cleartext ceremony"},
		{"not http at all", "ftp://host.example/c?ceremony=x&nonce=y", "refusing scheme 'ftp'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveCeremony(tc.input)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("input %q: want error containing %q, got %v", tc.input, tc.want, err)
			}
		})
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
	if car.Nonce != stubNonce || car.Ceremony != stubCeremonyID {
		t.Fatalf("triple: %+v", car)
	}
	if car.Via != "short code at "+stub.authority() {
		t.Fatalf("via: %q", car.Via)
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
		t.Fatalf("triple: %+v", car)
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

// A carriage URI is three values. A `relay` query member on one is the
// operator's own routing, carried through to the endpoint like any other — it is
// not an oracle, because only a resolution can name one.
func TestKeysProve_ACarriageURICarriesNoRelay(t *testing.T) {
	car, err := resolveCeremony("https://ceremony.example/c?ceremony=x&nonce=y&relay=https%3A%2F%2Frelay.example")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if car.Relay != "" {
		t.Fatalf("relay: %q, want none", car.Relay)
	}
	if car.Endpoint != "https://ceremony.example/c?relay=https%3A%2F%2Frelay.example" {
		t.Fatalf("endpoint: %q", car.Endpoint)
	}
}

// The rule that makes the short form safe: a code typed at one host can never
// resolve to a ceremony completing at another.
func TestKeysProve_RefusesAnOffAuthorityResolution(t *testing.T) {
	stub := newStubCeremony(t)
	stub.resolveURI = "https://elsewhere.example/keys/complete?ceremony=cer&nonce=n"

	_, err := resolveCeremony(stub.shortCode())
	if err == nil || !strings.Contains(err.Error(), "REFUSING") ||
		!strings.Contains(err.Error(), "elsewhere.example") {
		t.Fatalf("want an off-authority refusal, got %v", err)
	}
	if stub.wellKnownHits != 1 {
		t.Fatalf("asked the well-known %d times, want exactly 1", stub.wellKnownHits)
	}
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

	// The disclosure a human is owed, before anything was signed.
	for _, want := range []string{"Audience:", stub.authority(), protocol.KeyAddJWSTyp, "no identity has ever declared this key"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("disclosure missing %q:\n%s", want, stderr)
		}
	}

	if result.Status != "completed" || result.KeyID != "key_ceremony" {
		t.Fatalf("result: %+v", result)
	}
	if result.Audience != stub.authority() || result.Ceremony != stubCeremonyID {
		t.Fatalf("result carriage: %+v", result)
	}
	if !result.Linkage.Checked || len(result.Linkage.Declaring) != 0 {
		t.Fatalf("linkage: %+v", result.Linkage)
	}

	// The completion body's shape, and what does NOT ride in it: the ceremony id
	// and the description travel beside the envelope, and the nonce rides only
	// inside the signed payload.
	if got := stub.lastCompletion["ceremony"]; got != stubCeremonyID {
		t.Fatalf("completion ceremony: %q", got)
	}
	envelope := stub.lastCompletion["envelope"]
	if envelope == "" {
		t.Fatal("completion carried no envelope")
	}
	// A machine that can name neither its user nor itself sends no description at
	// all, so the member count follows the default rather than assuming it.
	wantMembers := 2
	if want := defaultKeyDescription(); want != "" {
		wantMembers = 3
		if got := stub.lastCompletion["description"]; got != want {
			t.Fatalf("completion description: %q, want %q", got, want)
		}
	}
	if len(stub.lastCompletion) != wantMembers {
		t.Fatalf("completion body has extra members: %v", stub.lastCompletion)
	}
	if stub.lastQuery.Get("ceremony") != "" || stub.lastQuery.Get("nonce") != "" {
		t.Fatalf("the completion POST carried the carriage query: %v", stub.lastQuery)
	}

	// The envelope itself, through the kit's own verifier: typ, audience,
	// freshness, and the signature against the payload's OWN public key.
	verified, err := protocol.VerifyKeyProof(envelope, protocol.KeyProofExpectations{
		Typ: protocol.KeyAddJWSTyp, Audience: stub.authority(),
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

	// The key is held, under a candidate account, because this operator did not
	// name the identity that adopted it.
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
	stub.answerDID = "did:dfos:z6MkexampleexampleexampleexA"

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
		!strings.Contains(err.Error(), "HAS-EVER-DECLARED") {
		t.Fatalf("want a linkage refusal, got %v", err)
	}
	if stub.completeHits != 0 {
		t.Fatal("a refused ceremony was completed anyway")
	}

	// --force-linked is the human saying they mean to publish the link.
	var result proveResult
	if _, stderr, err := runProve(t, stub.carriageURI(),
		map[string]string{"yes": "true", "key": held, "force-linked": "true"}, &result); err != nil {
		t.Fatalf("--force-linked: %v", err)
	} else if !strings.Contains(stderr, "already declares this key") {
		t.Fatalf("the forced run did not say what it was overriding:\n%s", stderr)
	}
	if result.Status != "completed" || !result.Forced {
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
	if err == nil || !strings.Contains(err.Error(), "already declared by "+did) {
		t.Fatalf("want a local linkage refusal, got %v", err)
	}
	if stub.completeHits != 0 {
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
	stub.answerDID = "did:dfos:z6MkexampleexampleexampleexA"

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
			if stub.completeHits != 0 {
				t.Fatal("signed anyway")
			}

			var result proveResult
			if _, stderr, err := runProve(t, stub.carriageURI(),
				map[string]string{"yes": "true", "force-linked": "true"}, &result); err != nil {
				t.Fatalf("--force-linked: %v", err)
			} else if !strings.Contains(stderr, "NOT CHECKED") {
				t.Fatalf("the forced run did not disclose the unchecked linkage:\n%s", stderr)
			}
			if result.Linkage.Checked || result.Status != "completed" {
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
	if stub.completeHits != 0 {
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
			if stub.completeHits != 0 {
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
	if stub.completeHits != 0 {
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
	stub.completeStatus = http.StatusBadRequest
	stub.completeBody = `{"error":"nonce already consumed"}`

	_, _, err := runProve(t, stub.carriageURI(), map[string]string{"yes": "true"}, nil)
	if err == nil {
		t.Fatal("a refused completion succeeded")
	}
	for _, want := range []string{"refused the proof (HTTP 400)", "nonce already consumed",
		"This ceremony is spent", "Mint a fresh code", "--key "} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("failure message missing %q:\n%v", want, err)
		}
	}
	if stub.completeHits != 1 {
		t.Fatalf("completed %d times — a burned ceremony is never retried", stub.completeHits)
	}
}

func TestKeysProve_AnUnreachableOperatorReadsAsUnreachable(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	wireOracle(t)
	stub := newStubCeremony(t)
	uri := stub.carriageURI()
	stub.server.Close() // the operator is gone before the completion is posted

	_, _, err := runProve(t, uri, map[string]string{"yes": "true"}, nil)
	if err == nil || !strings.Contains(err.Error(), "could not reach the ceremony operator") {
		t.Fatalf("want an unreachable-operator failure, got %v", err)
	}
	// It is still spent as far as this machine knows, and it still is not retried.
	if !strings.Contains(err.Error(), "If the request arrived, the ceremony is spent") {
		t.Fatalf("the failure did not state the ambiguity: %v", err)
	}
}

func TestKeysProve_A200ThatDoesNotCompleteIsAFailure(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	wireOracle(t)
	stub := newStubCeremony(t)
	stub.completeStatus = http.StatusOK
	stub.completeBody = `{"status":"pending","message":"awaiting operator approval"}`

	_, _, err := runProve(t, stub.carriageURI(), map[string]string{"yes": "true"}, nil)
	if err == nil || !strings.Contains(err.Error(), "without completing the ceremony") ||
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
	if stub.completeHits != 0 {
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
		if result.Description != want || stub.lastCompletion["description"] != want {
			t.Fatalf("description: result %q, wire %q, want %q",
				result.Description, stub.lastCompletion["description"], want)
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
		if stub.lastCompletion["description"] != "work laptop" || result.Description != "work laptop" {
			t.Fatalf("description: result %q, wire %q", result.Description, stub.lastCompletion["description"])
		}
		if !strings.Contains(stderr, "work laptop") {
			t.Fatalf("the disclosure did not show the label being sent:\n%s", stderr)
		}
		// It is a label beside the proof, and nothing about the signed bytes.
		envelope := stub.lastCompletion["envelope"]
		verified, err := protocol.VerifyKeyProof(envelope, protocol.KeyProofExpectations{
			Typ: protocol.KeyAddJWSTyp, Audience: stub.authority(),
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
		if _, present := stub.lastCompletion["description"]; present {
			t.Fatalf("--name '' still sent a description: %v", stub.lastCompletion)
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
	stub.answerDID = "did:dfos:z6MkexampleexampleexampleexA"

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

	// An operator that named no identity has no settings screen to point at.
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
