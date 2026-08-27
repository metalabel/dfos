package relay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// INGESTION ADMISSION.
//
// The admission ladder of specs/WEB-RELAY.md "Ingestion Admission", asserted in
// its normative order: structural caps -> proof verification when one is
// presented -> the relay-local admission policy -> full per-item verification.
//
// Two properties are load-bearing and each has its own case here. A policy
// REFUSAL is request-level — no per-item results are produced, and the expensive
// per-item work never runs. A policy that cannot be evaluated FAILS CLOSED
// (503), because an unevaluable gate is the server's condition, not a judgment
// about the caller. Byte twin of tests/ingestion-admission.spec.ts.

const operationsPath = proofBasePath + "/operations"

var admissionJti int

// submitOps posts a batch, optionally carrying an identity proof signed by
// `signer`. jti defaults to a fresh value; pass jtiNone to omit it entirely.
const jtiNone = "\x00none"

func submitOps(t *testing.T, r *Relay, operations []string, signer *testIdentity,
	overrides dfos.IdentityProofOptions, jti string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"operations": operations})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, operationsPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if signer != nil {
		overrides.Body = body
		if jti != jtiNone {
			if jti == "" {
				admissionJti++
				jti = fmt.Sprintf("admission-%d", admissionJti)
			}
			overrides.ExtraMembers = dfos.ProofExtraMembers{"jti": jti}
		}
		proof, err := dfos.BuildIdentityProof(http.MethodPost, testAuthority, operationsPath,
			signer.did+"#"+signer.auth.keyID, ed25519.PrivateKey(signer.auth.priv), overrides)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "DFOS "+proof)
	}
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, req)
	return w
}

func admissionRelay(t *testing.T, opts RelayOptions) (*Relay, Store) {
	t.Helper()
	store := opts.Store
	if store == nil {
		store = NewMemoryStore()
		opts.Store = store
	}
	if opts.Authority == "" {
		opts.Authority = testAuthority
	}
	r, err := NewRelay(opts)
	if err != nil {
		t.Fatal(err)
	}
	return r, store
}

func wellKnownBody(t *testing.T, r *Relay) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/dfos-relay", nil)
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, req)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

// ---------------------------------------------------------------------------
// the well-known hint
// ---------------------------------------------------------------------------

func TestIngestionAdvertisement(t *testing.T) {
	open, _ := admissionRelay(t, RelayOptions{})
	if got := wellKnownBody(t, open)["ingestion"]; got != IngestionOpen {
		t.Fatalf("default ingestion = %v, want open", got)
	}

	disabled := false
	lite, _ := admissionRelay(t, RelayOptions{Write: &disabled})
	if got := wellKnownBody(t, lite)["ingestion"]; got != IngestionClosed {
		t.Fatalf("write:false ingestion = %v, want closed", got)
	}

	proven, _ := admissionRelay(t, RelayOptions{Ingestion: IngestionProofRequired})
	if got := wellKnownBody(t, proven)["ingestion"]; got != IngestionProofRequired {
		t.Fatalf("configured ingestion = %v, want proof-required", got)
	}

	// write:false overrides a configured "open": a lite node ingests nothing.
	overridden, _ := admissionRelay(t, RelayOptions{Write: &disabled, Ingestion: IngestionOpen})
	if got := wellKnownBody(t, overridden)["ingestion"]; got != IngestionClosed {
		t.Fatalf("write:false + open = %v, want closed", got)
	}
}

func TestIngestionClosedAnswers501(t *testing.T) {
	r, _ := admissionRelay(t, RelayOptions{Ingestion: IngestionClosed})
	id := createTestIdentity(t)
	if got := submitOps(t, r, []string{id.token}, nil, dfos.IdentityProofOptions{}, ""); got.Code != 501 {
		t.Fatalf("closed ingestion: %d %s", got.Code, got.Body.String())
	}
}

// ---------------------------------------------------------------------------
// the ladder
// ---------------------------------------------------------------------------

func TestAdmissionAdmitsAnonymousByDefault(t *testing.T) {
	r, _ := admissionRelay(t, RelayOptions{})
	id := createTestIdentity(t)
	got := submitOps(t, r, []string{id.token}, nil, dfos.IdentityProofOptions{}, "")
	if got.Code != 200 {
		t.Fatalf("anonymous submission: %d %s", got.Code, got.Body.String())
	}
}

func TestAdmissionNamesThePrincipalToThePolicy(t *testing.T) {
	var seen []string
	r, _ := admissionRelay(t, RelayOptions{
		AdmissionPolicy: func(principal string) (bool, error) {
			seen = append(seen, principal)
			return true, nil
		},
	})
	submitter := createTestIdentity(t)
	// The submitter's own chain has to be resolvable before its proof can be
	// verified: current-state key resolution is a LOCAL lookup.
	if got := submitOps(t, r, []string{submitter.token}, nil, dfos.IdentityProofOptions{}, ""); got.Code != 200 {
		t.Fatalf("seed submitter: %d %s", got.Code, got.Body.String())
	}
	other := createTestIdentity(t)
	if got := submitOps(t, r, []string{other.token}, &submitter, dfos.IdentityProofOptions{}, ""); got.Code != 200 {
		t.Fatalf("proven submission: %d %s", got.Code, got.Body.String())
	}
	if len(seen) != 2 || seen[0] != "" || seen[1] != submitter.did {
		t.Fatalf("policy saw %v, want [anonymous, %s]", seen, submitter.did)
	}
}

// A policy refusal is REQUEST-LEVEL: nothing in the batch is examined further,
// no per-item results are produced, and the expensive step is never spent.
func TestAdmissionPolicyRefusalIsRequestLevel(t *testing.T) {
	r, store := admissionRelay(t, RelayOptions{
		AdmissionPolicy: func(string) (bool, error) { return false, nil },
	})
	id := createTestIdentity(t)
	got := submitOps(t, r, []string{id.token}, nil, dfos.IdentityProofOptions{}, "")
	if got.Code != http.StatusForbidden {
		t.Fatalf("policy refusal: %d %s", got.Code, got.Body.String())
	}
	if strings.Contains(got.Body.String(), "results") {
		t.Fatalf("a refusal must produce NO per-item results: %s", got.Body.String())
	}
	chain, err := store.GetIdentityChain(id.did)
	if err != nil {
		t.Fatal(err)
	}
	if chain != nil {
		t.Fatal("the expensive per-item step ran despite a policy refusal")
	}
}

func TestAdmissionProofRequiredRefusesAnonymous(t *testing.T) {
	// Seed the submitter's chain through an OPEN relay on the same store, then
	// reopen the store proof-required: a proof-required relay cannot be handed the
	// submitter's own genesis anonymously, and saying so is more honest than
	// pretending the bootstrap is free.
	store := NewMemoryStore()
	seedRelay, _ := admissionRelay(t, RelayOptions{Store: store})
	submitter := createTestIdentity(t)
	if got := submitOps(t, seedRelay, []string{submitter.token}, nil, dfos.IdentityProofOptions{}, ""); got.Code != 200 {
		t.Fatalf("seed submitter: %d %s", got.Code, got.Body.String())
	}

	r, err := NewRelay(RelayOptions{
		Store: store, Authority: testAuthority, Ingestion: IngestionProofRequired,
		Identity: &RelayIdentity{DID: seedRelay.DID(), ProfileArtifactJWS: seedRelay.ProfileArtifactJWS()},
	})
	if err != nil {
		t.Fatal(err)
	}
	other := createTestIdentity(t)
	if got := submitOps(t, r, []string{other.token}, nil, dfos.IdentityProofOptions{}, ""); got.Code != http.StatusForbidden {
		t.Fatalf("anonymous under proof-required: %d %s", got.Code, got.Body.String())
	}
	if got := submitOps(t, r, []string{other.token}, &submitter, dfos.IdentityProofOptions{}, ""); got.Code != 200 {
		t.Fatalf("proven under proof-required: %d %s", got.Code, got.Body.String())
	}
}

// A policy that cannot be evaluated FAILS CLOSED with 503, not 403: the server
// could not answer the question, and reporting a refusal would blame the caller
// for the relay's outage.
func TestAdmissionPolicyFailsClosed(t *testing.T) {
	r, store := admissionRelay(t, RelayOptions{
		AdmissionPolicy: func(string) (bool, error) {
			return false, errors.New("quota backend unreachable")
		},
	})
	id := createTestIdentity(t)
	got := submitOps(t, r, []string{id.token}, nil, dfos.IdentityProofOptions{}, "")
	if got.Code != http.StatusServiceUnavailable {
		t.Fatalf("unevaluable policy: %d %s", got.Code, got.Body.String())
	}
	chain, _ := store.GetIdentityChain(id.did)
	if chain != nil {
		t.Fatal("per-item work ran despite a fail-closed policy")
	}
}

func TestAdmissionInvalidProofIsNotDowngradedToAnonymous(t *testing.T) {
	r, _ := admissionRelay(t, RelayOptions{})
	submitter := createTestIdentity(t)
	if got := submitOps(t, r, []string{submitter.token}, nil, dfos.IdentityProofOptions{}, ""); got.Code != 200 {
		t.Fatalf("seed submitter: %d", got.Code)
	}
	other := createTestIdentity(t)

	// Bound to a different authority: a proof this relay must not accept.
	body, _ := json.Marshal(map[string]any{"operations": []string{other.token}})
	proof, err := dfos.BuildIdentityProof(http.MethodPost, "other-relay.example.com", operationsPath,
		submitter.did+"#"+submitter.auth.keyID, ed25519.PrivateKey(submitter.auth.priv),
		dfos.IdentityProofOptions{Body: body, ExtraMembers: dfos.ProofExtraMembers{"jti": "wrong-host"}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, operationsPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "DFOS "+proof)
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("host-mismatched proof: %d %s", w.Code, w.Body.String())
	}
}

// "Could not check" is the server's condition; only "checked and failed" is the
// caller's.
func TestAdmissionUnresolvablePresenterIs503(t *testing.T) {
	r, _ := admissionRelay(t, RelayOptions{})
	stranger := createTestIdentity(t) // never ingested here
	other := createTestIdentity(t)
	got := submitOps(t, r, []string{other.token}, &stranger, dfos.IdentityProofOptions{}, "")
	if got.Code != http.StatusServiceUnavailable {
		t.Fatalf("unresolvable presenter: %d %s", got.Code, got.Body.String())
	}
}

func TestAdmissionUnconfiguredAuthorityIs503(t *testing.T) {
	store := NewMemoryStore()
	r, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	submitter := createTestIdentity(t)
	// Anonymous ingestion still works with no authority: nothing needs a binding.
	if got := submitOps(t, r, []string{submitter.token}, nil, dfos.IdentityProofOptions{}, ""); got.Code != 200 {
		t.Fatalf("anonymous submission without an authority: %d", got.Code)
	}
	other := createTestIdentity(t)
	if got := submitOps(t, r, []string{other.token}, &submitter, dfos.IdentityProofOptions{}, ""); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("proven submission without an authority: %d %s", got.Code, got.Body.String())
	}
}

// The capability gate fires FIRST — before authentication, body parsing, or
// policy — uniformly across every gated family.
func TestAdmissionCapabilityGateFiresFirst(t *testing.T) {
	disabled := false
	var policyCalls int
	r, _ := admissionRelay(t, RelayOptions{
		Write:           &disabled,
		AdmissionPolicy: func(string) (bool, error) { policyCalls++; return true, nil },
	})
	id := createTestIdentity(t)
	if got := submitOps(t, r, []string{id.token}, nil, dfos.IdentityProofOptions{}, ""); got.Code != 501 {
		t.Fatalf("write:false: %d", got.Code)
	}
	if policyCalls != 0 {
		t.Fatalf("policy ran behind a closed capability gate (%d calls)", policyCalls)
	}
}

func TestAdmissionStructuralCapsPrecedeThePolicy(t *testing.T) {
	var policyCalls int
	r, _ := admissionRelay(t, RelayOptions{
		AdmissionPolicy: func(string) (bool, error) { policyCalls++; return false, nil },
	})
	// A structurally invalid batch is a 400, never the policy's 403 — the ladder
	// is cheapest-first and each rung has its own status code.
	if got := submitOps(t, r, []string{}, nil, dfos.IdentityProofOptions{}, ""); got.Code != 400 {
		t.Fatalf("empty batch: %d %s", got.Code, got.Body.String())
	}
	if policyCalls != 0 {
		t.Fatalf("policy ran before the structural caps (%d calls)", policyCalls)
	}
}

// ---------------------------------------------------------------------------
// jti on the write-shaped ingestion surface
// ---------------------------------------------------------------------------

func TestAdmissionJtiDiscipline(t *testing.T) {
	r, _ := admissionRelay(t, RelayOptions{})
	submitter := createTestIdentity(t)
	if got := submitOps(t, r, []string{submitter.token}, nil, dfos.IdentityProofOptions{}, ""); got.Code != 200 {
		t.Fatalf("seed submitter: %d", got.Code)
	}
	other := createTestIdentity(t)

	// No jti at all — ingestion is write-shaped.
	if got := submitOps(t, r, []string{other.token}, &submitter, dfos.IdentityProofOptions{}, jtiNone); got.Code != http.StatusUnauthorized {
		t.Fatalf("proof without jti: %d %s", got.Code, got.Body.String())
	}
	// A jti over the cap — enforced identically by the TS twin.
	if got := submitOps(t, r, []string{other.token}, &submitter, dfos.IdentityProofOptions{},
		strings.Repeat("x", MaxJtiBytes+1)); got.Code != http.StatusUnauthorized {
		t.Fatalf("oversized jti: %d %s", got.Code, got.Body.String())
	}
	// First use accepted, byte-identical replay refused. Idempotent ingestion does
	// NOT make the replay free: policy already ran, and an admission-layer effect
	// was already granted.
	if got := submitOps(t, r, []string{other.token}, &submitter, dfos.IdentityProofOptions{}, "replay-me-once"); got.Code != 200 {
		t.Fatalf("first jti use: %d %s", got.Code, got.Body.String())
	}
	if got := submitOps(t, r, []string{other.token}, &submitter, dfos.IdentityProofOptions{}, "replay-me-once"); got.Code != http.StatusUnauthorized {
		t.Fatalf("replayed jti: %d %s", got.Code, got.Body.String())
	}
}

// The replay cache is keyed (presenter, jti), so two presenters may legitimately
// choose the same value.
func TestAdmissionJtiIsScopedToThePresenter(t *testing.T) {
	r, _ := admissionRelay(t, RelayOptions{})
	first := createTestIdentity(t)
	second := createTestIdentity(t)
	if got := submitOps(t, r, []string{first.token, second.token}, nil, dfos.IdentityProofOptions{}, ""); got.Code != 200 {
		t.Fatalf("seed submitters: %d", got.Code)
	}
	other := createTestIdentity(t)
	if got := submitOps(t, r, []string{other.token}, &first, dfos.IdentityProofOptions{}, "shared"); got.Code != 200 {
		t.Fatalf("first presenter: %d %s", got.Code, got.Body.String())
	}
	if got := submitOps(t, r, []string{other.token}, &second, dfos.IdentityProofOptions{}, "shared"); got.Code != 200 {
		t.Fatalf("second presenter with the same jti: %d %s", got.Code, got.Body.String())
	}
}
