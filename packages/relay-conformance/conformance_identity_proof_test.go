// IDENTITY-PROOF AUTHENTICATION conformance.
//
// The relay owns no authentication grammar of its own: every authenticated
// request presents the API-AUTH envelope, "Authorization: DFOS <did:dfos:
// identity-proof JWS>", bound to that one request. These tests assert what a
// conforming relay MUST do with it — refuse what is absent, unbound, or already
// spent, and admit exactly the proof that names this request.
//
// The freshness and host bindings live with the other auth edge cases in
// conformance_test.go (TestAuthWrongHost, TestAuthStaleProof, TestAuthRotatedOutKey).
// What is here is the gate itself: which routes require a proof, which shape of
// proof each requires, and what the relay advertises about who may submit.
//
// See specs/WEB-RELAY.md "Authentication" and specs/API-AUTH.md "The Identity Proof".
package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// ===================================================================
// the gate on a write-shaped surface: blob upload
// ===================================================================

// TestBlobUploadRequiresAnIdentityProof walks the refusals a write-shaped
// surface owes before it accepts anything: no proof, a proof bound to a
// different request, a proof with no jti, and a header that is not this family
// at all. Only the proof naming THIS request gets through.
func TestBlobUploadRequiresAnIdentityProof(t *testing.T) {
	base := relayURL(t)
	creator := createIdentity(t, base)
	cc := createContent(t, base, creator)
	blob, _ := json.Marshal(cc.document)
	signer := signerFor(creator)
	target := fmt.Sprintf("/content/%s/blob/%s", cc.contentID, cc.genCID)

	t.Run("anonymous", func(t *testing.T) {
		res := putBlobWithProof(t, base, cc.contentID, cc.genCID, "", blob)
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthenticated upload: status %d, want 401", res.StatusCode)
		}
		res.Body.Close()
	})

	// A stale Bearer JWT is NOT this family and never was. It is a 401, not a
	// silent downgrade to anonymous: a client that thinks it is authenticated
	// must hear that the relay disagrees.
	t.Run("wrong scheme", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPut,
			fmt.Sprintf("%s/content/%s/blob/%s", base, cc.contentID, cc.genCID), nil)
		req.Header.Set("authorization", "Bearer "+buildProof(t, base, signer, http.MethodPut, target, nil, newJTI(t)))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Bearer-schemed proof: status %d, want 401", res.StatusCode)
		}
		res.Body.Close()
	})

	// Bound to a DIFFERENT path — the proof is valid, for another request.
	t.Run("bound to another request", func(t *testing.T) {
		elsewhere := buildProof(t, base, signer, http.MethodPut,
			fmt.Sprintf("/content/%s/blob/%s", cc.contentID, "bafyotheroperation"), blob, newJTI(t))
		res := putBlobWithProof(t, base, cc.contentID, cc.genCID, elsewhere, blob)
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("proof bound to another path: status %d, want 401", res.StatusCode)
		}
		res.Body.Close()
	})

	// Bound to different BYTES — bodyHash covers the upload.
	t.Run("bound to other bytes", func(t *testing.T) {
		otherBytes := buildProof(t, base, signer, http.MethodPut, target, []byte("different bytes"), newJTI(t))
		res := putBlobWithProof(t, base, cc.contentID, cc.genCID, otherBytes, blob)
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("proof bound to other bytes: status %d, want 401", res.StatusCode)
		}
		res.Body.Close()
	})

	// jti is REQUIRED on a write-shaped surface: admission-layer effects are
	// granted before the relay knows the payload is a duplicate, so a replayable
	// proof is not made harmless by ingestion being idempotent.
	t.Run("no jti", func(t *testing.T) {
		noJti := buildProof(t, base, signer, http.MethodPut, target, blob, "")
		res := putBlobWithProof(t, base, cc.contentID, cc.genCID, noJti, blob)
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("write-shaped proof without jti: status %d, want 401", res.StatusCode)
		}
		res.Body.Close()
	})

	t.Run("bound to this request", func(t *testing.T) {
		res := putBlob(t, base, cc.contentID, cc.genCID, signer, blob)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("well-formed upload: status %d, body: %s", res.StatusCode, readBody(t, res))
		}
		res.Body.Close()
	})
}

// TestIdentityProofReplayRefused proves the jti replay cache: presenting the
// SAME proof a second time on a write-shaped route is refused, even though the
// identical upload under a FRESH proof is accepted (blob upload is idempotent).
// The refusal is about the proof having been spent, not about the payload.
func TestIdentityProofReplayRefused(t *testing.T) {
	base := relayURL(t)
	creator := createIdentity(t, base)
	cc := createContent(t, base, creator)
	blob, _ := json.Marshal(cc.document)
	signer := signerFor(creator)

	proof := buildProof(t, base, signer, http.MethodPut,
		fmt.Sprintf("/content/%s/blob/%s", cc.contentID, cc.genCID), blob, newJTI(t))

	first := putBlobWithProof(t, base, cc.contentID, cc.genCID, proof, blob)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first presentation: status %d, body: %s", first.StatusCode, readBody(t, first))
	}
	first.Body.Close()

	replay := putBlobWithProof(t, base, cc.contentID, cc.genCID, proof, blob)
	if replay.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed proof: status %d, want 401", replay.StatusCode)
	}
	replay.Body.Close()

	// The same bytes under a fresh proof still land: idempotent upload is
	// unaffected: what the cache refuses is the spent proof.
	fresh := putBlob(t, base, cc.contentID, cc.genCID, signer, blob)
	if fresh.StatusCode != http.StatusOK {
		t.Fatalf("re-upload under a fresh proof: status %d, body: %s", fresh.StatusCode, readBody(t, fresh))
	}
	fresh.Body.Close()
}

// ===================================================================
// the gate on a read-shaped surface: non-public blob read
// ===================================================================

// TestNonPublicBlobReadRequiresAnIdentityProof asserts the read-shaped half of
// the gate. A blob with no standing public grant is unreachable without a
// proof; with one, the requester is authenticated and the credential question
// is asked separately. No jti is required — a re-read returns the same bytes,
// which is the within-window replay API-AUTH accepts.
func TestNonPublicBlobReadRequiresAnIdentityProof(t *testing.T) {
	base := relayURL(t)
	creator := createIdentity(t, base)
	cc := createContent(t, base, creator)
	blob, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, signerFor(creator), blob).Body.Close()

	anonymous := getBlob(t, base, cc.contentID, nil)
	if anonymous.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous non-public read: status %d, want 401", anonymous.StatusCode)
	}
	anonymous.Body.Close()

	// The creator always has access, and a read-shaped proof carries no jti — so
	// two successive reads under two proofs both succeed.
	for i := 0; i < 2; i++ {
		res := getBlob(t, base, cc.contentID, signerFor(creator))
		body := readBody(t, res)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("creator read %d: status %d, body: %s", i, res.StatusCode, body)
		}
		if string(body) != string(blob) {
			t.Fatalf("creator read %d returned different bytes", i)
		}
	}

	// A stranger authenticates fine and is then refused on authorization —
	// 403, not 401. The two halves are separate answers.
	stranger := getBlob(t, base, cc.contentID, signerFor(createIdentity(t, base)))
	if stranger.StatusCode != http.StatusForbidden {
		t.Fatalf("authenticated stranger read: status %d, want 403", stranger.StatusCode)
	}
	stranger.Body.Close()
}

// ===================================================================
// the advertisement
// ===================================================================

// TestWellKnownAdvertisesIngestion asserts the well-known carries `ingestion`,
// the hint a client reads to learn the submission posture before it submits.
// The advertisement is a hint; the policy decision at submission is the
// authority, which is why this only pins the vocabulary.
func TestWellKnownAdvertisesIngestion(t *testing.T) {
	base := relayURL(t)

	var top map[string]json.RawMessage
	resp := getJSON(t, base+"/.well-known/dfos-relay", &top)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /.well-known/dfos-relay: status %d", resp.StatusCode)
	}
	raw, ok := top["ingestion"]
	if !ok {
		t.Fatal("well-known missing ingestion field")
	}
	var mode string
	if err := json.Unmarshal(raw, &mode); err != nil {
		t.Fatalf("ingestion is not a JSON string: %v (raw: %s)", err, raw)
	}
	switch mode {
	case "open", "proof-required", "closed":
	default:
		t.Fatalf("ingestion = %q, want open|proof-required|closed", mode)
	}
}

// ===================================================================
// proof-required ingestion
// ===================================================================

// TestIngestionProofRequired runs against a relay booted in proof-required
// mode, which the default harness is not — scripts/run-proof-required.sh starts
// one and points PROOF_REQUIRED_RELAY_URL at it.
//
// The property: an anonymous submission is refused 403 at the admission ladder,
// and the SAME batch carrying an identity proof is admitted. The refusal is
// request-level, so no per-item results come back with it.
func TestIngestionProofRequired(t *testing.T) {
	base := os.Getenv("PROOF_REQUIRED_RELAY_URL")
	if base == "" {
		t.Skip("PROOF_REQUIRED_RELAY_URL not set — skipping proof-required conformance")
	}

	// The submitter's own chain has to be on the relay before its proofs can
	// resolve, and on a proof-required relay it cannot put itself there. Seeding
	// is the operator's job; the harness script does it over a second, open
	// relay sharing the store, or by pre-ingesting. Here the identity is created
	// against the seeding URL when one is named, else against this relay itself.
	seedBase := os.Getenv("PROOF_REQUIRED_SEED_URL")
	if seedBase == "" {
		seedBase = base
	}
	submitter := createIdentity(t, seedBase)
	signer := signerFor(submitter)

	// A fresh content op to submit — anonymous first.
	doc := map[string]any{"type": "post", "title": "proof-required submission"}
	docCID, _, err := dfos.DocumentCID(doc)
	if err != nil {
		t.Fatal(err)
	}
	op, _, _, err := dfos.SignContentCreate(submitter.did, docCID,
		submitter.did+"#"+submitter.auth.keyID, submitter.auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	anonymous := postOperations(t, base, []string{op})
	anonymousBody := readBody(t, anonymous)
	if anonymous.StatusCode != http.StatusForbidden {
		t.Fatalf("anonymous submission: status %d, want 403 (body: %s)", anonymous.StatusCode, anonymousBody)
	}
	// Request-level refusal: an error envelope, never per-item results.
	var refusal map[string]json.RawMessage
	if err := json.Unmarshal(anonymousBody, &refusal); err != nil {
		t.Fatalf("refusal body is not JSON: %v (%s)", err, anonymousBody)
	}
	if _, hasResults := refusal["results"]; hasResults {
		t.Fatalf("request-level refusal produced per-item results: %s", anonymousBody)
	}

	// The same batch, carrying a proof.
	payload, _ := json.Marshal(map[string]any{"operations": []string{op}})
	req, _ := http.NewRequest(http.MethodPost, base+"/proof/v1/operations", bytes.NewReader(payload))
	req.Header.Set("content-type", "application/json")
	signRequest(t, base, req, signer, payload, newJTI(t))
	admitted, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	admittedBody := readBody(t, admitted)
	if admitted.StatusCode != http.StatusOK {
		t.Fatalf("proven submission: status %d, body: %s", admitted.StatusCode, admittedBody)
	}
	var results struct {
		Results []struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal(admittedBody, &results); err != nil || len(results.Results) != 1 {
		t.Fatalf("proven submission results: %s", admittedBody)
	}
	if results.Results[0].Status == "rejected" {
		t.Fatalf("proven submission rejected: %s", results.Results[0].Error)
	}
}
