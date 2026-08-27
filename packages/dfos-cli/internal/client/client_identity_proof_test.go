package client

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// The client half of the API-AUTH byte contract: every authenticated request
// carries its OWN identity proof, bound to that request's method, the peer's
// authority, the origin-form target it actually sent, and the body bytes.
//
// The verifier here is the reference one — the same dfos.VerifyIdentityProof the
// relay runs — checked against the test server's own authority, so a client that
// signed a template, a normalized path, or the wrong host fails these tests for
// the same reason it would fail a real relay.

type signedRequest struct {
	verified *protocol.VerifiedIdentityProof
	header   string
	target   string
}

// proofServer records what each request presented, verifying any identity proof
// against its own authority. Its handler answers 200 with an empty JSON object
// unless respond is set.
func proofServer(t *testing.T, key ed25519.PublicKey, kid string, respond http.HandlerFunc) (*httptest.Server, *[]signedRequest) {
	t.Helper()
	var seen []signedRequest
	var authority string

	resolve := protocol.KeyResolver(func(gotKid string) (ed25519.PublicKey, error) {
		if gotKid != kid {
			t.Fatalf("proof kid = %q, want %q", gotKid, kid)
		}
		return key, nil
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		record := signedRequest{header: req.Header.Get("Authorization"), target: req.RequestURI}
		if token := protocol.ParseDFOSAuthorization(record.header); token != "" {
			verified, err := protocol.VerifyIdentityProof(token, protocol.IdentityProofExpectations{
				Method: req.Method,
				Host:   authority,
				Path:   req.RequestURI,
				Body:   body,
			}, resolve, time.Now())
			if err != nil {
				t.Errorf("verify identity proof for %s %s: %v", req.Method, req.RequestURI, err)
			}
			record.verified = verified
		}
		seen = append(seen, record)
		if respond != nil {
			respond(w, req)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	authority = u.Host
	return srv, &seen
}

func testSigner(t *testing.T) (*Signer, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Signer{Kid: "did:dfos:zexamplechainidentifierzzzzzzz#key_1", PrivateKey: priv}, pub
}

func TestUploadBlobSignsTheRequestItSends(t *testing.T) {
	signer, pub := testSigner(t)
	srv, seen := proofServer(t, pub, signer.Kid, nil)

	c := New(srv.URL)
	c.Signer = signer
	blob := []byte(`{"hello":"world"}`)
	if err := c.UploadBlob("content_abc", "bafyoperation", blob); err != nil {
		t.Fatalf("UploadBlob: %v", err)
	}

	if len(*seen) != 1 {
		t.Fatalf("requests = %d, want 1", len(*seen))
	}
	got := (*seen)[0]
	if got.verified == nil {
		t.Fatal("blob upload carried no identity proof")
	}
	if got.verified.Payload.Method != http.MethodPut {
		t.Fatalf("proof method = %q, want PUT", got.verified.Payload.Method)
	}
	if got.verified.Payload.Path != got.target {
		t.Fatalf("proof path = %q, want the sent target %q", got.verified.Payload.Path, got.target)
	}
	if got.verified.Payload.BodyHash != protocol.Sha256BodyHash(blob) {
		t.Fatal("proof bodyHash does not cover the uploaded bytes")
	}
	// Blob upload is write-shaped: without jti the relay answers 401.
	if jti, _ := got.verified.RawPayload["jti"].(string); jti == "" {
		t.Fatal("blob upload proof carries no jti")
	}
}

func TestUploadBlobWithoutSignerRefusesLocally(t *testing.T) {
	srv, seen := proofServer(t, nil, "", nil)

	c := New(srv.URL)
	err := c.UploadBlob("content_abc", "bafyoperation", []byte("{}"))
	if err == nil {
		t.Fatal("UploadBlob with no signer: want an error")
	}
	if !strings.Contains(err.Error(), "no signing key") {
		t.Fatalf("UploadBlob with no signer: %v", err)
	}
	if len(*seen) != 0 {
		t.Fatal("an unsignable upload still hit the network")
	}
}

func TestDownloadBlobSignsWithoutJtiAndStaysAnonymousWhenUnsigned(t *testing.T) {
	signer, pub := testSigner(t)
	srv, seen := proofServer(t, pub, signer.Kid, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("blob bytes"))
	})

	c := New(srv.URL)
	// A public read needs nothing, and an unsigned client must not invent a proof.
	if _, _, err := c.DownloadBlob("content_abc", ""); err != nil {
		t.Fatalf("anonymous DownloadBlob: %v", err)
	}
	if (*seen)[0].header != "" {
		t.Fatalf("anonymous download sent Authorization: %q", (*seen)[0].header)
	}

	c.Signer = signer
	if _, _, err := c.DownloadBlob("content_abc", "cred-jws", "bafyref"); err != nil {
		t.Fatalf("signed DownloadBlob: %v", err)
	}
	got := (*seen)[1]
	if got.verified == nil {
		t.Fatal("signed download carried no identity proof")
	}
	if got.verified.Payload.Path != got.target {
		t.Fatalf("proof path = %q, want the sent target %q", got.verified.Payload.Path, got.target)
	}
	// A blob read is read-shaped — the freshness window alone, no jti.
	if _, has := got.verified.RawPayload["jti"]; has {
		t.Fatal("read-shaped blob download proof carries a jti")
	}
	if got.verified.Payload.BodyHash != protocol.EmptyBodySHA256 {
		t.Fatal("bodyless request did not hash the empty body")
	}
}

func TestSubmitOperationsIsAnonymousFirstAndRetriesOnceWithAProof(t *testing.T) {
	signer, pub := testSigner(t)
	srv, seen := proofServer(t, pub, signer.Kid, func(w http.ResponseWriter, req *http.Request) {
		// Stand in for a proof-required relay: refuse the anonymous submission
		// at the admission ladder, accept the one naming a principal.
		if req.Header.Get("Authorization") == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"ingestion requires an identity proof"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"results":[{"cid":"bafyop","status":"new"}]}`))
	})

	c := New(srv.URL)
	c.Signer = signer
	results, err := c.SubmitOperations([]string{"eyJ.op.sig"})
	if err != nil {
		t.Fatalf("SubmitOperations: %v", err)
	}
	if len(results) != 1 || results[0].Status != "new" {
		t.Fatalf("results = %+v, want one new op", results)
	}

	if len(*seen) != 2 {
		t.Fatalf("requests = %d, want 2 (anonymous, then signed)", len(*seen))
	}
	if (*seen)[0].header != "" {
		t.Fatalf("first submission sent Authorization: %q", (*seen)[0].header)
	}
	retry := (*seen)[1]
	if retry.verified == nil {
		t.Fatal("retried submission carried no identity proof")
	}
	// Ingestion is write-shaped: the proof MUST carry jti.
	if jti, _ := retry.verified.RawPayload["jti"].(string); jti == "" {
		t.Fatal("submission proof carries no jti")
	}
}

func TestSubmitOperationsWithoutSignerDoesNotRetry(t *testing.T) {
	srv, seen := proofServer(t, nil, "", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"ingestion requires an identity proof"}`))
	})

	c := New(srv.URL)
	if _, err := c.SubmitOperations([]string{"eyJ.op.sig"}); err == nil {
		t.Fatal("SubmitOperations against a refusing relay: want an error")
	}
	if len(*seen) != 1 {
		t.Fatalf("requests = %d, want 1 — nothing to retry with", len(*seen))
	}
}

func TestAuthorizationForBindsTheQueryString(t *testing.T) {
	signer, pub := testSigner(t)
	srv, _ := proofServer(t, pub, signer.Kid, nil)

	c := New(srv.URL)
	authorization, err := c.AuthorizationFor(signer, http.MethodGet, "/signing/v0/requests?after=x&limit=10", nil, false)
	if err != nil {
		t.Fatalf("AuthorizationFor: %v", err)
	}
	if !strings.HasPrefix(authorization, "DFOS ") {
		t.Fatalf("authorization = %q, want a DFOS-scheme value", authorization)
	}

	_, payload, err := protocol.DecodeJWSUnsafe(strings.TrimPrefix(authorization, "DFOS "))
	if err != nil {
		t.Fatal(err)
	}
	// The wire string, not a normalization: no query reordering, no re-escaping.
	if got := payload["path"]; got != "/signing/v0/requests?after=x&limit=10" {
		t.Fatalf("proof path = %v, want the target as written", got)
	}
	if got := payload["host"]; got != strings.ToLower(strings.TrimPrefix(srv.URL, "http://")) {
		t.Fatalf("proof host = %v, want the peer authority", got)
	}
}

func TestGetRelayInfoReadsTheIngestionMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"did":          "did:dfos:zrelay",
			"ingestion":    "proof-required",
			"capabilities": map[string]any{"proof": true},
		})
	}))
	defer srv.Close()

	info, err := New(srv.URL).GetRelayInfo()
	if err != nil {
		t.Fatalf("GetRelayInfo: %v", err)
	}
	if info.Ingestion != "proof-required" {
		t.Fatalf("ingestion = %q, want proof-required", info.Ingestion)
	}
}
