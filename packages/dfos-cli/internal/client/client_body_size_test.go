package client

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// LARGE BODIES ARE SIGNED WHOLE, AND A SIZE REFUSAL SAYS SO.
//
// A body over 1 MiB used to fail 100% deterministically with a bare
// `401 authentication required` — the relay's envelope verifier inherited the
// library's 1 MiB MaxBodyBytes default while its routes buffered 16 MiB, so the
// proof over an in-spec body was refused as invalid. The relay fix is the cap
// alignment; the client's half of the contract is what these pin: the signature
// covers EVERY octet at and past that boundary, and a genuine over-cap refusal
// arrives as a sentence about size rather than a status code.

// sizedProofServer verifies each request's identity proof the way a CORRECTLY
// CONFIGURED relay does: with MaxBodyBytes set to the same ceiling the transport
// enforces. Leaving it nil would rebuild the very defect these tests exist for —
// a verifier refusing bytes the route already accepted.
func sizedProofServer(t *testing.T, key ed25519.PublicKey, kid string) (*httptest.Server, *[]int) {
	t.Helper()
	var verifiedSizes []int
	var authority string

	resolve := protocol.KeyResolver(func(gotKid string) (ed25519.PublicKey, error) {
		if gotKid != kid {
			t.Errorf("proof kid = %q, want %q", gotKid, kid)
		}
		return key, nil
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(io.LimitReader(req.Body, RelayMaxBodyBytes+1))
		if err != nil {
			http.Error(w, "read body", http.StatusInternalServerError)
			return
		}
		if len(body) > RelayMaxBodyBytes {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			w.Write([]byte(`{"error":"request body too large"}`))
			return
		}
		token := protocol.ParseDFOSAuthorization(req.Header.Get("Authorization"))
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"authentication required"}`))
			return
		}
		if _, err := protocol.VerifyIdentityProof(token, protocol.IdentityProofExpectations{
			Method:       req.Method,
			Host:         authority,
			Path:         req.RequestURI,
			Body:         body,
			MaxBodyBytes: protocol.Int64Ptr(RelayMaxBodyBytes),
		}, resolve, time.Now()); err != nil {
			t.Errorf("verify identity proof over a %d-byte body: %v", len(body), err)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"authentication required"}`))
			return
		}
		verifiedSizes = append(verifiedSizes, len(body))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"results":[]}`))
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	authority = u.Host
	return srv, &verifiedSizes
}

// TestUploadBlobSignsWholeBodyAcrossTheOneMiBBoundary walks the exact boundary
// the failure sat on: 1 MiB minus one, 1 MiB, 1 MiB plus one, and a body several
// times over it.
func TestUploadBlobSignsWholeBodyAcrossTheOneMiBBoundary(t *testing.T) {
	const oneMiB = 1 << 20
	for _, size := range []int{oneMiB - 1, oneMiB, oneMiB + 1, 4 << 20} {
		t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
			signer, pub := testSigner(t)
			srv, verified := sizedProofServer(t, pub, signer.Kid)

			c := New(srv.URL)
			c.Signer = signer
			blob := bytes.Repeat([]byte("x"), size)
			if err := c.UploadBlob("content_abc", "bafyoperation", blob); err != nil {
				t.Fatalf("UploadBlob(%d bytes): %v", size, err)
			}
			if len(*verified) != 1 || (*verified)[0] != size {
				t.Fatalf("server verified %v, want one proof over %d bytes", *verified, size)
			}
		})
	}
}

// TestUploadBlobRendersSizeRefusalHonestly is the follow-on the relay fix made
// reachable: with the verifier cap aligned, an over-cap body finally reaches the
// transport cap, and that refusal must not read as a bare status code.
func TestUploadBlobRendersSizeRefusalHonestly(t *testing.T) {
	signer, pub := testSigner(t)
	srv, _ := sizedProofServer(t, pub, signer.Kid)

	c := New(srv.URL)
	c.Signer = signer
	err := c.UploadBlob("content_abc", "bafyoperation", bytes.Repeat([]byte("x"), RelayMaxBodyBytes+1))
	if err == nil {
		t.Fatal("over-cap upload: want an error")
	}
	for _, want := range []string{"exceeds", "16.0 MiB", "413"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("over-cap upload error %q does not mention %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "authentication") {
		t.Fatalf("a size refusal was reported as an authentication failure: %v", err)
	}
}

// TestSubmitOperationsRendersSizeRefusalHonestly is the same contract on the
// other body-carrying write surface.
func TestSubmitOperationsRendersSizeRefusalHonestly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		w.Write([]byte(`{"error":"request body too large"}`))
	}))
	t.Cleanup(srv.Close)

	c := New(srv.URL)
	_, err := c.SubmitOperations([]string{strings.Repeat("a", 32)})
	if err == nil {
		t.Fatal("over-cap batch: want an error")
	}
	if !strings.Contains(err.Error(), "exceeds") || !strings.Contains(err.Error(), "16.0 MiB") {
		t.Fatalf("over-cap batch error is not a size sentence: %v", err)
	}
}
