package relay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// THE VERIFIER'S HASH CAP IS THE DEPLOYMENT'S TRANSPORT CAP.
//
// The envelope verifier refuses to hash a body over its configured
// MaxBodyBytes, and refuses it as an INVALID PROOF — which every route maps to
// a bare `401 authentication required`. Leaving that cap unset takes the
// library default (1 MiB) while the routes themselves buffer up to 16 MiB, so
// every authenticated write between those two numbers died at a 401 that said
// nothing about size. These pin the two caps to the same number.

// oneMiB is the library's MaxBodyBytesDefault — the value this relay must NOT
// be silently inheriting.
const oneMiB = 1 << 20

// contentOfExactSize builds a content chain whose document serializes to exactly
// size bytes of JSON, and returns the chain plus those bytes — so a PUT of the
// blob passes the content-addressing gate and the only thing left to fail is
// authentication.
func contentOfExactSize(t *testing.T, id testIdentity, size int) (token, contentID, opCID string, blob []byte) {
	t.Helper()
	doc := map[string]any{"type": "post", "body": ""}
	base, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if size < len(base) {
		t.Fatalf("size %d is smaller than the minimum document (%d bytes)", size, len(base))
	}
	doc["body"] = strings.Repeat("x", size-len(base))
	blob, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) != size {
		t.Fatalf("document is %d bytes, want %d", len(blob), size)
	}
	docCID, _, err := dfos.DocumentCID(doc)
	if err != nil {
		t.Fatal(err)
	}
	kid := id.did + "#" + id.auth.keyID
	token, contentID, opCID, err = dfos.SignContentCreate(id.did, docCID, kid, id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	return token, contentID, opCID, blob
}

func TestPutBlobAuthenticatesBodiesToTheTransportCap(t *testing.T) {
	for _, size := range []int{oneMiB - 1, oneMiB, oneMiB + 1, 4 << 20, maxRequestBodyBytes} {
		t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
			store := NewMemoryStore()
			r, err := NewRelay(RelayOptions{Store: store, Authority: testAuthority})
			if err != nil {
				t.Fatal(err)
			}
			creator := createTestIdentity(t)
			contentToken, contentID, operationCID, blob := contentOfExactSize(t, creator, size)
			if results := r.Ingest([]string{creator.token, contentToken}); results[0].Status != "new" || results[1].Status != "new" {
				t.Fatalf("seed content: %+v", results)
			}

			path := "/content/" + contentID + "/blob/" + operationCID
			req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(string(blob)))
			req.SetPathValue("contentId", contentID)
			req.SetPathValue("operationCID", operationCID)
			req.Header.Set("Authorization", proofFor(t, creator, http.MethodPut, path,
				blob, dfos.IdentityProofOptions{
					ExtraMembers: dfos.ProofExtraMembers{"jti": fmt.Sprintf("body-size-%d", size)}}))
			recorder := httptest.NewRecorder()
			r.handlePutBlob(recorder, req)
			if recorder.Code == http.StatusUnauthorized {
				t.Fatalf("%d-byte blob was refused as unauthenticated — the verifier is hashing "+
					"less than the route buffers; body=%s", size, recorder.Body.String())
			}
			if recorder.Code != http.StatusOK {
				t.Fatalf("%d-byte blob status = %d, want 200; body=%s", size, recorder.Code, recorder.Body.String())
			}
		})
	}
}

// TestPutBlobRefusesOverTheTransportCap is the other edge: one octet past the
// route's own buffer is a 413 about SIZE, never a 401 about authentication.
func TestPutBlobRefusesOverTheTransportCap(t *testing.T) {
	store := NewMemoryStore()
	r, err := NewRelay(RelayOptions{Store: store, Authority: testAuthority})
	if err != nil {
		t.Fatal(err)
	}
	creator := createTestIdentity(t)
	contentToken, contentID, operationCID, blob := contentOfExactSize(t, creator, maxRequestBodyBytes+1)
	if results := r.Ingest([]string{creator.token, contentToken}); results[0].Status != "new" || results[1].Status != "new" {
		t.Fatalf("seed content: %+v", results)
	}
	path := "/content/" + contentID + "/blob/" + operationCID
	req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(string(blob)))
	req.SetPathValue("contentId", contentID)
	req.SetPathValue("operationCID", operationCID)
	req.Header.Set("Authorization", proofFor(t, creator, http.MethodPut, path,
		blob, dfos.IdentityProofOptions{
			ExtraMembers: dfos.ProofExtraMembers{"jti": "body-size-over-cap"}}))
	recorder := httptest.NewRecorder()
	r.handlePutBlob(recorder, req)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-cap blob status = %d, want 413; body=%s", recorder.Code, recorder.Body.String())
	}
}

// TestPostOperationsAuthenticatesBodiesOverOneMiB covers the second
// identity-proof-over-a-body surface. A batch big enough to cross 1 MiB is
// ordinary once a chain carries any real payload, and an over-cap verifier
// turned the whole batch into a 401.
func TestPostOperationsAuthenticatesBodiesOverOneMiB(t *testing.T) {
	store := NewMemoryStore()
	r, err := NewRelay(RelayOptions{Store: store, Authority: testAuthority,
		Ingestion: IngestionProofRequired})
	if err != nil {
		t.Fatal(err)
	}
	id := createTestIdentity(t)
	// Seed the identity so its key resolves — the proof is signed by it.
	if results := r.Ingest([]string{id.token}); results[0].Status != "new" {
		t.Fatalf("seed identity: %+v", results)
	}
	contentToken, _, _ := createTestContent(t, id)

	// One real operation plus a padding entry that carries the body past 1 MiB.
	// The padding is not a valid token — ingestion reports it per-item, which is
	// a 200 with a rejected result, not an authentication failure.
	padding := strings.Repeat("a", oneMiB)
	raw, err := json.Marshal(map[string]any{"operations": []string{contentToken, padding}})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= oneMiB {
		t.Fatalf("test body is %d bytes, want > %d", len(raw), oneMiB)
	}

	path := "/proof/v1/operations"
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", proofFor(t, id, http.MethodPost, path, raw,
		dfos.IdentityProofOptions{ExtraMembers: dfos.ProofExtraMembers{"jti": "ops-over-one-mib"}}))
	recorder := httptest.NewRecorder()
	r.Handler().ServeHTTP(recorder, req)
	if recorder.Code == http.StatusUnauthorized {
		t.Fatalf("%d-byte batch was refused as unauthenticated — the verifier is hashing "+
			"less than the route buffers; body=%s", len(raw), recorder.Body.String())
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("over-1MiB batch status = %d, want 200; body=%s", recorder.Code, recorder.Body.String())
	}
}
