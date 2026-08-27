package relay

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// IDENTITY-PROOF AUTHENTICATION.
//
// These carry forward the rules the retired DID-signed auth token asserted — its
// `aud` became the HOST BINDING, its `exp` became the RELAY-OWNED freshness
// window, its lifetime ceiling became unnecessary (a presenter can no longer
// choose how long its own credential lives) — plus the rules the envelope adds.
// Byte twin of the identity-proof cases in packages/dfos-web-relay/tests.

// testAuthority is THE RELAY'S OWN CONFIGURED AUTHORITY in these tests.
// httptest.NewRequest defaults the request host to example.com, and the relay's
// authority is CONFIGURATION either way — it is never read from the request.
const testAuthority = "example.com"

type authCountingStore struct {
	Store
	identityReads int
}

func (s *authCountingStore) GetIdentityChain(did string) (*StoredIdentityChain, error) {
	s.identityReads++
	return s.Store.GetIdentityChain(did)
}

// proofFor signs an identity proof for EXACTLY one request. There is no reusable
// token: that is the whole point of what replaced the auth-token JWT.
func proofFor(t *testing.T, id testIdentity, method, path string, body []byte,
	opts dfos.IdentityProofOptions) string {
	t.Helper()
	opts.Body = body
	token, err := dfos.BuildIdentityProof(method, testAuthority, path,
		id.did+"#"+id.auth.keyID, ed25519.PrivateKey(id.auth.priv), opts)
	if err != nil {
		t.Fatal(err)
	}
	return "DFOS " + token
}

// TestIdentityProofResolverVerdicts pins the resolver's verdict split, which is
// what keeps a DELETED presenter (a judgment, 401) from being reported as an
// outage (503) — and what keeps a garbage kid from costing a store read.
func TestIdentityProofResolverVerdicts(t *testing.T) {
	base := NewMemoryStore()
	id := createTestIdentity(t)
	if result := IngestOperations([]string{id.token}, base); result[0].Status != "new" {
		t.Fatalf("seed identity: %+v", result[0])
	}
	counting := &authCountingStore{Store: base}
	resolve := CreateCurrentStateProofResolver(counting)

	if _, err := resolve(id.did + "#" + id.auth.keyID); err != nil {
		t.Fatalf("current key rejected: %v", err)
	}
	if counting.identityReads != 1 {
		t.Fatalf("identity chain reads = %d, want 1", counting.identityReads)
	}

	// A kid whose DID is not a canonical did:dfos is refused BEFORE the store
	// read: a flood of garbage kids costs a regex, never a lookup per request.
	counting.identityReads = 0
	_, err := resolve("did:dfos:not-canonical#attacker-key")
	if !errors.Is(err, dfos.ErrProofPresenterInvalid) {
		t.Fatalf("non-canonical DID: got %v, want a presenter-invalid verdict", err)
	}
	if counting.identityReads != 0 {
		t.Fatalf("invalid DID reached the store: reads=%d, want 0", counting.identityReads)
	}

	// A key that is not in CURRENT state is checked-and-failed, not unverifiable.
	if _, err := resolve(id.did + "#key_never_existed"); !errors.Is(err, dfos.ErrProofPresenterInvalid) {
		t.Fatalf("absent key: got %v, want a presenter-invalid verdict", err)
	}

	// An unknown chain is something the resolver could NOT check: unverifiable.
	unknown := createTestIdentity(t)
	if _, err := resolve(unknown.did + "#" + unknown.auth.keyID); errors.Is(err, dfos.ErrProofPresenterInvalid) {
		t.Fatal("an unknown identity must be UNVERIFIABLE, never a judgment about the caller")
	}
}

// TestIdentityProofDeletedThenRestored is the auth-token suite's delete/restore
// case, carried forward: deletion is the terminal off-switch for live
// authentication, and a valid restore reopens it.
func TestIdentityProofDeletedThenRestored(t *testing.T) {
	store := NewMemoryStore()
	id := createTestIdentity(t)
	if result := IngestOperations([]string{id.token}, store); result[0].Status != "new" {
		t.Fatalf("seed identity: %+v", result[0])
	}
	resolve := CreateCurrentStateProofResolver(store)
	kid := id.did + "#" + id.auth.keyID
	if _, err := resolve(kid); err != nil {
		t.Fatalf("genesis identity did not resolve: %v", err)
	}

	_, genesisPayload, err := dfos.DecodeJWSUnsafe(id.token)
	if err != nil {
		t.Fatal(err)
	}
	genesisAt, err := time.Parse(time.RFC3339Nano, genesisPayload["createdAt"].(string))
	if err != nil {
		t.Fatal(err)
	}
	signIdentityOp := func(payload map[string]any) string {
		t.Helper()
		_, _, cid, err := dfos.DagCborCID(payload)
		if err != nil {
			t.Fatal(err)
		}
		token, err := dfos.CreateJWS(dfos.JWSHeader{
			Alg: "EdDSA", Typ: "did:dfos:identity-op",
			Kid: id.did + "#" + id.controller.keyID, CID: cid,
		}, payload, ed25519.PrivateKey(id.controller.priv))
		if err != nil {
			t.Fatal(err)
		}
		return token
	}

	deleteToken := signIdentityOp(map[string]any{
		"version": int64(1), "type": "delete",
		"previousOperationCID": id.opCID,
		"createdAt":            genesisAt.Add(time.Second).UTC().Format("2006-01-02T15:04:05.000Z"),
	})
	if result := IngestOperations([]string{deleteToken}, store); result[0].Status != "new" {
		t.Fatalf("delete identity: %+v", result[0])
	}
	if _, err := resolve(kid); !errors.Is(err, dfos.ErrProofPresenterInvalid) {
		t.Fatalf("deleted identity: got %v, want a presenter-invalid verdict", err)
	}

	deleteHeader, _, err := dfos.DecodeJWSUnsafe(deleteToken)
	if err != nil {
		t.Fatal(err)
	}
	restore := signIdentityOp(map[string]any{
		"version": int64(1), "type": "restore",
		"previousOperationCID": deleteHeader.CID,
		"createdAt":            genesisAt.Add(2 * time.Second).UTC().Format("2006-01-02T15:04:05.000Z"),
	})
	if result := IngestOperations([]string{restore}, store); result[0].Status != "new" {
		t.Fatalf("restore: %+v", result[0])
	}
	if _, err := resolve(kid); err != nil {
		t.Fatalf("restored identity did not resolve: %v", err)
	}
}

// blobFixture seeds an identity, a content chain, and its uploaded blob, and
// returns the relay serving them.
func blobFixture(t *testing.T, opts RelayOptions) (*Relay, testIdentity, proofFixtureContent) {
	t.Helper()
	if opts.Store == nil {
		opts.Store = NewMemoryStore()
	}
	if opts.Authority == "" {
		opts.Authority = testAuthority
	}
	r, err := NewRelay(opts)
	if err != nil {
		t.Fatal(err)
	}
	creator := createTestIdentity(t)
	contentToken, contentID, operationCID := createTestContent(t, creator)
	if results := r.Ingest([]string{creator.token, contentToken}); results[0].Status != "new" || results[1].Status != "new" {
		t.Fatalf("seed content: %+v", results)
	}
	return r, creator, proofFixtureContent{contentID: contentID, operationCID: operationCID}
}

type proofFixtureContent struct {
	contentID    string
	operationCID string
}

func (c proofFixtureContent) blobPath() string {
	return "/content/" + c.contentID + "/blob/" + c.operationCID
}

// testContentDocumentBytes is the exact JSON body createTestContent committed a
// documentCID for. The relay re-canonicalizes it (decode JSON -> dag-cbor ->
// sha-256) before storing, so member order here is free.
func testContentDocumentBytes(t *testing.T, _ testIdentity, _ proofFixtureContent) []byte {
	t.Helper()
	return []byte(`{"type":"post","title":"hello world","body":"test content"}`)
}

func TestBlobUploadIdentityProofBindings(t *testing.T) {
	r, creator, c := blobFixture(t, RelayOptions{})
	body := testContentDocumentBytes(t, creator, c)

	send := func(auth string) int {
		req := httptest.NewRequest(http.MethodPut, c.blobPath(), strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/octet-stream")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		r.Handler().ServeHTTP(rec, req)
		return rec.Code
	}

	// Anonymous — no proof at all.
	if got := send(""); got != 401 {
		t.Fatalf("anonymous upload: got %d, want 401", got)
	}
	// A Bearer token: the relay owns no other authentication grammar.
	if got := send("Bearer anything-at-all"); got != 401 {
		t.Fatalf("bearer upload: got %d, want 401", got)
	}
	// A proof with NO jti — ingestion and blob upload are write-shaped.
	if got := send(proofFor(t, creator, http.MethodPut, c.blobPath(), body,
		dfos.IdentityProofOptions{})); got != 401 {
		t.Fatalf("upload without jti: got %d, want 401", got)
	}
	// A valid, jti-bearing proof.
	if got := send(proofFor(t, creator, http.MethodPut, c.blobPath(), body,
		dfos.IdentityProofOptions{ExtraMembers: dfos.ProofExtraMembers{"jti": "go-upload-1"}})); got != 200 {
		t.Fatalf("valid upload: got %d, want 200", got)
	}
	// The byte-identical request inside the freshness window is a REPLAY.
	if got := send(proofFor(t, creator, http.MethodPut, c.blobPath(), body,
		dfos.IdentityProofOptions{ExtraMembers: dfos.ProofExtraMembers{"jti": "go-upload-1"}})); got != 401 {
		t.Fatalf("replayed jti: got %d, want 401", got)
	}
	// A jti over the cap is refused; the cap is identical in both relays.
	if got := send(proofFor(t, creator, http.MethodPut, c.blobPath(), body,
		dfos.IdentityProofOptions{ExtraMembers: dfos.ProofExtraMembers{
			"jti": strings.Repeat("x", MaxJtiBytes+1)}})); got != 401 {
		t.Fatalf("oversized jti: got %d, want 401", got)
	}
}

func TestBlobReadIdentityProofBindings(t *testing.T) {
	r, creator, c := blobFixture(t, RelayOptions{})
	body := testContentDocumentBytes(t, creator, c)
	upload := httptest.NewRequest(http.MethodPut, c.blobPath(), strings.NewReader(string(body)))
	upload.Header.Set("Content-Type", "application/octet-stream")
	upload.Header.Set("Authorization", proofFor(t, creator, http.MethodPut, c.blobPath(), body,
		dfos.IdentityProofOptions{ExtraMembers: dfos.ProofExtraMembers{"jti": "go-read-seed"}}))
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, upload)
	if rec.Code != 200 {
		t.Fatalf("seed upload: %d %s", rec.Code, rec.Body.String())
	}

	readPath := "/content/" + c.contentID + "/blob"
	get := func(auth string) int {
		req := httptest.NewRequest(http.MethodGet, readPath, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		r.Handler().ServeHTTP(w, req)
		return w.Code
	}

	// The creator can always read their own blobs with just an identity proof —
	// read-shaped, so no jti.
	if got := get(proofFor(t, creator, http.MethodGet, readPath, nil,
		dfos.IdentityProofOptions{})); got != 200 {
		t.Fatalf("creator read: got %d, want 200", got)
	}
	// Case-insensitive scheme matching, per RFC 9110.
	lower := strings.Replace(proofFor(t, creator, http.MethodGet, readPath, nil,
		dfos.IdentityProofOptions{}), "DFOS ", "dfos ", 1)
	if got := get(lower); got != 200 {
		t.Fatalf("lowercase scheme: got %d, want 200", got)
	}
	// A proof bound to a DIFFERENT path is refused: one proof, one request.
	wrongPath, err := dfos.BuildIdentityProof(http.MethodGet, testAuthority, "/content/other/blob",
		creator.did+"#"+creator.auth.keyID, ed25519.PrivateKey(creator.auth.priv),
		dfos.IdentityProofOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := get("DFOS " + wrongPath); got != 401 {
		t.Fatalf("path mismatch: got %d, want 401", got)
	}
	// A proof bound to a DIFFERENT authority is refused.
	wrongHost, err := dfos.BuildIdentityProof(http.MethodGet, "other-relay.example.com", readPath,
		creator.did+"#"+creator.auth.keyID, ed25519.PrivateKey(creator.auth.priv),
		dfos.IdentityProofOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := get("DFOS " + wrongHost); got != 401 {
		t.Fatalf("host mismatch: got %d, want 401", got)
	}
	// A stale proof is refused — the VERIFIER owns the freshness window.
	if got := get(proofFor(t, creator, http.MethodGet, readPath, nil,
		dfos.IdentityProofOptions{Iat: time.Now().Unix() - 3600})); got != 401 {
		t.Fatalf("stale proof: got %d, want 401", got)
	}
	// A forward-dated proof is refused past the clock-skew allowance.
	if got := get(proofFor(t, creator, http.MethodGet, readPath, nil,
		dfos.IdentityProofOptions{Iat: time.Now().Unix() + 3600})); got != 401 {
		t.Fatalf("forward-dated proof: got %d, want 401", got)
	}
	// A presenter this relay has never seen is UNVERIFIABLE, never invalid.
	stranger := createTestIdentity(t)
	if got := get(proofFor(t, stranger, http.MethodGet, readPath, nil,
		dfos.IdentityProofOptions{})); got != 503 {
		t.Fatalf("unknown presenter: got %d, want 503", got)
	}
}

// TestUnconfiguredAuthorityAnswers503 pins the safe explicit behavior: the host
// binding is the deployment's to supply, and a relay that cannot supply it says
// so rather than blaming the caller (401) or inventing a binding from a header.
func TestUnconfiguredAuthorityAnswers503(t *testing.T) {
	store := NewMemoryStore()
	r, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	creator := createTestIdentity(t)
	contentToken, contentID, operationCID := createTestContent(t, creator)
	if results := r.Ingest([]string{creator.token, contentToken}); results[1].Status != "new" {
		t.Fatalf("seed content: %+v", results)
	}
	readPath := "/content/" + contentID + "/blob"
	_ = operationCID

	req := httptest.NewRequest(http.MethodGet, readPath, nil)
	req.Header.Set("Authorization", proofFor(t, creator, http.MethodGet, readPath, nil,
		dfos.IdentityProofOptions{}))
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, req)
	if w.Code != 503 {
		t.Fatalf("unconfigured authority: got %d, want 503", w.Code)
	}
}
