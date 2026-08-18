package relay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

const signingTestContentID = "cv7n8vkvr64cctf3294h9k4eanhff8z"

type signingTestFixture struct {
	requester  testIdentity
	subject    testIdentity
	request    string
	cid        string
	response   string
	payload    []byte
	credential string
}

type signingTestStore interface {
	Store
	SigningStore
}

type nonSigningTestStore struct {
	Store
}

type limitCapturingSigningStore struct {
	Store
	SigningStore
	limits []int
}

func (s *limitCapturingSigningStore) ListPendingSignRequests(subjectDID, after string, limit int, now time.Time) ([]StoredSignRequest, string, error) {
	s.limits = append(s.limits, limit)
	return s.SigningStore.ListPendingSignRequests(subjectDID, after, limit, now)
}

func signingMailbox(id testIdentity) string {
	return "mailbox:" + strings.TrimPrefix(id.did, "did:dfos:")
}

func signingCredential(t *testing.T, issuer testIdentity, aud, resource, action string, ttl time.Duration) string {
	t.Helper()
	token, err := dfos.CreateCredential(
		issuer.did, aud, issuer.did+"#"+issuer.auth.keyID,
		resource, action, ttl, ed25519.PrivateKey(issuer.auth.priv),
	)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func newSigningFixture(t *testing.T, store Store, role string) signingTestFixture {
	t.Helper()
	requester := createTestIdentity(t)
	subject := createTestIdentity(t)
	results := IngestOperations([]string{requester.token, subject.token}, store)
	for _, result := range results {
		if result.Status != "new" {
			t.Fatalf("seed identity: %+v", result)
		}
	}
	response, _, err := dfos.SignCreditClaim(
		subject.did, signingTestContentID, role, subject.auth.keyID,
		ed25519.PrivateKey(subject.auth.priv),
	)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(response, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	request, cid, err := dfos.BuildSignRequest(
		requester.did, subject.did, "did:dfos:credit-claim", payload,
		time.Now().Add(5*time.Minute), requester.auth.keyID,
		ed25519.PrivateKey(requester.auth.priv), dfos.SignRequestOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return signingTestFixture{
		requester: requester, subject: subject, request: request, cid: cid,
		response: response, payload: payload,
		credential: signingCredential(t, subject, requester.did, signingMailbox(subject), "deposit", 10*time.Minute),
	}
}

func signingRequest(t *testing.T, r *Relay, method, path string, body any, auth string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else if raw, ok := body.([]byte); ok {
		reader = bytes.NewReader(raw)
	} else {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("content-type", "application/json")
	if auth != "" {
		req.Header.Set("authorization", "Bearer "+auth)
	}
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, req)
	return w
}

func signingAuthToken(t *testing.T, r *Relay, id testIdentity) string {
	t.Helper()
	token, err := dfos.CreateAuthToken(
		id.did, r.did, id.did+"#"+id.auth.keyID, 5*time.Minute,
		ed25519.PrivateKey(id.auth.priv),
	)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func signingRawResponse(t *testing.T, did, keyID, typ string, payload []byte, privateKey []byte) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{
		"alg": "EdDSA", "typ": typ, "kid": did + "#" + keyID,
	})
	headerB64 := base64.RawURLEncoding.EncodeToString(header)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	input := headerB64 + "." + payloadB64
	signature := ed25519.Sign(ed25519.PrivateKey(privateKey), []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signingNonCanonicalSignature(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, parts[2][len(parts[2])-1])
	parts[2] = parts[2][:len(parts[2])-1] + string(alphabet[last+1])
	return strings.Join(parts, ".")
}

func signingCustomRequest(t *testing.T, requester testIdentity, subject string, payload []byte, createdAt, expiresAt time.Time, padding int) string {
	t.Helper()
	body := map[string]any{
		"version": 1, "type": "sign-request", "did": requester.did,
		"subject": subject, "payloadTyp": "did:dfos:credit-claim",
		"payload":   base64.RawURLEncoding.EncodeToString(payload),
		"createdAt": createdAt.UTC().Truncate(time.Second).Format(signingTimeFormat),
		"expiresAt": expiresAt.UTC().Truncate(time.Second).Format(signingTimeFormat),
	}
	if padding > 0 {
		body["padding"] = strings.Repeat("x", padding)
	}
	_, _, cid, err := dfos.DagCborCID(body)
	if err != nil {
		t.Fatal(err)
	}
	token, err := dfos.CreateJWS(dfos.JWSHeader{
		Alg: "EdDSA", Typ: "did:dfos:sign-request",
		Kid: requester.did + "#" + requester.auth.keyID, CID: cid,
	}, body, ed25519.PrivateKey(requester.auth.priv))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestSigningDisabledByDefault(t *testing.T) {
	r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	meta := signingRequest(t, r, http.MethodGet, "/.well-known/dfos-relay", nil, "")
	if meta.Code != http.StatusOK || !bytes.Contains(meta.Body.Bytes(), []byte(`"signing":false`)) {
		t.Fatalf("well-known signing flag: %d %s", meta.Code, meta.Body.String())
	}
	cid := "bafyreidummy"
	tests := []struct{ method, path string }{
		{http.MethodPost, signingBasePath + "/requests"},
		{http.MethodGet, signingBasePath + "/requests"},
		{http.MethodPost, signingBasePath + "/requests/" + cid + "/response"},
		{http.MethodGet, signingBasePath + "/requests/" + cid + "/response"},
		{http.MethodPost, signingBasePath + "/requests/" + cid + "/decline"},
	}
	for _, tc := range tests {
		if got := signingRequest(t, r, tc.method, tc.path, []byte(`not-json`), ""); got.Code != http.StatusNotImplemented {
			t.Fatalf("%s %s: got %d, want 501", tc.method, tc.path, got.Code)
		}
	}
}

func TestSigningStoreRequiredOnlyWhenEnabled(t *testing.T) {
	store := nonSigningTestStore{Store: NewMemoryStore()}
	if _, err := NewRelay(RelayOptions{Store: store}); err != nil {
		t.Fatalf("signing-disabled relay rejected non-signing store: %v", err)
	}
	enabled := true
	if _, err := NewRelay(RelayOptions{Store: store, Signing: &enabled}); err == nil || !strings.Contains(err.Error(), "SigningStore") {
		t.Fatalf("signing-enabled relay accepted non-signing store: %v", err)
	}
}

var signingStoreFactories = []struct {
	name string
	open func(*testing.T) (signingTestStore, func())
}{
	{"memory", func(_ *testing.T) (signingTestStore, func()) { return NewMemoryStore(), func() {} }},
	{"sqlite", func(t *testing.T) (signingTestStore, func()) {
		store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "signing.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		return store, func() { _ = store.Close() }
	}},
}

func forEachSigningStore(t *testing.T, test func(*testing.T, signingTestStore)) {
	t.Helper()
	for _, factory := range signingStoreFactories {
		factory := factory
		t.Run(factory.name, func(t *testing.T) {
			store, closeStore := factory.open(t)
			defer closeStore()
			test(t, store)
		})
	}
}

func TestSigningHappyPathBothStores(t *testing.T) {
	forEachSigningStore(t, func(t *testing.T, store signingTestStore) {
		enabled := true
		r, err := NewRelay(RelayOptions{Store: store, Signing: &enabled})
		if err != nil {
			t.Fatal(err)
		}
		f := newSigningFixture(t, store, "happy")
		deposit := map[string]any{"request": f.request, "credential": f.credential}
		if got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests", deposit, ""); got.Code != http.StatusCreated {
			t.Fatalf("deposit: %d %s", got.Code, got.Body.String())
		}
		if got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests", deposit, ""); got.Code != http.StatusOK {
			t.Fatalf("idempotent deposit: %d %s", got.Code, got.Body.String())
		}
		if got := signingRequest(t, r, http.MethodGet, signingBasePath+"/requests", nil, ""); got.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated poll: %d", got.Code)
		}
		auth := signingAuthToken(t, r, f.subject)
		poll := signingRequest(t, r, http.MethodGet, signingBasePath+"/requests", nil, auth)
		if poll.Code != http.StatusOK || !bytes.Contains(poll.Body.Bytes(), []byte(f.cid)) {
			t.Fatalf("poll: %d %s", poll.Code, poll.Body.String())
		}
		var pollBody map[string]any
		if err := json.Unmarshal(poll.Body.Bytes(), &pollBody); err != nil || pollBody["next"] != nil {
			t.Fatalf("poll envelope: %s (%v)", poll.Body.String(), err)
		}
		if _, exists := pollBody["cursor"]; exists {
			t.Fatalf("poll emitted removed cursor field: %s", poll.Body.String())
		}
		path := signingBasePath + "/requests/" + f.cid + "/response"
		if got := signingRequest(t, r, http.MethodPost, path, map[string]string{"response": f.response}, ""); got.Code != http.StatusCreated {
			t.Fatalf("respond: %d %s", got.Code, got.Body.String())
		}
		if got := signingRequest(t, r, http.MethodPost, path, map[string]string{"response": f.response}, ""); got.Code != http.StatusOK {
			t.Fatalf("idempotent respond: %d %s", got.Code, got.Body.String())
		}
		fetch := signingRequest(t, r, http.MethodGet, path, nil, "")
		if fetch.Code != http.StatusOK || !bytes.Contains(fetch.Body.Bytes(), []byte(`"status":"responded"`)) || !bytes.Contains(fetch.Body.Bytes(), []byte(f.response)) {
			t.Fatalf("fetch response: %d %s", fetch.Code, fetch.Body.String())
		}
	})
}

func TestSigningDepositAuthorizationAndEnvelopeGates(t *testing.T) {
	forEachSigningStore(t, testSigningDepositAuthorizationAndEnvelopeGates)
}

func testSigningDepositAuthorizationAndEnvelopeGates(t *testing.T, store signingTestStore) {
	enabled := true
	r, err := NewRelay(RelayOptions{Store: store, Signing: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	f := newSigningFixture(t, store, "deposit-gates")
	third := createTestIdentity(t)
	platform := createTestIdentity(t)
	IngestOperations([]string{third.token, platform.token}, store)

	rejected := []string{
		signingCredential(t, third, f.requester.did, signingMailbox(f.subject), "deposit", time.Minute),
		signingCredential(t, f.subject, third.did, signingMailbox(f.subject), "deposit", time.Minute),
		signingCredential(t, f.subject, f.requester.did, "mailbox:*", "deposit", time.Minute),
		signingCredential(t, f.subject, f.requester.did, signingMailbox(third), "deposit", time.Minute),
		signingCredential(t, f.subject, f.requester.did, signingMailbox(f.subject), "read", time.Minute),
		signingCredential(t, f.subject, f.requester.did, signingMailbox(f.subject), "deposit", -time.Second),
	}
	for _, token := range rejected {
		got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests", map[string]string{"request": f.request, "credential": token}, "")
		if got.Code != http.StatusForbidden {
			t.Fatalf("credential rejection: %d %s", got.Code, got.Body.String())
		}
	}

	leaf := signingCredential(t, f.subject, f.requester.did, signingMailbox(f.subject), "deposit", time.Minute)
	leafHeader, _, _ := dfos.DecodeJWSUnsafe(leaf)
	revocation, _, err := dfos.SignRevocation(f.subject.did, leafHeader.CID, f.subject.did+"#"+f.subject.auth.keyID, ed25519.PrivateKey(f.subject.auth.priv))
	if err != nil {
		t.Fatal(err)
	}
	IngestOperations([]string{revocation}, store)
	if got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests", map[string]string{"request": f.request, "credential": leaf}, ""); got.Code != http.StatusForbidden {
		t.Fatalf("revoked leaf: %d %s", got.Code, got.Body.String())
	}

	parent := signingCredential(t, f.subject, platform.did, signingMailbox(f.subject), "deposit", 2*time.Minute)
	child, _ := mintDelegatedCredential(t, platform.did, platform.did+"#"+platform.auth.keyID, platform.auth.priv, f.requester.did, signingMailbox(f.subject), "deposit", []string{parent}, time.Minute)
	delegated := newSigningFixture(t, store, "delegated")
	delegatedParent := signingCredential(t, delegated.subject, platform.did, signingMailbox(delegated.subject), "deposit", 2*time.Minute)
	delegatedChild, _ := mintDelegatedCredential(t, platform.did, platform.did+"#"+platform.auth.keyID, platform.auth.priv, delegated.requester.did, signingMailbox(delegated.subject), "deposit", []string{delegatedParent}, time.Minute)
	if got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests", map[string]string{"request": delegated.request, "credential": delegatedChild}, ""); got.Code != http.StatusCreated {
		t.Fatalf("delegated deposit: %d %s", got.Code, got.Body.String())
	}
	parentHeader, _, _ := dfos.DecodeJWSUnsafe(parent)
	parentRevocation, _, _ := dfos.SignRevocation(f.subject.did, parentHeader.CID, f.subject.did+"#"+f.subject.auth.keyID, ed25519.PrivateKey(f.subject.auth.priv))
	IngestOperations([]string{parentRevocation}, store)
	if got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests", map[string]string{"request": f.request, "credential": child}, ""); got.Code != http.StatusForbidden {
		t.Fatalf("revoked parent: %d %s", got.Code, got.Body.String())
	}

	openFixture := newSigningFixture(t, store, "open")
	open := signingCredential(t, openFixture.subject, "*", signingMailbox(openFixture.subject), "deposit", time.Minute)
	if got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests", map[string]string{"request": openFixture.request, "credential": open}, ""); got.Code != http.StatusCreated {
		t.Fatalf("open mailbox: %d %s", got.Code, got.Body.String())
	}

	now := time.Now()
	for _, request := range []string{
		signingCustomRequest(t, f.requester, f.subject.did, f.payload, now.Add(-time.Minute), now.Add(-time.Second), 0),
		signingCustomRequest(t, f.requester, f.subject.did, f.payload, now, now.Add(604801*time.Second), 0),
		signingCustomRequest(t, f.requester, f.subject.did, f.payload, now, now.Add(time.Minute), 9000),
	} {
		if got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests", map[string]string{"request": request, "credential": f.credential}, ""); got.Code != http.StatusBadRequest {
			t.Fatalf("invalid envelope: %d %s", got.Code, got.Body.String())
		}
	}
	huge := []byte(`{"padding":"` + strings.Repeat("x", maxSigningDepositBody) + `"}`)
	if got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests", huge, ""); got.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d %s", got.Code, got.Body.String())
	}

	unknown := createTestIdentity(t)
	unknownClaim, _, _ := dfos.SignCreditClaim(unknown.did, signingTestContentID, "unknown", unknown.auth.keyID, ed25519.PrivateKey(unknown.auth.priv))
	unknownPayload, _ := base64.RawURLEncoding.DecodeString(strings.Split(unknownClaim, ".")[1])
	unknownRequest, _, _ := dfos.BuildSignRequest(f.requester.did, unknown.did, "did:dfos:credit-claim", unknownPayload, time.Now().Add(time.Minute), f.requester.auth.keyID, ed25519.PrivateKey(f.requester.auth.priv), dfos.SignRequestOptions{})
	unknownCredential := signingCredential(t, unknown, f.requester.did, signingMailbox(unknown), "deposit", time.Minute)
	got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests", map[string]any{"request": unknownRequest, "credential": unknownCredential, "chain": []string{unknown.token}}, "")
	if got.Code != http.StatusNotFound {
		t.Fatalf("unknown subject: %d %s", got.Code, got.Body.String())
	}
}

func TestSigningDeletedSubjectDepositAndPoll(t *testing.T) {
	forEachSigningStore(t, func(t *testing.T, store signingTestStore) {
		enabled := true
		r, err := NewRelay(RelayOptions{Store: store, Signing: &enabled})
		if err != nil {
			t.Fatal(err)
		}
		f := newSigningFixture(t, store, "deleted-subject")
		deposit := map[string]string{"request": f.request, "credential": f.credential}
		if got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests", deposit, ""); got.Code != http.StatusCreated {
			t.Fatalf("deposit before delete: %d %s", got.Code, got.Body.String())
		}
		auth := signingAuthToken(t, r, f.subject)
		deleted, _, err := dfos.SignIdentityDelete(f.subject.opCID, f.subject.did+"#"+f.subject.controller.keyID, f.subject.controller.priv)
		if err != nil {
			t.Fatal(err)
		}
		if result := IngestOperations([]string{deleted}, store)[0]; result.Status != "new" {
			t.Fatalf("delete subject: %+v", result)
		}
		if got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests", deposit, ""); got.Code != http.StatusNotFound {
			t.Fatalf("deposit after delete: %d %s", got.Code, got.Body.String())
		}
		if got := signingRequest(t, r, http.MethodGet, signingBasePath+"/requests", nil, auth); got.Code != http.StatusUnauthorized {
			t.Fatalf("poll after delete: %d %s", got.Code, got.Body.String())
		}
	})
}

func TestSigningPollLimitAndMalformedCursor(t *testing.T) {
	base := NewMemoryStore()
	store := &limitCapturingSigningStore{Store: base, SigningStore: base}
	enabled := true
	r, err := NewRelay(RelayOptions{Store: store, Signing: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	subject := createTestIdentity(t)
	if result := IngestOperations([]string{subject.token}, store)[0]; result.Status != "new" {
		t.Fatalf("seed subject: %+v", result)
	}
	auth := signingAuthToken(t, r, subject)
	for _, path := range []string{
		signingBasePath + "/requests?limit=1001",
		signingBasePath + "/requests?limit=wat",
	} {
		if got := signingRequest(t, r, http.MethodGet, path, nil, auth); got.Code != http.StatusOK {
			t.Fatalf("poll %s: %d %s", path, got.Code, got.Body.String())
		}
	}
	if !slices.Equal(store.limits, []int{1000, 100}) {
		t.Fatalf("poll limits = %v, want [1000 100]", store.limits)
	}
	if got := signingRequest(t, r, http.MethodGet, signingBasePath+"/requests?after=not-a-cursor", nil, auth); got.Code != http.StatusBadRequest {
		t.Fatalf("malformed cursor: %d %s", got.Code, got.Body.String())
	}
	if !slices.Equal(store.limits, []int{1000, 100, 100}) {
		t.Fatalf("malformed cursor was not rejected by store authority: %v", store.limits)
	}
}

func TestSigningResponseDeclineExpiryIsolationAndWriteFalse(t *testing.T) {
	forEachSigningStore(t, testSigningResponseDeclineExpiryIsolationAndWriteFalse)
}

func testSigningResponseDeclineExpiryIsolationAndWriteFalse(t *testing.T, store signingTestStore) {
	enabled, disabled := true, false
	r, err := NewRelay(RelayOptions{Store: store, Signing: &enabled, Write: &disabled})
	if err != nil {
		t.Fatal(err)
	}
	f := newSigningFixture(t, store, "response-gates")
	deposit := map[string]string{"request": f.request, "credential": f.credential}
	if got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests", deposit, ""); got.Code != http.StatusCreated {
		t.Fatalf("write:false deposit: %d %s", got.Code, got.Body.String())
	}
	if got := signingRequest(t, r, http.MethodPost, proofBasePath+"/operations", map[string]any{"operations": []string{f.requester.token}}, ""); got.Code != http.StatusNotImplemented {
		t.Fatalf("write:false proof ingest: %d", got.Code)
	}
	path := signingBasePath + "/requests/" + f.cid + "/response"
	if got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests/unknown/response", map[string]string{"response": f.response}, ""); got.Code != http.StatusNotFound {
		t.Fatalf("unknown response cid: %d", got.Code)
	}
	wrongTyp := signingRawResponse(t, f.subject.did, f.subject.auth.keyID, "wrong", f.payload, f.subject.auth.priv)
	wrongDID := signingRawResponse(t, f.requester.did, f.requester.auth.keyID, "did:dfos:credit-claim", f.payload, f.requester.auth.priv)
	changed := append([]byte(nil), f.payload...)
	changed[len(changed)-2] ^= 1
	wrongPayload := signingRawResponse(t, f.subject.did, f.subject.auth.keyID, "did:dfos:credit-claim", changed, f.subject.auth.priv)
	for _, response := range []string{wrongTyp, wrongDID, wrongPayload} {
		if got := signingRequest(t, r, http.MethodPost, path, map[string]string{"response": response}, ""); got.Code != http.StatusBadRequest {
			t.Fatalf("invalid response: %d %s", got.Code, got.Body.String())
		}
	}
	if got := signingRequest(t, r, http.MethodPost, path, map[string]string{"response": signingNonCanonicalSignature(t, f.response)}, ""); got.Code != http.StatusBadRequest {
		t.Fatalf("non-canonical response: %d %s", got.Code, got.Body.String())
	}
	if got := signingRequest(t, r, http.MethodPost, path, map[string]string{"response": strings.Repeat("x", 8700)}, ""); got.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized response body: %d %s", got.Code, got.Body.String())
	}

	second := newTestKeypair()
	genesisHeader, genesisPayload, _ := dfos.DecodeJWSUnsafe(f.subject.token)
	createdAt, _ := time.Parse(time.RFC3339Nano, genesisPayload["createdAt"].(string))
	updatePayload := map[string]any{
		"version": int64(1), "type": "update",
		"authKeys":             []dfos.MultikeyPublicKey{f.subject.auth.mk, second.mk},
		"assertKeys":           []dfos.MultikeyPublicKey{},
		"controllerKeys":       []dfos.MultikeyPublicKey{f.subject.controller.mk},
		"previousOperationCID": genesisHeader.CID,
		"createdAt":            createdAt.Add(time.Second).UTC().Format(signingTimeFormat),
	}
	_, _, updateCID, _ := dfos.DagCborCID(updatePayload)
	update, _ := dfos.CreateJWS(dfos.JWSHeader{Alg: "EdDSA", Typ: "did:dfos:identity-op", Kid: f.subject.did + "#" + f.subject.controller.keyID, CID: updateCID}, updatePayload, ed25519.PrivateKey(f.subject.controller.priv))
	if result := IngestOperations([]string{update}, store)[0]; result.Status != "new" {
		t.Fatalf("identity update: %+v", result)
	}
	if got := signingRequest(t, r, http.MethodPost, path, map[string]string{"response": f.response}, ""); got.Code != http.StatusCreated {
		t.Fatalf("first response: %d %s", got.Code, got.Body.String())
	}
	secondResponse := signingRawResponse(t, f.subject.did, second.keyID, "did:dfos:credit-claim", f.payload, second.priv)
	if got := signingRequest(t, r, http.MethodPost, path, map[string]string{"response": secondResponse}, ""); got.Code != http.StatusConflict {
		t.Fatalf("second valid response: %d %s", got.Code, got.Body.String())
	}
	if got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests/"+f.cid+"/decline", nil, ""); got.Code != http.StatusConflict {
		t.Fatalf("decline after response: %d", got.Code)
	}

	declineFixture := newSigningFixture(t, store, "decline")
	signingRequest(t, r, http.MethodPost, signingBasePath+"/requests", map[string]string{"request": declineFixture.request, "credential": declineFixture.credential}, "")
	declinePath := signingBasePath + "/requests/" + declineFixture.cid + "/decline"
	if got := signingRequest(t, r, http.MethodPost, declinePath, map[string]bool{"unexpected": true}, ""); got.Code != http.StatusBadRequest {
		t.Fatalf("non-empty decline: %d %s", got.Code, got.Body.String())
	}
	if got := signingRequest(t, r, http.MethodPost, declinePath, bytes.Repeat([]byte("x"), maxSigningDeclineBody+1), ""); got.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized decline: %d %s", got.Code, got.Body.String())
	}
	if got := signingRequest(t, r, http.MethodPost, declinePath, nil, ""); got.Code != http.StatusNoContent {
		t.Fatalf("decline: %d", got.Code)
	}
	if got := signingRequest(t, r, http.MethodPost, declinePath, nil, ""); got.Code != http.StatusNoContent {
		t.Fatalf("idempotent decline: %d", got.Code)
	}
	fetch := signingRequest(t, r, http.MethodGet, signingBasePath+"/requests/"+declineFixture.cid+"/response", nil, "")
	if !bytes.Contains(fetch.Body.Bytes(), []byte(`"status":"declined"`)) {
		t.Fatalf("declined fetch: %s", fetch.Body.String())
	}
	declinedAuth := signingAuthToken(t, r, declineFixture.subject)
	declinedPoll := signingRequest(t, r, http.MethodGet, signingBasePath+"/requests", nil, declinedAuth)
	if !bytes.Contains(declinedPoll.Body.Bytes(), []byte(`"declined":true`)) {
		t.Fatalf("declined subject poll: %s", declinedPoll.Body.String())
	}
	if got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests/"+declineFixture.cid+"/response", map[string]string{"response": declineFixture.response}, ""); got.Code != http.StatusCreated {
		t.Fatalf("response after decline: %d %s", got.Code, got.Body.String())
	}

	auth := signingAuthToken(t, r, declineFixture.subject)
	other := createTestIdentity(t)
	IngestOperations([]string{other.token}, store)
	otherPoll := signingRequest(t, r, http.MethodGet, signingBasePath+"/requests", nil, signingAuthToken(t, r, other))
	if !bytes.Contains(otherPoll.Body.Bytes(), []byte(`"requests":[]`)) {
		t.Fatalf("mailbox isolation: %s", otherPoll.Body.String())
	}

	expires := time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
	expiringTarget, _, _ := dfos.SignCreditClaim(declineFixture.subject.did, signingTestContentID, "expires", declineFixture.subject.auth.keyID, ed25519.PrivateKey(declineFixture.subject.auth.priv))
	expiringPayload, _ := base64.RawURLEncoding.DecodeString(strings.Split(expiringTarget, ".")[1])
	expiring, expiringCID, _ := dfos.BuildSignRequest(declineFixture.requester.did, declineFixture.subject.did, "did:dfos:credit-claim", expiringPayload, expires, declineFixture.requester.auth.keyID, ed25519.PrivateKey(declineFixture.requester.auth.priv), dfos.SignRequestOptions{CreatedAt: time.Now().Add(-5 * time.Second)})
	if got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests", map[string]string{"request": expiring, "credential": declineFixture.credential}, ""); got.Code != http.StatusCreated {
		t.Fatalf("expiring deposit: %d %s", got.Code, got.Body.String())
	}
	time.Sleep(time.Until(expires) + 25*time.Millisecond)
	poll := signingRequest(t, r, http.MethodGet, signingBasePath+"/requests", nil, auth)
	if !bytes.Contains(poll.Body.Bytes(), []byte(`"requests":[]`)) {
		t.Fatalf("expired poll: %s", poll.Body.String())
	}
	if got := signingRequest(t, r, http.MethodGet, signingBasePath+"/requests/"+expiringCID+"/response", nil, ""); got.Code != http.StatusNotFound {
		t.Fatalf("expired requester poll: %d", got.Code)
	}
	if got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests/"+expiringCID+"/response", map[string]string{"response": expiringTarget}, ""); got.Code != http.StatusNotFound {
		t.Fatalf("expired response submission: %d", got.Code)
	}
}

func TestSigningStoreCursorScopeStabilityAndPruning(t *testing.T) {
	forEachSigningStore(t, func(t *testing.T, store signingTestStore) {
		now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		subject := "did:dfos:pagination-subject"
		put := func(cid string, depositedAt time.Time, expiresAt time.Time) {
			t.Helper()
			result, err := store.PutSignRequest(StoredSignRequest{
				CID: cid, Request: "request-" + cid, RequesterDID: "did:dfos:pagination-requester",
				SubjectDID: subject, PayloadTyp: "test", PayloadBytes: []byte{1},
				ExpiresAt: expiresAt.Format(signingTimeFormat), DepositedAt: depositedAt.Format(signingTimeFormat),
			}, now)
			if err != nil || result != SigningCreated {
				t.Fatalf("put %s: %s %v", cid, result, err)
			}
		}
		put("a", now, now.Add(time.Second))
		put("b", now.Add(time.Second), now.Add(time.Minute))
		put("c", now.Add(2*time.Second), now.Add(time.Minute))

		first, cursorA, err := store.ListPendingSignRequests(subject, "", 1, now)
		if err != nil || len(first) != 1 || first[0].CID != "a" || cursorA == "" {
			t.Fatalf("first page: %+v %q %v", first, cursorA, err)
		}
		wantCursorA := base64.RawURLEncoding.EncodeToString([]byte(subject + "|" + now.Format(signingTimeFormat) + "|a"))
		if cursorA != wantCursorA {
			t.Fatalf("first cursor = %q, want %q", cursorA, wantCursorA)
		}
		later := now.Add(2 * time.Second)
		second, cursorB, err := store.ListPendingSignRequests(subject, cursorA, 1, later)
		if err != nil || len(second) != 1 || second[0].CID != "b" || cursorB == "" {
			t.Fatalf("page after expired cursor: %+v %q %v", second, cursorB, err)
		}
		partial, partialNext, err := store.ListPendingSignRequests(subject, cursorB, 2, later)
		if err != nil || len(partial) != 1 || partial[0].CID != "c" || partialNext != "" {
			t.Fatalf("partial page: %+v %q %v", partial, partialNext, err)
		}
		if result, err := store.PutSignResponse("b", "response-b", later); err != nil || result != SigningCreated {
			t.Fatalf("respond b: %s %v", result, err)
		}
		third, _, err := store.ListPendingSignRequests(subject, cursorB, 1, later)
		if err != nil || len(third) != 1 || third[0].CID != "c" {
			t.Fatalf("page after responded cursor: %+v %v", third, err)
		}
		foreign, foreignCursor, err := store.ListPendingSignRequests("did:dfos:foreign-subject", cursorA, 1, later)
		if !errors.Is(err, ErrInvalidSigningCursor) || foreign != nil || foreignCursor != "" {
			t.Fatalf("foreign cursor accepted: %+v %q %v", foreign, foreignCursor, err)
		}
		if malformed, malformedNext, err := store.ListPendingSignRequests(subject, "a", 1, later); err == nil || malformed != nil || malformedNext != "" {
			t.Fatalf("malformed cursor: %+v %q %v", malformed, malformedNext, err)
		}
		assertSigningRequestPruned(t, store, "a")
	})
}

func TestSigningMailboxCapAndIdempotentRedeposit(t *testing.T) {
	forEachSigningStore(t, func(t *testing.T, store signingTestStore) {
		now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		subject := "did:dfos:capacity-subject"
		var first StoredSignRequest
		for i := 0; i < MaxPendingSignRequestsPerMailbox; i++ {
			request := StoredSignRequest{
				CID: fmt.Sprintf("request-%04d", i), Request: fmt.Sprintf("token-%04d", i),
				RequesterDID: "did:dfos:capacity-requester", SubjectDID: subject,
				PayloadTyp: "test", PayloadBytes: []byte{1}, ExpiresAt: now.Add(time.Hour).Format(signingTimeFormat),
				DepositedAt: now.Add(time.Duration(i) * time.Millisecond).Format(signingTimeFormat),
			}
			if i == 0 {
				first = request
			}
			if result, err := store.PutSignRequest(request, now); err != nil || result != SigningCreated {
				t.Fatalf("put %d: result=%s err=%v", i, result, err)
			}
		}
		if result, err := store.PutSignRequest(first, now); err != nil || result != SigningIdentical {
			t.Fatalf("idempotent re-deposit at cap: result=%s err=%v", result, err)
		}
		over := first
		over.CID = "over-cap"
		over.Request = "over-cap-token"
		if result, err := store.PutSignRequest(over, now); err != nil || result != SigningAtCapacity {
			t.Fatalf("deposit above cap: result=%s err=%v", result, err)
		}
	})
}

func TestSigningDepositReturns429AtMailboxCap(t *testing.T) {
	store := NewMemoryStore()
	enabled := true
	r, err := NewRelay(RelayOptions{Store: store, Signing: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	f := newSigningFixture(t, store, "capacity-route")
	now := time.Now().UTC()
	for i := 0; i < MaxPendingSignRequestsPerMailbox; i++ {
		result, err := store.PutSignRequest(StoredSignRequest{
			CID: fmt.Sprintf("route-cap-%04d", i), Request: fmt.Sprintf("route-token-%04d", i),
			RequesterDID: f.requester.did, SubjectDID: f.subject.did, PayloadTyp: "test",
			PayloadBytes: []byte{1}, ExpiresAt: now.Add(time.Hour).Format(signingTimeFormat),
			DepositedAt: now.Add(time.Duration(i) * time.Millisecond).Format(signingTimeFormat),
		}, now)
		if err != nil || result != SigningCreated {
			t.Fatalf("fill mailbox %d: result=%s err=%v", i, result, err)
		}
	}
	got := signingRequest(t, r, http.MethodPost, signingBasePath+"/requests", map[string]string{
		"request": f.request, "credential": f.credential,
	}, "")
	if got.Code != http.StatusTooManyRequests || !bytes.Contains(got.Body.Bytes(), []byte(`"error"`)) {
		t.Fatalf("deposit at cap: %d %s", got.Code, got.Body.String())
	}
}

func TestSigningPollRejectsCrossSubjectCursor(t *testing.T) {
	forEachSigningStore(t, func(t *testing.T, store signingTestStore) {
		enabled := true
		r, err := NewRelay(RelayOptions{Store: store, Signing: &enabled})
		if err != nil {
			t.Fatal(err)
		}
		subjectA := createTestIdentity(t)
		subjectB := createTestIdentity(t)
		IngestOperations([]string{subjectA.token, subjectB.token}, store)
		now := time.Now().UTC()
		for i := 0; i < 2; i++ {
			_, err := store.PutSignRequest(StoredSignRequest{
				CID: fmt.Sprintf("cross-%d", i), Request: fmt.Sprintf("token-%d", i),
				RequesterDID: subjectB.did, SubjectDID: subjectA.did, PayloadTyp: "test",
				PayloadBytes: []byte{1}, ExpiresAt: now.Add(time.Hour).Format(signingTimeFormat),
				DepositedAt: now.Add(time.Duration(i) * time.Millisecond).Format(signingTimeFormat),
			}, now)
			if err != nil {
				t.Fatal(err)
			}
		}
		_, cursor, err := store.ListPendingSignRequests(subjectA.did, "", 1, now)
		if err != nil || cursor == "" {
			t.Fatalf("mint cursor: %q %v", cursor, err)
		}
		got := signingRequest(t, r, http.MethodGet, signingBasePath+"/requests?after="+url.QueryEscape(cursor), nil, signingAuthToken(t, r, subjectB))
		if got.Code != http.StatusBadRequest || !bytes.Contains(got.Body.Bytes(), []byte(`"error":"invalid cursor"`)) {
			t.Fatalf("cross-subject cursor: %d %s", got.Code, got.Body.String())
		}
	})
}

func TestNewRelayPrunesExpiredSigningRowsWhenCapabilityDisabled(t *testing.T) {
	forEachSigningStore(t, func(t *testing.T, store signingTestStore) {
		now := time.Now().UTC()
		_, err := store.PutSignRequest(StoredSignRequest{
			CID: "startup-expired", Request: "expired-token", RequesterDID: "did:dfos:requester",
			SubjectDID: "did:dfos:subject", PayloadTyp: "test", PayloadBytes: []byte{1},
			ExpiresAt: now.Add(-time.Second).Format(signingTimeFormat), DepositedAt: now.Add(-time.Minute).Format(signingTimeFormat),
		}, now.Add(-time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewRelay(RelayOptions{Store: store}); err != nil {
			t.Fatal(err)
		}
		assertSigningRequestPruned(t, store, "startup-expired")
	})
}

func assertSigningRequestPruned(t *testing.T, store Store, cid string) {
	t.Helper()
	switch typed := store.(type) {
	case *MemoryStore:
		typed.mu.RLock()
		defer typed.mu.RUnlock()
		if _, ok := typed.signRequests[cid]; ok {
			t.Fatalf("expired request %s retained in memory", cid)
		}
	case *SQLiteStore:
		var count int
		if err := typed.readerDB().QueryRow("SELECT COUNT(*) FROM signing_requests WHERE cid = ?", cid).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("expired request %s retained in sqlite", cid)
		}
	default:
		t.Fatalf("uncovered signing store type %T", store)
	}
}
