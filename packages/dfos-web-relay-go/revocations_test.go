package relay

// Route coverage for the revocation-status family (/revocations/v1) —
// revocations.go. The dual-relay parity harness proves TS≡Go on the wire; these
// give a red bar independent of harness spin-up (they run under the existing
// `go test -race ./...` CI job).

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// revocationRelay boots a memory-store relay + httptest server and mints one
// identity with one revoked credential. Returns the server, identity, and the
// (credentialCID, revocation JWS) pair.
func revocationRelay(t *testing.T) (srv *httptest.Server, id testIdentity, credentialCID, revToken string) {
	t.Helper()
	r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	srv = httptest.NewServer(r.Handler())
	t.Cleanup(srv.Close)

	id = createTestIdentity(t)
	if res := r.Ingest([]string{id.token}); res[0].Status != "new" {
		t.Fatalf("identity ingest: %+v", res[0])
	}

	kid := id.did + "#" + id.auth.keyID
	cred, err := dfos.CreateCredential(id.did, "*", kid, "chain:someContentId", "read", time.Hour, id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	header, _, err := dfos.DecodeJWSUnsafe(cred)
	if err != nil {
		t.Fatal(err)
	}
	credentialCID = header.CID

	revToken, _, err = dfos.SignRevocation(id.did, credentialCID, kid, id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Ingest([]string{cred, revToken}); res[1].Status != "new" {
		t.Fatalf("revocation ingest: %+v", res[1])
	}
	return srv, id, credentialCID, revToken
}

func getJSONBody(t *testing.T, url string) (int, map[string]any, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode %s: %v (body: %s)", url, err, raw)
	}
	return resp.StatusCode, body, string(raw)
}

func TestRevocationStatus_RevokedCredential(t *testing.T) {
	srv, id, credentialCID, revToken := revocationRelay(t)

	status, body, _ := getJSONBody(t, srv.URL+"/revocations/v1/credential/"+credentialCID)
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	if body["credentialCID"] != credentialCID || body["revoked"] != true {
		t.Fatalf("body = %v", body)
	}
	if body["revocation"] != revToken {
		t.Fatalf("revocation JWS = %v, want the ingested token", body["revocation"])
	}

	// the JWS is the proof — it decodes to the revoked CID and the issuer
	header, payload, err := dfos.DecodeJWSUnsafe(revToken)
	if err != nil || header.Typ != "did:dfos:revocation" {
		t.Fatalf("revocation decode: header=%+v err=%v", header, err)
	}
	if payload["credentialCID"] != credentialCID || payload["did"] != id.did {
		t.Fatalf("revocation payload = %v", payload)
	}
}

func TestRevocationStatus_UnknownCredentialCID(t *testing.T) {
	srv, _, _, _ := revocationRelay(t)

	// well-formed dag-cbor CID the relay has never seen — honest known-nothing
	unknownCID := "bafyrei" + strings.Repeat("a", 52)
	status, body, raw := getJSONBody(t, srv.URL+"/revocations/v1/credential/"+unknownCID)
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	if body["credentialCID"] != unknownCID || body["revoked"] != false {
		t.Fatalf("body = %v", body)
	}
	// omitempty: the revocation key must be ABSENT, not null
	if strings.Contains(raw, "revocation\":") {
		t.Fatalf("revocation key must be omitted on the known-nothing answer: %s", raw)
	}
}

func TestRevocationStatus_MalformedCID(t *testing.T) {
	srv, _, _, _ := revocationRelay(t)

	status, body, _ := getJSONBody(t, srv.URL+"/revocations/v1/credential/not-a-cid")
	if status != 400 {
		t.Fatalf("status = %d, want 400", status)
	}
	if body["error"] != "invalid credential CID" {
		t.Fatalf("error = %v", body["error"])
	}
}

func TestRevocationStatus_IssuerListing(t *testing.T) {
	srv, id, credentialCID, revToken := revocationRelay(t)

	status, body, _ := getJSONBody(t, srv.URL+"/revocations/v1/issuer/"+id.did)
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	if body["did"] != id.did {
		t.Fatalf("did = %v", body["did"])
	}
	revs, ok := body["revocations"].([]any)
	if !ok || len(revs) != 1 {
		t.Fatalf("revocations = %v, want exactly 1 entry", body["revocations"])
	}
	entry, _ := revs[0].(map[string]any)
	if entry["credentialCID"] != credentialCID || entry["revocation"] != revToken {
		t.Fatalf("entry = %v", entry)
	}
}

func TestRevocationStatus_IssuerWithNoRevocations(t *testing.T) {
	srv, _, _, _ := revocationRelay(t)

	// a different, well-formed DID that has revoked nothing → empty array
	other := createTestIdentity(t)
	status, body, raw := getJSONBody(t, srv.URL+"/revocations/v1/issuer/"+other.did)
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	revs, ok := body["revocations"].([]any)
	if !ok || len(revs) != 0 {
		t.Fatalf("revocations = %v, want [] (raw: %s)", body["revocations"], raw)
	}
}

func TestRevocationStatus_MalformedDID(t *testing.T) {
	srv, _, _, _ := revocationRelay(t)

	status, body, _ := getJSONBody(t, srv.URL+"/revocations/v1/issuer/did:dfos:tooshort")
	if status != 400 {
		t.Fatalf("status = %d, want 400", status)
	}
	if body["error"] != "invalid DID" {
		t.Fatalf("error = %v", body["error"])
	}
}

func TestRevocationStatus_WellKnownCapability(t *testing.T) {
	srv, _, _, _ := revocationRelay(t)

	status, body, _ := getJSONBody(t, srv.URL+"/.well-known/dfos-relay")
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	caps, _ := body["capabilities"].(map[string]any)
	if caps["revocations"] != true {
		t.Fatalf("capabilities.revocations = %v, want true", caps["revocations"])
	}
}
