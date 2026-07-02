// Revocation-status conformance (/revocations/v1 — additive, own 0.x clock).
//
// A relay MAY expose a read-only projection of its revocation set. When it
// does, it advertises `capabilities.revocations: true` in the well-known and
// serves:
//
//	GET /revocations/v1/credential/{credentialCID} → { credentialCID, revoked, revocation? }
//	GET /revocations/v1/issuer/{did}               → { did, revocations: [...] }
//
// The revocation JWS itself rides every positive answer, so these tests
// re-verify the proof (decode → typ, credentialCID, issuer did) rather than
// trusting the relay's boolean. `revoked: false` is an honest known-nothing
// answer — absence is NOT proof of non-revocation.
//
// Tests self-skip against a relay that does not advertise the capability
// (consistent with the suite's optional-capability handling); the reference
// relays always do.
package conformance

import (
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// requireRevocationsCapability fetches the well-known and skips the test unless
// capabilities.revocations is true.
func requireRevocationsCapability(t *testing.T, base string) {
	t.Helper()
	var wellKnown struct {
		Capabilities map[string]any `json:"capabilities"`
	}
	resp := getJSON(t, base+"/.well-known/dfos-relay", &wellKnown)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /.well-known/dfos-relay: status %d", resp.StatusCode)
	}
	if wellKnown.Capabilities["revocations"] != true {
		t.Skip("relay does not advertise capabilities.revocations — skipping revocation-status conformance")
	}
}

// revokeCredential issues a credential from the identity, revokes it, and
// ingests both. Returns the credential CID and the revocation JWS.
func revokeCredential(t *testing.T, base string, id identity) (credentialCID, revToken string) {
	t.Helper()

	issuerKid := id.did + "#" + id.auth.keyID
	cred, err := dfos.CreateCredential(
		id.did, "did:dfos:somereader00000000000000000000", issuerKid, "chain:someContentId", "read",
		5*time.Minute, id.auth.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	credHeader, _, err := dfos.DecodeJWSUnsafe(cred)
	if err != nil {
		t.Fatal(err)
	}
	credentialCID = credHeader.CID

	revToken, _ = createRevocation(t, id.did, credentialCID, id.auth)
	res := postOperations(t, base, []string{cred, revToken})
	body := readBody(t, res)
	if res.StatusCode != 200 {
		t.Fatalf("credential+revocation ingest: status %d, body: %s", res.StatusCode, body)
	}
	return credentialCID, revToken
}

func TestRevocationStatusRevokedCredential(t *testing.T) {
	base := relayURL(t)
	requireRevocationsCapability(t, base)
	id := createIdentity(t, base)
	credentialCID, _ := revokeCredential(t, base, id)

	var body struct {
		CredentialCID string `json:"credentialCID"`
		Revoked       bool   `json:"revoked"`
		Revocation    string `json:"revocation"`
	}
	resp := getJSON(t, base+"/revocations/v1/credential/"+credentialCID, &body)
	if resp.StatusCode != 200 {
		t.Fatalf("credential status: status %d", resp.StatusCode)
	}
	if body.CredentialCID != credentialCID || !body.Revoked {
		t.Fatalf("body = %+v, want revoked:true for %s", body, credentialCID)
	}

	// zero-trust: the returned JWS must itself prove the revocation — decode
	// and check typ, the revoked CID, and that the kid DID matches payload did
	header, payload, err := dfos.DecodeJWSUnsafe(body.Revocation)
	if err != nil {
		t.Fatalf("revocation JWS decode: %v", err)
	}
	if header.Typ != "did:dfos:revocation" {
		t.Fatalf("revocation typ = %s", header.Typ)
	}
	if payload["credentialCID"] != credentialCID {
		t.Fatalf("revocation payload credentialCID = %v, want %s", payload["credentialCID"], credentialCID)
	}
	if payload["did"] != id.did {
		t.Fatalf("revocation payload did = %v, want %s", payload["did"], id.did)
	}
	if kidDID, _, _ := strings.Cut(header.Kid, "#"); kidDID != id.did {
		t.Fatalf("revocation kid DID = %s, want %s", kidDID, id.did)
	}
}

func TestRevocationStatusUnknownCredential(t *testing.T) {
	base := relayURL(t)
	requireRevocationsCapability(t, base)

	// well-formed dag-cbor CID no relay has seen — honest known-nothing answer
	unknownCID := "bafyrei" + strings.Repeat("a", 52)
	var body struct {
		CredentialCID string `json:"credentialCID"`
		Revoked       bool   `json:"revoked"`
	}
	resp := getJSON(t, base+"/revocations/v1/credential/"+unknownCID, &body)
	if resp.StatusCode != 200 {
		t.Fatalf("unknown credential status: status %d", resp.StatusCode)
	}
	if body.CredentialCID != unknownCID || body.Revoked {
		t.Fatalf("body = %+v, want revoked:false for %s", body, unknownCID)
	}
}

func TestRevocationStatusMalformedCID(t *testing.T) {
	base := relayURL(t)
	requireRevocationsCapability(t, base)

	var body struct {
		Error string `json:"error"`
	}
	resp := getJSON(t, base+"/revocations/v1/credential/not-a-cid", &body)
	if resp.StatusCode != 400 {
		t.Fatalf("malformed CID: status %d, want 400", resp.StatusCode)
	}
}

func TestRevocationStatusIssuerListing(t *testing.T) {
	base := relayURL(t)
	requireRevocationsCapability(t, base)
	id := createIdentity(t, base)
	credentialCID, revToken := revokeCredential(t, base, id)

	var body struct {
		DID         string `json:"did"`
		Revocations []struct {
			CredentialCID string `json:"credentialCID"`
			Revocation    string `json:"revocation"`
		} `json:"revocations"`
	}
	resp := getJSON(t, base+"/revocations/v1/issuer/"+id.did, &body)
	if resp.StatusCode != 200 {
		t.Fatalf("issuer listing: status %d", resp.StatusCode)
	}
	if body.DID != id.did {
		t.Fatalf("did = %s, want %s", body.DID, id.did)
	}
	if len(body.Revocations) != 1 {
		t.Fatalf("revocations = %+v, want exactly 1 entry", body.Revocations)
	}
	if body.Revocations[0].CredentialCID != credentialCID || body.Revocations[0].Revocation != revToken {
		t.Fatalf("entry = %+v", body.Revocations[0])
	}
}

func TestRevocationStatusIssuerWithNoRevocations(t *testing.T) {
	base := relayURL(t)
	requireRevocationsCapability(t, base)
	id := createIdentity(t, base) // never revoked anything

	var body struct {
		DID         string `json:"did"`
		Revocations []any  `json:"revocations"`
	}
	resp := getJSON(t, base+"/revocations/v1/issuer/"+id.did, &body)
	if resp.StatusCode != 200 {
		t.Fatalf("empty issuer listing: status %d", resp.StatusCode)
	}
	if body.Revocations == nil || len(body.Revocations) != 0 {
		t.Fatalf("revocations = %v, want []", body.Revocations)
	}
}

func TestRevocationStatusMalformedDID(t *testing.T) {
	base := relayURL(t)
	requireRevocationsCapability(t, base)

	var body struct {
		Error string `json:"error"`
	}
	resp := getJSON(t, base+"/revocations/v1/issuer/did:dfos:tooshort", &body)
	if resp.StatusCode != 400 {
		t.Fatalf("malformed DID: status %d, want 400", resp.StatusCode)
	}
}
