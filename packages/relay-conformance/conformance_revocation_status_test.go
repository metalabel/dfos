// Revocation-status conformance (/revocations/v1 — frozen v1, own clock).
//
// A relay MAY expose a read-only projection of its revocation set. When it
// does, it advertises `capabilities.revocations: true` in the well-known and
// serves:
//
//	GET /revocations/v1/credential/{credentialCID} → { credentialCID, revoked, revocation? }
//	GET /revocations/v1/issuer/{did}               → { did, revocations: [...], next }
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
	return revokeCredentialForResource(t, base, id, "chain:someContentId")
}

func revokeCredentialForResource(t *testing.T, base string, id identity, resource string) (credentialCID, revToken string) {
	t.Helper()
	issuerKid := id.did + "#" + id.auth.keyID
	cred, err := dfos.CreateCredential(
		id.did, "did:dfos:somereader00000000000000000000", issuerKid, resource, "read",
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

func TestRevocationStatusIssuerPagination(t *testing.T) {
	base := relayURL(t)
	requireRevocationsCapability(t, base)
	id := createIdentity(t, base)

	credentialCIDs := make(map[string]bool)
	for _, resource := range []string{"chain:pageA", "chain:pageB", "chain:pageC"} {
		credentialCID, _ := revokeCredentialForResource(t, base, id, resource)
		credentialCIDs[credentialCID] = true
	}

	type revocationEntry struct {
		CredentialCID string `json:"credentialCID"`
		Revocation    string `json:"revocation"`
	}
	var firstPage struct {
		DID         string            `json:"did"`
		Revocations []revocationEntry `json:"revocations"`
		Next        *string           `json:"next"`
	}
	resp := getJSON(t, base+"/revocations/v1/issuer/"+id.did+"?limit=2", &firstPage)
	if resp.StatusCode != 200 {
		t.Fatalf("issuer pagination page 1: status %d", resp.StatusCode)
	}
	if firstPage.DID != id.did {
		t.Fatalf("page 1 did = %s, want %s", firstPage.DID, id.did)
	}
	if len(firstPage.Revocations) != 2 {
		t.Fatalf("page 1 revocations = %+v, want 2 entries", firstPage.Revocations)
	}
	if firstPage.Next == nil || *firstPage.Next != firstPage.Revocations[1].CredentialCID {
		t.Fatalf("page 1 next = %v, want second entry credentialCID", firstPage.Next)
	}

	var secondPage struct {
		DID         string            `json:"did"`
		Revocations []revocationEntry `json:"revocations"`
		Next        *string           `json:"next"`
	}
	resp = getJSON(t, base+"/revocations/v1/issuer/"+id.did+"?after="+*firstPage.Next+"&limit=2", &secondPage)
	if resp.StatusCode != 200 {
		t.Fatalf("issuer pagination page 2: status %d", resp.StatusCode)
	}
	if len(secondPage.Revocations) != 1 {
		t.Fatalf("page 2 revocations = %+v, want 1 entry", secondPage.Revocations)
	}
	if secondPage.Next != nil {
		t.Fatalf("page 2 next = %v, want nil", *secondPage.Next)
	}

	paged := append(append([]revocationEntry{}, firstPage.Revocations...), secondPage.Revocations...)
	seen := make(map[string]bool)
	for _, entry := range paged {
		seen[entry.CredentialCID] = true
	}
	if len(seen) != 3 {
		t.Fatalf("paged credential CIDs = %v, want 3 unique entries", seen)
	}
	for credentialCID := range credentialCIDs {
		if !seen[credentialCID] {
			t.Fatalf("paged credential CIDs missing %s; got %v", credentialCID, seen)
		}
	}

	createdAt := func(entry revocationEntry) string {
		t.Helper()
		_, payload, err := dfos.DecodeJWSUnsafe(entry.Revocation)
		if err != nil {
			t.Fatalf("decode revocation %s: %v", entry.CredentialCID, err)
		}
		value, _ := payload["createdAt"].(string)
		return value
	}
	for i := 1; i < len(paged); i++ {
		prev := paged[i-1]
		current := paged[i]
		prevCreatedAt := createdAt(prev)
		currentCreatedAt := createdAt(current)
		if prevCreatedAt > currentCreatedAt || (prevCreatedAt == currentCreatedAt && prev.CredentialCID > current.CredentialCID) {
			t.Fatalf("revocations not sorted by createdAt, credentialCID: prev=%+v current=%+v", prev, current)
		}
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
