package conformance

import (
	"encoding/json"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// Identity timestamp ordering and strict linearity. createdAt MUST be strictly
// greater than the one parent, and the head is the last committed linear op.
//
// Exercising these requires controlling createdAt, which the wall-clock public
// signers do not expose. We therefore build the identity-update operation
// directly from the exported primitives (DagCborCID + CreateJWS), mirroring the
// library's SignIdentityUpdateWithServices construction exactly. A POSITIVE
// CONTROL (a properly-ordered update built the same way is accepted) proves the
// construction is byte-valid, so a rejection is provably the ordering rule and
// not a malformed-op artifact.

const tsLayout = "2006-01-02T15:04:05.000Z"

// signIdentityUpdateAt builds + signs an identity-update operation with an
// explicit createdAt, mirroring SignIdentityUpdateWithServices (same payload
// shape, header typ, dag-cbor CID). Signed by the identity's controller key.
func signIdentityUpdateAt(t *testing.T, id identity, prevCID, createdAt string, services []dfos.ServiceEntry) (token, opCID string) {
	t.Helper()
	payload := map[string]any{
		"version":              1,
		"type":                 "update",
		"previousOperationCID": prevCID,
		"authKeys":             []dfos.MultikeyPublicKey{id.auth.mk},
		"assertKeys":           []dfos.MultikeyPublicKey{},
		"controllerKeys":       []dfos.MultikeyPublicKey{id.controller.mk},
		"createdAt":            createdAt,
	}
	if len(services) > 0 {
		payload["services"] = services
	}
	_, _, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}
	header := dfos.JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:identity-op",
		Kid: id.did + "#" + id.controller.keyID,
		CID: cidStr,
	}
	token, err = dfos.CreateJWS(header, payload, id.controller.priv)
	if err != nil {
		t.Fatalf("CreateJWS: %v", err)
	}
	return token, cidStr
}

// postStatus submits one operation and returns its ingestion result status.
func postStatus(t *testing.T, base, token string) (status, errMsg string) {
	t.Helper()
	res := postOperations(t, base, []string{token})
	var body struct {
		Results []struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	b := readBody(t, res)
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatalf("decode /operations response: %v (body: %s)", err, b)
	}
	if len(body.Results) != 1 {
		t.Fatalf("expected 1 result, got %d (body: %s)", len(body.Results), b)
	}
	return body.Results[0].Status, body.Results[0].Error
}

func TestIdentityRejectsNonIncreasingTimestamp(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	t1 := time.Now().UTC().Add(2 * time.Second)
	t1s := t1.Format(tsLayout)

	// positive control: a properly-ordered update (createdAt > genesis) built the
	// same way is accepted — proves the manual construction is valid.
	tok1, cid1 := signIdentityUpdateAt(t, id, id.genCID, t1s, nil)
	if st, e := postStatus(t, base, tok1); st != "new" {
		t.Fatalf("positive control: properly-ordered update should be accepted, got %q (%s)", st, e)
	}

	// equal createdAt to the parent → not strictly greater → rejected.
	tokEq, _ := signIdentityUpdateAt(t, id, cid1, t1s, nil)
	if st, _ := postStatus(t, base, tokEq); st != "rejected" {
		t.Fatalf("equal-createdAt update should be rejected, got %q", st)
	}

	// earlier than the parent → rejected.
	tokBack, _ := signIdentityUpdateAt(t, id, cid1, t1.Add(-time.Millisecond).Format(tsLayout), nil)
	if st, _ := postStatus(t, base, tokBack); st != "rejected" {
		t.Fatalf("backdated update should be rejected, got %q", st)
	}
}

func TestIdentityTimestampOrderingIsLinear(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	parentAt := time.Now().UTC().Add(5 * time.Second).Format(tsLayout)
	parent, parentCID := signIdentityUpdateAt(t, id, id.genCID, parentAt, nil)
	if st, e := postStatus(t, base, parent); st != "new" {
		t.Fatalf("parent update should be accepted, got %q (%s)", st, e)
	}
	child, _ := signIdentityUpdateAt(t, id, parentCID, parentAt, nil)
	if st, _ := postStatus(t, base, child); st != "rejected" {
		t.Fatalf("identity child with createdAt <= parent should be rejected, got %q", st)
	}
}

func TestIdentityHeadIsLastLinearOperation(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	tokA, cidA := signIdentityUpdateAt(t, id, id.genCID, time.Now().UTC().Add(5*time.Second).Format(tsLayout),
		[]dfos.ServiceEntry{relaySvc("a", "https://a.example.com")})
	tokB, _ := signIdentityUpdateAt(t, id, id.genCID, time.Now().UTC().Add(6*time.Second).Format(tsLayout),
		[]dfos.ServiceEntry{relaySvc("b", "https://b.example.com")})
	if st, e := postStatus(t, base, tokA); st != "new" {
		t.Fatalf("linear update should be accepted, got %q (%s)", st, e)
	}
	if st, e := postStatus(t, base, tokB); st != "rejected" || e != "identity chains are linear: conflicting extension refused" {
		t.Fatalf("conflicting extension = %q (%s), want named permanent rejection", st, e)
	}

	var resp struct {
		HeadCID string `json:"headCID"`
		State   struct {
			Services []map[string]any `json:"services"`
		} `json:"state"`
	}
	if r := getJSON(t, base+"/proof/v1/identities/"+id.did, &resp); r.StatusCode != 200 {
		t.Fatalf("GET /identities/%s: status %d", id.did, r.StatusCode)
	}
	if resp.HeadCID != cidA {
		t.Fatalf("head = %q, want last committed linear CID %q", resp.HeadCID, cidA)
	}
	if findSvc(resp.State.Services, "a") == nil {
		t.Fatalf("conflicting extension changed head state: %+v", resp.State.Services)
	}
}
