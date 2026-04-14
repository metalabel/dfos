// Credential and revocation conformance tests.
//
// These cover:
//   - revocation ingestion
//   - revocation blocking credential use
//   - public credential ingestion
//   - standing authorization via public credential
//   - documents endpoint
package conformance

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// createRevocation creates a revocation JWS for a credential CID.
// Follows the same pattern as the TS signRevocation function:
//
//	payload: {version: 1, type: "revocation", did: issuerDID, credentialCID, createdAt}
//	header:  {alg: "EdDSA", typ: "did:dfos:revocation", kid, cid}
func createRevocation(t *testing.T, issuerDID, credentialCID string, kp keypair) (jwsToken string, revocationCID string) {
	t.Helper()

	kid := issuerDID + "#" + kp.keyID
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)

	payload := map[string]any{
		"version":       int64(1),
		"type":          "revocation",
		"did":           issuerDID,
		"credentialCID": credentialCID,
		"createdAt":     now,
	}

	_, _, cid, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID for revocation: %v", err)
	}

	header := dfos.JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:revocation",
		Kid: kid,
		CID: cid,
	}

	token, err := dfos.CreateJWS(header, payload, kp.priv)
	if err != nil {
		t.Fatalf("CreateJWS for revocation: %v", err)
	}

	return token, cid
}

// createPublicCredential creates a public credential (aud: "*") for a content chain.
func createPublicCredential(t *testing.T, issuerDID, kid string, action string, contentID string, ttl time.Duration, privateKey ed25519.PrivateKey) string {
	t.Helper()

	now := time.Now().Unix()
	exp := now + int64(ttl.Seconds())

	att := []map[string]string{
		{
			"resource": "chain:" + contentID,
			"action":   action,
		},
	}

	payload := map[string]any{
		"version": int64(1),
		"type":    "DFOSCredential",
		"iss":     issuerDID,
		"aud":     "*",
		"att":     att,
		"prf":     []string{},
		"exp":     exp,
		"iat":     now,
	}

	_, _, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID for public credential: %v", err)
	}

	header := dfos.JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:credential",
		Kid: kid,
		CID: cidStr,
	}

	token, err := dfos.CreateJWS(header, payload, privateKey)
	if err != nil {
		t.Fatalf("CreateJWS for public credential: %v", err)
	}

	return token
}

// ===================================================================
// revocation ingestion
// ===================================================================

func TestRevocationIngestion(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// issue a read credential
	issuerKid := id.did + "#" + id.auth.keyID
	cred, err := dfos.CreateCredential(
		id.did, "did:dfos:somereader0000000000000", issuerKid, "DFOSContentRead",
		5*time.Minute, cc.contentID, id.auth.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	// decode credential to get its CID
	credHeader, _, err := dfos.DecodeJWSUnsafe(cred)
	if err != nil {
		t.Fatal(err)
	}
	credCID := credHeader.CID

	// create and submit revocation
	revToken, _ := createRevocation(t, id.did, credCID, id.auth)
	res := postOperations(t, base, []string{revToken})
	body := readBody(t, res)

	if res.StatusCode != 200 {
		t.Fatalf("revocation ingestion: status %d, body: %s", res.StatusCode, body)
	}

	var batchResp struct {
		Results []struct {
			Status string `json:"status"`
			Kind   string `json:"kind"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &batchResp)

	if len(batchResp.Results) == 0 {
		t.Fatal("expected at least one result")
	}
	if batchResp.Results[0].Status != "new" {
		t.Fatalf("revocation should be accepted: status=%s error=%s",
			batchResp.Results[0].Status, batchResp.Results[0].Error)
	}
	if batchResp.Results[0].Kind != "revocation" {
		t.Fatalf("expected kind=revocation, got %s", batchResp.Results[0].Kind)
	}
}

// ===================================================================
// revocation blocking credential use
// ===================================================================

func TestRevocationBlocksCredentialUse(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// upload blob as creator
	tok := authToken(t, base, id)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	// create reader and issue read credential
	reader := createIdentity(t, base)
	issuerKid := id.did + "#" + id.auth.keyID
	cred, err := dfos.CreateCredential(
		id.did, reader.did, issuerKid, "DFOSContentRead",
		5*time.Minute, cc.contentID, id.auth.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	// verify blob access works with credential
	readerTok := authToken(t, base, reader)
	dlRes := getBlobWithCred(t, base, cc.contentID, readerTok, cred)
	if dlRes.StatusCode != 200 {
		body := readBody(t, dlRes)
		t.Fatalf("expected blob access with credential to succeed: status %d, body: %s", dlRes.StatusCode, body)
	}
	dlRes.Body.Close()

	// decode credential to get its CID, then revoke it
	credHeader, _, err := dfos.DecodeJWSUnsafe(cred)
	if err != nil {
		t.Fatal(err)
	}
	credCID := credHeader.CID

	revToken, _ := createRevocation(t, id.did, credCID, id.auth)
	res := postOperations(t, base, []string{revToken})
	body := readBody(t, res)
	if res.StatusCode != 200 {
		t.Fatalf("revocation submit: status %d, body: %s", res.StatusCode, body)
	}

	// verify blob access is now denied
	dlRes2 := getBlobWithCred(t, base, cc.contentID, readerTok, cred)
	if dlRes2.StatusCode == 200 {
		t.Fatal("expected rejection after credential revocation")
	}
	dlRes2.Body.Close()
}

// ===================================================================
// public credential ingestion
// ===================================================================

func TestPublicCredentialIngestion(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	kid := id.did + "#" + id.auth.keyID
	credToken := createPublicCredential(t, id.did, kid, "read", cc.contentID, 5*time.Minute, id.auth.priv)

	res := postOperations(t, base, []string{credToken})
	body := readBody(t, res)

	if res.StatusCode != 200 {
		t.Fatalf("public credential ingestion: status %d, body: %s", res.StatusCode, body)
	}

	var batchResp struct {
		Results []struct {
			Status string `json:"status"`
			Kind   string `json:"kind"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &batchResp)

	if len(batchResp.Results) == 0 {
		t.Fatal("expected at least one result")
	}
	if batchResp.Results[0].Status != "new" {
		t.Fatalf("public credential should be accepted: status=%s error=%s",
			batchResp.Results[0].Status, batchResp.Results[0].Error)
	}
	if batchResp.Results[0].Kind != "credential" {
		t.Fatalf("expected kind=credential, got %s", batchResp.Results[0].Kind)
	}
}

// ===================================================================
// standing authorization via public credential
// ===================================================================

func TestStandingAuthorizationViaPublicCredential(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// upload blob as creator
	tok := authToken(t, base, id)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	// issue and submit public read credential (aud: "*")
	kid := id.did + "#" + id.auth.keyID
	credToken := createPublicCredential(t, id.did, kid, "read", cc.contentID, 5*time.Minute, id.auth.priv)
	res := postOperations(t, base, []string{credToken})
	body := readBody(t, res)
	if res.StatusCode != 200 {
		t.Fatalf("submit public credential: status %d, body: %s", res.StatusCode, body)
	}

	// create a second identity (reader) — no per-request credential issued
	reader := createIdentity(t, base)
	readerTok := authToken(t, base, reader)

	// reader should be able to access blob via standing authorization (no x-credential header)
	dlRes := getBlob(t, base, cc.contentID, readerTok)
	if dlRes.StatusCode != 200 {
		dlBody := readBody(t, dlRes)
		t.Fatalf("expected standing auth to grant read access: status %d, body: %s", dlRes.StatusCode, dlBody)
	}
	dlBody := readBody(t, dlRes)
	if string(dlBody) != string(blobData) {
		t.Fatal("downloaded blob does not match uploaded data via standing auth")
	}
}

// ===================================================================
// documents endpoint
// ===================================================================

func TestDocumentsEndpoint(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	// create content chain with first document
	doc1 := map[string]any{"type": "post", "title": "first document", "body": "v1"}
	docCID1, _, err := dfos.DocumentCID(doc1)
	if err != nil {
		t.Fatal(err)
	}
	kid := id.did + "#" + id.auth.keyID
	createToken, contentID, genCID, err := dfos.SignContentCreate(id.did, docCID1, kid, "", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	postOperations(t, base, []string{createToken}).Body.Close()

	// upload blob for first document
	tok := authToken(t, base, id)
	blobData1, _ := json.Marshal(doc1)
	putBlob(t, base, contentID, genCID, tok, blobData1).Body.Close()

	// update with second document
	doc2 := map[string]any{"type": "post", "title": "second document", "body": "v2"}
	docCID2, _, _ := dfos.DocumentCID(doc2)
	updateToken, updateCID, err := dfos.SignContentUpdate(id.did, genCID, docCID2, kid, "", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	postOperations(t, base, []string{updateToken}).Body.Close()

	// upload blob for second document
	blobData2, _ := json.Marshal(doc2)
	putBlob(t, base, contentID, updateCID, tok, blobData2).Body.Close()

	// GET /content/<contentId>/documents
	url := fmt.Sprintf("%s/content/%s/documents", base, contentID)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)

	if resp.StatusCode != 200 {
		t.Fatalf("GET documents: status %d, body: %s", resp.StatusCode, body)
	}

	var docsResp struct {
		ContentId string `json:"contentId"`
		Documents []struct {
			OperationCID string `json:"operationCID"`
			DocumentCID  string `json:"documentCID"`
			SignerDID    string `json:"signerDID"`
			CreatedAt    string `json:"createdAt"`
		} `json:"documents"`
	}
	if err := json.Unmarshal(body, &docsResp); err != nil {
		t.Fatalf("decode documents response: %v", err)
	}

	if docsResp.ContentId != contentID {
		t.Fatalf("contentId: got %s, want %s", docsResp.ContentId, contentID)
	}
	if len(docsResp.Documents) != 2 {
		t.Fatalf("expected 2 documents, got %d", len(docsResp.Documents))
	}

	// first document should be the create operation
	if docsResp.Documents[0].OperationCID != genCID {
		t.Fatalf("doc[0] operationCID: got %s, want %s", docsResp.Documents[0].OperationCID, genCID)
	}
	if docsResp.Documents[0].DocumentCID != docCID1 {
		t.Fatalf("doc[0] documentCID: got %s, want %s", docsResp.Documents[0].DocumentCID, docCID1)
	}
	if docsResp.Documents[0].SignerDID != id.did {
		t.Fatalf("doc[0] signerDID: got %s, want %s", docsResp.Documents[0].SignerDID, id.did)
	}

	// second document should be the update operation
	if docsResp.Documents[1].OperationCID != updateCID {
		t.Fatalf("doc[1] operationCID: got %s, want %s", docsResp.Documents[1].OperationCID, updateCID)
	}
	if docsResp.Documents[1].DocumentCID != docCID2 {
		t.Fatalf("doc[1] documentCID: got %s, want %s", docsResp.Documents[1].DocumentCID, docCID2)
	}
}
