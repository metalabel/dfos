// Credential and revocation conformance tests.
//
// These cover:
//   - revocation ingestion
//   - revocation blocking credential use
//   - public credential ingestion
//   - standing authorization via public credential
//   - documents endpoint
//   - credential ingestion survives key rotation
//   - per-request credential survives key rotation
//   - chain:* wildcard standing authorization
//   - chain:* wildcard per-request credential
//   - audience mismatch rejection
//   - cascading revocation (parent revoked blocks child)
//   - delegation expiry bounds enforcement
//   - attenuation violation rejection
//   - delegation gap rejection
//   - multi-hop delegation chain (3 levels)
//   - delegation root mismatch rejection
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
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

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
		id.did, "did:dfos:somereader0000000000000", issuerKid, "chain:"+cc.contentID, "read",
		5*time.Minute, id.auth.priv,
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
		id.did, reader.did, issuerKid, "chain:"+cc.contentID, "read",
		5*time.Minute, id.auth.priv,
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
// credential ingestion survives key rotation
// ===================================================================

func TestPublicCredentialIngestionAfterKeyRotation(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// issue a public credential signed with the CURRENT auth key
	kid := id.did + "#" + id.auth.keyID
	credToken := createPublicCredential(t, id.did, kid, "read", cc.contentID, 5*time.Minute, id.auth.priv)

	// rotate the auth key BEFORE submitting the credential
	newAuth := newKeypair()
	ctrlKid := id.did + "#" + id.controller.keyID
	rotateToken, _, err := dfos.SignIdentityUpdate(
		id.genCID,
		[]dfos.MultikeyPublicKey{id.controller.mk},
		[]dfos.MultikeyPublicKey{newAuth.mk},
		[]dfos.MultikeyPublicKey{},
		ctrlKid,
		id.controller.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	postOperations(t, base, []string{rotateToken}).Body.Close()

	// submit the credential signed with the OLD (rotated-out) key
	// it should still be accepted — revocation, not key rotation, invalidates
	res := postOperations(t, base, []string{credToken})
	body := readBody(t, res)

	if res.StatusCode != 200 {
		t.Fatalf("credential ingestion after key rotation: status %d, body: %s", res.StatusCode, body)
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
		t.Fatalf("credential signed with rotated-out key should be accepted: status=%s error=%s",
			batchResp.Results[0].Status, batchResp.Results[0].Error)
	}
}

// ===================================================================
// per-request credential survives key rotation
// ===================================================================

func TestPerRequestCredentialAfterKeyRotation(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// upload blob as creator
	tok := authToken(t, base, id)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	// issue a read credential to a reader, signed with CURRENT auth key
	reader := createIdentity(t, base)
	issuerKid := id.did + "#" + id.auth.keyID
	cred, err := dfos.CreateCredential(
		id.did, reader.did, issuerKid, "chain:"+cc.contentID, "read",
		5*time.Minute, id.auth.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	// rotate the auth key AFTER issuing the credential
	newAuth := newKeypair()
	ctrlKid := id.did + "#" + id.controller.keyID
	rotateToken, _, err := dfos.SignIdentityUpdate(
		id.genCID,
		[]dfos.MultikeyPublicKey{id.controller.mk},
		[]dfos.MultikeyPublicKey{newAuth.mk},
		[]dfos.MultikeyPublicKey{},
		ctrlKid,
		id.controller.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	postOperations(t, base, []string{rotateToken}).Body.Close()

	// reader uses credential signed with the OLD key — should still work
	readerTok := authToken(t, base, reader)
	dlRes := getBlobWithCred(t, base, cc.contentID, readerTok, cred)
	if dlRes.StatusCode != 200 {
		dlBody := readBody(t, dlRes)
		t.Fatalf("credential signed with rotated-out key should grant access: status %d, body: %s", dlRes.StatusCode, dlBody)
	}
	dlRes.Body.Close()
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

// ===================================================================
// credential helpers for delegation chain tests
// ===================================================================

// createCustomCredential creates a credential JWS with full control over
// iss, aud, att, prf, and exp. Used for building multi-hop delegation chains.
func createCustomCredential(t *testing.T, iss, aud, kid string, att []map[string]string, prf []string, exp int64, privateKey ed25519.PrivateKey) string {
	t.Helper()

	now := time.Now().Unix()
	payload := map[string]any{
		"version": int64(1),
		"type":    "DFOSCredential",
		"iss":     iss,
		"aud":     aud,
		"att":     att,
		"prf":     prf,
		"exp":     exp,
		"iat":     now,
	}

	_, _, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID for custom credential: %v", err)
	}

	header := dfos.JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:credential",
		Kid: kid,
		CID: cidStr,
	}

	token, err := dfos.CreateJWS(header, payload, privateKey)
	if err != nil {
		t.Fatalf("CreateJWS for custom credential: %v", err)
	}

	return token
}

// ===================================================================
// chain:* wildcard standing authorization
// ===================================================================

func TestChainWildcardStandingAuth(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// upload blob as creator
	tok := authToken(t, base, id)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	// issue and submit public credential with chain:* (covers all content)
	kid := id.did + "#" + id.auth.keyID
	credToken := createPublicCredential(t, id.did, kid, "read", "*", 5*time.Minute, id.auth.priv)
	res := postOperations(t, base, []string{credToken})
	body := readBody(t, res)
	if res.StatusCode != 200 {
		t.Fatalf("submit chain:* public credential: status %d, body: %s", res.StatusCode, body)
	}

	// create a second content chain (different from cc)
	cc2 := createContent(t, base, id)
	blobData2, _ := json.Marshal(cc2.document)
	putBlob(t, base, cc2.contentID, cc2.genCID, tok, blobData2).Body.Close()

	// reader should be able to access both content chains via chain:* standing auth
	reader := createIdentity(t, base)
	readerTok := authToken(t, base, reader)

	dlRes1 := getBlob(t, base, cc.contentID, readerTok)
	if dlRes1.StatusCode != 200 {
		dlBody := readBody(t, dlRes1)
		t.Fatalf("chain:* should grant access to first content: status %d, body: %s", dlRes1.StatusCode, dlBody)
	}
	dlRes1.Body.Close()

	dlRes2 := getBlob(t, base, cc2.contentID, readerTok)
	if dlRes2.StatusCode != 200 {
		dlBody := readBody(t, dlRes2)
		t.Fatalf("chain:* should grant access to second content: status %d, body: %s", dlRes2.StatusCode, dlBody)
	}
	dlRes2.Body.Close()
}

// ===================================================================
// chain:* wildcard per-request credential
// ===================================================================

func TestChainWildcardPerRequestCredential(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// upload blob
	tok := authToken(t, base, id)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	// issue a chain:* read credential to a specific reader
	reader := createIdentity(t, base)
	issuerKid := id.did + "#" + id.auth.keyID
	att := []map[string]string{{"resource": "chain:*", "action": "read"}}
	exp := time.Now().Unix() + 300
	cred := createCustomCredential(t, id.did, reader.did, issuerKid, att, []string{}, exp, id.auth.priv)

	// reader uses chain:* credential to access specific content
	readerTok := authToken(t, base, reader)
	dlRes := getBlobWithCred(t, base, cc.contentID, readerTok, cred)
	if dlRes.StatusCode != 200 {
		dlBody := readBody(t, dlRes)
		t.Fatalf("chain:* credential should grant access: status %d, body: %s", dlRes.StatusCode, dlBody)
	}
	dlRes.Body.Close()
}

// ===================================================================
// audience mismatch rejection
// ===================================================================

func TestAudienceMismatchRejection(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// upload blob
	tok := authToken(t, base, id)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	// issue credential to a specific reader
	reader := createIdentity(t, base)
	interloper := createIdentity(t, base)

	issuerKid := id.did + "#" + id.auth.keyID
	cred, err := dfos.CreateCredential(
		id.did, reader.did, issuerKid, "chain:"+cc.contentID, "read",
		5*time.Minute, id.auth.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	// interloper tries to use credential meant for reader — should be rejected
	interloperTok := authToken(t, base, interloper)
	dlRes := getBlobWithCred(t, base, cc.contentID, interloperTok, cred)
	if dlRes.StatusCode == 200 {
		t.Fatal("credential with wrong audience should be rejected")
	}
	dlRes.Body.Close()
}

// ===================================================================
// cascading revocation — parent revoked blocks child use
// ===================================================================

func TestCascadingRevocationBlocksDelegatedAccess(t *testing.T) {
	base := relayURL(t)
	creator := createIdentity(t, base)
	cc := createContent(t, base, creator)

	// upload blob
	tok := authToken(t, base, creator)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	// create a delegate who will receive a delegated credential
	delegate := createIdentity(t, base)

	// creator issues root credential to delegate
	creatorKid := creator.did + "#" + creator.auth.keyID
	rootAtt := []map[string]string{{"resource": "chain:" + cc.contentID, "action": "read"}}
	rootExp := time.Now().Unix() + 300
	rootCred := createCustomCredential(t, creator.did, delegate.did, creatorKid, rootAtt, []string{}, rootExp, creator.auth.priv)

	// delegate issues sub-credential to a reader, chaining via prf
	reader := createIdentity(t, base)
	delegateKid := delegate.did + "#" + delegate.auth.keyID
	leafAtt := []map[string]string{{"resource": "chain:" + cc.contentID, "action": "read"}}
	leafExp := time.Now().Unix() + 200
	leafCred := createCustomCredential(t, delegate.did, reader.did, delegateKid, leafAtt, []string{rootCred}, leafExp, delegate.auth.priv)

	// reader should be able to access blob via delegated credential
	readerTok := authToken(t, base, reader)
	dlRes := getBlobWithCred(t, base, cc.contentID, readerTok, leafCred)
	if dlRes.StatusCode != 200 {
		dlBody := readBody(t, dlRes)
		t.Fatalf("delegated credential should grant access: status %d, body: %s", dlRes.StatusCode, dlBody)
	}
	dlRes.Body.Close()

	// revoke the root credential
	rootHeader, _, err := dfos.DecodeJWSUnsafe(rootCred)
	if err != nil {
		t.Fatal(err)
	}
	revToken, _ := createRevocation(t, creator.did, rootHeader.CID, creator.auth)
	revRes := postOperations(t, base, []string{revToken})
	revBody := readBody(t, revRes)
	if revRes.StatusCode != 200 {
		t.Fatalf("revocation submit: status %d, body: %s", revRes.StatusCode, revBody)
	}

	// reader's delegated credential should now be rejected (parent is revoked)
	dlRes2 := getBlobWithCred(t, base, cc.contentID, readerTok, leafCred)
	if dlRes2.StatusCode == 200 {
		t.Fatal("delegated credential should be rejected after parent revocation")
	}
	dlRes2.Body.Close()
}

// ===================================================================
// delegation expiry bounds — child exp exceeds parent exp
// ===================================================================

func TestDelegationExpiryBoundsRejection(t *testing.T) {
	base := relayURL(t)
	creator := createIdentity(t, base)
	cc := createContent(t, base, creator)

	// upload blob
	tok := authToken(t, base, creator)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	delegate := createIdentity(t, base)

	// creator issues root credential with SHORT expiry (60s)
	creatorKid := creator.did + "#" + creator.auth.keyID
	rootAtt := []map[string]string{{"resource": "chain:" + cc.contentID, "action": "read"}}
	rootExp := time.Now().Unix() + 60
	rootCred := createCustomCredential(t, creator.did, delegate.did, creatorKid, rootAtt, []string{}, rootExp, creator.auth.priv)

	// delegate issues sub-credential with LONGER expiry (300s) — violates monotonic constraint
	reader := createIdentity(t, base)
	delegateKid := delegate.did + "#" + delegate.auth.keyID
	leafAtt := []map[string]string{{"resource": "chain:" + cc.contentID, "action": "read"}}
	leafExp := time.Now().Unix() + 300 // exceeds parent's 60s
	leafCred := createCustomCredential(t, delegate.did, reader.did, delegateKid, leafAtt, []string{rootCred}, leafExp, delegate.auth.priv)

	// reader tries to use — should be rejected due to expiry violation
	readerTok := authToken(t, base, reader)
	dlRes := getBlobWithCred(t, base, cc.contentID, readerTok, leafCred)
	if dlRes.StatusCode == 200 {
		t.Fatal("delegated credential with exp exceeding parent should be rejected")
	}
	dlRes.Body.Close()
}

// ===================================================================
// attenuation violation — child widens scope
// ===================================================================

func TestAttenuationViolationRejection(t *testing.T) {
	base := relayURL(t)
	creator := createIdentity(t, base)
	cc := createContent(t, base, creator)

	// create a second content chain
	cc2 := createContent(t, base, creator)

	// upload blobs
	tok := authToken(t, base, creator)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()
	blobData2, _ := json.Marshal(cc2.document)
	putBlob(t, base, cc2.contentID, cc2.genCID, tok, blobData2).Body.Close()

	delegate := createIdentity(t, base)

	// creator issues root credential scoped to cc only (NOT cc2)
	creatorKid := creator.did + "#" + creator.auth.keyID
	rootAtt := []map[string]string{{"resource": "chain:" + cc.contentID, "action": "read"}}
	rootExp := time.Now().Unix() + 300
	rootCred := createCustomCredential(t, creator.did, delegate.did, creatorKid, rootAtt, []string{}, rootExp, creator.auth.priv)

	// delegate issues sub-credential claiming access to cc2 — violates attenuation
	reader := createIdentity(t, base)
	delegateKid := delegate.did + "#" + delegate.auth.keyID
	leafAtt := []map[string]string{{"resource": "chain:" + cc2.contentID, "action": "read"}}
	leafExp := time.Now().Unix() + 200
	leafCred := createCustomCredential(t, delegate.did, reader.did, delegateKid, leafAtt, []string{rootCred}, leafExp, delegate.auth.priv)

	// reader tries to access cc2 — should be rejected (scope widening)
	readerTok := authToken(t, base, reader)
	dlRes := getBlobWithCred(t, base, cc2.contentID, readerTok, leafCred)
	if dlRes.StatusCode == 200 {
		t.Fatal("delegated credential with widened scope should be rejected")
	}
	dlRes.Body.Close()
}

// ===================================================================
// delegation gap — child issuer not in parent audience
// ===================================================================

func TestDelegationGapRejection(t *testing.T) {
	base := relayURL(t)
	creator := createIdentity(t, base)
	cc := createContent(t, base, creator)

	// upload blob
	tok := authToken(t, base, creator)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	// creator issues root credential to "delegate"
	delegate := createIdentity(t, base)
	creatorKid := creator.did + "#" + creator.auth.keyID
	rootAtt := []map[string]string{{"resource": "chain:" + cc.contentID, "action": "read"}}
	rootExp := time.Now().Unix() + 300
	rootCred := createCustomCredential(t, creator.did, delegate.did, creatorKid, rootAtt, []string{}, rootExp, creator.auth.priv)

	// "outsider" (not the delegate) tries to chain from root credential
	outsider := createIdentity(t, base)
	reader := createIdentity(t, base)
	outsiderKid := outsider.did + "#" + outsider.auth.keyID
	leafAtt := []map[string]string{{"resource": "chain:" + cc.contentID, "action": "read"}}
	leafExp := time.Now().Unix() + 200
	leafCred := createCustomCredential(t, outsider.did, reader.did, outsiderKid, leafAtt, []string{rootCred}, leafExp, outsider.auth.priv)

	// reader tries to use — should fail because outsider is not root's audience
	readerTok := authToken(t, base, reader)
	dlRes := getBlobWithCred(t, base, cc.contentID, readerTok, leafCred)
	if dlRes.StatusCode == 200 {
		t.Fatal("delegated credential with delegation gap should be rejected")
	}
	dlRes.Body.Close()
}

// ===================================================================
// multi-hop delegation chain (3 levels: creator → A → B → reader)
// ===================================================================

func TestMultiHopDelegationChain(t *testing.T) {
	base := relayURL(t)
	creator := createIdentity(t, base)
	cc := createContent(t, base, creator)

	// upload blob
	tok := authToken(t, base, creator)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	// creator → delegateA
	delegateA := createIdentity(t, base)
	creatorKid := creator.did + "#" + creator.auth.keyID
	att := []map[string]string{{"resource": "chain:" + cc.contentID, "action": "read"}}
	exp := time.Now().Unix() + 300
	credA := createCustomCredential(t, creator.did, delegateA.did, creatorKid, att, []string{}, exp, creator.auth.priv)

	// delegateA → delegateB
	delegateB := createIdentity(t, base)
	delegateAKid := delegateA.did + "#" + delegateA.auth.keyID
	credB := createCustomCredential(t, delegateA.did, delegateB.did, delegateAKid, att, []string{credA}, exp-50, delegateA.auth.priv)

	// delegateB → reader (leaf)
	reader := createIdentity(t, base)
	delegateBKid := delegateB.did + "#" + delegateB.auth.keyID
	credLeaf := createCustomCredential(t, delegateB.did, reader.did, delegateBKid, att, []string{credB}, exp-100, delegateB.auth.priv)

	// reader uses the 3-hop delegated credential
	readerTok := authToken(t, base, reader)
	dlRes := getBlobWithCred(t, base, cc.contentID, readerTok, credLeaf)
	if dlRes.StatusCode != 200 {
		dlBody := readBody(t, dlRes)
		t.Fatalf("3-hop delegation chain should grant access: status %d, body: %s", dlRes.StatusCode, dlBody)
	}
	dlBody := readBody(t, dlRes)
	if string(dlBody) != string(blobData) {
		t.Fatal("downloaded blob does not match uploaded data via 3-hop delegation")
	}
}

// ===================================================================
// delegation root mismatch — chain doesn't root at creator
// ===================================================================

func TestDelegationRootMismatchRejection(t *testing.T) {
	base := relayURL(t)
	creator := createIdentity(t, base)
	cc := createContent(t, base, creator)

	// upload blob
	tok := authToken(t, base, creator)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	// non-creator issues a root credential (they don't own the content)
	nonCreator := createIdentity(t, base)
	reader := createIdentity(t, base)
	nonCreatorKid := nonCreator.did + "#" + nonCreator.auth.keyID
	att := []map[string]string{{"resource": "chain:" + cc.contentID, "action": "read"}}
	exp := time.Now().Unix() + 300
	cred := createCustomCredential(t, nonCreator.did, reader.did, nonCreatorKid, att, []string{}, exp, nonCreator.auth.priv)

	// reader tries to use — should fail because chain roots at nonCreator, not creator
	readerTok := authToken(t, base, reader)
	dlRes := getBlobWithCred(t, base, cc.contentID, readerTok, cred)
	if dlRes.StatusCode == 200 {
		t.Fatal("credential not rooted at content creator should be rejected")
	}
	dlRes.Body.Close()
}
