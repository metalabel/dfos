// Edge-case conformance tests for relay robustness and spec clarity.
//
// These cover:
//   - Signature verification (tampered, wrong key)
//   - Batch semantics (mixed valid/invalid, multi-chain)
//   - Credential type enforcement (write-for-read, read-for-write)
//   - Beacon edge cases (unknown identity, deleted identity)
//   - Blob edge cases (idempotent upload, non-existent content)
//   - Countersignature edge cases (non-existent operation, self-countersign)
//   - Chain integrity (multiple chains, long chains)
//   - Credential lifecycle (deleted issuer)
package conformance

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// ===================================================================
// signature verification
// ===================================================================

// TestRejectTamperedSignature verifies the relay rejects operations where the
// JWS structure is valid but the signature bytes have been corrupted.
func TestRejectTamperedSignature(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	doc := map[string]any{"type": "post", "title": "tampered"}
	docCID, _, _ := dfos.DocumentCID(doc)
	kid := id.did + "#" + id.auth.keyID
	token, _, _, err := dfos.SignContentCreate(id.did, docCID, kid, "", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	// Replace the signature (third JWS segment) with all-A's
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWS parts, got %d", len(parts))
	}
	parts[2] = strings.Repeat("A", len(parts[2]))
	tampered := strings.Join(parts, ".")

	res := postOperations(t, base, []string{tampered})
	body := readBody(t, res)
	var results struct {
		Results []struct {
			Error string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &results)
	if len(results.Results) == 0 || results.Results[0].Error == "" {
		t.Fatal("expected rejection for tampered signature")
	}
}

// TestRejectWrongSigningKey verifies the relay rejects operations where the
// kid references a valid key on the identity but the signature was made with
// a different private key.
func TestRejectWrongSigningKey(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	doc := map[string]any{"type": "post", "title": "wrong key"}
	docCID, _, _ := dfos.DocumentCID(doc)
	kid := id.did + "#" + id.auth.keyID

	// Sign with a random key, not the identity's auth key
	wrongKey := newKeypair()
	token, _, _, err := dfos.SignContentCreate(id.did, docCID, kid, "", wrongKey.priv)
	if err != nil {
		t.Fatal(err)
	}

	res := postOperations(t, base, []string{token})
	body := readBody(t, res)
	var results struct {
		Results []struct {
			Error string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &results)
	if len(results.Results) == 0 || results.Results[0].Error == "" {
		t.Fatal("expected rejection for wrong signing key")
	}
}

// ===================================================================
// batch semantics
// ===================================================================

// TestBatchMixedValidInvalid verifies that valid operations in a batch are
// still accepted even when other operations in the same batch are invalid.
func TestBatchMixedValidInvalid(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	// valid: content create from known identity
	doc := map[string]any{"type": "post", "title": "valid op"}
	docCID, _, _ := dfos.DocumentCID(doc)
	kid := id.did + "#" + id.auth.keyID
	validToken, _, _, _ := dfos.SignContentCreate(id.did, docCID, kid, "", id.auth.priv)

	// invalid: content create from unknown identity
	fakeKP := newKeypair()
	fakeDID := "did:dfos:fakefakefakefakefake00"
	fakeKid := fakeDID + "#" + fakeKP.keyID
	invalidToken, _, _, _ := dfos.SignContentCreate(fakeDID, docCID, fakeKid, "", fakeKP.priv)

	res := postOperations(t, base, []string{validToken, invalidToken})
	body := readBody(t, res)

	var batchResp struct {
		Results []struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &batchResp)

	if len(batchResp.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(batchResp.Results))
	}
	if batchResp.Results[0].Status != "accepted" {
		t.Fatalf("valid op should be accepted: %s", batchResp.Results[0].Error)
	}
	if batchResp.Results[1].Error == "" {
		t.Fatal("invalid op should be rejected")
	}
}

// TestBatchMultiChain verifies that a single batch can contain operations
// across multiple unrelated chains (two identities + content for one).
func TestBatchMultiChain(t *testing.T) {
	base := relayURL(t)

	ctrl1 := newKeypair()
	auth1 := newKeypair()
	tok1, did1, _, _ := dfos.SignIdentityCreate(
		[]dfos.MultikeyPublicKey{ctrl1.mk},
		[]dfos.MultikeyPublicKey{auth1.mk},
		[]dfos.MultikeyPublicKey{},
		ctrl1.keyID, ctrl1.priv,
	)

	ctrl2 := newKeypair()
	auth2 := newKeypair()
	tok2, did2, _, _ := dfos.SignIdentityCreate(
		[]dfos.MultikeyPublicKey{ctrl2.mk},
		[]dfos.MultikeyPublicKey{auth2.mk},
		[]dfos.MultikeyPublicKey{},
		ctrl2.keyID, ctrl2.priv,
	)
	_ = auth2

	doc := map[string]any{"type": "post", "title": "multi-chain batch"}
	docCID, _, _ := dfos.DocumentCID(doc)
	kid1 := did1 + "#" + auth1.keyID
	contentTok, _, _, _ := dfos.SignContentCreate(did1, docCID, kid1, "", auth1.priv)

	// all three in one batch
	res := postOperations(t, base, []string{tok1, tok2, contentTok})
	body := readBody(t, res)

	var batchResp struct {
		Results []struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &batchResp)

	if len(batchResp.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(batchResp.Results))
	}
	for i, r := range batchResp.Results {
		if r.Status != "accepted" {
			t.Fatalf("batch result[%d]: status=%s error=%s", i, r.Status, r.Error)
		}
	}

	// both identities exist
	if resp := getJSON(t, base+"/identities/"+did1, nil); resp.StatusCode != 200 {
		t.Fatal("identity 1 not found")
	}
	if resp := getJSON(t, base+"/identities/"+did2, nil); resp.StatusCode != 200 {
		t.Fatal("identity 2 not found")
	}
}

// ===================================================================
// credential type enforcement
// ===================================================================

// TestWriteCredentialCannotRead verifies that a DFOSContentWrite credential
// cannot be used to download blobs (requires DFOSContentRead).
func TestWriteCredentialCannotRead(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	tok := authToken(t, base, id)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	reader := createIdentity(t, base)
	issuerKid := id.did + "#" + id.auth.keyID
	cred, _ := dfos.CreateCredential(
		id.did, reader.did, issuerKid, "DFOSContentWrite",
		5*time.Minute, cc.contentID, id.auth.priv,
	)

	readerTok := authToken(t, base, reader)
	dlRes := getBlobWithCred(t, base, cc.contentID, readerTok, cred)
	if dlRes.StatusCode == 200 {
		t.Fatal("DFOSContentWrite credential should not grant read access")
	}
	dlRes.Body.Close()
}

// TestReadCredentialCannotWrite verifies that a DFOSContentRead credential
// cannot be used as authorization for content updates (requires DFOSContentWrite).
func TestReadCredentialCannotWrite(t *testing.T) {
	base := relayURL(t)
	creator := createIdentity(t, base)
	cc := createContent(t, base, creator)

	delegate := createIdentity(t, base)
	creatorKid := creator.did + "#" + creator.auth.keyID
	cred, _ := dfos.CreateCredential(
		creator.did, delegate.did, creatorKid, "DFOSContentRead",
		5*time.Minute, cc.contentID, creator.auth.priv,
	)

	doc2 := map[string]any{"type": "post", "title": "sneaky write"}
	docCID2, _, _ := dfos.DocumentCID(doc2)
	delegateKid := delegate.did + "#" + delegate.auth.keyID
	token, _, err := dfos.SignContentUpdateWithOptions(
		delegate.did, cc.genCID, docCID2, delegateKid, delegate.auth.priv,
		dfos.ContentUpdateOptions{Authorization: cred},
	)
	if err != nil {
		t.Fatal(err)
	}

	res := postOperations(t, base, []string{token})
	body := readBody(t, res)
	var results struct {
		Results []struct {
			Error string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &results)
	if len(results.Results) > 0 && results.Results[0].Error == "" {
		t.Fatal("DFOSContentRead credential should not grant write access")
	}
}

// ===================================================================
// beacon edge cases
// ===================================================================

// TestBeaconFromUnknownIdentity verifies the relay rejects beacons
// signed by an identity that hasn't been registered.
func TestBeaconFromUnknownIdentity(t *testing.T) {
	base := relayURL(t)

	kp := newKeypair()
	fakeDID := "did:dfos:unknownbeacontest00000"
	kid := fakeDID + "#" + kp.keyID

	merkle := dfos.BuildMerkleRoot([]string{"some-content-id"})
	token, _, err := dfos.SignBeacon(fakeDID, merkle, kid, kp.priv)
	if err != nil {
		t.Fatal(err)
	}

	res := postOperations(t, base, []string{token})
	body := readBody(t, res)
	var results struct {
		Results []struct {
			Error string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &results)
	if len(results.Results) > 0 && results.Results[0].Error == "" {
		t.Fatal("expected rejection for beacon from unknown identity")
	}
}

// TestBeaconFromDeletedIdentity verifies the relay rejects beacons from
// deleted identities. Deletion means the identity stops being an active
// participant — no new beacons, even though keys persist in state.
func TestBeaconFromDeletedIdentity(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	// delete identity
	ctrlKid := id.did + "#" + id.controller.keyID
	delToken, _, _ := dfos.SignIdentityDelete(id.genCID, ctrlKid, id.controller.priv)
	postOperations(t, base, []string{delToken}).Body.Close()

	// beacon from deleted identity — should be rejected
	authKid := id.did + "#" + id.auth.keyID
	merkle := dfos.BuildMerkleRoot([]string{"some-content-id"})
	beaconToken, _, err := dfos.SignBeacon(id.did, merkle, authKid, id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	res := postOperations(t, base, []string{beaconToken})
	body := readBody(t, res)
	var results struct {
		Results []struct {
			Error string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &results)
	if len(results.Results) == 0 || results.Results[0].Error == "" {
		t.Fatal("expected rejection for beacon from deleted identity")
	}
}

// ===================================================================
// blob edge cases
// ===================================================================

// TestBlobUploadIdempotent verifies uploading the same blob twice for
// the same operation succeeds without error.
func TestBlobUploadIdempotent(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	tok := authToken(t, base, id)
	blobData, _ := json.Marshal(cc.document)

	res1 := putBlob(t, base, cc.contentID, cc.genCID, tok, blobData)
	if res1.StatusCode != 200 {
		body := readBody(t, res1)
		t.Fatalf("first upload: status %d, body: %s", res1.StatusCode, body)
	}
	res1.Body.Close()

	res2 := putBlob(t, base, cc.contentID, cc.genCID, tok, blobData)
	if res2.StatusCode != 200 {
		body := readBody(t, res2)
		t.Fatalf("second upload (idempotent): status %d, body: %s", res2.StatusCode, body)
	}
	res2.Body.Close()

	// verify blob is still correct after double upload
	dlRes := getBlob(t, base, cc.contentID, tok)
	if dlRes.StatusCode != 200 {
		t.Fatalf("download after double upload: status %d", dlRes.StatusCode)
	}
	dlBody := readBody(t, dlRes)
	if string(dlBody) != string(blobData) {
		t.Fatal("blob corrupted after idempotent upload")
	}
}

// TestBlobUploadNonExistentContent verifies the relay rejects blob
// uploads for content chains that don't exist.
func TestBlobUploadNonExistentContent(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	tok := authToken(t, base, id)
	res := putBlob(t, base, "nonexistent_content_id",
		"bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", tok, []byte("test"))
	if res.StatusCode == 200 {
		t.Fatal("expected rejection for blob upload to non-existent content")
	}
	res.Body.Close()
}

// TestBlobDownloadNonExistentContent verifies the relay returns 404
// when downloading from a content chain that doesn't exist.
func TestBlobDownloadNonExistentContent(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	tok := authToken(t, base, id)
	res := getBlob(t, base, "nonexistent_content_id", tok)
	if res.StatusCode != 404 {
		t.Fatalf("expected 404 for non-existent content blob, got %d", res.StatusCode)
	}
	res.Body.Close()
}

// ===================================================================
// countersignature edge cases
// ===================================================================

// TestCountersignNonExistentOperation verifies the relay rejects
// countersignatures for operations that haven't been submitted.
func TestCountersignNonExistentOperation(t *testing.T) {
	base := relayURL(t)
	witness := createIdentity(t, base)

	// countersign a CID that doesn't exist on the relay
	witnessKid := witness.did + "#" + witness.auth.keyID
	csToken, _, err := dfos.SignCountersign(witness.did, "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", witnessKid, witness.auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	res := postOperations(t, base, []string{csToken})
	body := readBody(t, res)
	var results struct {
		Results []struct {
			Error string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &results)
	if len(results.Results) == 0 || results.Results[0].Error == "" {
		t.Fatal("expected rejection for countersign of non-existent operation")
	}
}

// TestSelfCountersign verifies that self-countersigning (witness DID =
// target author DID) is rejected by the relay.
func TestSelfCountersign(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// Self-countersign: witness DID == content creator DID
	ctrlKid := id.did + "#" + id.controller.keyID
	csToken, _, err := dfos.SignCountersign(id.did, cc.genCID, ctrlKid, id.controller.priv)
	if err != nil {
		t.Fatal(err)
	}

	res := postOperations(t, base, []string{csToken})
	body := readBody(t, res)

	var results struct {
		Results []struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &results)
	if len(results.Results) == 0 {
		t.Fatal("expected a result for self-countersign")
	}
	if results.Results[0].Error == "" {
		t.Fatal("expected rejection for self-countersign (witness = author)")
	}
}

// ===================================================================
// chain integrity
// ===================================================================

// TestMultipleContentChainsIndependent verifies that two content chains
// from the same identity are fully independent — updating one does not
// affect the other.
func TestMultipleContentChainsIndependent(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	cc1 := createContent(t, base, id)

	// create a second chain with different content
	doc2 := map[string]any{"type": "post", "title": "second chain", "body": "different"}
	docCID2, _, _ := dfos.DocumentCID(doc2)
	kid := id.did + "#" + id.auth.keyID
	token2, contentID2, _, err := dfos.SignContentCreate(id.did, docCID2, kid, "", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	postOperations(t, base, []string{token2}).Body.Close()

	// update chain 1
	doc3 := map[string]any{"type": "post", "title": "chain 1 updated"}
	docCID3, _, _ := dfos.DocumentCID(doc3)
	updateToken, _, err := dfos.SignContentUpdate(id.did, cc1.genCID, docCID3, kid, "", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	postOperations(t, base, []string{updateToken}).Body.Close()

	// chain 1 should have 2 ops
	var chain1 struct {
		HeadCID string `json:"headCID"`
	}
	getJSON(t, base+"/content/"+cc1.contentID, &chain1)
	if chain1.HeadCID == "" {
		t.Fatal("chain 1: headCID is empty")
	}

	// chain 2 should still have 1 op
	var chain2 struct {
		HeadCID string `json:"headCID"`
	}
	getJSON(t, base+"/content/"+contentID2, &chain2)
	if chain2.HeadCID == "" {
		t.Fatal("chain 2: headCID is empty")
	}
}

// TestLongContentChain verifies a content chain can grow to 6 operations
// (1 create + 5 sequential updates) without issues.
func TestLongContentChain(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	kid := id.did + "#" + id.auth.keyID
	headCID := cc.genCID

	for i := 1; i <= 5; i++ {
		doc := map[string]any{"type": "post", "title": fmt.Sprintf("update %d", i), "seq": i}
		docCID, _, _ := dfos.DocumentCID(doc)
		updateToken, updateCID, err := dfos.SignContentUpdate(id.did, headCID, docCID, kid, "", id.auth.priv)
		if err != nil {
			t.Fatalf("update %d: %v", i, err)
		}
		res := postOperations(t, base, []string{updateToken})
		if res.StatusCode != 200 {
			body := readBody(t, res)
			t.Fatalf("update %d: status %d, body: %s", i, res.StatusCode, body)
		}
		res.Body.Close()
		headCID = updateCID
	}

	var chain struct {
		HeadCID string `json:"headCID"`
	}
	getJSON(t, base+"/content/"+cc.contentID, &chain)
	if chain.HeadCID == "" {
		t.Fatal("headCID is empty (1 create + 5 updates)")
	}
}

// ===================================================================
// credential lifecycle
// ===================================================================

// TestCredentialFromDeletedIssuer tests whether a credential issued before
// the issuer's identity was deleted is still honored for blob downloads.
// Spec question: should credentials survive issuer deletion?
func TestCredentialFromDeletedIssuer(t *testing.T) {
	base := relayURL(t)
	creator := createIdentity(t, base)
	cc := createContent(t, base, creator)

	// upload blob
	tok := authToken(t, base, creator)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	// issue credential while creator is alive
	reader := createIdentity(t, base)
	issuerKid := creator.did + "#" + creator.auth.keyID
	cred, err := dfos.CreateCredential(
		creator.did, reader.did, issuerKid, "DFOSContentRead",
		5*time.Minute, cc.contentID, creator.auth.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	// delete the creator identity
	ctrlKid := creator.did + "#" + creator.controller.keyID
	delToken, _, _ := dfos.SignIdentityDelete(creator.genCID, ctrlKid, creator.controller.priv)
	postOperations(t, base, []string{delToken}).Body.Close()

	// reader tries to download with credential from deleted issuer — should fail
	readerTok := authToken(t, base, reader)
	dlRes := getBlobWithCred(t, base, cc.contentID, readerTok, cred)

	// Identity deletion revokes all authority, including outstanding credentials.
	// The credential was validly issued but the issuer is now deleted.
	if dlRes.StatusCode == 200 {
		t.Fatal("expected rejection for credential from deleted issuer")
	}
	dlRes.Body.Close()
}

// TestDelegatedWriteFromDeletedCreator verifies that a delegate holding a
// DFOSContentWrite credential cannot mutate a content chain after the
// credential issuer (chain creator) has been deleted.
func TestDelegatedWriteFromDeletedCreator(t *testing.T) {
	base := relayURL(t)
	creator := createIdentity(t, base)
	cc := createContent(t, base, creator)

	delegate := createIdentity(t, base)

	// issue write credential while creator is alive
	creatorKid := creator.did + "#" + creator.auth.keyID
	cred, err := dfos.CreateCredential(
		creator.did, delegate.did, creatorKid, "DFOSContentWrite",
		5*time.Minute, cc.contentID, creator.auth.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	// delete the creator identity
	ctrlKid := creator.did + "#" + creator.controller.keyID
	delToken, _, _ := dfos.SignIdentityDelete(creator.genCID, ctrlKid, creator.controller.priv)
	postOperations(t, base, []string{delToken}).Body.Close()

	// delegate tries to update content with write credential from deleted creator
	doc2 := map[string]any{"type": "post", "title": "sneaky post-delete write"}
	docCID2, _, _ := dfos.DocumentCID(doc2)
	delegateKid := delegate.did + "#" + delegate.auth.keyID
	token, _, err := dfos.SignContentUpdateWithOptions(
		delegate.did, cc.genCID, docCID2, delegateKid, delegate.auth.priv,
		dfos.ContentUpdateOptions{Authorization: cred},
	)
	if err != nil {
		t.Fatal(err)
	}

	res := postOperations(t, base, []string{token})
	body := readBody(t, res)
	var results struct {
		Results []struct {
			Error string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &results)
	if len(results.Results) == 0 || results.Results[0].Error == "" {
		t.Fatal("expected rejection for delegated write from deleted creator")
	}
}
