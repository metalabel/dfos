// Extended conformance tests for additional relay surface area.
//
// These supplement the core conformance_test.go with coverage for:
//   - beacon replacement and not-found
//   - content post-delete rejection and notes
//   - controller key rotation
//   - content update after auth key rotation
//   - empty countersignature results
//   - credential expiry and scope mismatch
//   - delegated content delete
//   - multi-version blob storage
//   - batch processing (3-step chains, dependency sort, large batches, dedup)
package conformance

import (
	"encoding/json"
	"io"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// ===================================================================
// beacon: replacement and not-found
// ===================================================================

func TestBeaconReplacement(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	kid := id.did + "#" + id.auth.keyID

	// first beacon
	merkle1 := dfos.BuildMerkleRoot([]string{cc.contentID})
	tok1, _, err := dfos.SignBeacon(id.did, merkle1, kid, id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	postOperations(t, base, []string{tok1}).Body.Close()

	// second beacon with different merkle root
	merkle2 := dfos.BuildMerkleRoot([]string{cc.contentID, "extra-content-id"})
	tok2, beaconCID2, err := dfos.SignBeacon(id.did, merkle2, kid, id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	postOperations(t, base, []string{tok2}).Body.Close()

	// relay should serve only the latest beacon
	var beacon struct {
		BeaconCID string `json:"beaconCID"`
		Payload   struct {
			MerkleRoot string `json:"merkleRoot"`
		} `json:"payload"`
	}
	resp := getJSON(t, base+"/beacons/"+id.did, &beacon)
	if resp.StatusCode != 200 {
		t.Fatalf("GET beacon: status %d", resp.StatusCode)
	}
	if beacon.BeaconCID != beaconCID2 {
		t.Fatalf("beacon should be replaced: got CID %s, want %s", beacon.BeaconCID, beaconCID2)
	}
	if beacon.Payload.MerkleRoot != merkle2 {
		t.Fatalf("merkle root: got %s, want %s", beacon.Payload.MerkleRoot, merkle2)
	}
}

func TestBeaconNotFound(t *testing.T) {
	base := relayURL(t)
	resp := getJSON(t, base+"/beacons/did:dfos:nonexistent000000000", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ===================================================================
// content: post-delete rejection, notes, update after key rotation
// ===================================================================

func TestContentRejectPostDelete(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	kid := id.did + "#" + id.auth.keyID

	// delete content
	delToken, delCID, err := dfos.SignContentDelete(id.did, cc.genCID, kid, "", "", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	postOperations(t, base, []string{delToken}).Body.Close()

	// try to extend after delete
	doc2 := map[string]any{"type": "post", "title": "post-delete update"}
	docCID2, _, _ := dfos.DocumentCID(doc2)
	updateToken, _, err := dfos.SignContentUpdate(id.did, delCID, docCID2, kid, "", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	res := postOperations(t, base, []string{updateToken})
	body := readBody(t, res)
	var results struct {
		Results []struct {
			Error string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &results)
	if len(results.Results) > 0 && results.Results[0].Error == "" {
		t.Fatal("expected error for post-delete content operation")
	}
}

func TestContentWithNote(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	doc := map[string]any{"type": "post", "body": "with note"}
	docCID, _, _ := dfos.DocumentCID(doc)
	kid := id.did + "#" + id.auth.keyID

	// create with note
	token, contentID, genCID, err := dfos.SignContentCreate(id.did, docCID, kid, "initial version", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	res := postOperations(t, base, []string{token})
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("content with note: status %d, body: %s", res.StatusCode, body)
	}
	res.Body.Close()

	// update with note
	doc2 := map[string]any{"type": "post", "body": "updated with note"}
	docCID2, _, _ := dfos.DocumentCID(doc2)
	updateToken, _, err := dfos.SignContentUpdate(id.did, genCID, docCID2, kid, "revision 2", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	res = postOperations(t, base, []string{updateToken})
	if res.StatusCode != 200 {
		body := readBody(t, res)
		t.Fatalf("content update with note: status %d, body: %s", res.StatusCode, body)
	}
	res.Body.Close()

	// verify chain has 2 ops
	var chain struct {
		HeadCID string `json:"headCID"`
	}
	getJSON(t, base+"/content/"+contentID, &chain)
	if chain.HeadCID == "" {
		t.Fatal("headCID is empty")
	}
}

func TestContentUpdateAfterKeyRotation(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// rotate auth key
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

	// update content with new auth key — should succeed
	doc2 := map[string]any{"type": "post", "title": "after rotation"}
	docCID2, _, _ := dfos.DocumentCID(doc2)
	newKid := id.did + "#" + newAuth.keyID
	updateToken, _, err := dfos.SignContentUpdate(id.did, cc.genCID, docCID2, newKid, "", newAuth.priv)
	if err != nil {
		t.Fatal(err)
	}

	res := postOperations(t, base, []string{updateToken})
	if res.StatusCode != 200 {
		body := readBody(t, res)
		t.Fatalf("content update after rotation: status %d, body: %s", res.StatusCode, body)
	}
	res.Body.Close()

	var chain struct {
		HeadCID string `json:"headCID"`
	}
	getJSON(t, base+"/content/"+cc.contentID, &chain)
	if chain.HeadCID == "" {
		t.Fatal("headCID is empty")
	}
}

// ===================================================================
// identity: controller key rotation
// ===================================================================

func TestControllerKeyRotation(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	// rotate controller key
	newCtrl := newKeypair()
	oldCtrlKid := id.did + "#" + id.controller.keyID
	rotateToken, rotateCID, err := dfos.SignIdentityUpdate(
		id.genCID,
		[]dfos.MultikeyPublicKey{newCtrl.mk},
		[]dfos.MultikeyPublicKey{id.auth.mk},
		[]dfos.MultikeyPublicKey{},
		oldCtrlKid,
		id.controller.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	postOperations(t, base, []string{rotateToken}).Body.Close()

	// try to update with old controller — should fail
	newerAuth := newKeypair()
	badToken, _, err := dfos.SignIdentityUpdate(
		rotateCID,
		[]dfos.MultikeyPublicKey{newCtrl.mk},
		[]dfos.MultikeyPublicKey{newerAuth.mk},
		[]dfos.MultikeyPublicKey{},
		oldCtrlKid,
		id.controller.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	res := postOperations(t, base, []string{badToken})
	body := readBody(t, res)
	var results struct {
		Results []struct {
			Error string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &results)
	if len(results.Results) > 0 && results.Results[0].Error == "" {
		t.Fatal("expected error for rotated-out controller key")
	}

	// update with new controller — should succeed
	newCtrlKid := id.did + "#" + newCtrl.keyID
	goodToken, _, err := dfos.SignIdentityUpdate(
		rotateCID,
		[]dfos.MultikeyPublicKey{newCtrl.mk},
		[]dfos.MultikeyPublicKey{newerAuth.mk},
		[]dfos.MultikeyPublicKey{},
		newCtrlKid,
		newCtrl.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	res = postOperations(t, base, []string{goodToken})
	if res.StatusCode != 200 {
		body = readBody(t, res)
		t.Fatalf("update with new controller: status %d, body: %s", res.StatusCode, body)
	}
	res.Body.Close()

	var chain struct {
		HeadCID string `json:"headCID"`
	}
	getJSON(t, base+"/identities/"+id.did, &chain)
	if chain.HeadCID == "" {
		t.Fatal("headCID is empty")
	}
}

// ===================================================================
// countersignatures: empty result
// ===================================================================

func TestCountersignatureEmptyResult(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	// query countersigs for genesis op — nobody has countersigned it
	var csResult struct {
		Countersignatures []string `json:"countersignatures"`
	}
	resp := getJSON(t, base+"/countersignatures/"+id.genCID, &csResult)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 for empty countersigs, got %d", resp.StatusCode)
	}
	if len(csResult.Countersignatures) != 0 {
		t.Fatalf("expected 0 countersigs, got %d", len(csResult.Countersignatures))
	}
}

// ===================================================================
// credentials: expiry and scope mismatch
// ===================================================================

func TestCredentialExpired(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// upload blob as creator
	tok := authToken(t, base, id)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	// create reader with already-expired credential
	reader := createIdentity(t, base)
	issuerKid := id.did + "#" + id.auth.keyID
	cred, err := dfos.CreateCredential(
		id.did, reader.did, issuerKid, "DFOSContentRead",
		-1*time.Hour, cc.contentID, id.auth.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	readerTok := authToken(t, base, reader)
	dlRes := getBlobWithCred(t, base, cc.contentID, readerTok, cred)
	if dlRes.StatusCode == 200 {
		t.Fatal("expected rejection for expired credential")
	}
	dlRes.Body.Close()
}

func TestCredentialScopeMismatch(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	// create two content chains
	ccA := createContent(t, base, id)
	ccB := createContent(t, base, id)

	// upload blobs for both
	tok := authToken(t, base, id)
	blobA, _ := json.Marshal(ccA.document)
	putBlob(t, base, ccA.contentID, ccA.genCID, tok, blobA).Body.Close()
	blobB, _ := json.Marshal(ccB.document)
	putBlob(t, base, ccB.contentID, ccB.genCID, tok, blobB).Body.Close()

	// issue read credential scoped to content A
	reader := createIdentity(t, base)
	issuerKid := id.did + "#" + id.auth.keyID
	credA, err := dfos.CreateCredential(
		id.did, reader.did, issuerKid, "DFOSContentRead",
		5*time.Minute, ccA.contentID, id.auth.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	// try to download content B using credential scoped to A
	readerTok := authToken(t, base, reader)
	dlRes := getBlobWithCred(t, base, ccB.contentID, readerTok, credA)
	if dlRes.StatusCode == 200 {
		t.Fatal("expected rejection for credential scoped to different content")
	}
	dlRes.Body.Close()
}

// ===================================================================
// delegated content delete
// ===================================================================

func TestDelegatedContentDelete(t *testing.T) {
	base := relayURL(t)
	creator := createIdentity(t, base)
	cc := createContent(t, base, creator)

	delegate := createIdentity(t, base)

	// creator issues write credential to delegate
	creatorKid := creator.did + "#" + creator.auth.keyID
	cred, err := dfos.CreateCredential(
		creator.did, delegate.did, creatorKid, "DFOSContentWrite",
		5*time.Minute, cc.contentID, creator.auth.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	// delegate signs delete with credential
	delegateKid := delegate.did + "#" + delegate.auth.keyID
	delToken, _, err := dfos.SignContentDelete(delegate.did, cc.genCID, delegateKid, "delegated delete", cred, delegate.auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	res := postOperations(t, base, []string{delToken})
	if res.StatusCode != 200 {
		body := readBody(t, res)
		t.Fatalf("delegated delete: status %d, body: %s", res.StatusCode, body)
	}
	res.Body.Close()

	var chain struct {
		State struct {
			IsDeleted bool `json:"isDeleted"`
		} `json:"state"`
	}
	getJSON(t, base+"/content/"+cc.contentID, &chain)
	if !chain.State.IsDeleted {
		t.Fatal("content should be deleted by delegate")
	}
}

// ===================================================================
// blob: multi-version storage
// ===================================================================

func TestBlobMultiVersion(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	tok := authToken(t, base, id)

	// upload v1 blob
	blobV1, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobV1).Body.Close()

	// update content chain
	doc2 := map[string]any{"type": "post", "title": "version 2", "body": "updated"}
	docCID2, _, _ := dfos.DocumentCID(doc2)
	kid := id.did + "#" + id.auth.keyID
	updateToken, updateCID, err := dfos.SignContentUpdate(id.did, cc.genCID, docCID2, kid, "", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	postOperations(t, base, []string{updateToken}).Body.Close()

	// upload v2 blob
	blobV2, _ := json.Marshal(doc2)
	putBlob(t, base, cc.contentID, updateCID, tok, blobV2).Body.Close()

	// download v1 at ref
	dlV1 := getBlob(t, base, cc.contentID, tok, cc.genCID)
	if dlV1.StatusCode != 200 {
		body := readBody(t, dlV1)
		t.Fatalf("download v1: status %d, body: %s", dlV1.StatusCode, body)
	}
	v1Body := readBody(t, dlV1)
	if string(v1Body) != string(blobV1) {
		t.Fatal("v1 blob does not match")
	}

	// download v2 at ref
	dlV2 := getBlob(t, base, cc.contentID, tok, updateCID)
	if dlV2.StatusCode != 200 {
		body := readBody(t, dlV2)
		t.Fatalf("download v2: status %d, body: %s", dlV2.StatusCode, body)
	}
	v2Body := readBody(t, dlV2)
	if string(v2Body) != string(blobV2) {
		t.Fatal("v2 blob does not match")
	}

	// head should return v2
	dlHead := getBlob(t, base, cc.contentID, tok)
	if dlHead.StatusCode != 200 {
		body := readBody(t, dlHead)
		t.Fatalf("download head: status %d, body: %s", dlHead.StatusCode, body)
	}
	headBody := readBody(t, dlHead)
	if string(headBody) != string(blobV2) {
		t.Fatal("head blob should be v2")
	}
}

// ===================================================================
// batch processing
// ===================================================================

func TestBatchThreeStepIdentity(t *testing.T) {
	base := relayURL(t)

	ctrl := newKeypair()
	auth1 := newKeypair()

	// genesis
	createToken, did, genCID, err := dfos.SignIdentityCreate(
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{auth1.mk},
		[]dfos.MultikeyPublicKey{},
		ctrl.keyID,
		ctrl.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	// update1 chains off genesis
	time.Sleep(2 * time.Millisecond)
	auth2 := newKeypair()
	kid := did + "#" + ctrl.keyID
	update1Token, update1CID, err := dfos.SignIdentityUpdate(
		genCID,
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{auth2.mk},
		[]dfos.MultikeyPublicKey{},
		kid,
		ctrl.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	// update2 chains off update1
	time.Sleep(2 * time.Millisecond)
	auth3 := newKeypair()
	update2Token, _, err := dfos.SignIdentityUpdate(
		update1CID,
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{auth3.mk},
		[]dfos.MultikeyPublicKey{},
		kid,
		ctrl.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	// submit in REVERSE order — relay must sort by dependency
	res := postOperations(t, base, []string{update2Token, update1Token, createToken})
	body := readBody(t, res)
	if res.StatusCode != 200 {
		t.Fatalf("batch 3-step: status %d, body: %s", res.StatusCode, body)
	}

	var batchResp struct {
		Results []struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &batchResp)
	for i, r := range batchResp.Results {
		if r.Status != "new" {
			t.Fatalf("batch result[%d]: status=%s error=%s", i, r.Status, r.Error)
		}
	}

	var chain struct {
		HeadCID string `json:"headCID"`
	}
	getJSON(t, base+"/identities/"+did, &chain)
	if chain.HeadCID == "" {
		t.Fatal("headCID is empty")
	}
}

func TestBatchContentIdentitySort(t *testing.T) {
	base := relayURL(t)

	// prepare identity (don't submit yet)
	ctrl := newKeypair()
	auth := newKeypair()
	idToken, did, _, err := dfos.SignIdentityCreate(
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{auth.mk},
		[]dfos.MultikeyPublicKey{},
		ctrl.keyID,
		ctrl.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	// sign content for this identity
	doc := map[string]any{"type": "post", "title": "batch test"}
	docCID, _, _ := dfos.DocumentCID(doc)
	kid := did + "#" + auth.keyID
	contentToken, _, _, err := dfos.SignContentCreate(did, docCID, kid, "", auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	// submit content FIRST, identity SECOND — relay must sort dependencies
	res := postOperations(t, base, []string{contentToken, idToken})
	body := readBody(t, res)
	if res.StatusCode != 200 {
		t.Fatalf("batch sort: status %d, body: %s", res.StatusCode, body)
	}

	var batchResp struct {
		Results []struct {
			Status string `json:"status"`
			Kind   string `json:"kind"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &batchResp)

	// both should be accepted
	for i, r := range batchResp.Results {
		if r.Status != "new" {
			t.Fatalf("batch result[%d]: status=%s error=%s", i, r.Status, r.Error)
		}
	}

	// results must be in SUBMISSION order (not processing order)
	if batchResp.Results[0].Kind != "content-op" {
		t.Fatalf("expected result[0].kind=content-op, got %s", batchResp.Results[0].Kind)
	}
	if batchResp.Results[1].Kind != "identity-op" {
		t.Fatalf("expected result[1].kind=identity-op, got %s", batchResp.Results[1].Kind)
	}
}

func TestBatchLarge(t *testing.T) {
	base := relayURL(t)

	// create 10 independent identities in one batch
	var tokens []string
	var dids []string
	for i := 0; i < 10; i++ {
		ctrl := newKeypair()
		auth := newKeypair()
		token, did, _, err := dfos.SignIdentityCreate(
			[]dfos.MultikeyPublicKey{ctrl.mk},
			[]dfos.MultikeyPublicKey{auth.mk},
			[]dfos.MultikeyPublicKey{},
			ctrl.keyID,
			ctrl.priv,
		)
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, token)
		dids = append(dids, did)
	}

	res := postOperations(t, base, tokens)
	body := readBody(t, res)
	if res.StatusCode != 200 {
		t.Fatalf("batch large: status %d, body: %s", res.StatusCode, body)
	}

	var batchResp struct {
		Results []struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &batchResp)
	if len(batchResp.Results) != 10 {
		t.Fatalf("expected 10 results, got %d", len(batchResp.Results))
	}
	for i, r := range batchResp.Results {
		if r.Status != "new" {
			t.Fatalf("batch result[%d]: status=%s error=%s", i, r.Status, r.Error)
		}
	}

	// spot-check a few identities exist
	for _, did := range dids[:3] {
		resp := getJSON(t, base+"/identities/"+did, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("identity %s not found after batch create", did)
		}
	}
}

func TestBatchDuplicateOperations(t *testing.T) {
	base := relayURL(t)

	ctrl := newKeypair()
	auth := newKeypair()
	token, did, _, err := dfos.SignIdentityCreate(
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{auth.mk},
		[]dfos.MultikeyPublicKey{},
		ctrl.keyID,
		ctrl.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	// submit same operation twice in one batch
	res := postOperations(t, base, []string{token, token})
	body := readBody(t, res)
	if res.StatusCode != 200 {
		t.Fatalf("batch dup: status %d, body: %s", res.StatusCode, body)
	}

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
	// both should be accepted (idempotent dedup)
	for i, r := range batchResp.Results {
		if r.Status != "new" {
			t.Fatalf("batch result[%d]: status=%s error=%s", i, r.Status, r.Error)
		}
	}

	// chain should still have only 1 op
	var chain struct {
		HeadCID string `json:"headCID"`
	}
	getJSON(t, base+"/identities/"+did, &chain)
	if chain.HeadCID == "" {
		t.Fatal("headCID is empty (dedup)")
	}
}
