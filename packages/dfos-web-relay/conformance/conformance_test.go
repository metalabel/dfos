// Package conformance tests a DFOS web relay for protocol compliance.
//
// Run against a live relay:
//
//	RELAY_URL=http://localhost:4444 go test -v -count=1 ./...
package conformance

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// ===================================================================
// well-known
// ===================================================================

func TestWellKnown(t *testing.T) {
	base := relayURL(t)

	// ---------------------------------------------------------------
	// 1. Fetch well-known and parse all fields
	// ---------------------------------------------------------------

	var meta struct {
		DID      string `json:"did"`
		Protocol string `json:"protocol"`
		Version  string `json:"version"`
		Proof    bool   `json:"proof"`
		Content  bool   `json:"content"`
		Profile  string `json:"profile"`
	}
	resp := getJSON(t, base+"/.well-known/dfos-relay", &meta)
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if meta.DID == "" {
		t.Fatal("relay DID is empty")
	}
	if meta.Protocol == "" {
		t.Fatal("protocol field is empty")
	}
	if !meta.Proof {
		t.Fatal("proof must be true")
	}

	relayDID := meta.DID

	// ---------------------------------------------------------------
	// 2. Relay DID resolves — identity chain exists and is not deleted
	// ---------------------------------------------------------------

	var chain struct {
		State struct {
			DID            string `json:"did"`
			IsDeleted      bool   `json:"isDeleted"`
			ControllerKeys []struct {
				ID                 string `json:"id"`
				Type               string `json:"type"`
				PublicKeyMultibase string `json:"publicKeyMultibase"`
			} `json:"controllerKeys"`
			AuthKeys []struct {
				ID                 string `json:"id"`
				Type               string `json:"type"`
				PublicKeyMultibase string `json:"publicKeyMultibase"`
			} `json:"authKeys"`
		} `json:"state"`
		HeadCID string `json:"headCID"`
	}
	idResp := getJSON(t, base+"/identities/"+relayDID, &chain)
	if idResp.StatusCode != 200 {
		t.Fatalf("relay DID %s did not resolve: status %d", relayDID, idResp.StatusCode)
	}
	if chain.State.IsDeleted {
		t.Fatal("relay identity is deleted")
	}

	// 3. Self-consistency: identity DID matches well-known DID
	if chain.State.DID != relayDID {
		t.Fatalf("identity chain DID %s does not match well-known DID %s", chain.State.DID, relayDID)
	}
	if chain.HeadCID == "" {
		t.Fatal("relay identity headCID is empty")
	}

	// ---------------------------------------------------------------
	// 4. Profile artifact validation (required — proof of DID controllership)
	// ---------------------------------------------------------------

	if meta.Profile == "" {
		t.Fatal("profile is required in well-known response (proof of DID controllership)")
	}

	profileToken := meta.Profile

	// 4a. Decode the JWS unsafely to get header + payload
	header, payload, err := dfos.DecodeJWSUnsafe(profileToken)
	if err != nil {
		t.Fatalf("decode profile JWS: %v", err)
	}

	// 4b. Header typ must be "did:dfos:artifact"
	if header.Typ != "did:dfos:artifact" {
		t.Fatalf("profile header.typ: got %q, want %q", header.Typ, "did:dfos:artifact")
	}

	// 4c. Header kid must reference the relay DID
	if !strings.HasPrefix(header.Kid, relayDID+"#") {
		t.Fatalf("profile header.kid %q does not start with relay DID %q", header.Kid, relayDID+"#")
	}

	// 4d. CID integrity — compute DagCborCID of payload, compare to header CID
	_, _, computedCID, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("compute DagCborCID of profile payload: %v", err)
	}
	if header.CID != computedCID {
		t.Fatalf("profile CID mismatch: header.cid=%s, computed=%s", header.CID, computedCID)
	}

	// 4e. Verify JWS signature against the relay's current key state
	//     Extract the key ID fragment from the kid
	kidParts := strings.SplitN(header.Kid, "#", 2)
	if len(kidParts) != 2 {
		t.Fatalf("profile kid %q has no fragment", header.Kid)
	}
	keyFragment := kidParts[1]

	// Search both controller and auth keys for the matching key
	var matchedMultibase string
	for _, k := range chain.State.ControllerKeys {
		if k.ID == keyFragment {
			matchedMultibase = k.PublicKeyMultibase
			break
		}
	}
	if matchedMultibase == "" {
		for _, k := range chain.State.AuthKeys {
			if k.ID == keyFragment {
				matchedMultibase = k.PublicKeyMultibase
				break
			}
		}
	}
	if matchedMultibase == "" {
		t.Fatalf("profile kid fragment %q not found in relay identity key state", keyFragment)
	}

	pubKeyBytes, err := dfos.DecodeMultikey(matchedMultibase)
	if err != nil {
		t.Fatalf("decode multikey %q: %v", matchedMultibase, err)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	_, _, err = dfos.VerifyJWS(profileToken, pubKey)
	if err != nil {
		t.Fatalf("profile JWS signature verification failed: %v", err)
	}

	// 4f. Payload semantic checks
	if v, ok := payload["version"]; !ok {
		t.Fatal("profile payload missing 'version' field")
	} else {
		// version may be int64 or float64 depending on normalization
		switch vt := v.(type) {
		case int64:
			if vt != 1 {
				t.Fatalf("profile payload version: got %d, want 1", vt)
			}
		case float64:
			if vt != 1 {
				t.Fatalf("profile payload version: got %v, want 1", vt)
			}
		default:
			t.Fatalf("profile payload version: unexpected type %T", v)
		}
	}

	if typ, ok := payload["type"]; !ok {
		t.Fatal("profile payload missing 'type' field")
	} else if typ != "artifact" {
		t.Fatalf("profile payload type: got %q, want %q", typ, "artifact")
	}

	if did, ok := payload["did"]; !ok {
		t.Fatal("profile payload missing 'did' field")
	} else if did != relayDID {
		t.Fatalf("profile payload did: got %q, want %q", did, relayDID)
	}

	// 4g. Content must exist and have a $schema field
	contentRaw, ok := payload["content"]
	if !ok {
		t.Fatal("profile payload missing 'content' field")
	}
	content, ok := contentRaw.(map[string]any)
	if !ok {
		t.Fatalf("profile payload content is not an object: %T", contentRaw)
	}
	if _, ok := content["$schema"]; !ok {
		t.Fatal("profile payload content missing '$schema' field")
	}
}

// ===================================================================
// identity operations
// ===================================================================

func TestIdentityCreate(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	// fetch the chain
	var chain struct {
		State struct {
			DID       string `json:"did"`
			IsDeleted bool   `json:"isDeleted"`
		} `json:"state"`
		HeadCID string `json:"headCID"`
	}
	resp := getJSON(t, base+"/identities/"+id.did, &chain)
	if resp.StatusCode != 200 {
		t.Fatalf("GET identity: status %d", resp.StatusCode)
	}
	if chain.State.DID != id.did {
		t.Fatalf("DID: got %s, want %s", chain.State.DID, id.did)
	}
	if chain.State.IsDeleted {
		t.Fatal("new identity should not be deleted")
	}
	if chain.HeadCID == "" {
		t.Fatal("headCID is empty")
	}
}

func TestIdentityNotFound(t *testing.T) {
	base := relayURL(t)
	resp := getJSON(t, base+"/identities/did:dfos:nonexistent000000000", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestIdentityUpdate(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	// rotate: add a new auth key
	newAuth := newKeypair()
	kid := id.did + "#" + id.controller.keyID
	token, _, err := dfos.SignIdentityUpdate(
		id.genCID,
		[]dfos.MultikeyPublicKey{id.controller.mk},
		[]dfos.MultikeyPublicKey{newAuth.mk},
		[]dfos.MultikeyPublicKey{},
		kid,
		id.controller.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	res := postOperations(t, base, []string{token})
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("update: status %d, body: %s", res.StatusCode, body)
	}
	res.Body.Close()

	// verify chain length is now 2
	var chain struct {
		HeadCID string `json:"headCID"`
	}
	getJSON(t, base+"/identities/"+id.did, &chain)
	if chain.HeadCID == "" {
		t.Fatal("headCID is empty")
	}
}

func TestIdentityBatchCreate(t *testing.T) {
	base := relayURL(t)
	ctrl := newKeypair()
	auth := newKeypair()

	// create
	createToken, did, genCID, err := dfos.SignIdentityCreate(
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{auth.mk},
		[]dfos.MultikeyPublicKey{},
		ctrl.keyID,
		ctrl.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	// update in same batch — small delay to ensure createdAt ordering
	time.Sleep(2 * time.Millisecond)
	newAuth := newKeypair()
	kid := did + "#" + ctrl.keyID
	updateToken, _, err := dfos.SignIdentityUpdate(
		genCID,
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{newAuth.mk},
		[]dfos.MultikeyPublicKey{},
		kid,
		ctrl.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	res := postOperations(t, base, []string{createToken, updateToken})
	body := readBody(t, res)
	if res.StatusCode != 200 {
		t.Fatalf("batch create+update: status %d, body: %s", res.StatusCode, body)
	}

	// check both results accepted
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

func TestIdentityIdempotent(t *testing.T) {
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

	// submit twice
	res1 := postOperations(t, base, []string{token})
	if res1.StatusCode != 200 {
		t.Fatalf("first submit: %d", res1.StatusCode)
	}
	res1.Body.Close()

	res2 := postOperations(t, base, []string{token})
	if res2.StatusCode != 200 {
		t.Fatalf("second submit (idempotent): %d", res2.StatusCode)
	}
	res2.Body.Close()

	var chain struct {
		HeadCID string `json:"headCID"`
	}
	getJSON(t, base+"/identities/"+did, &chain)
	if chain.HeadCID == "" {
		t.Fatal("headCID is empty after idempotent resubmit")
	}
}

func TestIdentityDelete(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	kid := id.did + "#" + id.controller.keyID
	token, _, err := dfos.SignIdentityDelete(id.genCID, kid, id.controller.priv)
	if err != nil {
		t.Fatal(err)
	}

	res := postOperations(t, base, []string{token})
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("delete: status %d, body: %s", res.StatusCode, body)
	}
	res.Body.Close()

	// verify isDeleted
	var chain struct {
		State struct {
			IsDeleted bool `json:"isDeleted"`
		} `json:"state"`
	}
	getJSON(t, base+"/identities/"+id.did, &chain)
	if !chain.State.IsDeleted {
		t.Fatal("identity should be deleted")
	}
}

func TestIdentityRejectPostDelete(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	// delete
	kid := id.did + "#" + id.controller.keyID
	delToken, delCID, err := dfos.SignIdentityDelete(id.genCID, kid, id.controller.priv)
	if err != nil {
		t.Fatal(err)
	}
	res := postOperations(t, base, []string{delToken})
	res.Body.Close()

	// try to update after delete
	newAuth := newKeypair()
	updateToken, _, err := dfos.SignIdentityUpdate(
		delCID,
		[]dfos.MultikeyPublicKey{id.controller.mk},
		[]dfos.MultikeyPublicKey{newAuth.mk},
		[]dfos.MultikeyPublicKey{},
		kid,
		id.controller.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	res = postOperations(t, base, []string{updateToken})
	body := readBody(t, res)
	// relay should reject or return error in results
	var results struct {
		Results []struct {
			Error string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &results)
	if len(results.Results) > 0 && results.Results[0].Error == "" {
		t.Fatal("expected error for post-delete operation")
	}
}

// ===================================================================
// content operations
// ===================================================================

func TestContentCreate(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// fetch the chain
	var chain struct {
		State struct {
			ContentID  string `json:"contentId"`
			CreatorDID string `json:"creatorDID"`
			IsDeleted  bool   `json:"isDeleted"`
		} `json:"state"`
		HeadCID string `json:"headCID"`
	}
	resp := getJSON(t, base+"/content/"+cc.contentID, &chain)
	if resp.StatusCode != 200 {
		t.Fatalf("GET content: status %d", resp.StatusCode)
	}
	if chain.State.ContentID != cc.contentID {
		t.Fatalf("contentId: got %s, want %s", chain.State.ContentID, cc.contentID)
	}
	if chain.State.CreatorDID != id.did {
		t.Fatalf("creatorDID: got %s, want %s", chain.State.CreatorDID, id.did)
	}
	if chain.HeadCID == "" {
		t.Fatal("headCID is empty")
	}
}

func TestContentRejectUnknownIdentity(t *testing.T) {
	base := relayURL(t)
	kp := newKeypair()
	fakeDID := "did:dfos:fakefakefakefakefakef"
	docCID, _, _ := dfos.DocumentCID(map[string]any{"test": true})
	kid := fakeDID + "#" + kp.keyID
	token, _, _, err := dfos.SignContentCreate(fakeDID, docCID, kid, "", kp.priv)
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
		t.Fatal("expected error for content op with unknown identity")
	}
}

func TestContentDelete(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	kid := id.did + "#" + id.auth.keyID
	token, _, err := dfos.SignContentDelete(id.did, cc.genCID, kid, "deleting", "", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	res := postOperations(t, base, []string{token})
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("content delete: status %d, body: %s", res.StatusCode, body)
	}
	res.Body.Close()

	var chain struct {
		State struct {
			IsDeleted bool `json:"isDeleted"`
		} `json:"state"`
	}
	getJSON(t, base+"/content/"+cc.contentID, &chain)
	if !chain.State.IsDeleted {
		t.Fatal("content should be deleted")
	}
}

func TestContentForkRejection(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	kid := id.did + "#" + id.auth.keyID

	// first update (succeeds)
	doc2 := map[string]any{"type": "post", "title": "update 1"}
	docCID2, _, _ := dfos.DocumentCID(doc2)
	tok1, opCID1, err := dfos.SignContentUpdate(id.did, cc.genCID, docCID2, kid, "", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	res := postOperations(t, base, []string{tok1})
	res.Body.Close()
	_ = opCID1

	// second update with same previousCID (fork — should be accepted)
	doc3 := map[string]any{"type": "post", "title": "fork attempt"}
	docCID3, _, _ := dfos.DocumentCID(doc3)
	tok2, _, err := dfos.SignContentUpdate(id.did, cc.genCID, docCID3, kid, "", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	res = postOperations(t, base, []string{tok2})
	body := readBody(t, res)
	var forkResult struct {
		Results []struct {
			Status string `json:"status"`
		} `json:"results"`
	}
	json.Unmarshal(body, &forkResult)
	if len(forkResult.Results) == 0 || forkResult.Results[0].Status == "rejected" {
		t.Fatal("expected fork to be accepted")
	}
}

// ===================================================================
// operations by CID
// ===================================================================

func TestOperationByCID(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	var op struct {
		CID string `json:"cid"`
	}
	resp := getJSON(t, base+"/operations/"+id.genCID, &op)
	if resp.StatusCode != 200 {
		t.Fatalf("GET operation: status %d", resp.StatusCode)
	}
	if op.CID != id.genCID {
		t.Fatalf("cid: got %s, want %s", op.CID, id.genCID)
	}
}

func TestOperationNotFound(t *testing.T) {
	base := relayURL(t)
	resp := getJSON(t, base+"/operations/bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ===================================================================
// beacons
// ===================================================================

func TestBeaconCreate(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	kid := id.did + "#" + id.auth.keyID
	merkle := dfos.BuildMerkleRoot([]string{cc.contentID})
	token, beaconCID, err := dfos.SignBeacon(id.did, merkle, kid, id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	res := postOperations(t, base, []string{token})
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("beacon: status %d, body: %s", res.StatusCode, body)
	}
	res.Body.Close()

	// verify beacon is retrievable
	var beacon struct {
		BeaconCID string `json:"beaconCID"`
	}
	resp := getJSON(t, base+"/beacons/"+id.did, &beacon)
	if resp.StatusCode != 200 {
		t.Fatalf("GET beacon: status %d", resp.StatusCode)
	}
	if beacon.BeaconCID != beaconCID {
		t.Fatalf("beacon CID: got %s, want %s", beacon.BeaconCID, beaconCID)
	}
}

// ===================================================================
// countersignatures
// ===================================================================

func TestCountersignature(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// create witness identity
	witness := createIdentity(t, base)
	witnessKid := witness.did + "#" + witness.auth.keyID

	// countersign using the new standalone format
	csToken, _, err := dfos.SignCountersign(witness.did, cc.genCID, witnessKid, witness.auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	res := postOperations(t, base, []string{csToken})
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("countersign: status %d, body: %s", res.StatusCode, body)
	}
	res.Body.Close()

	// query countersigs
	var csResult struct {
		Countersignatures []string `json:"countersignatures"`
	}
	resp := getJSON(t, base+"/countersignatures/"+cc.genCID, &csResult)
	if resp.StatusCode != 200 {
		t.Fatalf("GET countersigs: status %d", resp.StatusCode)
	}
	if len(csResult.Countersignatures) != 1 {
		t.Fatalf("expected 1 countersig, got %d", len(csResult.Countersignatures))
	}
}

func TestCountersignatureIdempotent(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	witness := createIdentity(t, base)
	witnessKid := witness.did + "#" + witness.auth.keyID

	csToken, _, _ := dfos.SignCountersign(witness.did, cc.genCID, witnessKid, witness.auth.priv)

	// submit twice — dedup by witness per target
	postOperations(t, base, []string{csToken}).Body.Close()
	postOperations(t, base, []string{csToken}).Body.Close()

	var csResult struct {
		Countersignatures []string `json:"countersignatures"`
	}
	getJSON(t, base+"/countersignatures/"+cc.genCID, &csResult)
	if len(csResult.Countersignatures) != 1 {
		t.Fatalf("expected 1 countersig after dedup, got %d", len(csResult.Countersignatures))
	}
}

func TestCountersignatureMultiWitness(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// two different witnesses
	for i := 0; i < 2; i++ {
		w := createIdentity(t, base)
		wKid := w.did + "#" + w.auth.keyID
		cs, _, _ := dfos.SignCountersign(w.did, cc.genCID, wKid, w.auth.priv)
		postOperations(t, base, []string{cs}).Body.Close()
	}

	var csResult struct {
		Countersignatures []string `json:"countersignatures"`
	}
	getJSON(t, base+"/operations/"+cc.genCID+"/countersignatures", &csResult)
	if len(csResult.Countersignatures) != 2 {
		t.Fatalf("expected 2 countersigs from different witnesses, got %d", len(csResult.Countersignatures))
	}
}

func TestCountersignatureQueryPaths(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	witness := createIdentity(t, base)
	witnessKid := witness.did + "#" + witness.auth.keyID

	csToken, _, _ := dfos.SignCountersign(witness.did, cc.genCID, witnessKid, witness.auth.priv)
	postOperations(t, base, []string{csToken}).Body.Close()

	// both query paths should return the same data
	var r1 struct {
		Countersignatures []string `json:"countersignatures"`
	}
	var r2 struct {
		Countersignatures []string `json:"countersignatures"`
	}
	getJSON(t, base+"/operations/"+cc.genCID+"/countersignatures", &r1)
	getJSON(t, base+"/countersignatures/"+cc.genCID, &r2)

	if len(r1.Countersignatures) != len(r2.Countersignatures) {
		t.Fatalf("query paths returned different counts: %d vs %d",
			len(r1.Countersignatures), len(r2.Countersignatures))
	}
}

func TestCountersignatureNotFound(t *testing.T) {
	base := relayURL(t)
	resp := getJSON(t, base+"/countersignatures/bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ===================================================================
// blob upload + download
// ===================================================================

func TestBlobUploadDownload(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	tok := authToken(t, base, id)
	blobData, _ := json.Marshal(cc.document)

	// upload
	res := putBlob(t, base, cc.contentID, cc.genCID, tok, blobData)
	if res.StatusCode != 200 {
		body := readBody(t, res)
		t.Fatalf("blob upload: status %d, body: %s", res.StatusCode, body)
	}
	res.Body.Close()

	// download
	dlRes := getBlob(t, base, cc.contentID, tok)
	if dlRes.StatusCode != 200 {
		body := readBody(t, dlRes)
		t.Fatalf("blob download: status %d, body: %s", dlRes.StatusCode, body)
	}
	dlBody := readBody(t, dlRes)
	if string(dlBody) != string(blobData) {
		t.Fatal("downloaded blob does not match uploaded data")
	}
}

func TestBlobRejectMismatch(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	tok := authToken(t, base, id)
	wrongData := []byte("this does not match the documentCID")

	res := putBlob(t, base, cc.contentID, cc.genCID, tok, wrongData)
	if res.StatusCode == 200 {
		t.Fatal("expected rejection for mismatched blob data")
	}
	res.Body.Close()
}

func TestBlobRequireAuth(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	blobData, _ := json.Marshal(cc.document)
	url := fmt.Sprintf("%s/content/%s/blob/%s", base, cc.contentID, cc.genCID)
	req, _ := http.NewRequest("PUT", url, bytes.NewReader(blobData))
	req.Header.Set("content-type", "application/octet-stream")
	// no auth header
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 without auth, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestBlobDownloadWithCredential(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// upload as creator
	tok := authToken(t, base, id)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	// create reader identity with read credential
	reader := createIdentity(t, base)
	readerKid := id.did + "#" + id.auth.keyID
	cred, err := dfos.CreateCredential(
		id.did, reader.did, readerKid, "DFOSContentRead",
		5*time.Minute, cc.contentID, id.auth.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	// reader needs their own auth token + the credential in x-credential header
	readerTok := authToken(t, base, reader)
	dlRes := getBlobWithCred(t, base, cc.contentID, readerTok, cred)
	if dlRes.StatusCode != 200 {
		body := readBody(t, dlRes)
		t.Fatalf("credential download: status %d, body: %s", dlRes.StatusCode, body)
	}
	dlRes.Body.Close()
}

func TestBlobRejectWithoutCredential(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// upload
	tok := authToken(t, base, id)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	// random identity tries to download without credential
	reader := createIdentity(t, base)
	readerTok := authToken(t, base, reader)
	dlRes := getBlob(t, base, cc.contentID, readerTok)
	if dlRes.StatusCode == 200 {
		t.Fatal("expected rejection for download without read credential")
	}
	dlRes.Body.Close()
}

func TestBlobRejectCredentialFromNonCreator(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// upload
	tok := authToken(t, base, id)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	// imposter issues read credential
	imposter := createIdentity(t, base)
	reader := createIdentity(t, base)
	imposterKid := imposter.did + "#" + imposter.auth.keyID
	cred, _ := dfos.CreateCredential(
		imposter.did, reader.did, imposterKid, "DFOSContentRead",
		5*time.Minute, cc.contentID, imposter.auth.priv,
	)

	readerTok := authToken(t, base, reader)
	dlRes := getBlobWithCred(t, base, cc.contentID, readerTok, cred)
	if dlRes.StatusCode == 200 {
		t.Fatal("expected rejection for credential from non-creator")
	}
	dlRes.Body.Close()
}

// ===================================================================
// delegated content operations
// ===================================================================

func TestDelegatedContentUpdate(t *testing.T) {
	base := relayURL(t)
	creator := createIdentity(t, base)
	cc := createContent(t, base, creator)

	// create delegate identity
	delegate := createIdentity(t, base)

	// creator issues DFOSContentWrite credential to delegate
	creatorKid := creator.did + "#" + creator.auth.keyID
	cred, err := dfos.CreateCredential(
		creator.did, delegate.did, creatorKid, "DFOSContentWrite",
		5*time.Minute, cc.contentID, creator.auth.priv,
	)
	if err != nil {
		t.Fatal(err)
	}

	// delegate signs update with credential
	doc2 := map[string]any{"type": "post", "title": "delegate update"}
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
	if res.StatusCode != 200 {
		body := readBody(t, res)
		t.Fatalf("delegated update: status %d, body: %s", res.StatusCode, body)
	}
	res.Body.Close()

	// verify chain length is 2
	var chain struct {
		HeadCID string `json:"headCID"`
	}
	getJSON(t, base+"/content/"+cc.contentID, &chain)
	if chain.HeadCID == "" {
		t.Fatal("headCID is empty")
	}
}

func TestDelegatedUpdateWithoutCredential(t *testing.T) {
	base := relayURL(t)
	creator := createIdentity(t, base)
	cc := createContent(t, base, creator)

	delegate := createIdentity(t, base)
	doc2 := map[string]any{"type": "post", "title": "sneaky update"}
	docCID2, _, _ := dfos.DocumentCID(doc2)
	delegateKid := delegate.did + "#" + delegate.auth.keyID
	// no authorization credential
	token, _, err := dfos.SignContentUpdate(
		delegate.did, cc.genCID, docCID2, delegateKid, "", delegate.auth.priv,
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
		t.Fatal("expected error for delegated update without credential")
	}
}

func TestDelegatedBlobUpload(t *testing.T) {
	base := relayURL(t)
	creator := createIdentity(t, base)
	cc := createContent(t, base, creator)

	delegate := createIdentity(t, base)

	// issue write credential
	creatorKid := creator.did + "#" + creator.auth.keyID
	cred, _ := dfos.CreateCredential(
		creator.did, delegate.did, creatorKid, "DFOSContentWrite",
		5*time.Minute, cc.contentID, creator.auth.priv,
	)

	// delegate signs update
	doc2 := map[string]any{"type": "post", "title": "delegate with blob"}
	docCID2, _, _ := dfos.DocumentCID(doc2)
	delegateKid := delegate.did + "#" + delegate.auth.keyID
	updateToken, updateCID, _ := dfos.SignContentUpdateWithOptions(
		delegate.did, cc.genCID, docCID2, delegateKid, delegate.auth.priv,
		dfos.ContentUpdateOptions{Authorization: cred},
	)

	// submit update
	postOperations(t, base, []string{updateToken}).Body.Close()

	// delegate uploads blob via their operation CID
	delegateTok := authToken(t, base, delegate)
	blobData, _ := json.Marshal(doc2)
	res := putBlob(t, base, cc.contentID, updateCID, delegateTok, blobData)
	if res.StatusCode != 200 {
		body := readBody(t, res)
		t.Fatalf("delegated blob upload: status %d, body: %s", res.StatusCode, body)
	}
	res.Body.Close()
}

func TestBlobUploadRejectNonSigner(t *testing.T) {
	base := relayURL(t)
	creator := createIdentity(t, base)
	cc := createContent(t, base, creator)

	// third party tries to upload via creator's operation CID
	thirdParty := createIdentity(t, base)
	thirdPartyTok := authToken(t, base, thirdParty)
	blobData, _ := json.Marshal(cc.document)

	res := putBlob(t, base, cc.contentID, cc.genCID, thirdPartyTok, blobData)
	if res.StatusCode == 200 {
		t.Fatal("expected rejection for blob upload by non-signer")
	}
	res.Body.Close()
}

// ===================================================================
// auth edge cases
// ===================================================================

func TestAuthWrongAudience(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// auth token with wrong audience
	kid := id.did + "#" + id.auth.keyID
	wrongTok, _ := dfos.CreateAuthToken(id.did, "did:dfos:wrongrelay", kid, 5*time.Minute, id.auth.priv)

	blobData, _ := json.Marshal(cc.document)
	res := putBlob(t, base, cc.contentID, cc.genCID, wrongTok, blobData)
	if res.StatusCode == 200 {
		t.Fatal("expected rejection for wrong audience")
	}
	res.Body.Close()
}

func TestAuthExpiredToken(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// create an already-expired token
	relayDID := getRelayDID(t, base)
	kid := id.did + "#" + id.auth.keyID
	expiredTok, _ := dfos.CreateAuthToken(id.did, relayDID, kid, -1*time.Hour, id.auth.priv)

	blobData, _ := json.Marshal(cc.document)
	res := putBlob(t, base, cc.contentID, cc.genCID, expiredTok, blobData)
	if res.StatusCode == 200 {
		t.Fatal("expected rejection for expired token")
	}
	res.Body.Close()
}

func TestAuthRotatedOutKey(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// save old auth key
	oldAuth := id.auth

	// rotate to new auth key
	newAuth := newKeypair()
	ctrlKid := id.did + "#" + id.controller.keyID
	updateToken, _, err := dfos.SignIdentityUpdate(
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
	postOperations(t, base, []string{updateToken}).Body.Close()

	// try to use old auth key
	oldTok := authTokenWithKey(t, base, id, oldAuth)
	blobData, _ := json.Marshal(cc.document)
	res := putBlob(t, base, cc.contentID, cc.genCID, oldTok, blobData)
	if res.StatusCode == 200 {
		t.Fatal("expected rejection for rotated-out auth key")
	}
	res.Body.Close()
}

// ===================================================================
// blob download at ref
// ===================================================================

func TestBlobDownloadAtRef(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// upload initial blob
	tok := authToken(t, base, id)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	// download at specific ref
	dlRes := getBlob(t, base, cc.contentID, tok, cc.genCID)
	if dlRes.StatusCode != 200 {
		body := readBody(t, dlRes)
		t.Fatalf("download at ref: status %d, body: %s", dlRes.StatusCode, body)
	}
	dlBody := readBody(t, dlRes)
	if string(dlBody) != string(blobData) {
		t.Fatal("downloaded blob at ref does not match")
	}
}

func TestBlobDownloadAtHead(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	tok := authToken(t, base, id)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	// download at head (no ref)
	dlRes := getBlob(t, base, cc.contentID, tok)
	if dlRes.StatusCode != 200 {
		body := readBody(t, dlRes)
		t.Fatalf("download at head: status %d, body: %s", dlRes.StatusCode, body)
	}
	dlBody := readBody(t, dlRes)
	if string(dlBody) != string(blobData) {
		t.Fatal("downloaded blob at head does not match")
	}
}

func TestBlobDownloadDeletedContent(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// upload, then delete
	tok := authToken(t, base, id)
	blobData, _ := json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blobData).Body.Close()

	kid := id.did + "#" + id.auth.keyID
	delToken, _, _ := dfos.SignContentDelete(id.did, cc.genCID, kid, "", "", id.auth.priv)
	postOperations(t, base, []string{delToken}).Body.Close()

	// download at head should 404
	dlRes := getBlob(t, base, cc.contentID, tok)
	if dlRes.StatusCode != 404 {
		t.Fatalf("expected 404 for deleted content blob, got %d", dlRes.StatusCode)
	}
	dlRes.Body.Close()
}

// ===================================================================
// input validation
// ===================================================================

func TestRejectInvalidJSON(t *testing.T) {
	base := relayURL(t)
	resp, err := http.Post(base+"/operations", "application/json", bytes.NewReader([]byte("not json")))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == 200 {
		t.Fatal("expected rejection for invalid JSON")
	}
	resp.Body.Close()
}

func TestRejectEmptyOperations(t *testing.T) {
	base := relayURL(t)
	payload, _ := json.Marshal(map[string]any{"operations": []string{}})
	resp, err := http.Post(base+"/operations", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == 200 {
		t.Fatal("expected rejection for empty operations")
	}
	resp.Body.Close()
}

func TestRejectMalformedJWS(t *testing.T) {
	base := relayURL(t)
	res := postOperations(t, base, []string{"not.a.valid-jws-token"})
	body := readBody(t, res)
	var results struct {
		Results []struct {
			Error string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &results)
	if len(results.Results) > 0 && results.Results[0].Error == "" {
		t.Fatal("expected error for malformed JWS")
	}
}
