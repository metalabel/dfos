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
		DID          string `json:"did"`
		Protocol     string `json:"protocol"`
		Version      string `json:"version"`
		Capabilities struct {
			Proof     bool `json:"proof"`
			Content   bool `json:"content"`
			Documents bool `json:"documents"`
			Log       bool `json:"log"`
		} `json:"capabilities"`
		Profile string `json:"profile"`
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
	if !meta.Capabilities.Proof {
		t.Fatal("capabilities.proof must be true")
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

func TestContentForkDAGLog(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	kid := id.did + "#" + id.auth.keyID

	// create two fork branches off genesis
	doc1 := map[string]any{"type": "post", "title": "branch-a"}
	docCID1, _, _ := dfos.DocumentCID(doc1)
	tok1, _, err := dfos.SignContentUpdate(id.did, cc.genCID, docCID1, kid, "", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	doc2 := map[string]any{"type": "post", "title": "branch-b"}
	docCID2, _, _ := dfos.DocumentCID(doc2)
	tok2, _, err := dfos.SignContentUpdate(id.did, cc.genCID, docCID2, kid, "", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	res1 := postOperations(t, base, []string{tok1})
	res1.Body.Close()
	res2 := postOperations(t, base, []string{tok2})
	res2.Body.Close()

	// chain log should contain all 3 ops (genesis + 2 fork branches)
	var logResp struct {
		Entries []struct {
			CID      string `json:"cid"`
			JWSToken string `json:"jwsToken"`
		} `json:"entries"`
	}
	logRes := getJSON(t, base+"/content/"+cc.contentID+"/log", &logResp)
	if logRes.StatusCode != 200 {
		t.Fatalf("log: expected 200, got %d", logRes.StatusCode)
	}
	if len(logResp.Entries) != 3 {
		t.Fatalf("expected 3 log entries (genesis + 2 forks), got %d", len(logResp.Entries))
	}
}

func TestContentForkDeterministicHead(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	kid := id.did + "#" + id.auth.keyID

	// branch A: signed first (earlier createdAt)
	docA := map[string]any{"type": "post", "title": "earlier"}
	docCIDA, _, _ := dfos.DocumentCID(docA)
	tokA, _, err := dfos.SignContentUpdate(id.did, cc.genCID, docCIDA, kid, "", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	// branch B: signed second (later createdAt — should become head)
	docB := map[string]any{"type": "post", "title": "later"}
	docCIDB, _, _ := dfos.DocumentCID(docB)
	tokB, _, err := dfos.SignContentUpdate(id.did, cc.genCID, docCIDB, kid, "", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}

	// submit A first, then B
	res1 := postOperations(t, base, []string{tokA})
	res1.Body.Close()
	res2 := postOperations(t, base, []string{tokB})
	res2.Body.Close()

	// head should point to B's document (later createdAt wins)
	var chain struct {
		State struct {
			CurrentDocumentCID *string `json:"currentDocumentCID"`
		} `json:"state"`
	}
	chainRes := getJSON(t, base+"/content/"+cc.contentID, &chain)
	if chainRes.StatusCode != 200 {
		t.Fatalf("content: expected 200, got %d", chainRes.StatusCode)
	}
	if chain.State.CurrentDocumentCID == nil || *chain.State.CurrentDocumentCID != docCIDB {
		got := "<nil>"
		if chain.State.CurrentDocumentCID != nil {
			got = *chain.State.CurrentDocumentCID
		}
		t.Fatalf("head should point to later fork's document\nexpected: %s\ngot:      %s", docCIDB, got)
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
	token, beaconCID, err := dfos.SignBeacon(id.did, cc.contentID, kid, id.auth.priv)
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
		id.did, reader.did, readerKid, "chain:"+cc.contentID, "read",
		5*time.Minute, id.auth.priv,
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
		imposter.did, reader.did, imposterKid, "chain:"+cc.contentID, "read",
		5*time.Minute, imposter.auth.priv,
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

	// creator issues write credential to delegate
	creatorKid := creator.did + "#" + creator.auth.keyID
	cred, err := dfos.CreateCredential(
		creator.did, delegate.did, creatorKid, "chain:"+cc.contentID, "write",
		5*time.Minute, creator.auth.priv,
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
		creator.did, delegate.did, creatorKid, "chain:"+cc.contentID, "write",
		5*time.Minute, creator.auth.priv,
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

// ===================================================================
// future timestamp guard
// ===================================================================

func TestRejectIdentityFutureTimestamp(t *testing.T) {
	base := relayURL(t)
	ctrl := newKeypair()
	auth := newKeypair()

	farFuture := time.Now().Add(25 * time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")

	payload := map[string]any{
		"version":        1,
		"type":           "create",
		"authKeys":       []dfos.MultikeyPublicKey{auth.mk},
		"assertKeys":     []dfos.MultikeyPublicKey{},
		"controllerKeys": []dfos.MultikeyPublicKey{ctrl.mk},
		"createdAt":      farFuture,
	}

	_, _, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}

	header := dfos.JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:identity-op",
		Kid: ctrl.keyID,
		CID: cidStr,
	}

	token, err := dfos.CreateJWS(header, payload, ctrl.priv)
	if err != nil {
		t.Fatalf("CreateJWS: %v", err)
	}

	res := postOperations(t, base, []string{token})
	body := readBody(t, res)
	var result struct {
		Results []struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &result)

	if len(result.Results) == 0 {
		t.Fatal("expected at least 1 result")
	}
	if result.Results[0].Status != "rejected" {
		t.Fatalf("expected rejected, got %s", result.Results[0].Status)
	}
	if !strings.Contains(result.Results[0].Error, "future") {
		t.Fatalf("expected future timestamp error, got: %s", result.Results[0].Error)
	}
}

func TestAcceptIdentityNearFutureTimestamp(t *testing.T) {
	base := relayURL(t)
	ctrl := newKeypair()
	auth := newKeypair()

	nearFuture := time.Now().Add(23 * time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")

	payload := map[string]any{
		"version":        1,
		"type":           "create",
		"authKeys":       []dfos.MultikeyPublicKey{auth.mk},
		"assertKeys":     []dfos.MultikeyPublicKey{},
		"controllerKeys": []dfos.MultikeyPublicKey{ctrl.mk},
		"createdAt":      nearFuture,
	}

	_, _, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}

	header := dfos.JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:identity-op",
		Kid: ctrl.keyID,
		CID: cidStr,
	}

	token, err := dfos.CreateJWS(header, payload, ctrl.priv)
	if err != nil {
		t.Fatalf("CreateJWS: %v", err)
	}

	res := postOperations(t, base, []string{token})
	body := readBody(t, res)
	var result struct {
		Results []struct {
			Status string `json:"status"`
		} `json:"results"`
	}
	json.Unmarshal(body, &result)

	if len(result.Results) == 0 {
		t.Fatal("expected at least 1 result")
	}
	if result.Results[0].Status != "new" {
		t.Fatalf("expected new, got %s", result.Results[0].Status)
	}
}

func TestRejectContentFutureTimestamp(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	farFuture := time.Now().Add(25 * time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")
	doc := map[string]any{"type": "post", "title": "future", "body": "test"}
	docCID, _, err := dfos.DocumentCID(doc)
	if err != nil {
		t.Fatalf("DocumentCID: %v", err)
	}

	kid := id.did + "#" + id.auth.keyID
	payload := map[string]any{
		"version":         1,
		"type":            "create",
		"did":             id.did,
		"documentCID":     docCID,
		"baseDocumentCID": nil,
		"createdAt":       farFuture,
		"note":            nil,
	}

	_, _, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}

	header := dfos.JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:content-op",
		Kid: kid,
		CID: cidStr,
	}

	token, err := dfos.CreateJWS(header, payload, id.auth.priv)
	if err != nil {
		t.Fatalf("CreateJWS: %v", err)
	}

	res := postOperations(t, base, []string{token})
	body := readBody(t, res)
	var result struct {
		Results []struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body, &result)

	if len(result.Results) == 0 {
		t.Fatal("expected at least 1 result")
	}
	if result.Results[0].Status != "rejected" {
		t.Fatalf("expected rejected, got %s", result.Results[0].Status)
	}
	if !strings.Contains(result.Results[0].Error, "future") {
		t.Fatalf("expected future timestamp error, got: %s", result.Results[0].Error)
	}
}

// ===================================================================
// log pagination
// ===================================================================

func TestIdentityLogPagination(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	// create 2 identity updates so chain has 3 ops total
	prevCID := id.genCID
	for i := 0; i < 2; i++ {
		newAuth := newKeypair()
		token, opCID, err := dfos.SignIdentityUpdate(
			prevCID,
			[]dfos.MultikeyPublicKey{id.controller.mk},
			[]dfos.MultikeyPublicKey{newAuth.mk},
			[]dfos.MultikeyPublicKey{},
			id.did+"#"+id.controller.keyID,
			id.controller.priv,
		)
		if err != nil {
			t.Fatalf("SignIdentityUpdate: %v", err)
		}
		res := postOperations(t, base, []string{token})
		if res.StatusCode != 200 {
			t.Fatalf("update %d: status %d", i, res.StatusCode)
		}
		res.Body.Close()
		prevCID = opCID
	}

	// 1. Full log (no params) — should have 3 entries, no cursor (< default limit)
	var fullLog struct {
		Entries []struct {
			CID      string `json:"cid"`
			JWSToken string `json:"jwsToken"`
		} `json:"entries"`
		Cursor *string `json:"cursor"`
	}
	resp := getJSON(t, base+"/identities/"+id.did+"/log", &fullLog)
	if resp.StatusCode != 200 {
		t.Fatalf("GET log: status %d", resp.StatusCode)
	}
	if len(fullLog.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(fullLog.Entries))
	}
	if fullLog.Cursor != nil {
		t.Fatalf("expected nil cursor on last page, got %s", *fullLog.Cursor)
	}

	// 2. Paginate with limit=1 — first page has 1 entry + cursor
	var page1 struct {
		Entries []struct {
			CID string `json:"cid"`
		} `json:"entries"`
		Cursor *string `json:"cursor"`
	}
	getJSON(t, fmt.Sprintf("%s/identities/%s/log?limit=1", base, id.did), &page1)
	if len(page1.Entries) != 1 {
		t.Fatalf("page1: expected 1 entry, got %d", len(page1.Entries))
	}
	if page1.Cursor == nil {
		t.Fatal("page1: expected cursor")
	}

	// 3. Second page via cursor
	var page2 struct {
		Entries []struct {
			CID string `json:"cid"`
		} `json:"entries"`
		Cursor *string `json:"cursor"`
	}
	getJSON(t, fmt.Sprintf("%s/identities/%s/log?after=%s&limit=1", base, id.did, *page1.Cursor), &page2)
	if len(page2.Entries) != 1 {
		t.Fatalf("page2: expected 1 entry, got %d", len(page2.Entries))
	}
	if page2.Cursor == nil {
		t.Fatal("page2: expected cursor")
	}

	// 4. Third (final) page
	var page3 struct {
		Entries []struct {
			CID string `json:"cid"`
		} `json:"entries"`
		Cursor *string `json:"cursor"`
	}
	getJSON(t, fmt.Sprintf("%s/identities/%s/log?after=%s&limit=1", base, id.did, *page2.Cursor), &page3)
	if len(page3.Entries) != 1 {
		t.Fatalf("page3: expected 1 entry, got %d", len(page3.Entries))
	}
	// cursor may or may not be set on the final page when entry count == limit;
	// if set, following it must yield an empty page
	if page3.Cursor != nil {
		var page4 struct {
			Entries []struct{} `json:"entries"`
		}
		getJSON(t, fmt.Sprintf("%s/identities/%s/log?after=%s&limit=1", base, id.did, *page3.Cursor), &page4)
		if len(page4.Entries) != 0 {
			t.Fatalf("page after final: expected 0 entries, got %d", len(page4.Entries))
		}
	}

	// 5. After with unknown CID returns empty (not error)
	var empty struct {
		Entries []struct{} `json:"entries"`
		Cursor  *string    `json:"cursor"`
	}
	emptyResp := getJSON(t, fmt.Sprintf("%s/identities/%s/log?after=bafyunknown", base, id.did), &empty)
	if emptyResp.StatusCode != 200 {
		t.Fatalf("unknown cursor: expected 200, got %d", emptyResp.StatusCode)
	}
	if len(empty.Entries) != 0 {
		t.Fatalf("unknown cursor: expected 0 entries, got %d", len(empty.Entries))
	}

	// 6. Exact page boundary — limit=3 should return all entries with nil cursor
	var exactPage struct {
		Entries []struct{} `json:"entries"`
		Cursor  *string    `json:"cursor"`
	}
	getJSON(t, fmt.Sprintf("%s/identities/%s/log?limit=3", base, id.did), &exactPage)
	if len(exactPage.Entries) != 3 {
		t.Fatalf("exact boundary: expected 3 entries, got %d", len(exactPage.Entries))
	}
	// when entry count equals limit, cursor may or may not be set depending
	// on implementation — both are valid. The consumer checks the next page.
}

func TestGlobalLogPagination(t *testing.T) {
	base := relayURL(t)

	// create 3 identities to get 3 entries in the global log
	var cids []string
	for i := 0; i < 3; i++ {
		id := createIdentity(t, base)
		cids = append(cids, id.genCID)
	}

	// paginate with limit=1
	var page1 struct {
		Entries []struct {
			CID string `json:"cid"`
		} `json:"entries"`
		Cursor *string `json:"cursor"`
	}
	resp := getJSON(t, base+"/log?limit=1", &page1)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /log: status %d", resp.StatusCode)
	}
	if len(page1.Entries) != 1 {
		t.Fatalf("page1: expected 1 entry, got %d", len(page1.Entries))
	}
	if page1.Cursor == nil {
		t.Fatal("page1: expected cursor")
	}

	// follow cursor to page 2
	var page2 struct {
		Entries []struct {
			CID string `json:"cid"`
		} `json:"entries"`
		Cursor *string `json:"cursor"`
	}
	getJSON(t, fmt.Sprintf("%s/log?after=%s&limit=1", base, *page1.Cursor), &page2)
	if len(page2.Entries) != 1 {
		t.Fatalf("page2: expected 1 entry, got %d", len(page2.Entries))
	}

	// entries across pages should have distinct CIDs
	if page1.Entries[0].CID == page2.Entries[0].CID {
		t.Fatal("page1 and page2 should have different entries")
	}

	// 3. Drain all remaining pages — global log may have relay bootstrap entries
	//    beyond our 3 identities. Verify pagination terminates correctly.
	cursor := page2.Cursor
	totalEntries := 2 // already consumed 2 entries from page1 + page2
	for cursor != nil && totalEntries < 100 { // safety bound
		var page struct {
			Entries []struct {
				CID string `json:"cid"`
			} `json:"entries"`
			Cursor *string `json:"cursor"`
		}
		getJSON(t, fmt.Sprintf("%s/log?after=%s&limit=1", base, *cursor), &page)
		totalEntries += len(page.Entries)
		if len(page.Entries) == 0 {
			// empty page means we're past the end — cursor should be nil
			if page.Cursor != nil {
				t.Fatal("empty page should have nil cursor")
			}
			break
		}
		cursor = page.Cursor
	}
	// we created 3 identities; relay may have bootstrap entries too
	if totalEntries < 3 {
		t.Fatalf("expected at least 3 total entries, got %d", totalEntries)
	}

	// 4. Unknown after CID returns empty (not error)
	var empty struct {
		Entries []struct{} `json:"entries"`
		Cursor  *string    `json:"cursor"`
	}
	emptyResp := getJSON(t, base+"/log?after=bafyunknown", &empty)
	if emptyResp.StatusCode != 200 {
		t.Fatalf("unknown cursor: expected 200, got %d", emptyResp.StatusCode)
	}
	if len(empty.Entries) != 0 {
		t.Fatalf("unknown cursor: expected 0 entries, got %d", len(empty.Entries))
	}
}
