package conformance

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// ===================================================================
// artifact ingestion
// ===================================================================

func TestArtifactCreate(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	kid := id.did + "#" + id.auth.keyID
	content := map[string]any{"$schema": "test/v1", "title": "hello artifact"}
	token, artifactCID, err := dfos.SignArtifact(id.did, content, kid, id.auth.priv)
	if err != nil {
		t.Fatalf("SignArtifact: %v", err)
	}

	res := postOperations(t, base, []string{token})
	body := readBody(t, res)

	var result struct {
		Results []struct {
			CID    string `json:"cid"`
			Status string `json:"status"`
			Kind   string `json:"kind"`
		} `json:"results"`
	}
	json.Unmarshal(body, &result)

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	if result.Results[0].Status != "new" {
		t.Fatalf("expected accepted, got %s", result.Results[0].Status)
	}
	if result.Results[0].Kind != "artifact" {
		t.Fatalf("expected kind artifact, got %s", result.Results[0].Kind)
	}
	if result.Results[0].CID != artifactCID {
		t.Fatalf("CID mismatch: got %s, want %s", result.Results[0].CID, artifactCID)
	}

	// artifact should be retrievable via GET /operations/:cid
	var op map[string]any
	resp := getJSON(t, base+"/operations/"+artifactCID, &op)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /operations/%s: status %d", artifactCID, resp.StatusCode)
	}
}

func TestArtifactFromUnknownIdentity(t *testing.T) {
	base := relayURL(t)

	// create identity but do NOT ingest it
	kp := newKeypair()
	_, did, _, err := dfos.SignIdentityCreate(
		[]dfos.MultikeyPublicKey{kp.mk},
		[]dfos.MultikeyPublicKey{kp.mk},
		[]dfos.MultikeyPublicKey{},
		kp.keyID,
		kp.priv,
	)
	if err != nil {
		t.Fatalf("SignIdentityCreate: %v", err)
	}

	kid := did + "#" + kp.keyID
	content := map[string]any{"$schema": "test/v1", "title": "unknown"}
	token, _, err := dfos.SignArtifact(did, content, kid, kp.priv)
	if err != nil {
		t.Fatalf("SignArtifact: %v", err)
	}

	res := postOperations(t, base, []string{token})
	body := readBody(t, res)

	var result struct {
		Results []struct {
			Status string `json:"status"`
		} `json:"results"`
	}
	json.Unmarshal(body, &result)

	if result.Results[0].Status != "rejected" {
		t.Fatalf("expected rejected, got %s", result.Results[0].Status)
	}
}

func TestArtifactFromDeletedIdentity(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	// delete the identity
	kid := id.did + "#" + id.controller.keyID
	deleteToken, _, err := dfos.SignIdentityDelete(id.genCID, kid, id.controller.priv)
	if err != nil {
		t.Fatalf("SignIdentityDelete: %v", err)
	}
	postOperations(t, base, []string{deleteToken})

	// try to create an artifact with the deleted identity
	artKid := id.did + "#" + id.auth.keyID
	content := map[string]any{"$schema": "test/v1", "title": "after delete"}
	token, _, err := dfos.SignArtifact(id.did, content, artKid, id.auth.priv)
	if err != nil {
		t.Fatalf("SignArtifact: %v", err)
	}

	res := postOperations(t, base, []string{token})
	body := readBody(t, res)

	var result struct {
		Results []struct {
			Status string `json:"status"`
		} `json:"results"`
	}
	json.Unmarshal(body, &result)

	if result.Results[0].Status != "rejected" {
		t.Fatalf("expected rejected, got %s", result.Results[0].Status)
	}
}

func TestArtifactIdempotent(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	kid := id.did + "#" + id.auth.keyID
	content := map[string]any{"$schema": "test/v1", "title": "dedup me"}
	token, _, err := dfos.SignArtifact(id.did, content, kid, id.auth.priv)
	if err != nil {
		t.Fatalf("SignArtifact: %v", err)
	}

	// submit twice
	res1 := postOperations(t, base, []string{token})
	body1 := readBody(t, res1)
	res2 := postOperations(t, base, []string{token})
	body2 := readBody(t, res2)

	var r1, r2 struct {
		Results []struct {
			Status string `json:"status"`
		} `json:"results"`
	}
	json.Unmarshal(body1, &r1)
	json.Unmarshal(body2, &r2)

	if r1.Results[0].Status != "new" {
		t.Fatalf("first submit: expected accepted, got %s", r1.Results[0].Status)
	}
	if r2.Results[0].Status != "new" {
		t.Fatalf("second submit: expected accepted (idempotent), got %s", r2.Results[0].Status)
	}
}

func TestArtifactRetrieveByCID(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	kid := id.did + "#" + id.auth.keyID
	content := map[string]any{"$schema": "test/v1", "title": "retrievable"}
	token, artifactCID, err := dfos.SignArtifact(id.did, content, kid, id.auth.priv)
	if err != nil {
		t.Fatalf("SignArtifact: %v", err)
	}
	postOperations(t, base, []string{token})

	// retrieve by CID
	var op map[string]any
	resp := getJSON(t, base+"/operations/"+artifactCID, &op)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	jwsToken, ok := op["jwsToken"].(string)
	if !ok || jwsToken == "" {
		t.Fatal("expected jwsToken in operation response")
	}
}

func TestArtifactInBatchWithIdentity(t *testing.T) {
	base := relayURL(t)

	// create identity + artifact in the same batch
	ctrl := newKeypair()
	auth := newKeypair()

	identityToken, did, _, err := dfos.SignIdentityCreate(
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{auth.mk},
		[]dfos.MultikeyPublicKey{},
		ctrl.keyID,
		ctrl.priv,
	)
	if err != nil {
		t.Fatalf("SignIdentityCreate: %v", err)
	}

	kid := did + "#" + auth.keyID
	content := map[string]any{"$schema": "test/v1", "title": "batched artifact"}
	artifactToken, _, err := dfos.SignArtifact(did, content, kid, auth.priv)
	if err != nil {
		t.Fatalf("SignArtifact: %v", err)
	}

	// submit artifact first, identity second — relay should sort by dependency
	res := postOperations(t, base, []string{artifactToken, identityToken})
	body := readBody(t, res)

	var result struct {
		Results []struct {
			Status string `json:"status"`
		} `json:"results"`
	}
	json.Unmarshal(body, &result)

	if len(result.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(result.Results))
	}
	// results are in input order, both should be accepted
	for i, r := range result.Results {
		if r.Status != "new" {
			t.Fatalf("result[%d]: expected accepted, got %s", i, r.Status)
		}
	}
}

// ===================================================================
// operation log
// ===================================================================

func TestLogGlobal(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	// create some content
	cc := createContent(t, base, id)
	_ = cc

	// fetch global log
	var logResp struct {
		Entries []struct {
			CID      string `json:"cid"`
			JWSToken string `json:"jwsToken"`
			Kind     string `json:"kind"`
			ChainID  string `json:"chainId"`
		} `json:"entries"`
		Cursor *string `json:"cursor"`
	}
	resp := getJSON(t, base+"/log", &logResp)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /log: status %d", resp.StatusCode)
	}

	if len(logResp.Entries) < 2 {
		t.Fatalf("expected at least 2 log entries (relay bootstrap ops), got %d", len(logResp.Entries))
	}

	// every entry should have a CID and jwsToken
	for i, e := range logResp.Entries {
		if e.CID == "" {
			t.Fatalf("entry[%d]: missing cid", i)
		}
		if e.JWSToken == "" {
			t.Fatalf("entry[%d]: missing jwsToken", i)
		}
		if e.Kind == "" {
			t.Fatalf("entry[%d]: missing kind", i)
		}
	}
}

func TestLogPagination(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	// create several content chains to have enough log entries
	for i := 0; i < 3; i++ {
		createContent(t, base, id)
	}

	// fetch with limit=2
	var page1 struct {
		Entries []struct {
			CID string `json:"cid"`
		} `json:"entries"`
		Cursor *string `json:"cursor"`
	}
	resp := getJSON(t, base+"/log?limit=2", &page1)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /log?limit=2: status %d", resp.StatusCode)
	}

	if len(page1.Entries) != 2 {
		t.Fatalf("expected 2 entries on page 1, got %d", len(page1.Entries))
	}
	if page1.Cursor == nil {
		t.Fatal("expected non-nil cursor on page 1")
	}

	// fetch page 2
	var page2 struct {
		Entries []struct {
			CID string `json:"cid"`
		} `json:"entries"`
		Cursor *string `json:"cursor"`
	}
	resp2 := getJSON(t, fmt.Sprintf("%s/log?limit=2&after=%s", base, *page1.Cursor), &page2)
	if resp2.StatusCode != 200 {
		t.Fatalf("GET /log page 2: status %d", resp2.StatusCode)
	}

	if len(page2.Entries) < 1 {
		t.Fatal("expected at least 1 entry on page 2")
	}

	// pages should not overlap
	if page2.Entries[0].CID == page1.Entries[0].CID {
		t.Fatal("page 2 first entry should differ from page 1 first entry")
	}
}

func TestLogPerIdentity(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	var logResp struct {
		Entries []struct {
			CID      string `json:"cid"`
			JWSToken string `json:"jwsToken"`
		} `json:"entries"`
		Cursor *string `json:"cursor"`
	}
	resp := getJSON(t, base+"/identities/"+id.did+"/log", &logResp)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /identities/%s/log: status %d", id.did, resp.StatusCode)
	}

	if len(logResp.Entries) != 1 {
		t.Fatalf("expected 1 identity log entry (genesis), got %d", len(logResp.Entries))
	}

	if logResp.Entries[0].CID != id.genCID {
		t.Fatalf("expected genesis CID %s, got %s", id.genCID, logResp.Entries[0].CID)
	}
	if logResp.Entries[0].JWSToken == "" {
		t.Fatal("expected jwsToken in per-identity log entry")
	}
}

func TestLogPerContent(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	var logResp struct {
		Entries []struct {
			CID      string `json:"cid"`
			JWSToken string `json:"jwsToken"`
		} `json:"entries"`
		Cursor *string `json:"cursor"`
	}
	resp := getJSON(t, base+"/content/"+cc.contentID+"/log", &logResp)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /content/%s/log: status %d", cc.contentID, resp.StatusCode)
	}

	if len(logResp.Entries) != 1 {
		t.Fatalf("expected 1 content log entry (genesis), got %d", len(logResp.Entries))
	}

	if logResp.Entries[0].CID != cc.genCID {
		t.Fatalf("expected genesis CID %s, got %s", cc.genCID, logResp.Entries[0].CID)
	}
	if logResp.Entries[0].JWSToken == "" {
		t.Fatal("expected jwsToken in per-content log entry")
	}
}

func TestLogContainsAllKinds(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	// create a beacon
	beaconKid := id.did + "#" + id.controller.keyID
	merkle := dfos.BuildMerkleRoot([]string{cc.contentID})
	beaconToken, _, err := dfos.SignBeacon(id.did, merkle, beaconKid, id.controller.priv)
	if err != nil {
		t.Fatalf("SignBeacon: %v", err)
	}
	postOperations(t, base, []string{beaconToken})

	// create an artifact
	artKid := id.did + "#" + id.auth.keyID
	artContent := map[string]any{"$schema": "test/v1", "title": "log test"}
	artToken, _, err := dfos.SignArtifact(id.did, artContent, artKid, id.auth.priv)
	if err != nil {
		t.Fatalf("SignArtifact: %v", err)
	}
	postOperations(t, base, []string{artToken})

	// create a countersignature (from a second identity)
	witness := createIdentity(t, base)
	witnessKid := witness.did + "#" + witness.auth.keyID
	csToken, _, err := dfos.SignCountersign(witness.did, cc.genCID, witnessKid, witness.auth.priv)
	if err != nil {
		t.Fatalf("SignCountersign: %v", err)
	}
	postOperations(t, base, []string{csToken})

	// fetch the global log
	var logResp struct {
		Entries []struct {
			Kind string `json:"kind"`
		} `json:"entries"`
	}
	getJSON(t, base+"/log?limit=1000", &logResp)

	kinds := map[string]bool{}
	for _, e := range logResp.Entries {
		kinds[e.Kind] = true
	}

	for _, expected := range []string{"identity-op", "content-op", "beacon", "artifact", "countersign"} {
		if !kinds[expected] {
			t.Errorf("expected kind %q in global log, not found", expected)
		}
	}
}

func TestLogUnknownIdentity(t *testing.T) {
	base := relayURL(t)
	resp, err := http.Get(base + "/identities/did:dfos:nonexistent/log")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestLogUnknownContent(t *testing.T) {
	base := relayURL(t)
	resp, err := http.Get(base + "/content/nonexistent/log")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ===================================================================
// countersign additional coverage
// ===================================================================

func TestCountersignFromDeletedWitness(t *testing.T) {
	base := relayURL(t)
	author := createIdentity(t, base)
	cc := createContent(t, base, author)

	witness := createIdentity(t, base)

	// delete the witness
	delKid := witness.did + "#" + witness.controller.keyID
	delToken, _, err := dfos.SignIdentityDelete(witness.genCID, delKid, witness.controller.priv)
	if err != nil {
		t.Fatalf("SignIdentityDelete: %v", err)
	}
	postOperations(t, base, []string{delToken})

	// try to countersign with deleted witness
	csKid := witness.did + "#" + witness.auth.keyID
	csToken, _, err := dfos.SignCountersign(witness.did, cc.genCID, csKid, witness.auth.priv)
	if err != nil {
		t.Fatalf("SignCountersign: %v", err)
	}

	res := postOperations(t, base, []string{csToken})
	body := readBody(t, res)

	var result struct {
		Results []struct {
			Status string `json:"status"`
		} `json:"results"`
	}
	json.Unmarshal(body, &result)

	if result.Results[0].Status != "rejected" {
		t.Fatalf("expected rejected for deleted witness, got %s", result.Results[0].Status)
	}
}

func TestCountersignTargetingCountersign(t *testing.T) {
	base := relayURL(t)

	author := createIdentity(t, base)
	cc := createContent(t, base, author)

	// witness 1 countersigns the content op
	w1 := createIdentity(t, base)
	w1Kid := w1.did + "#" + w1.auth.keyID
	cs1Token, cs1CID, err := dfos.SignCountersign(w1.did, cc.genCID, w1Kid, w1.auth.priv)
	if err != nil {
		t.Fatalf("SignCountersign w1: %v", err)
	}
	postOperations(t, base, []string{cs1Token})

	// witness 2 countersigns the first countersign (meta-attestation)
	w2 := createIdentity(t, base)
	w2Kid := w2.did + "#" + w2.auth.keyID
	cs2Token, _, err := dfos.SignCountersign(w2.did, cs1CID, w2Kid, w2.auth.priv)
	if err != nil {
		t.Fatalf("SignCountersign w2: %v", err)
	}

	res := postOperations(t, base, []string{cs2Token})
	body := readBody(t, res)

	var result struct {
		Results []struct {
			Status string `json:"status"`
		} `json:"results"`
	}
	json.Unmarshal(body, &result)

	if result.Results[0].Status != "new" {
		t.Fatalf("expected accepted for countersign-on-countersign, got %s", result.Results[0].Status)
	}
}
