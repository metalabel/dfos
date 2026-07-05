package relay

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

const testProfileSchema = "https://schemas.dfos.com/profile/v1"

var testArtifactAnchor = "bafyrei" + strings.Repeat("a", 52)

type testContent struct {
	contentID    string
	operationCID string
	documentCID  string
	document     map[string]any
}

func indexRelay(t *testing.T) (*Relay, *MemoryStore) {
	t.Helper()
	store := NewMemoryStore()
	r, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	return r, store
}

func getIndexJSONBody(t *testing.T, handler http.Handler, path string) (int, map[string]any, string) {
	t.Helper()
	req := httptest.NewRequest("GET", "http://localhost"+path, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode %s: %v (body: %s)", path, err, raw)
	}
	return resp.StatusCode, body, string(raw)
}

func ingestIdentity(t *testing.T, r *Relay, services ...dfos.ServiceEntry) testIdentity {
	t.Helper()
	if len(services) == 0 {
		id := createTestIdentity(t)
		if res := r.Ingest([]string{id.token}); res[0].Status != "new" {
			t.Fatalf("ingest identity: %+v", res[0])
		}
		return id
	}
	controller := newTestKeypair()
	auth := newTestKeypair()
	token, did, opCID, err := dfos.SignIdentityCreateWithServices(
		[]dfos.MultikeyPublicKey{controller.mk},
		[]dfos.MultikeyPublicKey{auth.mk},
		nil,
		services,
		controller.keyID,
		controller.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Ingest([]string{token}); res[0].Status != "new" {
		t.Fatalf("ingest identity with services: %+v", res[0])
	}
	return testIdentity{token: token, did: did, opCID: opCID, controller: controller, auth: auth}
}

func updateIdentityServices(t *testing.T, r *Relay, id testIdentity, services []dfos.ServiceEntry) string {
	t.Helper()
	token, opCID, err := dfos.SignIdentityUpdateWithServices(
		id.opCID,
		[]dfos.MultikeyPublicKey{id.controller.mk},
		[]dfos.MultikeyPublicKey{id.auth.mk},
		nil,
		services,
		id.did+"#"+id.controller.keyID,
		id.controller.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Ingest([]string{token}); res[0].Status != "new" {
		t.Fatalf("ingest identity services update: %+v", res[0])
	}
	return opCID
}

func createIndexedContent(t *testing.T, r *Relay, store *MemoryStore, id testIdentity, document map[string]any, holdBlob bool) testContent {
	t.Helper()
	documentCID, _, err := dfos.DocumentCID(document)
	if err != nil {
		t.Fatal(err)
	}
	kid := id.did + "#" + id.auth.keyID
	token, contentID, opCID, err := dfos.SignContentCreate(id.did, documentCID, kid, id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Ingest([]string{token}); res[0].Status != "new" {
		t.Fatalf("ingest content: %+v", res[0])
	}
	if holdBlob {
		bytes, _ := json.Marshal(document)
		if err := store.PutBlob(BlobKey{CreatorDID: id.did, DocumentCID: documentCID}, bytes); err != nil {
			t.Fatal(err)
		}
	}
	return testContent{contentID: contentID, operationCID: opCID, documentCID: documentCID, document: document}
}

func addPublicRead(t *testing.T, r *Relay, id testIdentity, contentID string) {
	t.Helper()
	kid := id.did + "#" + id.auth.keyID
	credential, err := dfos.CreateCredential(id.did, "*", kid, "chain:"+contentID, "read", time.Hour, id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Ingest([]string{credential}); res[0].Status != "new" {
		t.Fatalf("ingest public read credential: %+v", res[0])
	}
}

func TestIndexCapabilityAndDisabledRoutes(t *testing.T) {
	r, _ := indexRelay(t)
	handler := r.Handler()

	status, body, _ := getIndexJSONBody(t, handler, "/.well-known/dfos-relay")
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	caps := body["capabilities"].(map[string]any)
	if caps["index"] != true {
		t.Fatalf("capabilities.index = %v, want true", caps["index"])
	}

	disabled := false
	disabledRelay, err := NewRelay(RelayOptions{
		Store: NewMemoryStore(),
		Identity: &RelayIdentity{
			DID:                r.DID(),
			ProfileArtifactJWS: r.ProfileArtifactJWS(),
		},
		Index: &disabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	disabledHandler := disabledRelay.Handler()

	status, body, _ = getIndexJSONBody(t, disabledHandler, "/.well-known/dfos-relay")
	caps = body["capabilities"].(map[string]any)
	if caps["index"] != false {
		t.Fatalf("capabilities.index = %v, want false", caps["index"])
	}
	for _, path := range []string{
		"/index/v0/identities",
		"/index/v0/content",
		"/index/v0/countersignatures?witness=" + url.QueryEscape(r.DID()),
	} {
		status, body, _ = getIndexJSONBody(t, disabledHandler, path)
		if status != 501 || body["error"] != "index not available" {
			t.Fatalf("%s => status %d body %v, want 501 index not available", path, status, body)
		}
	}
}

func TestIndexIdentitiesProjectionFiltersPaginationAndDeleted(t *testing.T) {
	r, store := indexRelay(t)
	handler := r.Handler()
	subject := ingestIdentity(t, r)
	unprofiled := ingestIdentity(t, r)
	profile := createIndexedContent(t, r, store, subject, map[string]any{"$schema": testProfileSchema, "name": "asha"}, true)
	addPublicRead(t, r, subject, profile.contentID)
	updateIdentityServices(t, r, subject, []dfos.ServiceEntry{
		{"id": "profile", "type": "ContentAnchor", "label": "profile", "anchor": profile.contentID},
	})
	deleteToken, _, err := dfos.SignIdentityDelete(unprofiled.opCID, unprofiled.did+"#"+unprofiled.controller.keyID, unprofiled.controller.priv)
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Ingest([]string{deleteToken}); res[0].Status != "new" {
		t.Fatalf("ingest delete: %+v", res[0])
	}

	status, body, _ := getIndexJSONBody(t, handler, "/index/v0/identities")
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	rows := body["identities"].([]any)
	dids := make([]string, 0, len(rows))
	byDID := map[string]map[string]any{}
	for _, raw := range rows {
		row := raw.(map[string]any)
		did := row["did"].(string)
		dids = append(dids, did)
		byDID[did] = row
	}
	if !sort.StringsAreSorted(dids) {
		t.Fatalf("DIDs not sorted: %v", dids)
	}
	subjectRow := byDID[subject.did]
	if subjectRow["opCount"] != float64(2) || subjectRow["isDeleted"] != false || subjectRow["genesisAt"] == "" || subjectRow["headAt"] == "" {
		t.Fatalf("subject row = %v", subjectRow)
	}
	projected := subjectRow["profile"].(map[string]any)
	if projected["anchor"] != profile.contentID || projected["publicRead"] != true || projected["docSchema"] != testProfileSchema || projected["name"] != "asha" {
		t.Fatalf("profile = %v", projected)
	}
	if byDID[unprofiled.did]["isDeleted"] != true {
		t.Fatalf("deleted identity row = %v", byDID[unprofiled.did])
	}

	status, body, _ = getIndexJSONBody(t, handler, "/index/v0/identities?hasPublicProfile=true")
	if status != 200 || len(body["identities"].([]any)) != 1 {
		t.Fatalf("public profile filter status=%d body=%v", status, body)
	}
	status, body, _ = getIndexJSONBody(t, handler, "/index/v0/identities?hasPublicProfile=false")
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	for _, raw := range body["identities"].([]any) {
		if raw.(map[string]any)["did"] == subject.did {
			t.Fatalf("public profile subject leaked into false filter: %v", body)
		}
	}

	status, page1, _ := getIndexJSONBody(t, handler, "/index/v0/identities?limit=2")
	if status != 200 || len(page1["identities"].([]any)) != 2 || page1["next"] == nil {
		t.Fatalf("page1 = %v status=%d", page1, status)
	}
	next := page1["next"].(string)
	status, page2, _ := getIndexJSONBody(t, handler, "/index/v0/identities?after="+url.QueryEscape(next)+"&limit=100")
	if status != 200 {
		t.Fatalf("page2 status = %d", status)
	}
	for _, raw := range page2["identities"].([]any) {
		if raw.(map[string]any)["did"] == page1["identities"].([]any)[0].(map[string]any)["did"] {
			t.Fatalf("page2 repeated page1 row: %v", page2)
		}
	}
	// Keyset semantics: a cursor that sorts at or beyond the last key yields an
	// empty page (all keys are <= after). "did:dfos:z...z" is > every real DID (z
	// is the max char in the id alphabet).
	status, empty, _ := getIndexJSONBody(t, handler, "/index/v0/identities?after=did:dfos:"+strings.Repeat("z", 31))
	if status != 200 || len(empty["identities"].([]any)) != 0 {
		t.Fatalf("beyond-last cursor page = %v status=%d", empty, status)
	}
}

func TestIndexProfileProjectionCircuitBreakers(t *testing.T) {
	r, store := indexRelay(t)
	handler := r.Handler()

	nonProfile := ingestIdentity(t, r)
	nonProfileContent := createIndexedContent(t, r, store, nonProfile, map[string]any{"$schema": "example/post", "name": "no"}, true)
	updateIdentityServices(t, r, nonProfile, []dfos.ServiceEntry{
		{"id": "profile", "type": "ContentAnchor", "label": "profile", "anchor": nonProfileContent.contentID},
	})

	missingBlob := ingestIdentity(t, r)
	missingBlobContent := createIndexedContent(t, r, store, missingBlob, map[string]any{"$schema": testProfileSchema, "name": "held"}, false)
	updateIdentityServices(t, r, missingBlob, []dfos.ServiceEntry{
		{"id": "profile", "type": "ContentAnchor", "label": "profile", "anchor": missingBlobContent.contentID},
	})

	artifactAnchor := ingestIdentity(t, r, dfos.ServiceEntry{"id": "profile", "type": "ContentAnchor", "label": "profile", "anchor": testArtifactAnchor})

	winner := ingestIdentity(t, r)
	losingContent := createIndexedContent(t, r, store, winner, map[string]any{"$schema": testProfileSchema, "name": "loser"}, true)
	winningContent := createIndexedContent(t, r, store, winner, map[string]any{"$schema": testProfileSchema, "name": "winner"}, true)
	updateIdentityServices(t, r, winner, []dfos.ServiceEntry{
		{"id": "z-profile", "type": "ContentAnchor", "label": "profile", "anchor": losingContent.contentID},
		{"id": "a-profile", "type": "ContentAnchor", "label": "PROFILE", "anchor": winningContent.contentID},
	})

	nameBreakers := []testIdentity{ingestIdentity(t, r), ingestIdentity(t, r), ingestIdentity(t, r)}
	breakerDocs := []map[string]any{
		{"$schema": testProfileSchema},
		{"$schema": testProfileSchema, "name": ""},
		{"$schema": testProfileSchema, "name": 123},
	}
	for i, id := range nameBreakers {
		content := createIndexedContent(t, r, store, id, breakerDocs[i], true)
		updateIdentityServices(t, r, id, []dfos.ServiceEntry{
			{"id": "profile", "type": "ContentAnchor", "label": "profile", "anchor": content.contentID},
		})
	}

	status, body, _ := getIndexJSONBody(t, handler, "/index/v0/identities")
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	byDID := map[string]map[string]any{}
	for _, raw := range body["identities"].([]any) {
		row := raw.(map[string]any)
		byDID[row["did"].(string)] = row
	}
	if profile := byDID[nonProfile.did]["profile"].(map[string]any); profile["docSchema"] != "example/post" || profile["name"] != nil {
		t.Fatalf("non-profile schema profile = %v", profile)
	}
	if profile := byDID[missingBlob.did]["profile"].(map[string]any); profile["docSchema"] != nil || profile["name"] != nil {
		t.Fatalf("missing blob profile = %v", profile)
	}
	if byDID[artifactAnchor.did]["profile"] != nil {
		t.Fatalf("artifact anchor profile = %v, want nil", byDID[artifactAnchor.did]["profile"])
	}
	if profile := byDID[winner.did]["profile"].(map[string]any); profile["anchor"] != winningContent.contentID || profile["name"] != "winner" {
		t.Fatalf("tiebreak profile = %v", profile)
	}
	for _, id := range nameBreakers {
		profile := byDID[id.did]["profile"].(map[string]any)
		if profile["docSchema"] != testProfileSchema || profile["name"] != nil {
			t.Fatalf("name breaker profile = %v", profile)
		}
	}
}

func TestIndexContentFiltersPaginationAndMalformedCreator(t *testing.T) {
	r, store := indexRelay(t)
	handler := r.Handler()
	creator := ingestIdentity(t, r)
	other := ingestIdentity(t, r)
	publicContent := createIndexedContent(t, r, store, creator, map[string]any{"$schema": "example/post", "title": "public"}, true)
	privateContent := createIndexedContent(t, r, store, creator, map[string]any{"$schema": "example/post", "title": "private"}, true)
	otherContent := createIndexedContent(t, r, store, other, map[string]any{"$schema": "example/note", "title": "other"}, true)
	addPublicRead(t, r, creator, publicContent.contentID)

	status, body, _ := getIndexJSONBody(t, handler, "/index/v0/content")
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	ids := []string{}
	for _, raw := range body["content"].([]any) {
		ids = append(ids, raw.(map[string]any)["contentId"].(string))
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatalf("content IDs not sorted: %v", ids)
	}

	status, filtered, _ := getIndexJSONBody(t, handler, "/index/v0/content?creator="+url.QueryEscape(creator.did)+"&docSchema=example/post&publicRead=true")
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	rows := filtered["content"].([]any)
	if len(rows) != 1 {
		t.Fatalf("filtered content = %v", filtered)
	}
	row := rows[0].(map[string]any)
	if row["contentId"] != publicContent.contentID || row["genesisCID"] != publicContent.operationCID || row["headCID"] != publicContent.operationCID || row["creatorDID"] != creator.did || row["currentDocumentCID"] != publicContent.documentCID || row["publicRead"] != true || row["docSchema"] != "example/post" {
		t.Fatalf("filtered row = %v", row)
	}
	_ = privateContent
	_ = otherContent

	status, noSchema, _ := getIndexJSONBody(t, handler, "/index/v0/content?docSchema=missing/schema")
	if status != 200 || len(noSchema["content"].([]any)) != 0 {
		t.Fatalf("missing schema filter = %v status=%d", noSchema, status)
	}
	status, page1, _ := getIndexJSONBody(t, handler, "/index/v0/content?limit=2")
	if status != 200 || len(page1["content"].([]any)) != 2 || page1["next"] == nil {
		t.Fatalf("page1 = %v status=%d", page1, status)
	}
	status, page2, _ := getIndexJSONBody(t, handler, "/index/v0/content?after="+url.QueryEscape(page1["next"].(string))+"&limit=2")
	if status != 200 || len(page2["content"].([]any)) < 1 {
		t.Fatalf("page2 = %v status=%d", page2, status)
	}
	status, malformed, _ := getIndexJSONBody(t, handler, "/index/v0/content?creator=did:dfos:tooshort")
	if status != 400 || malformed["error"] != "invalid DID" {
		t.Fatalf("malformed creator = %v status=%d", malformed, status)
	}
}

func TestIndexCountersignaturesByWitness(t *testing.T) {
	r, _ := indexRelay(t)
	handler := r.Handler()
	author := ingestIdentity(t, r)
	witness := ingestIdentity(t, r)
	otherWitness := ingestIdentity(t, r)
	contentA := createIndexedContent(t, r, NewMemoryStore(), author, map[string]any{"$schema": "example/post", "title": "a"}, false)
	contentB := createIndexedContent(t, r, NewMemoryStore(), author, map[string]any{"$schema": "example/post", "title": "b"}, false)

	witnessKid := witness.did + "#" + witness.auth.keyID
	csA, cidA, err := dfos.SignCountersignWithRelation(witness.did, contentA.operationCID, "endorses", witnessKid, witness.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	csB, cidB, err := dfos.SignCountersign(witness.did, contentB.operationCID, witnessKid, witness.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	otherKid := otherWitness.did + "#" + otherWitness.auth.keyID
	otherCS, _, err := dfos.SignCountersign(otherWitness.did, contentA.operationCID, otherKid, otherWitness.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Ingest([]string{csA, csB, otherCS}); res[0].Status != "new" || res[1].Status != "new" || res[2].Status != "new" {
		t.Fatalf("ingest countersignatures: %+v", res)
	}

	status, page1, _ := getIndexJSONBody(t, handler, "/index/v0/countersignatures?witness="+url.QueryEscape(witness.did)+"&limit=1")
	if status != 200 || page1["witness"] != witness.did || len(page1["countersignatures"].([]any)) != 1 || page1["next"] == nil {
		t.Fatalf("page1 = %v status=%d", page1, status)
	}
	status, page2, _ := getIndexJSONBody(t, handler, "/index/v0/countersignatures?witness="+url.QueryEscape(witness.did)+"&after="+url.QueryEscape(page1["next"].(string))+"&limit=2")
	if status != 200 || len(page2["countersignatures"].([]any)) != 1 || page2["next"] != nil {
		t.Fatalf("page2 = %v status=%d", page2, status)
	}

	all := append(page1["countersignatures"].([]any), page2["countersignatures"].([]any)...)
	gotCIDs := []string{all[0].(map[string]any)["cid"].(string), all[1].(map[string]any)["cid"].(string)}
	wantCIDs := []string{cidA, cidB}
	sort.Strings(wantCIDs)
	if gotCIDs[0] != wantCIDs[0] || gotCIDs[1] != wantCIDs[1] {
		t.Fatalf("countersignature CID order = %v, want %v", gotCIDs, wantCIDs)
	}
	targets := []string{all[0].(map[string]any)["targetCID"].(string), all[1].(map[string]any)["targetCID"].(string)}
	sort.Strings(targets)
	wantTargets := []string{contentA.operationCID, contentB.operationCID}
	sort.Strings(wantTargets)
	if targets[0] != wantTargets[0] || targets[1] != wantTargets[1] {
		t.Fatalf("targets = %v, want %v", targets, wantTargets)
	}
	relations := []any{all[0].(map[string]any)["relation"], all[1].(map[string]any)["relation"]}
	if !(relations[0] == "endorses" && relations[1] == nil || relations[0] == nil && relations[1] == "endorses") {
		t.Fatalf("relations = %v", relations)
	}

	status, missing, _ := getIndexJSONBody(t, handler, "/index/v0/countersignatures")
	if status != 400 || missing["error"] != "invalid DID" {
		t.Fatalf("missing witness = %v status=%d", missing, status)
	}
	status, malformed, _ := getIndexJSONBody(t, handler, "/index/v0/countersignatures?witness=did:dfos:tooshort")
	if status != 400 || malformed["error"] != "invalid DID" {
		t.Fatalf("malformed witness = %v status=%d", malformed, status)
	}
}
