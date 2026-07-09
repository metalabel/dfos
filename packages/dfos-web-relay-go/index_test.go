package relay

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

const testProfileSchema = "https://schemas.dfos.com/profile/v1"
const testPostSchema = "https://schemas.dfos.com/post/v1"

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

// addPublicRead grants public read and returns the credential CID (so the grant
// can later be revoked to exercise the publicRead true→false cascade).
func addPublicRead(t *testing.T, r *Relay, id testIdentity, contentID string) string {
	t.Helper()
	kid := id.did + "#" + id.auth.keyID
	credential, err := dfos.CreateCredential(id.did, "*", kid, "chain:"+contentID, "read", time.Hour, id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Ingest([]string{credential}); res[0].Status != "new" {
		t.Fatalf("ingest public read credential: %+v", res[0])
	}
	header, _, err := dfos.DecodeJWSUnsafe(credential)
	if err != nil || header == nil {
		t.Fatalf("decode credential CID: %v", err)
	}
	return header.CID
}

func revokeGrant(t *testing.T, r *Relay, id testIdentity, credentialCID string) {
	t.Helper()
	kid := id.did + "#" + id.auth.keyID
	token, _, err := dfos.SignRevocation(id.did, credentialCID, kid, id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Ingest([]string{token}); res[0].Status != "new" {
		t.Fatalf("ingest revocation: %+v", res[0])
	}
}

// uploadBlobViaRoute PUTs a document blob through the relay's content-plane route
// (authenticated as the content creator), which fires maintainIndexAfterBlob —
// unlike a direct store.PutBlob, this exercises the late-arrival recompute hook.
func uploadBlobViaRoute(t *testing.T, r *Relay, id testIdentity, c testContent) {
	t.Helper()
	kid := id.did + "#" + id.auth.keyID
	authToken, err := dfos.CreateAuthToken(id.did, r.DID(), kid, time.Minute, id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(c.document)
	req := httptest.NewRequest("PUT", "http://localhost/content/"+c.contentID+"/blob/"+c.operationCID, strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, req)
	if rec.Result().StatusCode != 200 {
		raw, _ := io.ReadAll(rec.Result().Body)
		t.Fatalf("upload blob via route: status %d body %s", rec.Result().StatusCode, raw)
	}
}

// indexIdentityRowByDID fetches a single identity projection row via the route.
func indexIdentityRowByDID(t *testing.T, handler http.Handler, did string) map[string]any {
	t.Helper()
	_, body, _ := getIndexJSONBody(t, handler, "/index/v0/identities?limit=1000")
	for _, raw := range body["identities"].([]any) {
		row := raw.(map[string]any)
		if row["did"] == did {
			return row
		}
	}
	return nil
}

// indexContentRowByID fetches a single content projection row via the route.
func indexContentRowByID(t *testing.T, handler http.Handler, contentID string) map[string]any {
	t.Helper()
	_, body, _ := getIndexJSONBody(t, handler, "/index/v0/content?limit=1000")
	for _, raw := range body["content"].([]any) {
		row := raw.(map[string]any)
		if row["contentId"] == contentID {
			return row
		}
	}
	return nil
}

func contentBodyHasID(body map[string]any, contentID string) bool {
	for _, raw := range body["content"].([]any) {
		if raw.(map[string]any)["contentId"] == contentID {
			return true
		}
	}
	return false
}

func identityDIDs(body map[string]any) []string {
	rows := body["identities"].([]any)
	dids := make([]string, 0, len(rows))
	for _, raw := range rows {
		dids = append(dids, raw.(map[string]any)["did"].(string))
	}
	return dids
}

func contentIDs(body map[string]any) []string {
	rows := body["content"].([]any)
	ids := make([]string, 0, len(rows))
	for _, raw := range rows {
		ids = append(ids, raw.(map[string]any)["contentId"].(string))
	}
	return ids
}

func walkIdentityPages(t *testing.T, handler http.Handler, basePath string) []string {
	t.Helper()
	out := []string{}
	after := ""
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatalf("identity ordered walk exceeded 20 pages")
		}
		path := basePath
		if after != "" {
			path += "&after=" + url.QueryEscape(after)
		}
		status, body, _ := getIndexJSONBody(t, handler, path)
		if status != 200 {
			t.Fatalf("%s status = %d body=%v", path, status, body)
		}
		out = append(out, identityDIDs(body)...)
		next, _ := body["next"].(string)
		if next == "" {
			return out
		}
		after = next
	}
}

func walkContentPages(t *testing.T, handler http.Handler, basePath string) []string {
	t.Helper()
	out := []string{}
	after := ""
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatalf("content ordered walk exceeded 20 pages")
		}
		path := basePath
		if after != "" {
			path += "&after=" + url.QueryEscape(after)
		}
		status, body, _ := getIndexJSONBody(t, handler, path)
		if status != 200 {
			t.Fatalf("%s status = %d body=%v", path, status, body)
		}
		out = append(out, contentIDs(body)...)
		next, _ := body["next"].(string)
		if next == "" {
			return out
		}
		after = next
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
	// name projects only for a publicly-readable profile; grant so this case
	// isolates the anchor-tiebreak breaker, not the publicRead gate
	addPublicRead(t, r, winner, winningContent.contentID)
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

func TestIndexContentTitleProjectionCircuitBreakersAndLateBlob(t *testing.T) {
	r, store := indexRelay(t)
	handler := r.Handler()
	creator := ingestIdentity(t, r)

	post := createIndexedContent(t, r, store, creator, map[string]any{"$schema": testPostSchema, "title": "hello"}, false)
	nonRegistry := createIndexedContent(t, r, store, creator, map[string]any{"$schema": "example/post", "title": "no"}, false)
	missing := createIndexedContent(t, r, store, creator, map[string]any{"$schema": testPostSchema}, false)
	empty := createIndexedContent(t, r, store, creator, map[string]any{"$schema": testPostSchema, "title": ""}, false)
	nonString := createIndexedContent(t, r, store, creator, map[string]any{"$schema": testPostSchema, "title": 123}, false)
	late := createIndexedContent(t, r, store, creator, map[string]any{"$schema": testPostSchema, "title": "late"}, false)
	// title projects only for a publicly-readable chain; grant so these cases
	// isolate the doc-level title breakers, not the publicRead gate
	for _, c := range []testContent{post, nonRegistry, missing, empty, nonString, late} {
		addPublicRead(t, r, creator, c.contentID)
	}
	for _, c := range []testContent{post, nonRegistry, missing, empty, nonString} {
		uploadBlobViaRoute(t, r, creator, c)
	}

	if row := indexContentRowByID(t, handler, post.contentID); row["title"] != "hello" {
		t.Fatalf("post title row = %v", row)
	}
	for _, c := range []testContent{nonRegistry, missing, empty, nonString, late} {
		if row := indexContentRowByID(t, handler, c.contentID); row["title"] != nil {
			t.Fatalf("breaker row %s title = %v, want nil", c.contentID, row["title"])
		}
	}
	uploadBlobViaRoute(t, r, creator, late)
	if row := indexContentRowByID(t, handler, late.contentID); row["title"] != "late" {
		t.Fatalf("late title row = %v", row)
	}
}

func TestIndexIdentitiesOrderedEnumeration(t *testing.T) {
	r, store := indexRelay(t)
	handler := r.Handler()

	first := ingestIdentity(t, r)
	time.Sleep(time.Millisecond)
	second := ingestIdentity(t, r)

	status, genesis, _ := getIndexJSONBody(t, handler, "/index/v0/identities?order=genesisAt.desc&limit=1000")
	if status != 200 {
		t.Fatalf("identity genesisAt.desc status = %d", status)
	}
	gotGenesis := identityDIDs(genesis)
	if len(gotGenesis) == 0 || gotGenesis[0] != second.did {
		t.Fatalf("genesisAt.desc first DID = %v, want %s", gotGenesis, second.did)
	}

	time.Sleep(time.Millisecond)
	updateIdentityServices(t, r, first, []dfos.ServiceEntry{
		{"id": "identity-order-head", "type": "ContentAnchor", "label": "noop", "anchor": strings.Repeat("2", 31)},
	})
	status, head, _ := getIndexJSONBody(t, handler, "/index/v0/identities?order=headAt.desc&limit=1000")
	if status != 200 {
		t.Fatalf("identity headAt.desc status = %d", status)
	}
	gotHead := identityDIDs(head)
	if len(gotHead) == 0 || gotHead[0] != first.did {
		t.Fatalf("headAt.desc first DID = %v, want %s", gotHead, first.did)
	}

	status, all, _ := getIndexJSONBody(t, handler, "/index/v0/identities?order=headAt.desc&limit=1000")
	if status != 200 {
		t.Fatalf("identity ordered all status = %d", status)
	}
	expected := identityDIDs(all)
	walked := walkIdentityPages(t, handler, "/index/v0/identities?order=headAt.desc&limit=1")
	if !reflect.DeepEqual(walked, expected) {
		t.Fatalf("identity ordered cursor walk = %v, want %v", walked, expected)
	}

	tieA := "did:dfos:identity-tie-a"
	tieB := "did:dfos:identity-tie-b"
	ts := "2999-01-01T00:00:00.000Z"
	for _, did := range []string{tieB, tieA} {
		if err := store.PutIndexIdentityRow(indexIdentityRow{DID: did, HeadCID: "h", GenesisAt: ts, HeadAt: ts}); err != nil {
			t.Fatal(err)
		}
	}
	status, tied, _ := getIndexJSONBody(t, handler, "/index/v0/identities?order=genesisAt.desc&limit=2")
	if status != 200 {
		t.Fatalf("identity tie status = %d", status)
	}
	gotTie := identityDIDs(tied)
	wantTie := []string{tieA, tieB}
	if !reflect.DeepEqual(gotTie, wantTie) {
		t.Fatalf("identity equal-timestamp tie order = %v, want %v", gotTie, wantTie)
	}

	status, malformed, _ := getIndexJSONBody(t, handler, "/index/v0/identities?order=genesisAt.desc&after=not-a-cursor")
	if status != 400 || malformed["error"] != "invalid cursor" {
		t.Fatalf("identity malformed ordered cursor = %v status=%d", malformed, status)
	}
}

func TestIndexOrderAndSignerFilters(t *testing.T) {
	r, store := indexRelay(t)
	handler := r.Handler()
	creator := ingestIdentity(t, r)
	delegate := ingestIdentity(t, r)
	never := ingestIdentity(t, r)

	c1 := createIndexedContent(t, r, store, creator, map[string]any{"$schema": "example/order", "title": "a"}, false)
	time.Sleep(time.Millisecond)
	c2 := createIndexedContent(t, r, store, creator, map[string]any{"$schema": "example/order", "title": "b"}, false)
	time.Sleep(time.Millisecond)
	c3 := createIndexedContent(t, r, store, delegate, map[string]any{"$schema": "example/order", "title": "c"}, false)

	status, ordered, _ := getIndexJSONBody(t, handler, "/index/v0/content?order=genesisAt.desc&limit=1000")
	if status != 200 {
		t.Fatalf("ordered content status = %d", status)
	}
	gotScoped := []string{}
	for _, raw := range ordered["content"].([]any) {
		id := raw.(map[string]any)["contentId"].(string)
		if id == c1.contentID || id == c2.contentID || id == c3.contentID {
			gotScoped = append(gotScoped, id)
		}
	}
	if len(gotScoped) != 3 || gotScoped[0] != c3.contentID || gotScoped[1] != c2.contentID || gotScoped[2] != c1.contentID {
		t.Fatalf("genesisAt.desc scoped order = %v", gotScoped)
	}
	expectedAll := contentIDs(ordered)
	walkedAll := walkContentPages(t, handler, "/index/v0/content?order=genesisAt.desc&limit=1")
	if !reflect.DeepEqual(walkedAll, expectedAll) {
		t.Fatalf("content ordered cursor walk = %v, want %v", walkedAll, expectedAll)
	}

	updateDoc := map[string]any{"$schema": testPostSchema, "title": "delegate"}
	updateCID, _, err := dfos.DocumentCID(updateDoc)
	if err != nil {
		t.Fatal(err)
	}
	creatorKid := creator.did + "#" + creator.auth.keyID
	writeCred, err := dfos.CreateCredential(creator.did, delegate.did, creatorKid, "chain:"+c1.contentID, "write", time.Hour, creator.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	delegateKid := delegate.did + "#" + delegate.auth.keyID
	updateToken, updateOpCID, err := dfos.SignContentUpdateWithOptions(delegate.did, c1.operationCID, updateCID, delegateKid, delegate.auth.priv, dfos.ContentUpdateOptions{Authorization: writeCred})
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Ingest([]string{updateToken}); res[0].Status != "new" {
		t.Fatalf("delegated update: %+v", res[0])
	}
	uploadBlobViaRoute(t, r, delegate, testContent{contentID: c1.contentID, operationCID: updateOpCID, documentCID: updateCID, document: updateDoc})
	addPublicRead(t, r, creator, c1.contentID)

	status, head, _ := getIndexJSONBody(t, handler, "/index/v0/content?order=headAt.desc&limit=1000")
	if status != 200 || head["content"].([]any)[0].(map[string]any)["contentId"] != c1.contentID {
		t.Fatalf("headAt.desc after update = %v status=%d", head, status)
	}
	filteredCreator := walkContentPages(t, handler, "/index/v0/content?order=headAt.desc&creator="+url.QueryEscape(creator.did)+"&limit=1")
	wantCreator := []string{c1.contentID, c2.contentID}
	if !reflect.DeepEqual(filteredCreator, wantCreator) {
		t.Fatalf("ordered creator-filter cursor walk = %v, want %v", filteredCreator, wantCreator)
	}

	status, byCreator, _ := getIndexJSONBody(t, handler, "/index/v0/content?signer="+url.QueryEscape(creator.did)+"&limit=1000")
	if status != 200 || !contentBodyHasID(byCreator, c1.contentID) {
		t.Fatalf("creator signer body = %v status=%d", byCreator, status)
	}
	status, byDelegate, _ := getIndexJSONBody(t, handler, "/index/v0/content?signer="+url.QueryEscape(delegate.did)+"&creator="+url.QueryEscape(creator.did)+"&docSchema="+url.QueryEscape(testPostSchema)+"&publicRead=true&limit=1000")
	if status != 200 || !contentBodyHasID(byDelegate, c1.contentID) {
		t.Fatalf("delegate signer body = %v status=%d", byDelegate, status)
	}
	status, orderedByDelegate, _ := getIndexJSONBody(t, handler, "/index/v0/content?order=headAt.desc&signer="+url.QueryEscape(delegate.did)+"&docSchema="+url.QueryEscape(testPostSchema)+"&limit=1000")
	if status != 200 || !reflect.DeepEqual(contentIDs(orderedByDelegate), []string{c1.contentID}) {
		t.Fatalf("ordered signer/docSchema body = %v status=%d", orderedByDelegate, status)
	}
	status, byNever, _ := getIndexJSONBody(t, handler, "/index/v0/content?signer="+url.QueryEscape(never.did)+"&limit=1000")
	if status != 200 || contentBodyHasID(byNever, c1.contentID) {
		t.Fatalf("never signer body = %v status=%d", byNever, status)
	}

	status, badOrder, _ := getIndexJSONBody(t, handler, "/index/v0/content?order=bogus")
	if status != 400 || badOrder["error"] != "invalid order" {
		t.Fatalf("bad order = %v status=%d", badOrder, status)
	}
	status, badCursor, _ := getIndexJSONBody(t, handler, "/index/v0/content?order=genesisAt.desc&after=not-a-cursor")
	if status != 400 || badCursor["error"] != "invalid cursor" {
		t.Fatalf("bad cursor = %v status=%d", badCursor, status)
	}
	status, badSigner, _ := getIndexJSONBody(t, handler, "/index/v0/content?signer=not-a-did")
	if status != 400 || badSigner["error"] != "invalid DID" {
		t.Fatalf("bad signer = %v status=%d", badSigner, status)
	}
}

func TestIndexOrderedTieBreaksByKey(t *testing.T) {
	r, store := indexRelay(t)
	handler := r.Handler()
	a := "2346789acdefhknrtvz2346789acdef"
	b := "2346789acdefhknrtvz2346789acdee"
	ts := "2026-01-01T00:00:00.000Z"
	for _, id := range []string{a, b} {
		if err := store.PutIndexContentRow(indexContentRow{ContentID: id, GenesisCID: "g", HeadCID: "h", CreatorDID: r.DID(), GenesisAt: ts, HeadAt: ts}); err != nil {
			t.Fatal(err)
		}
	}
	status, body, _ := getIndexJSONBody(t, handler, "/index/v0/content?order=genesisAt.desc&limit=1000")
	if status != 200 {
		t.Fatalf("ordered tiebreak status = %d", status)
	}
	got := []string{}
	for _, raw := range body["content"].([]any) {
		id := raw.(map[string]any)["contentId"].(string)
		if id == a || id == b {
			got = append(got, id)
		}
	}
	want := []string{b, a}
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("tie order = %v, want %v", got, want)
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

// ---------------------------------------------------------------------------
// materialized projection: keyset cursor + recompute-on-change
// ---------------------------------------------------------------------------

func didsFromIdentities(body map[string]any) []string {
	rows := body["identities"].([]any)
	dids := make([]string, 0, len(rows))
	for _, raw := range rows {
		dids = append(dids, raw.(map[string]any)["did"].(string))
	}
	return dids
}

// A cursor that is NOT a stored key but sorts strictly between dids[1] and
// dids[2] must resume at dids[2] — the old exact-match cursor returned an empty
// page here (silent enumeration truncation); keyset (> after) is deterministic.
func TestIndexKeysetResumesOnUnknownCursor(t *testing.T) {
	r, _ := indexRelay(t)
	handler := r.Handler()
	for i := 0; i < 4; i++ {
		ingestIdentity(t, r)
	}

	_, all, _ := getIndexJSONBody(t, handler, "/index/v0/identities?limit=1000")
	dids := didsFromIdentities(all)
	if len(dids) < 4 || !sort.StringsAreSorted(dids) {
		t.Fatalf("dids not sorted or too few: %v", dids)
	}

	// append a char ⇒ longer than dids[1] so > dids[1]; the shared prefix with
	// dids[2] diverges before the appended char so < dids[2].
	between := dids[1] + "0"
	if !(between > dids[1] && between < dids[2]) {
		t.Fatalf("cursor %q not strictly between %q and %q", between, dids[1], dids[2])
	}

	_, page, _ := getIndexJSONBody(t, handler, "/index/v0/identities?after="+url.QueryEscape(between)+"&limit=1000")
	pageDids := didsFromIdentities(page)
	if len(pageDids) == 0 || pageDids[0] != dids[2] {
		t.Fatalf("keyset resume: got %v, want first=%s", pageDids, dids[2])
	}
	for _, d := range pageDids {
		if d == dids[0] || d == dids[1] {
			t.Fatalf("keyset page leaked an already-enumerated key: %v", pageDids)
		}
	}
}

// When the cursor ROW is mutated out of the filtered set between pages (a
// publicRead=true content whose grant is revoked), keyset resume still returns
// the remaining rows > cursor. The old exact-match cursor findIndex(-1)'d and
// truncated to an empty page.
func TestIndexContentCursorMutatedOutOfFilter(t *testing.T) {
	r, store := indexRelay(t)
	handler := r.Handler()
	creator := ingestIdentity(t, r)

	type made struct {
		contentID     string
		credentialCID string
	}
	entries := []made{}
	for i := 0; i < 3; i++ {
		doc := map[string]any{"$schema": "example/post", "title": "p"}
		c := createIndexedContent(t, r, store, creator, doc, true)
		cid := addPublicRead(t, r, creator, c.contentID)
		entries = append(entries, made{contentID: c.contentID, credentialCID: cid})
	}

	_, page1, _ := getIndexJSONBody(t, handler, "/index/v0/content?publicRead=true&limit=1")
	rows := page1["content"].([]any)
	if len(rows) != 1 || page1["next"] == nil {
		t.Fatalf("page1 = %v", page1)
	}
	cursor := page1["next"].(string)

	// revoke the CURSOR row's grant → publicRead flips false → it drops out of the
	// publicRead=true set entirely.
	var cursorCred string
	for _, e := range entries {
		if e.contentID == cursor {
			cursorCred = e.credentialCID
		}
	}
	revokeGrant(t, r, creator, cursorCred)

	_, page2, _ := getIndexJSONBody(t, handler, "/index/v0/content?publicRead=true&after="+url.QueryEscape(cursor)+"&limit=1000")
	remaining := []string{}
	for _, raw := range page2["content"].([]any) {
		remaining = append(remaining, raw.(map[string]any)["contentId"].(string))
	}
	// still-public contents whose contentId > cursor
	expected := []string{}
	for _, e := range entries {
		if e.contentID > cursor {
			expected = append(expected, e.contentID)
		}
	}
	sort.Strings(expected)
	if len(remaining) != len(expected) {
		t.Fatalf("keyset remaining = %v, want %v", remaining, expected)
	}
	for i := range expected {
		if remaining[i] != expected[i] {
			t.Fatalf("keyset remaining = %v, want %v", remaining, expected)
		}
	}
	// the mutated cursor row is now private in the projection
	if row := indexContentRowByID(t, handler, cursor); row == nil || row["publicRead"] != false {
		t.Fatalf("revoked cursor row = %v, want publicRead false", row)
	}
}

// A blob arriving LATE (via the content-plane route, after the content op + the
// anchoring identity op) must recompute the content row's docSchema and cascade
// to the anchored identity's profile projection.
func TestIndexBlobLateArrivalRecompute(t *testing.T) {
	r, store := indexRelay(t)
	handler := r.Handler()
	subject := ingestIdentity(t, r)
	profileDoc := map[string]any{"$schema": testProfileSchema, "name": "lena"}
	// holdBlob=false ⇒ the blob is NOT present when the content + identity rows are
	// first projected.
	profile := createIndexedContent(t, r, store, subject, profileDoc, false)
	addPublicRead(t, r, subject, profile.contentID)
	updateIdentityServices(t, r, subject, []dfos.ServiceEntry{
		{"id": "profile", "type": "ContentAnchor", "label": "profile", "anchor": profile.contentID},
	})

	before := indexContentRowByID(t, handler, profile.contentID)
	if before["currentDocumentCID"] != profile.documentCID || before["docSchema"] != nil {
		t.Fatalf("pre-blob content row = %v, want docSchema nil", before)
	}
	beforeID := indexIdentityRowByDID(t, handler, subject.did)
	if p := beforeID["profile"].(map[string]any); p["docSchema"] != nil || p["name"] != nil {
		t.Fatalf("pre-blob profile = %v, want docSchema/name nil", p)
	}

	// blob lands late → recompute cascades content → anchored identity
	uploadBlobViaRoute(t, r, subject, profile)

	after := indexContentRowByID(t, handler, profile.contentID)
	if after["docSchema"] != testProfileSchema {
		t.Fatalf("post-blob content row = %v, want docSchema %s", after, testProfileSchema)
	}
	afterID := indexIdentityRowByDID(t, handler, subject.did)
	p := afterID["profile"].(map[string]any)
	if p["anchor"] != profile.contentID || p["publicRead"] != true || p["docSchema"] != testProfileSchema || p["name"] != "lena" {
		t.Fatalf("post-blob profile = %v", p)
	}
}

// Granting then revoking public read flips publicRead on the content row AND the
// anchored profile row (both directions), including the hasPublicProfile filter.
func TestIndexPublicReadFlipCascade(t *testing.T) {
	r, store := indexRelay(t)
	handler := r.Handler()
	subject := ingestIdentity(t, r)
	profileDoc := map[string]any{"$schema": testProfileSchema, "name": "ravi"}
	profile := createIndexedContent(t, r, store, subject, profileDoc, true)
	updateIdentityServices(t, r, subject, []dfos.ServiceEntry{
		{"id": "profile", "type": "ContentAnchor", "label": "profile", "anchor": profile.contentID},
	})

	hasInPublicFilter := func() bool {
		_, body, _ := getIndexJSONBody(t, handler, "/index/v0/identities?hasPublicProfile=true")
		for _, d := range didsFromIdentities(body) {
			if d == subject.did {
				return true
			}
		}
		return false
	}

	// before any grant: private on both, absent from hasPublicProfile=true
	if indexContentRowByID(t, handler, profile.contentID)["publicRead"] != false {
		t.Fatalf("pre-grant content publicRead != false")
	}
	if indexIdentityRowByDID(t, handler, subject.did)["profile"].(map[string]any)["publicRead"] != false {
		t.Fatalf("pre-grant profile publicRead != false")
	}
	if hasInPublicFilter() {
		t.Fatalf("pre-grant subject leaked into hasPublicProfile=true")
	}

	// grant flips both true
	credentialCID := addPublicRead(t, r, subject, profile.contentID)
	if indexContentRowByID(t, handler, profile.contentID)["publicRead"] != true {
		t.Fatalf("post-grant content publicRead != true")
	}
	if indexIdentityRowByDID(t, handler, subject.did)["profile"].(map[string]any)["publicRead"] != true {
		t.Fatalf("post-grant profile publicRead != true")
	}
	if !hasInPublicFilter() {
		t.Fatalf("post-grant subject missing from hasPublicProfile=true")
	}

	// revoke flips both back to false
	revokeGrant(t, r, subject, credentialCID)
	if indexContentRowByID(t, handler, profile.contentID)["publicRead"] != false {
		t.Fatalf("post-revoke content publicRead != false")
	}
	if indexIdentityRowByDID(t, handler, subject.did)["profile"].(map[string]any)["publicRead"] != false {
		t.Fatalf("post-revoke profile publicRead != false")
	}
	if hasInPublicFilter() {
		t.Fatalf("post-revoke subject leaked into hasPublicProfile=true")
	}
}

// Deleting the identity that issued a public-read grant flips the granted
// content's publicRead true→false in the projection — even though the only op is
// on the IDENTITY chain, not the content chain. hasPublicStandingAuth
// re-verifies the grant's issuer live and rejects a deleted identity, so the
// content row (and the deleted identity's own anchored profile) must converge.
func TestIndexPublicReadFlipsWhenGrantingIdentityDeleted(t *testing.T) {
	r, store := indexRelay(t)
	handler := r.Handler()
	creator := ingestIdentity(t, r)
	profileDoc := map[string]any{"$schema": testProfileSchema, "name": "mara"}
	content := createIndexedContent(t, r, store, creator, profileDoc, true)
	addPublicRead(t, r, creator, content.contentID)
	updateOpCID := updateIdentityServices(t, r, creator, []dfos.ServiceEntry{
		{"id": "profile", "type": "ContentAnchor", "label": "profile", "anchor": content.contentID},
	})

	// grant + anchor in place: public on both the content row and the profile
	if indexContentRowByID(t, handler, content.contentID)["publicRead"] != true {
		t.Fatalf("pre-delete content publicRead != true")
	}
	if indexIdentityRowByDID(t, handler, creator.did)["profile"].(map[string]any)["publicRead"] != true {
		t.Fatalf("pre-delete profile publicRead != true")
	}

	// delete the granting identity (terminal op on its own chain)
	deleteToken, _, err := dfos.SignIdentityDelete(updateOpCID, creator.did+"#"+creator.controller.keyID, creator.controller.priv)
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Ingest([]string{deleteToken}); res[0].Status != "new" {
		t.Fatalf("ingest delete: %+v", res[0])
	}

	// content row's publicRead must reflect the now-invalid issuer
	if indexContentRowByID(t, handler, content.contentID)["publicRead"] != false {
		t.Fatalf("post-delete content publicRead != false")
	}
	deletedRow := indexIdentityRowByDID(t, handler, creator.did)
	if deletedRow["isDeleted"] != true {
		t.Fatalf("post-delete identity isDeleted != true")
	}
	if deletedRow["profile"].(map[string]any)["publicRead"] != false {
		t.Fatalf("post-delete profile publicRead != false")
	}
	// and it drops out of the publicRead=true content set
	_, body, _ := getIndexJSONBody(t, handler, "/index/v0/content?publicRead=true&limit=1000")
	for _, raw := range body["content"].([]any) {
		if raw.(map[string]any)["contentId"] == content.contentID {
			t.Fatalf("deleted-issuer content still in publicRead=true set")
		}
	}
}

// A second countersign from the same witness on the same target is deduped by
// the store (status "duplicate"); the projection must NOT gain a second row and
// must keep the ACCEPTED (first) row's cid + relation.
func TestIndexCountersignDedupReflected(t *testing.T) {
	r, _ := indexRelay(t)
	handler := r.Handler()
	author := ingestIdentity(t, r)
	witness := ingestIdentity(t, r)
	content := createIndexedContent(t, r, NewMemoryStore(), author, map[string]any{"$schema": "example/post", "title": "dedup"}, false)

	witnessKid := witness.did + "#" + witness.auth.keyID
	first, firstCID, err := dfos.SignCountersignWithRelation(witness.did, content.operationCID, "endorses", witnessKid, witness.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Ingest([]string{first}); res[0].Status != "new" {
		t.Fatalf("first countersign: %+v", res[0])
	}

	q := "/index/v0/countersignatures?witness=" + url.QueryEscape(witness.did) + "&limit=100"
	_, afterFirst, _ := getIndexJSONBody(t, handler, q)
	rows := afterFirst["countersignatures"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["cid"] != firstCID || rows[0].(map[string]any)["relation"] != "endorses" {
		t.Fatalf("after first = %v", afterFirst)
	}

	// second countersign, same witness + target, no relation ⇒ store dedups it.
	second, _, err := dfos.SignCountersign(witness.did, content.operationCID, witnessKid, witness.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	res := r.Ingest([]string{second})
	if res[0].Status != "duplicate" {
		t.Fatalf("second countersign status = %q, want duplicate", res[0].Status)
	}

	_, afterSecond, _ := getIndexJSONBody(t, handler, q)
	rows = afterSecond["countersignatures"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["cid"] != firstCID || rows[0].(map[string]any)["relation"] != "endorses" {
		t.Fatalf("after second (deduped) = %v", afterSecond)
	}
}

// On boot, a durable store whose stamped projection_version differs from
// IndexProjectionVersion (a bumped schema, or a pre-existing corpus ingested
// while a stale/absent projection) is rebuilt from the authoritative chain +
// countersign tables — synchronously, before serving.
func TestIndexRebuildOnVersionBump(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rebuild.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	r, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	handler := r.Handler()

	author := ingestIdentity(t, r)
	witness := ingestIdentity(t, r)
	content := createIndexedContent(t, r, NewMemoryStore(), author, map[string]any{"$schema": testPostSchema, "title": "seed"}, false)
	uploadBlobViaRoute(t, r, author, content)
	addPublicRead(t, r, author, content.contentID) // title projects only when public
	witnessKid := witness.did + "#" + witness.auth.keyID
	cs, csCID, err := dfos.SignCountersign(witness.did, content.operationCID, witnessKid, witness.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Ingest([]string{cs}); res[0].Status != "new" {
		t.Fatalf("countersign: %+v", res[0])
	}

	// projection currently populated
	if indexContentRowByID(t, handler, content.contentID) == nil {
		t.Fatal("seed content row missing before rebuild")
	}

	// Simulate a stale projection: wipe the rows and reset the stamped version, as
	// if the DB predates this projection schema (or was ingested index-off).
	if err := store.ClearIndexProjection(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIndexProjectionVersion(0); err != nil {
		t.Fatal(err)
	}
	if indexContentRowByID(t, handler, content.contentID) != nil {
		t.Fatal("expected empty projection after clear")
	}

	// Boot a fresh relay on the SAME store (same identity ⇒ no re-bootstrap). The
	// version mismatch (0 != IndexProjectionVersion) triggers a synchronous rebuild.
	r2, err := NewRelay(RelayOptions{
		Store:    store,
		Identity: &RelayIdentity{DID: r.DID(), ProfileArtifactJWS: r.ProfileArtifactJWS()},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler2 := r2.Handler()

	// version stamped current again
	if v, _ := store.GetIndexProjectionVersion(); v != IndexProjectionVersion {
		t.Fatalf("projection_version = %d, want %d", v, IndexProjectionVersion)
	}
	// content row rebuilt WITH the late blob's docSchema (rebuild reads current
	// chain + held blob + standing credentials)
	row := indexContentRowByID(t, handler2, content.contentID)
	if row == nil || row["docSchema"] != testPostSchema || row["title"] != "seed" {
		t.Fatalf("rebuilt content row = %v", row)
	}
	_, signerBody, _ := getIndexJSONBody(t, handler2, "/index/v0/content?signer="+url.QueryEscape(author.did)+"&limit=1000")
	if !contentBodyHasID(signerBody, content.contentID) {
		t.Fatalf("rebuilt signer rows = %v, want content %s", signerBody, content.contentID)
	}
	// countersign projection rebuilt and queryable by witness
	_, csBody, _ := getIndexJSONBody(t, handler2, "/index/v0/countersignatures?witness="+url.QueryEscape(witness.did)+"&limit=100")
	csRows := csBody["countersignatures"].([]any)
	if len(csRows) != 1 || csRows[0].(map[string]any)["cid"] != csCID {
		t.Fatalf("rebuilt countersign rows = %v, want cid %s", csBody, csCID)
	}
	// identity rows rebuilt
	if indexIdentityRowByDID(t, handler2, author.did) == nil {
		t.Fatal("author identity row missing after rebuild")
	}
}

// TestSQLiteQueryIndexIdentitiesNameContains locks the `nameContains` substring
// filter directly at the SQLite store layer — the bespoke
// `instr(lower(profile_name), lower(?)) > 0` clause. The shared conformance corpus
// holds no named profiles, so it can only exercise the invariant (no non-matching
// row leaks), never a positive match; this proves a match, exclusion of a
// non-match, case-insensitivity, and null-profile exclusion against real SQLite.
func TestSQLiteQueryIndexIdentitiesNameContains(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "namecontains.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	put := func(did, name string, publicRead bool) {
		t.Helper()
		var profile *indexProfile
		if name != "" {
			n := name
			profile = &indexProfile{Anchor: "anchor-" + did, PublicRead: publicRead, Name: &n}
		}
		if err := store.PutIndexIdentityRow(indexIdentityRow{DID: did, HeadCID: "head-" + did, Profile: profile}); err != nil {
			t.Fatalf("PutIndexIdentityRow(%s): %v", did, err)
		}
	}
	put("did:dfos:aaa", "Asha", true)  // public, contains "sh"
	put("did:dfos:bbb", "Boris", true) // public, contains "or"
	put("did:dfos:ccc", "", true)      // no profile — must never match
	// A non-public row carrying a name (as a pre-gate builder might persist) shares
	// the "sh" substring but MUST stay closed to the nameContains oracle.
	put("did:dfos:ddd", "Ashanti", false)

	query := func(needle string) []string {
		t.Helper()
		rows, err := store.QueryIndexIdentities(IndexIdentityQuery{NameContains: needle, Limit: 100})
		if err != nil {
			t.Fatalf("QueryIndexIdentities(%q): %v", needle, err)
		}
		dids := make([]string, len(rows))
		for i, row := range rows {
			dids[i] = row.DID
		}
		return dids
	}

	// positive substring match (stored "Asha" vs lowercase query "sh"); the
	// non-public "Ashanti" row also contains "sh" but stays excluded (oracle closed)
	if got := query("sh"); len(got) != 1 || got[0] != "did:dfos:aaa" {
		t.Fatalf("nameContains=sh → %v, want [did:dfos:aaa]", got)
	}
	// case-insensitive: an uppercase query still matches the lowercase-folded name
	if got := query("SH"); len(got) != 1 || got[0] != "did:dfos:aaa" {
		t.Fatalf("nameContains=SH → %v, want [did:dfos:aaa]", got)
	}
	// a different substring selects the other row (not always-first, not the null one)
	if got := query("or"); len(got) != 1 || got[0] != "did:dfos:bbb" {
		t.Fatalf("nameContains=or → %v, want [did:dfos:bbb]", got)
	}
	// no match → empty; the null-profile row is never a false positive
	if got := query("zzq-no-such"); len(got) != 0 {
		t.Fatalf("nameContains=zzq-no-such → %v, want []", got)
	}
}

// A non-public profile whose anchored doc is held and well-formed must NOT
// project its name onto the anonymous index surface — at rest (stored row),
// on the wire (served row), or via the nameContains oracle. Granting public
// read flips the same name into view.
func TestIndexProfileNameGatedOnPublicRead(t *testing.T) {
	r, store := indexRelay(t)
	handler := r.Handler()
	subject := ingestIdentity(t, r)
	profile := createIndexedContent(t, r, store, subject, map[string]any{"$schema": testProfileSchema, "name": "hidden"}, true)
	updateIdentityServices(t, r, subject, []dfos.ServiceEntry{
		{"id": "profile", "type": "ContentAnchor", "label": "profile", "anchor": profile.contentID},
	})

	// non-public: stored row carries no name (write gate)
	stored, err := store.QueryIndexIdentities(IndexIdentityQuery{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range stored {
		if row.DID == subject.did {
			if row.Profile == nil || row.Profile.PublicRead || row.Profile.Name != nil {
				t.Fatalf("stored non-public profile leaked name: %+v", row.Profile)
			}
		}
	}
	served := indexIdentityRowByDID(t, handler, subject.did)["profile"].(map[string]any)
	if served["publicRead"] != false || served["name"] != nil {
		t.Fatalf("served non-public profile = %v, want publicRead false + name nil", served)
	}
	_, byName, _ := getIndexJSONBody(t, handler, "/index/v0/identities?nameContains=hidden")
	for _, d := range identityDIDs(byName) {
		if d == subject.did {
			t.Fatalf("nameContains confirmed a non-public name")
		}
	}

	// grant public read → the same name now projects everywhere
	addPublicRead(t, r, subject, profile.contentID)
	served = indexIdentityRowByDID(t, handler, subject.did)["profile"].(map[string]any)
	if served["publicRead"] != true || served["name"] != "hidden" {
		t.Fatalf("served public profile = %v, want publicRead true + name hidden", served)
	}
	foundPublic := false
	_, byNamePublic, _ := getIndexJSONBody(t, handler, "/index/v0/identities?nameContains=hidden")
	for _, d := range identityDIDs(byNamePublic) {
		if d == subject.did {
			foundPublic = true
		}
	}
	if !foundPublic {
		t.Fatalf("nameContains did not match the now-public name")
	}
}

// The content-title twin of the profile-name gate: a non-public post's title is
// withheld at rest and on the wire until public read is granted.
func TestIndexContentTitleGatedOnPublicRead(t *testing.T) {
	r, store := indexRelay(t)
	handler := r.Handler()
	creator := ingestIdentity(t, r)
	post := createIndexedContent(t, r, store, creator, map[string]any{"$schema": testPostSchema, "title": "secret"}, true)

	stored, err := store.QueryIndexContent(IndexContentQuery{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range stored {
		if row.ContentID == post.contentID && (row.PublicRead || row.Title != nil) {
			t.Fatalf("stored non-public content leaked title: %+v", row)
		}
	}
	served := indexContentRowByID(t, handler, post.contentID)
	if served["publicRead"] != false || served["title"] != nil {
		t.Fatalf("served non-public content = %v, want publicRead false + title nil", served)
	}

	addPublicRead(t, r, creator, post.contentID)
	served = indexContentRowByID(t, handler, post.contentID)
	if served["publicRead"] != true || served["title"] != "secret" {
		t.Fatalf("served public content = %v, want publicRead true + title secret", served)
	}
}

// Defense in depth: a row a pre-gate builder persisted with a non-public
// name/title is redacted at serve time and stays closed to the nameContains
// oracle — even though the current builder would never write such a row.
func TestIndexServeTimeRedactsStaleNonPublicRow(t *testing.T) {
	r, store := indexRelay(t)
	handler := r.Handler()

	name := "stale"
	did := "did:dfos:" + strings.Repeat("2", 31)
	if err := store.PutIndexIdentityRow(indexIdentityRow{
		DID: did, HeadCID: "h",
		Profile: &indexProfile{Anchor: strings.Repeat("3", 31), PublicRead: false, Name: &name},
	}); err != nil {
		t.Fatal(err)
	}
	title := "stale-title"
	cid := "2346789acdefhknrtvz2346789acdef"
	if err := store.PutIndexContentRow(indexContentRow{
		ContentID: cid, GenesisCID: "g", HeadCID: "h", CreatorDID: r.DID(),
		PublicRead: false, Title: &title,
	}); err != nil {
		t.Fatal(err)
	}

	if served := indexIdentityRowByDID(t, handler, did)["profile"].(map[string]any); served["name"] != nil {
		t.Fatalf("stale non-public name served: %v", served)
	}
	if indexContentRowByID(t, handler, cid)["title"] != nil {
		t.Fatalf("stale non-public title served")
	}
	_, byName, _ := getIndexJSONBody(t, handler, "/index/v0/identities?nameContains=stale")
	for _, d := range identityDIDs(byName) {
		if d == did {
			t.Fatalf("nameContains confirmed a stale non-public name")
		}
	}
}
