// Index conformance (/index/v0 — optional, non-authoritative query surface).
//
// The index is capability-gated. These tests self-skip when the relay does not
// advertise capabilities.index or when a probed route returns 501.
package conformance

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

func requireIndexCapability(t *testing.T, base string) {
	t.Helper()
	var wellKnown struct {
		Capabilities map[string]any `json:"capabilities"`
	}
	resp := getJSON(t, base+"/.well-known/dfos-relay", &wellKnown)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /.well-known/dfos-relay: status %d", resp.StatusCode)
	}
	if wellKnown.Capabilities["index"] != true {
		t.Skip("relay does not advertise capabilities.index — skipping index conformance")
	}
}

func skipIndex501(t *testing.T, respStatus int) {
	t.Helper()
	if respStatus == 501 {
		t.Skip("relay returned 501 for /index/v0 route — skipping index conformance")
	}
}

func createContentWithDocument(t *testing.T, base string, id identity, doc map[string]any, uploadBlob bool) contentChain {
	t.Helper()
	docCID, _, err := dfos.DocumentCID(doc)
	if err != nil {
		t.Fatalf("DocumentCID: %v", err)
	}

	kid := id.did + "#" + id.auth.keyID
	token, contentID, opCID, err := dfos.SignContentCreate(id.did, docCID, kid, id.auth.priv)
	if err != nil {
		t.Fatalf("SignContentCreate: %v", err)
	}

	res := postOperations(t, base, []string{token})
	if res.StatusCode != 200 {
		t.Fatalf("create content: status %d, body: %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()

	if uploadBlob {
		body, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("Marshal document: %v", err)
		}
		resp := putBlob(t, base, contentID, opCID, authToken(t, base, id), body)
		if resp.StatusCode != 200 {
			t.Fatalf("upload content blob: status %d, body: %s", resp.StatusCode, readBody(t, resp))
		}
		resp.Body.Close()
	}

	return contentChain{
		contentID:   contentID,
		genCID:      opCID,
		headCID:     opCID,
		documentCID: docCID,
		document:    doc,
	}
}

func TestIndexIdentitiesHappyPath(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	id := createIdentity(t, base)

	var body struct {
		Identities []struct {
			DID       string `json:"did"`
			HeadCID   string `json:"headCID"`
			OpCount   int    `json:"opCount"`
			GenesisAt string `json:"genesisAt"`
			HeadAt    string `json:"headAt"`
			IsDeleted bool   `json:"isDeleted"`
			Profile   *struct {
				Anchor     string  `json:"anchor"`
				PublicRead bool    `json:"publicRead"`
				DocSchema  *string `json:"docSchema"`
				Name       *string `json:"name"`
			} `json:"profile"`
		} `json:"identities"`
		Next *string `json:"next"`
	}
	resp := getJSON(t, base+"/index/v0/identities?limit=1000", &body)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("identity index: status %d", resp.StatusCode)
	}
	found := false
	for _, row := range body.Identities {
		if row.DID != id.did {
			continue
		}
		found = true
		if row.HeadCID == "" || row.OpCount < 1 || row.GenesisAt == "" || row.HeadAt == "" {
			t.Fatalf("identity row has incomplete shape: %+v", row)
		}
	}
	if !found {
		t.Fatalf("identity index did not include created DID %s", id.did)
	}
	_ = body.Next
}

func TestIndexContentCreatorFilter(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	creator := createIdentity(t, base)
	other := createIdentity(t, base)
	creatorContent := createContent(t, base, creator)
	otherContent := createContent(t, base, other)

	var body struct {
		Content []struct {
			ContentID  string `json:"contentId"`
			CreatorDID string `json:"creatorDID"`
		} `json:"content"`
		Next *string `json:"next"`
	}
	resp := getJSON(t, base+"/index/v0/content?creator="+url.QueryEscape(creator.did)+"&limit=1000", &body)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("content creator filter: status %d", resp.StatusCode)
	}
	foundCreator := false
	for _, row := range body.Content {
		if row.CreatorDID != creator.did {
			t.Fatalf("creator-filtered row has creatorDID %s, want %s: %+v", row.CreatorDID, creator.did, row)
		}
		if row.ContentID == creatorContent.contentID {
			foundCreator = true
		}
		if row.ContentID == otherContent.contentID {
			t.Fatalf("creator filter leaked other creator content %s", otherContent.contentID)
		}
	}
	if !foundCreator {
		t.Fatalf("creator filter did not include created content %s", creatorContent.contentID)
	}
	_ = body.Next
}

func TestIndexContentDocSchemaFilter(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	creator := createIdentity(t, base)
	schema := "urn:dfos-conformance:index-doc-schema-filter:" + creator.did
	matching := createContentWithDocument(t, base, creator, map[string]any{
		"$schema": schema,
		"type":    "index-conformance-doc-schema-filter",
		"title":   "matching",
	}, true)
	nonMatching := createContentWithDocument(t, base, creator, map[string]any{
		"$schema": schema + "/other",
		"type":    "index-conformance-doc-schema-filter",
		"title":   "other",
	}, true)

	var body struct {
		Content []struct {
			ContentID string  `json:"contentId"`
			DocSchema *string `json:"docSchema"`
		} `json:"content"`
		Next *string `json:"next"`
	}
	resp := getJSON(t, base+"/index/v0/content?docSchema="+url.QueryEscape(schema)+"&limit=1000", &body)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("content docSchema filter: status %d", resp.StatusCode)
	}
	found := false
	for _, row := range body.Content {
		if row.DocSchema == nil || *row.DocSchema != schema {
			t.Fatalf("docSchema-filtered row has docSchema %v, want %s: %+v", row.DocSchema, schema, row)
		}
		if row.ContentID == matching.contentID {
			found = true
		}
		if row.ContentID == nonMatching.contentID {
			t.Fatalf("docSchema filter leaked non-matching content %s", nonMatching.contentID)
		}
	}
	if !found {
		t.Fatalf("docSchema filter did not include created content %s", matching.contentID)
	}
	_ = body.Next
}

func TestIndexContentDocumentCIDFilter(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	creator := createIdentity(t, base)
	matching := createContentWithDocument(t, base, creator, map[string]any{
		"$schema": "urn:dfos-conformance:index-document-cid-filter",
		"type":    "index-conformance-document-cid-filter",
		"title":   "matching",
	}, true)
	nonMatching := createContentWithDocument(t, base, creator, map[string]any{
		"$schema": "urn:dfos-conformance:index-document-cid-filter",
		"type":    "index-conformance-document-cid-filter",
		"title":   "other",
	}, true)

	var body struct {
		Content []struct {
			ContentID          string  `json:"contentId"`
			CurrentDocumentCID *string `json:"currentDocumentCID"`
		} `json:"content"`
		Next *string `json:"next"`
	}
	resp := getJSON(t, base+"/index/v0/content?documentCID="+url.QueryEscape(matching.documentCID)+"&limit=1000", &body)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("content documentCID filter: status %d", resp.StatusCode)
	}
	found := false
	for _, row := range body.Content {
		if row.CurrentDocumentCID == nil || *row.CurrentDocumentCID != matching.documentCID {
			t.Fatalf("documentCID-filtered row has currentDocumentCID %v, want %s: %+v", row.CurrentDocumentCID, matching.documentCID, row)
		}
		if row.ContentID == matching.contentID {
			found = true
		}
		if row.ContentID == nonMatching.contentID {
			t.Fatalf("documentCID filter leaked non-matching content %s", nonMatching.contentID)
		}
	}
	if !found {
		t.Fatalf("documentCID filter did not include created content %s", matching.contentID)
	}
	_ = body.Next
}

func TestIndexContentPublicReadFilter(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	creator := createIdentity(t, base)
	publicContent := createContentWithDocument(t, base, creator, map[string]any{
		"$schema": "https://schemas.example.com/dfos/conformance/index/public-read-filter/v1",
		"type":    "index-conformance-public-read",
		"title":   "public",
	}, true)
	privateContent := createContentWithDocument(t, base, creator, map[string]any{
		"$schema": "https://schemas.example.com/dfos/conformance/index/public-read-filter/v1",
		"type":    "index-conformance-public-read",
		"title":   "private",
	}, true)

	kid := creator.did + "#" + creator.auth.keyID
	credToken := createPublicCredential(t, creator.did, kid, "read", publicContent.contentID, 5*time.Minute, creator.auth.priv)
	res := postOperations(t, base, []string{credToken})
	if res.StatusCode != 200 {
		t.Fatalf("submit public credential: status %d, body: %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()

	var publicBody struct {
		Content []struct {
			ContentID  string `json:"contentId"`
			CreatorDID string `json:"creatorDID"`
			PublicRead bool   `json:"publicRead"`
		} `json:"content"`
		Next *string `json:"next"`
	}
	resp := getJSON(t, base+"/index/v0/content?creator="+url.QueryEscape(creator.did)+"&publicRead=true&limit=1000", &publicBody)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("content publicRead=true filter: status %d", resp.StatusCode)
	}
	foundPublic := false
	for _, row := range publicBody.Content {
		if row.CreatorDID != creator.did || !row.PublicRead {
			t.Fatalf("publicRead=true row violates filter: %+v", row)
		}
		if row.ContentID == publicContent.contentID {
			foundPublic = true
		}
		if row.ContentID == privateContent.contentID {
			t.Fatalf("publicRead=true filter leaked private content %s", privateContent.contentID)
		}
	}
	if !foundPublic {
		t.Fatalf("publicRead=true filter did not include created content %s", publicContent.contentID)
	}

	var privateBody struct {
		Content []struct {
			ContentID  string `json:"contentId"`
			CreatorDID string `json:"creatorDID"`
			PublicRead bool   `json:"publicRead"`
		} `json:"content"`
		Next *string `json:"next"`
	}
	resp = getJSON(t, base+"/index/v0/content?creator="+url.QueryEscape(creator.did)+"&publicRead=false&limit=1000", &privateBody)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("content publicRead=false filter: status %d", resp.StatusCode)
	}
	foundPrivate := false
	for _, row := range privateBody.Content {
		if row.CreatorDID != creator.did || row.PublicRead {
			t.Fatalf("publicRead=false row violates filter: %+v", row)
		}
		if row.ContentID == privateContent.contentID {
			foundPrivate = true
		}
		if row.ContentID == publicContent.contentID {
			t.Fatalf("publicRead=false filter leaked public content %s", publicContent.contentID)
		}
	}
	if !foundPrivate {
		t.Fatalf("publicRead=false filter did not include created content %s", privateContent.contentID)
	}
	_ = publicBody.Next
	_ = privateBody.Next
}

// A spec-valid credential MAY carry att keys beyond {resource, action} — the
// Attenuation schema is a loose object. The index att projection must be exactly
// {resource, action} on BOTH relays (the Go relay drops extras when it rebuilds
// att at ingest; the TS relay normalizes at projection), because this is the first
// route to serialize att structurally over the wire. The full-fidelity att lives
// in the self-proving jwsToken; the decoded row att is an amber convenience.
func TestIndexCredentialsAttProjection(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	issuer := createIdentity(t, base)
	kid := issuer.did + "#" + issuer.auth.keyID
	exp := time.Now().Add(5 * time.Minute).Unix()
	resource := "chain:" + createContent(t, base, issuer).contentID
	token := signCredentialV(t, 1, issuer.did, "*", kid, []map[string]string{
		{"resource": resource, "action": "read", "caveat": "before-2027"},
	}, []string{}, exp, issuer.auth.priv)
	credCID := postPublicCredential(t, base, token)

	var body struct {
		Credentials []struct {
			CID string           `json:"cid"`
			Att []map[string]any `json:"att"`
		} `json:"credentials"`
	}
	resp := getJSON(t, base+"/index/v0/credentials?resource="+url.QueryEscape(resource)+"&limit=1000", &body)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("credentials att projection: status %d", resp.StatusCode)
	}
	found := false
	for _, row := range body.Credentials {
		if row.CID != credCID {
			continue
		}
		found = true
		for _, entry := range row.Att {
			if _, ok := entry["resource"]; !ok {
				t.Fatalf("att entry missing resource: %+v", entry)
			}
			if _, ok := entry["action"]; !ok {
				t.Fatalf("att entry missing action: %+v", entry)
			}
			if len(entry) != 2 {
				t.Fatalf("att entry has %d keys, want exactly {resource, action} (extension keys must be dropped): %+v", len(entry), entry)
			}
		}
	}
	if !found {
		t.Fatalf("att projection test did not find credential %s", credCID)
	}
}

type indexCredentialTestRow struct {
	CID       string `json:"cid"`
	IssuerDID string `json:"issuerDID"`
	Att       []struct {
		Resource string `json:"resource"`
		Action   string `json:"action"`
	} `json:"att"`
	Exp      int64  `json:"exp"`
	JWSToken string `json:"jwsToken"`
}

func credentialCID(t *testing.T, token string) string {
	t.Helper()
	header, _, err := dfos.DecodeJWSUnsafe(token)
	if err != nil {
		t.Fatalf("decode credential JWS: %v", err)
	}
	return header.CID
}

func postPublicCredential(t *testing.T, base string, token string) string {
	t.Helper()
	cid := credentialCID(t, token)
	res := postOperations(t, base, []string{token})
	if res.StatusCode != 200 {
		t.Fatalf("submit public credential: status %d, body: %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()
	return cid
}

func rowHasAttResource(row indexCredentialTestRow, resource string) bool {
	for _, att := range row.Att {
		if att.Resource == resource {
			return true
		}
	}
	return false
}

func rowMatchesCredentialResource(row indexCredentialTestRow, resource string) bool {
	if rowHasAttResource(row, resource) {
		return true
	}
	return strings.HasPrefix(resource, "chain:") && rowHasAttResource(row, "chain:*")
}

func TestIndexCredentialsIssuerFilter(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	issuer := createIdentity(t, base)
	cc := createContent(t, base, issuer)
	kid := issuer.did + "#" + issuer.auth.keyID
	credToken := createPublicCredential(t, issuer.did, kid, "read", cc.contentID, 5*time.Minute, issuer.auth.priv)
	credCID := postPublicCredential(t, base, credToken)

	var body struct {
		Credentials []indexCredentialTestRow `json:"credentials"`
		Next        *string                  `json:"next"`
	}
	resp := getJSON(t, base+"/index/v0/credentials?issuer="+url.QueryEscape(issuer.did)+"&limit=1000", &body)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("credentials issuer filter: status %d", resp.StatusCode)
	}
	found := false
	for _, row := range body.Credentials {
		if row.IssuerDID != issuer.did {
			t.Fatalf("issuer-filtered credential row has issuerDID %s, want %s: %+v", row.IssuerDID, issuer.did, row)
		}
		if row.CID == credCID {
			found = true
			if row.JWSToken != credToken || row.Exp == 0 || !rowHasAttResource(row, "chain:"+cc.contentID) {
				t.Fatalf("credential row has incomplete stored shape: %+v", row)
			}
		}
	}
	if !found {
		t.Fatalf("issuer filter did not include credential %s", credCID)
	}
	_ = body.Next
}

func TestIndexCredentialsResourceExactFilter(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	issuer := createIdentity(t, base)
	cc := createContent(t, base, issuer)
	kid := issuer.did + "#" + issuer.auth.keyID
	credToken := createPublicCredential(t, issuer.did, kid, "read", cc.contentID, 5*time.Minute, issuer.auth.priv)
	credCID := postPublicCredential(t, base, credToken)
	resource := "chain:" + cc.contentID

	var body struct {
		Credentials []indexCredentialTestRow `json:"credentials"`
		Next        *string                  `json:"next"`
	}
	resp := getJSON(t, base+"/index/v0/credentials?resource="+url.QueryEscape(resource)+"&limit=1000", &body)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("credentials resource filter: status %d", resp.StatusCode)
	}
	found := false
	for _, row := range body.Credentials {
		if !rowMatchesCredentialResource(row, resource) {
			t.Fatalf("resource-filtered credential row does not match %s or chain:*: %+v", resource, row)
		}
		if row.CID == credCID {
			found = true
		}
	}
	if !found {
		t.Fatalf("resource filter did not include credential %s", credCID)
	}
	_ = body.Next
}

func TestIndexCredentialsWildcardUnion(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	issuer := createIdentity(t, base)
	other := createIdentity(t, base)
	otherContent := createContent(t, base, other)
	kid := issuer.did + "#" + issuer.auth.keyID
	exp := time.Now().Add(5 * time.Minute).Unix()
	credToken := signCredentialV(t, 1, issuer.did, "*", kid, []map[string]string{
		{"resource": "chain:*", "action": "read"},
	}, []string{}, exp, issuer.auth.priv)
	credCID := postPublicCredential(t, base, credToken)
	resource := "chain:" + otherContent.contentID

	var body struct {
		Credentials []indexCredentialTestRow `json:"credentials"`
		Next        *string                  `json:"next"`
	}
	resp := getJSON(t, base+"/index/v0/credentials?resource="+url.QueryEscape(resource)+"&limit=1000", &body)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("credentials wildcard-union filter: status %d", resp.StatusCode)
	}
	found := false
	for _, row := range body.Credentials {
		if !rowMatchesCredentialResource(row, resource) {
			t.Fatalf("wildcard-union row does not match %s or chain:*: %+v", resource, row)
		}
		if row.CID == credCID {
			found = true
			if !rowHasAttResource(row, "chain:*") {
				t.Fatalf("wildcard credential row missing chain:* att: %+v", row)
			}
		}
	}
	if !found {
		t.Fatalf("wildcard union did not include chain:* credential %s for resource %s", credCID, resource)
	}
	_ = body.Next
}

func TestIndexCredentialsIssuerAndResourceFilter(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	issuer := createIdentity(t, base)
	otherIssuer := createIdentity(t, base)
	cc := createContent(t, base, issuer)
	resource := "chain:" + cc.contentID

	issuerKid := issuer.did + "#" + issuer.auth.keyID
	issuerCred := createPublicCredential(t, issuer.did, issuerKid, "read", cc.contentID, 5*time.Minute, issuer.auth.priv)
	issuerCID := postPublicCredential(t, base, issuerCred)

	otherKid := otherIssuer.did + "#" + otherIssuer.auth.keyID
	otherCred := createPublicCredential(t, otherIssuer.did, otherKid, "read", cc.contentID, 5*time.Minute, otherIssuer.auth.priv)
	otherCID := postPublicCredential(t, base, otherCred)

	var body struct {
		Credentials []indexCredentialTestRow `json:"credentials"`
		Next        *string                  `json:"next"`
	}
	resp := getJSON(t, base+"/index/v0/credentials?issuer="+url.QueryEscape(issuer.did)+"&resource="+url.QueryEscape(resource)+"&limit=1000", &body)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("credentials issuer+resource filter: status %d", resp.StatusCode)
	}
	found := false
	for _, row := range body.Credentials {
		if row.IssuerDID != issuer.did || !rowMatchesCredentialResource(row, resource) {
			t.Fatalf("issuer+resource row violates filter: %+v", row)
		}
		if row.CID == issuerCID {
			found = true
		}
		if row.CID == otherCID {
			t.Fatalf("issuer+resource filter leaked other issuer credential %s", otherCID)
		}
	}
	if !found {
		t.Fatalf("issuer+resource filter did not include credential %s", issuerCID)
	}
	_ = body.Next
}

func TestIndexCredentialsKeysetPagination(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	issuer := createIdentity(t, base)
	kid := issuer.did + "#" + issuer.auth.keyID
	created := map[string]bool{}
	for i := 0; i < 3; i++ {
		cc := createContent(t, base, issuer)
		credToken := createPublicCredential(t, issuer.did, kid, "read", cc.contentID, 5*time.Minute, issuer.auth.priv)
		created[postPublicCredential(t, base, credToken)] = false
	}

	seen := map[string]bool{}
	after := ""
	firstPage := true
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatal("issuer-scoped credentials keyset pagination exceeded 20 pages")
		}
		u := base + "/index/v0/credentials?issuer=" + url.QueryEscape(issuer.did) + "&limit=1"
		if after != "" {
			u += "&after=" + url.QueryEscape(after)
		}
		var body struct {
			Credentials []indexCredentialTestRow `json:"credentials"`
			Next        *string                  `json:"next"`
		}
		resp := getJSON(t, u, &body)
		skipIndex501(t, resp.StatusCode)
		if resp.StatusCode != 200 {
			t.Fatalf("credential keyset page: status %d", resp.StatusCode)
		}
		if len(body.Credentials) > 1 {
			t.Fatalf("limit=1 returned %d credential rows", len(body.Credentials))
		}
		if firstPage {
			if len(body.Credentials) != 1 || body.Next == nil {
				t.Fatalf("first credential page = %+v, want one row and non-null next", body)
			}
			firstPage = false
		}
		if len(body.Credentials) == 1 {
			row := body.Credentials[0]
			if row.IssuerDID != issuer.did {
				t.Fatalf("issuer-scoped credential page returned row for %s, want %s", row.IssuerDID, issuer.did)
			}
			if seen[row.CID] {
				t.Fatalf("credential keyset pagination returned duplicate cid %s", row.CID)
			}
			seen[row.CID] = true
			if _, ok := created[row.CID]; ok {
				created[row.CID] = true
			}
		}
		if body.Next == nil {
			if len(body.Credentials) != 0 {
				t.Fatalf("limit=1 final credential page had one row but next was null: %+v", body)
			}
			break
		}
		if len(body.Credentials) != 1 || *body.Next != body.Credentials[0].CID {
			t.Fatalf("credential next cursor = %v, page = %+v", body.Next, body)
		}
		after = *body.Next
	}
	for cid, found := range created {
		if !found {
			t.Fatalf("credential keyset walk did not include created credential %s", cid)
		}
	}
}

func TestIndexCredentialsBadIssuer(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)

	var body struct {
		Error string `json:"error"`
	}
	resp := getJSON(t, base+"/index/v0/credentials?issuer=not-a-did", &body)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 400 {
		t.Fatalf("credentials invalid issuer: status %d, want 400", resp.StatusCode)
	}
	if body.Error != "invalid DID" {
		t.Fatalf("credentials invalid issuer: error = %q, want invalid DID", body.Error)
	}
}

func TestIndexIdentitiesHasPublicProfileFilter(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)

	var body struct {
		Identities []struct {
			DID     string `json:"did"`
			Profile *struct {
				Anchor     string  `json:"anchor"`
				PublicRead bool    `json:"publicRead"`
				DocSchema  *string `json:"docSchema"`
				Name       *string `json:"name"`
			} `json:"profile"`
		} `json:"identities"`
		Next *string `json:"next"`
	}
	resp := getJSON(t, base+"/index/v0/identities?hasPublicProfile=true&limit=1000", &body)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("identity hasPublicProfile filter: status %d", resp.StatusCode)
	}
	for _, row := range body.Identities {
		if row.Profile == nil || !row.Profile.PublicRead {
			t.Fatalf("hasPublicProfile=true row has profile %+v for DID %s", row.Profile, row.DID)
		}
	}
	_ = body.Next
}

func TestIndexIdentitiesNameContainsFilter(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)

	var body struct {
		Identities []struct {
			DID     string `json:"did"`
			Profile *struct {
				Anchor     string  `json:"anchor"`
				PublicRead bool    `json:"publicRead"`
				DocSchema  *string `json:"docSchema"`
				Name       *string `json:"name"`
			} `json:"profile"`
		} `json:"identities"`
		Next *string `json:"next"`
	}
	resp := getJSON(t, base+"/index/v0/identities?limit=1000", &body)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("identity unfiltered index: status %d", resp.StatusCode)
	}

	sourceDID := ""
	needle := "zzq-no-such-name-marker"
	for _, row := range body.Identities {
		if row.Profile != nil && row.Profile.Name != nil && len(*row.Profile.Name) >= 3 {
			name := *row.Profile.Name
			start := (len(name) - 3) / 2
			needle = strings.ToUpper(name[start : start+3])
			sourceDID = row.DID
			break
		}
	}
	if sourceDID == "" {
		t.Logf("no named identity available for positive nameContains check")
	}

	var filtered struct {
		Identities []struct {
			DID     string `json:"did"`
			Profile *struct {
				Anchor     string  `json:"anchor"`
				PublicRead bool    `json:"publicRead"`
				DocSchema  *string `json:"docSchema"`
				Name       *string `json:"name"`
			} `json:"profile"`
		} `json:"identities"`
		Next *string `json:"next"`
	}
	resp = getJSON(t, base+"/index/v0/identities?nameContains="+url.QueryEscape(needle)+"&limit=1000", &filtered)
	if resp.StatusCode != 200 {
		t.Fatalf("identity nameContains filter: status %d", resp.StatusCode)
	}

	foundSource := sourceDID == ""
	for _, row := range filtered.Identities {
		if row.DID == sourceDID {
			foundSource = true
		}
		if row.Profile == nil || row.Profile.Name == nil || !strings.Contains(strings.ToLower(*row.Profile.Name), strings.ToLower(needle)) {
			t.Fatalf("nameContains=%q row has profile %+v for DID %s", needle, row.Profile, row.DID)
		}
	}
	if !foundSource {
		t.Fatalf("nameContains=%q did not include source DID %s", needle, sourceDID)
	}
	_ = filtered.Next
}

func TestIndexIdentitiesKeysetPagination(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	created := map[string]bool{}
	for i := 0; i < 3; i++ {
		id := createIdentity(t, base)
		created[id.did] = false
	}

	seen := map[string]bool{}
	after := ""
	firstPage := true
	for pages := 0; ; pages++ {
		if pages > 5000 {
			t.Fatal("identity keyset pagination exceeded 5000 pages")
		}
		u := base + "/index/v0/identities?limit=1"
		if after != "" {
			u += "&after=" + url.QueryEscape(after)
		}
		var body struct {
			Identities []struct {
				DID string `json:"did"`
			} `json:"identities"`
			Next *string `json:"next"`
		}
		resp := getJSON(t, u, &body)
		skipIndex501(t, resp.StatusCode)
		if resp.StatusCode != 200 {
			t.Fatalf("identity keyset page: status %d", resp.StatusCode)
		}
		if len(body.Identities) > 1 {
			t.Fatalf("limit=1 returned %d identity rows", len(body.Identities))
		}
		if firstPage {
			if len(body.Identities) != 1 || body.Next == nil {
				t.Fatalf("first identity page = %+v, want one row and non-null next", body)
			}
			firstPage = false
		}
		if len(body.Identities) == 1 {
			did := body.Identities[0].DID
			if seen[did] {
				t.Fatalf("identity keyset pagination returned duplicate DID %s", did)
			}
			seen[did] = true
			if _, ok := created[did]; ok {
				created[did] = true
			}
		}
		if body.Next == nil {
			if len(body.Identities) != 0 {
				t.Fatalf("limit=1 final page had one row but next was null: %+v", body)
			}
			break
		}
		if len(body.Identities) != 1 || *body.Next != body.Identities[0].DID {
			t.Fatalf("identity next cursor = %v, page = %+v", body.Next, body)
		}
		after = *body.Next
	}
	for did, found := range created {
		if !found {
			t.Fatalf("identity keyset walk did not include created DID %s", did)
		}
	}
}

func TestIndexContentKeysetPagination(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	creator := createIdentity(t, base)
	created := map[string]bool{}
	for i := 0; i < 3; i++ {
		cc := createContent(t, base, creator)
		created[cc.contentID] = false
	}

	seen := map[string]bool{}
	after := ""
	firstContentID := ""
	firstPage := true
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatal("creator-scoped content keyset pagination exceeded 20 pages")
		}
		u := base + "/index/v0/content?creator=" + url.QueryEscape(creator.did) + "&limit=1"
		if after != "" {
			u += "&after=" + url.QueryEscape(after)
		}
		var body struct {
			Content []struct {
				ContentID  string `json:"contentId"`
				CreatorDID string `json:"creatorDID"`
			} `json:"content"`
			Next *string `json:"next"`
		}
		resp := getJSON(t, u, &body)
		skipIndex501(t, resp.StatusCode)
		if resp.StatusCode != 200 {
			t.Fatalf("content keyset page: status %d", resp.StatusCode)
		}
		if len(body.Content) > 1 {
			t.Fatalf("limit=1 returned %d content rows", len(body.Content))
		}
		if firstPage {
			if len(body.Content) != 1 || body.Next == nil {
				t.Fatalf("first content page = %+v, want one row and non-null next", body)
			}
			firstContentID = body.Content[0].ContentID
			firstPage = false
		} else if len(body.Content) == 1 && body.Content[0].ContentID == firstContentID {
			t.Fatalf("second-or-later content page repeated first row %s", firstContentID)
		}
		if len(body.Content) == 1 {
			row := body.Content[0]
			if row.CreatorDID != creator.did {
				t.Fatalf("creator-scoped content page returned row for %s, want %s", row.CreatorDID, creator.did)
			}
			if seen[row.ContentID] {
				t.Fatalf("content keyset pagination returned duplicate contentId %s", row.ContentID)
			}
			seen[row.ContentID] = true
			if _, ok := created[row.ContentID]; ok {
				created[row.ContentID] = true
			}
		}
		if body.Next == nil {
			if len(body.Content) != 0 {
				t.Fatalf("limit=1 final content page had one row but next was null: %+v", body)
			}
			break
		}
		if len(body.Content) != 1 || *body.Next != body.Content[0].ContentID {
			t.Fatalf("content next cursor = %v, page = %+v", body.Next, body)
		}
		after = *body.Next
	}
	for contentID, found := range created {
		if !found {
			t.Fatalf("content keyset walk did not include created content %s", contentID)
		}
	}
}

func TestIndexParseLimitRejectsAndClamps(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)

	for _, raw := range []string{"0", "-5", "abc", "1.5"} {
		var body struct {
			Identities []struct {
				DID string `json:"did"`
			} `json:"identities"`
			Next *string `json:"next"`
		}
		resp := getJSON(t, base+"/index/v0/identities?limit="+url.QueryEscape(raw), &body)
		skipIndex501(t, resp.StatusCode)
		if resp.StatusCode != 200 {
			t.Fatalf("limit=%q: status %d", raw, resp.StatusCode)
		}
		if len(body.Identities) > 100 {
			t.Fatalf("limit=%q returned %d rows, want <= default 100", raw, len(body.Identities))
		}
		_ = body.Next
	}

	var body struct {
		Identities []struct {
			DID string `json:"did"`
		} `json:"identities"`
		Next *string `json:"next"`
	}
	resp := getJSON(t, base+"/index/v0/identities?limit=99999", &body)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("limit=99999: status %d", resp.StatusCode)
	}
	if len(body.Identities) > 1000 {
		t.Fatalf("limit=99999 returned %d rows, want <= max 1000", len(body.Identities))
	}
	_ = body.Next
}

func TestIndexBadRequestSurface(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)

	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "content invalid creator", path: "/index/v0/content?creator=not-a-did"},
		{name: "countersignatures missing witness", path: "/index/v0/countersignatures"},
		{name: "countersignatures invalid witness", path: "/index/v0/countersignatures?witness=not-a-did"},
	} {
		var body struct {
			Error string `json:"error"`
		}
		resp := getJSON(t, base+tc.path, &body)
		skipIndex501(t, resp.StatusCode)
		if resp.StatusCode != 400 {
			t.Fatalf("%s: status %d, want 400", tc.name, resp.StatusCode)
		}
		if body.Error != "invalid DID" {
			t.Fatalf("%s: error = %q, want invalid DID", tc.name, body.Error)
		}
	}
}

func TestIndexContentHappyPath(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	var body struct {
		Content []struct {
			ContentID          string  `json:"contentId"`
			GenesisCID         string  `json:"genesisCID"`
			HeadCID            string  `json:"headCID"`
			CreatorDID         string  `json:"creatorDID"`
			IsDeleted          bool    `json:"isDeleted"`
			OpCount            int     `json:"opCount"`
			GenesisAt          string  `json:"genesisAt"`
			HeadAt             string  `json:"headAt"`
			CurrentDocumentCID *string `json:"currentDocumentCID"`
			PublicRead         bool    `json:"publicRead"`
			DocSchema          *string `json:"docSchema"`
		} `json:"content"`
		Next *string `json:"next"`
	}
	resp := getJSON(t, base+"/index/v0/content?creator="+url.QueryEscape(id.did)+"&limit=1000", &body)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("content index: status %d", resp.StatusCode)
	}
	found := false
	for _, row := range body.Content {
		if row.ContentID != cc.contentID {
			continue
		}
		found = true
		if row.GenesisCID != cc.genCID || row.HeadCID == "" || row.CreatorDID != id.did || row.OpCount < 1 {
			t.Fatalf("content row has incomplete shape: %+v", row)
		}
		if row.CurrentDocumentCID == nil || *row.CurrentDocumentCID != cc.documentCID {
			t.Fatalf("currentDocumentCID = %v, want %s", row.CurrentDocumentCID, cc.documentCID)
		}
	}
	if !found {
		t.Fatalf("content index did not include created content %s", cc.contentID)
	}
	_ = body.Next
}

func TestIndexCountersignaturesByWitnessHappyPath(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)
	witness := createIdentity(t, base)

	witnessKid := witness.did + "#" + witness.auth.keyID
	csToken, csCID, err := dfos.SignCountersign(witness.did, cc.genCID, witnessKid, witness.auth.priv)
	if err != nil {
		t.Fatalf("SignCountersign: %v", err)
	}
	res := postOperations(t, base, []string{csToken})
	if res.StatusCode != 200 {
		t.Fatalf("submit countersignature: status %d, body: %s", res.StatusCode, readBody(t, res))
	}

	var body struct {
		Witness           string `json:"witness"`
		Countersignatures []struct {
			CID       string  `json:"cid"`
			TargetCID string  `json:"targetCID"`
			Relation  *string `json:"relation"`
			JWSToken  string  `json:"jwsToken"`
		} `json:"countersignatures"`
		Next *string `json:"next"`
	}
	resp := getJSON(t, base+"/index/v0/countersignatures?witness="+url.QueryEscape(witness.did)+"&limit=1000", &body)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("countersignature witness index: status %d", resp.StatusCode)
	}
	if body.Witness != witness.did {
		t.Fatalf("witness = %s, want %s", body.Witness, witness.did)
	}
	found := false
	for _, row := range body.Countersignatures {
		if row.CID != csCID {
			continue
		}
		found = true
		if row.TargetCID != cc.genCID || row.JWSToken != csToken {
			t.Fatalf("countersignature row = %+v", row)
		}
	}
	if !found {
		t.Fatalf("witness index did not include countersignature %s", csCID)
	}
	_ = body.Next
}
