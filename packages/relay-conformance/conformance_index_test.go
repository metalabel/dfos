// Index conformance (/index/v0 — optional, non-authoritative query surface).
//
// The index is capability-gated. These tests self-skip when the relay does not
// advertise capabilities.index or when a probed route returns 501.
package conformance

import (
	"encoding/json"
	"net/url"
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
