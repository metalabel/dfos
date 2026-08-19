// Credits index conformance (/index/v0/credits — public-head assertion projection).
package conformance

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

type conformanceCreditRow struct {
	ContentID string  `json:"contentId"`
	DID       string  `json:"did"`
	Role      *string `json:"role"`
	Position  int     `json:"position"`
	HasClaim  bool    `json:"hasClaim"`
}

type conformanceCreditPage struct {
	Credits []conformanceCreditRow `json:"credits"`
	Next    *string                `json:"next"`
}

func getCreditPage(t *testing.T, base, route string) (int, conformanceCreditPage) {
	t.Helper()
	var page conformanceCreditPage
	resp := getJSON(t, base+route, &page)
	return resp.StatusCode, page
}

func TestIndexCreditsPublicSnapshotFiltersAndCursor(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	status, _ := getCreditPage(t, base, "/index/v0/credits?limit=1")
	skipIndex501(t, status)
	if status != http.StatusOK {
		t.Fatalf("credits index probe: status %d", status)
	}

	creator := createIdentity(t, base)
	shared := createIdentity(t, base)
	other := createIdentity(t, base)
	docA := map[string]any{
		"$schema": "https://schemas.dfos.com/post/v1",
		"credits": []any{
			map[string]any{"did": shared.did, "role": "writing", "claim": "opaque", "name": "never projected"},
			map[string]any{"did": 42, "role": "malformed"},
			map[string]any{"did": other.did},
		},
	}
	docB := map[string]any{
		"$schema": "https://schemas.dfos.com/post/v1",
		"credits": []any{
			map[string]any{"did": other.did, "role": "photography"},
			map[string]any{"did": shared.did, "role": "editing"},
		},
	}
	a := createContentWithDocument(t, base, creator, docA, true)
	b := createContentWithDocument(t, base, creator, docB, true)
	kid := creator.did + "#" + creator.auth.keyID
	grantA := postPublicCredential(t, base, createPublicCredential(t, creator.did, kid, "read", a.contentID, 5*time.Minute, creator.auth.priv))
	postPublicCredential(t, base, createPublicCredential(t, creator.did, kid, "read", b.contentID, 5*time.Minute, creator.auth.priv))

	status, byContent := getCreditPage(t, base, "/index/v0/credits?contentId="+url.QueryEscape(a.contentID)+"&limit=1000")
	if status != http.StatusOK {
		t.Fatalf("credits contentId filter: status %d", status)
	}
	if len(byContent.Credits) != 2 {
		t.Fatalf("credits for content A = %+v", byContent)
	}
	writing := "writing"
	wantA := []conformanceCreditRow{
		{ContentID: a.contentID, DID: shared.did, Role: &writing, Position: 0, HasClaim: true},
		{ContentID: a.contentID, DID: other.did, Role: nil, Position: 2, HasClaim: false},
	}
	if !reflect.DeepEqual(byContent.Credits, wantA) {
		t.Fatalf("credits for content A = %+v, want %+v", byContent.Credits, wantA)
	}

	status, byDID := getCreditPage(t, base, "/index/v0/credits?did="+url.QueryEscape(shared.did)+"&limit=1000")
	if status != http.StatusOK || len(byDID.Credits) != 2 {
		t.Fatalf("credits did filter = %+v status=%d", byDID, status)
	}
	for _, row := range byDID.Credits {
		if row.DID != shared.did {
			t.Fatalf("did filter returned %+v", row)
		}
	}
	if byDID.Credits[0].ContentID > byDID.Credits[1].ContentID {
		t.Fatalf("did filter order = %+v", byDID.Credits)
	}

	walked := []conformanceCreditRow{}
	after := ""
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("credits cursor walk exceeded 10 pages")
		}
		route := "/index/v0/credits?did=" + url.QueryEscape(shared.did) + "&limit=1"
		if after != "" {
			route += "&after=" + url.QueryEscape(after)
		}
		status, page := getCreditPage(t, base, route)
		if status != http.StatusOK {
			t.Fatalf("credits cursor page: status %d", status)
		}
		walked = append(walked, page.Credits...)
		if page.Next == nil {
			break
		}
		if len(page.Credits) != 1 || *page.Next == "" || strings.Contains(*page.Next, page.Credits[0].ContentID) {
			t.Fatalf("credits cursor is not an opaque continuation token: page=%+v", page)
		}
		after = *page.Next
	}
	if !reflect.DeepEqual(walked, byDID.Credits) {
		t.Fatalf("credits cursor walk = %+v, want %+v", walked, byDID.Credits)
	}

	revocation, _ := createRevocation(t, creator.did, grantA, creator.auth)
	res := postOperations(t, base, []string{revocation})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("revoke public credit grant: status %d, body: %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()
	status, dark := getCreditPage(t, base, "/index/v0/credits?contentId="+url.QueryEscape(a.contentID)+"&limit=1000")
	if status != http.StatusOK || len(dark.Credits) != 0 {
		t.Fatalf("dark content retained credit rows: %+v status=%d", dark, status)
	}
}
