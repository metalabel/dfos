// /index/v0/artifacts and /index/v0/operations conformance — the two newest
// index families. Same capability gating as the rest of the index suite:
// self-skip when the relay does not advertise capabilities.index or a probed
// route returns 501.
package conformance

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

type indexArtifactRowBody struct {
	CID        string  `json:"cid"`
	SignerDID  string  `json:"signerDID"`
	CreatedAt  string  `json:"createdAt"`
	IngestedAt string  `json:"ingestedAt"`
	DocSchema  *string `json:"docSchema"`
}

type indexOperationRowBody struct {
	CID        string `json:"cid"`
	Kind       string `json:"kind"`
	ChainID    string `json:"chainId"`
	CreatedAt  string `json:"createdAt"`
	IngestedAt string `json:"ingestedAt"`
}

func createArtifactForIndex(t *testing.T, base string, id identity, schema string, value int) string {
	t.Helper()
	kid := id.did + "#" + id.auth.keyID
	token, artifactCID, err := dfos.SignArtifact(id.did, map[string]any{"$schema": schema, "value": value}, kid, id.auth.priv)
	if err != nil {
		t.Fatalf("SignArtifact: %v", err)
	}
	res := postOperations(t, base, []string{token})
	if res.StatusCode != 200 {
		t.Fatalf("post artifact: status %d, body: %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()
	return artifactCID
}

func TestIndexArtifactsFiltersAndReceiptTime(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	id := createIdentity(t, base)
	first := createArtifactForIndex(t, base, id, "conformance/index-artifact-a", 1)
	second := createArtifactForIndex(t, base, id, "conformance/index-artifact-b", 2)

	var bySigner struct {
		Artifacts []indexArtifactRowBody `json:"artifacts"`
		Next      *string                `json:"next"`
	}
	resp := getJSON(t, base+"/index/v0/artifacts?signer="+url.QueryEscape(id.did), &bySigner)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("artifacts by signer: status %d", resp.StatusCode)
	}
	if len(bySigner.Artifacts) != 2 {
		t.Fatalf("artifacts by signer: got %d rows, want 2", len(bySigner.Artifacts))
	}
	for _, row := range bySigner.Artifacts {
		if row.SignerDID != id.did || row.CreatedAt == "" || row.IngestedAt == "" || row.DocSchema == nil {
			t.Fatalf("artifact row incomplete: %+v", row)
		}
	}

	var bySchema struct {
		Artifacts []indexArtifactRowBody `json:"artifacts"`
	}
	resp = getJSON(t, base+"/index/v0/artifacts?signer="+url.QueryEscape(id.did)+"&docSchema="+url.QueryEscape("conformance/index-artifact-a"), &bySchema)
	if resp.StatusCode != 200 || len(bySchema.Artifacts) != 1 || bySchema.Artifacts[0].CID != first {
		t.Fatalf("artifacts by docSchema: status %d rows %+v", resp.StatusCode, bySchema.Artifacts)
	}

	var byCID struct {
		Artifacts []indexArtifactRowBody `json:"artifacts"`
	}
	resp = getJSON(t, base+"/index/v0/artifacts?cid="+url.QueryEscape(second), &byCID)
	if resp.StatusCode != 200 || len(byCID.Artifacts) != 1 || byCID.Artifacts[0].CID != second {
		t.Fatalf("artifacts by cid: status %d rows %+v", resp.StatusCode, byCID.Artifacts)
	}

	// Receipt-time coherence: /index/v0/artifacts and /index/v0/operations MUST
	// report the same ingestedAt for the same operation — two index surfaces,
	// one relay receipt.
	var ops struct {
		Operations []indexOperationRowBody `json:"operations"`
	}
	resp = getJSON(t, base+"/index/v0/operations?kind=artifact&chainId="+url.QueryEscape(id.did)+"&limit=1000", &ops)
	if resp.StatusCode != 200 {
		t.Fatalf("operations kind=artifact: status %d", resp.StatusCode)
	}
	opIngested := map[string]string{}
	for _, row := range ops.Operations {
		opIngested[row.CID] = row.IngestedAt
	}
	for _, row := range bySigner.Artifacts {
		if got, ok := opIngested[row.CID]; !ok || got != row.IngestedAt {
			t.Fatalf("receipt-time divergence for %s: artifacts=%q operations=%q (present=%v)", row.CID, row.IngestedAt, got, ok)
		}
	}
}

func TestIndexArtifactsOrderedPaginationAndBadInputs(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	id := createIdentity(t, base)
	createArtifactForIndex(t, base, id, "conformance/index-artifact-page", 1)
	createArtifactForIndex(t, base, id, "conformance/index-artifact-page", 2)

	walked := []string{}
	after := ""
	for page := 0; page < 10; page++ {
		route := base + "/index/v0/artifacts?signer=" + url.QueryEscape(id.did) + "&order=createdAt.desc&limit=1"
		if after != "" {
			route += "&after=" + url.QueryEscape(after)
		}
		var body struct {
			Artifacts []indexArtifactRowBody `json:"artifacts"`
			Next      *string                `json:"next"`
		}
		resp := getJSON(t, route, &body)
		skipIndex501(t, resp.StatusCode)
		if resp.StatusCode != 200 {
			t.Fatalf("ordered artifacts page: status %d", resp.StatusCode)
		}
		for _, row := range body.Artifacts {
			walked = append(walked, row.CID)
		}
		if body.Next == nil {
			break
		}
		after = *body.Next
	}
	if len(walked) != 2 {
		t.Fatalf("ordered artifact walk visited %d rows, want 2", len(walked))
	}

	for _, route := range []string{
		"/index/v0/artifacts?order=bogus",
		"/index/v0/artifacts?order=createdAt.desc&after=not-a-cursor",
	} {
		var errBody struct {
			Error string `json:"error"`
		}
		resp := getJSON(t, base+route, &errBody)
		if resp.StatusCode != 400 {
			t.Fatalf("%s: status %d, want 400", route, resp.StatusCode)
		}
	}

	// Non-canonical base64 variants of a well-formed cursor MUST be rejected —
	// canonicality is part of the cursor contract, not an implementation detail.
	canonical := base64.RawURLEncoding.EncodeToString([]byte("2026-01-01T00:00:00Z~conformance"))
	for _, variant := range []string{canonical + "=", canonical + "\n", canonical + " "} {
		var errBody struct {
			Error string `json:"error"`
		}
		route := base + "/index/v0/artifacts?order=createdAt.desc&after=" + url.QueryEscape(variant)
		resp := getJSON(t, route, &errBody)
		if resp.StatusCode != 400 || errBody.Error != "invalid cursor" {
			t.Fatalf("non-canonical cursor %q: status %d error %q, want 400 invalid cursor", variant, resp.StatusCode, errBody.Error)
		}
	}
}

func TestIndexOperationsFiltersAndBadInputs(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	id := createIdentity(t, base)
	artifactCID := createArtifactForIndex(t, base, id, "conformance/index-op", 1)

	var byChain struct {
		Operations []indexOperationRowBody `json:"operations"`
		Next       *string                 `json:"next"`
	}
	resp := getJSON(t, base+"/index/v0/operations?chainId="+url.QueryEscape(id.did)+"&limit=1000", &byChain)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("operations by chainId: status %d", resp.StatusCode)
	}
	// the identity genesis and the artifact both chain to the DID
	kinds := map[string]bool{}
	sawArtifact := false
	for _, row := range byChain.Operations {
		kinds[row.Kind] = true
		if row.CID == artifactCID {
			sawArtifact = true
			if row.Kind != "artifact" || row.IngestedAt == "" {
				t.Fatalf("artifact operation row incomplete: %+v", row)
			}
		}
	}
	if !sawArtifact || !kinds["identity-op"] {
		t.Fatalf("operations by chainId missing expected rows (sawArtifact=%v kinds=%v)", sawArtifact, kinds)
	}

	var byKind struct {
		Operations []indexOperationRowBody `json:"operations"`
	}
	resp = getJSON(t, base+"/index/v0/operations?kind=artifact&chainId="+url.QueryEscape(id.did), &byKind)
	if resp.StatusCode != 200 {
		t.Fatalf("operations by kind: status %d", resp.StatusCode)
	}
	for _, row := range byKind.Operations {
		if row.Kind != "artifact" {
			t.Fatalf("kind filter leaked row: %+v", row)
		}
	}

	for _, route := range []string{
		"/index/v0/operations?kind=bogus",
		"/index/v0/operations?order=bogus",
		"/index/v0/operations?after=not-a-cursor",
	} {
		var errBody struct {
			Error string `json:"error"`
		}
		resp := getJSON(t, base+route, &errBody)
		if resp.StatusCode != 400 {
			t.Fatalf("%s: status %d, want 400", route, resp.StatusCode)
		}
	}

	canonical := base64.RawURLEncoding.EncodeToString([]byte("2026-01-01T00:00:00Z~conformance"))
	for _, variant := range []string{canonical + "=", canonical + "\n", canonical + " "} {
		var errBody struct {
			Error string `json:"error"`
		}
		resp := getJSON(t, base+"/index/v0/operations?after="+url.QueryEscape(variant), &errBody)
		if resp.StatusCode != 400 || !strings.Contains(errBody.Error, "invalid cursor") {
			t.Fatalf("non-canonical operations cursor %q: status %d error %q, want 400 invalid cursor", variant, resp.StatusCode, errBody.Error)
		}
	}
}
