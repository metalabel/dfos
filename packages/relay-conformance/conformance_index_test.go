// Index conformance (/index/v0 — optional, non-authoritative query surface).
//
// The index is capability-gated. These tests self-skip when the relay does not
// advertise capabilities.index or when a probed route returns 501.
package conformance

import (
	"net/url"
	"testing"

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
