package conformance

import (
	"encoding/json"
	"io"
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// Services discovery vocabulary + countersignature relation — both 0.11.0
// additions. A conforming relay MUST validate service entries on ingest,
// project the full-state services set into verified identity state, and serve
// it on GET /identities/{did}; and it MUST round-trip a countersignature's
// optional `relation` tag intact. These assertions are what distinguish a
// 0.11.0 relay from a pre-services (0.10.x) one.

// relaySvc / anchorSvc are well-formed service entries of the two recognized
// types. ServiceEntry is an open-namespace map[string]any.
func relaySvc(id, endpoint string) dfos.ServiceEntry {
	return dfos.ServiceEntry{"id": id, "type": "DfosRelay", "endpoint": endpoint}
}

func anchorSvc(id, label, anchor string) dfos.ServiceEntry {
	return dfos.ServiceEntry{"id": id, "type": "ContentAnchor", "label": label, "anchor": anchor}
}

// createIdentityWithServices creates a fresh identity carrying a services set.
func createIdentityWithServices(t *testing.T, base string, services []dfos.ServiceEntry) identity {
	t.Helper()
	ctrl := newKeypair()
	auth := newKeypair()
	token, did, opCID, err := dfos.SignIdentityCreateWithServices(
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{auth.mk},
		[]dfos.MultikeyPublicKey{},
		services,
		ctrl.keyID,
		ctrl.priv,
	)
	if err != nil {
		t.Fatalf("SignIdentityCreateWithServices: %v", err)
	}
	res := postOperations(t, base, []string{token})
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		t.Fatalf("create identity w/ services: status %d, body: %s", res.StatusCode, body)
	}
	res.Body.Close()
	return identity{did: did, genCID: opCID, headCID: opCID, controller: ctrl, auth: auth}
}

// fetchServices returns the projected services from the relay's served identity
// state at GET /identities/{did}.
func fetchServices(t *testing.T, base, did string) []map[string]any {
	t.Helper()
	var chain struct {
		State struct {
			Services []map[string]any `json:"services"`
		} `json:"state"`
	}
	resp := getJSON(t, base+"/identities/"+did, &chain)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /identities/%s: status %d", did, resp.StatusCode)
	}
	return chain.State.Services
}

// updateServices submits a full-state identity update that replaces the services
// set with the given entries (pass nil to clear). Returns the new head CID.
func updateServices(t *testing.T, base string, id *identity, services []dfos.ServiceEntry) {
	t.Helper()
	kid := id.controller.keyID // controller signs identity ops; bare-kid form resolved by relay via did
	token, opCID, err := dfos.SignIdentityUpdateWithServices(
		id.headCID,
		[]dfos.MultikeyPublicKey{id.controller.mk},
		[]dfos.MultikeyPublicKey{id.auth.mk},
		[]dfos.MultikeyPublicKey{},
		services,
		id.did+"#"+kid,
		id.controller.priv,
	)
	if err != nil {
		t.Fatalf("SignIdentityUpdateWithServices: %v", err)
	}
	res := postOperations(t, base, []string{token})
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		t.Fatalf("update services: status %d, body: %s", res.StatusCode, body)
	}
	res.Body.Close()
	id.headCID = opCID
}

// svcField pulls a string field from a served service entry.
func svcField(e map[string]any, k string) string {
	if v, ok := e[k].(string); ok {
		return v
	}
	return ""
}

// findSvc returns the served entry with the given id, or nil.
func findSvc(svcs []map[string]any, id string) map[string]any {
	for _, e := range svcs {
		if svcField(e, "id") == id {
			return e
		}
	}
	return nil
}

func TestServicesProjection(t *testing.T) {
	base := relayURL(t)
	const anchor = "cv7n8vkvr64cctf3294h9k4eanhff8z" // 31-char content id
	id := createIdentityWithServices(t, base, []dfos.ServiceEntry{
		relaySvc("relay", "https://relay.dfos.com"),
		anchorSvc("avatar", "avatar", anchor),
	})

	svcs := fetchServices(t, base, id.did)
	if len(svcs) != 2 {
		t.Fatalf("expected 2 projected services, got %d: %+v", len(svcs), svcs)
	}
	r := findSvc(svcs, "relay")
	if r == nil || svcField(r, "type") != "DfosRelay" || svcField(r, "endpoint") != "https://relay.dfos.com" {
		t.Fatalf("DfosRelay entry not served correctly: %+v", r)
	}
	a := findSvc(svcs, "avatar")
	if a == nil || svcField(a, "type") != "ContentAnchor" || svcField(a, "label") != "avatar" || svcField(a, "anchor") != anchor {
		t.Fatalf("ContentAnchor entry not served correctly: %+v", a)
	}
}

func TestServicesFullStateReplace(t *testing.T) {
	base := relayURL(t)
	id := createIdentityWithServices(t, base, []dfos.ServiceEntry{
		relaySvc("old", "https://old.example.com"),
	})
	if got := fetchServices(t, base, id.did); len(got) != 1 || findSvc(got, "old") == nil {
		t.Fatalf("genesis services not as expected: %+v", got)
	}

	// an update REPLACES the entire set — the old entry must disappear.
	updateServices(t, base, &id, []dfos.ServiceEntry{
		relaySvc("new", "https://new.example.com"),
		anchorSvc("pin", "pin", "cv7n8vkvr64cctf3294h9k4eanhff8z"),
	})
	got := fetchServices(t, base, id.did)
	if len(got) != 2 {
		t.Fatalf("expected 2 services after replace, got %d: %+v", len(got), got)
	}
	if findSvc(got, "old") != nil {
		t.Fatal("full-state replace failed: stale 'old' entry still served after update")
	}
	if findSvc(got, "new") == nil || findSvc(got, "pin") == nil {
		t.Fatalf("replacement services not served: %+v", got)
	}
}

func TestServicesClearOnUpdate(t *testing.T) {
	base := relayURL(t)
	id := createIdentityWithServices(t, base, []dfos.ServiceEntry{
		relaySvc("relay", "https://relay.dfos.com"),
	})
	if got := fetchServices(t, base, id.did); len(got) != 1 {
		t.Fatalf("genesis services not as expected: %+v", got)
	}

	// an update that omits services CLEARS them (full-state, not delta).
	updateServices(t, base, &id, nil)
	if got := fetchServices(t, base, id.did); len(got) != 0 {
		t.Fatalf("expected services cleared on service-less update, got %d: %+v", len(got), got)
	}
}

func TestServicesInvalidEntryRejected(t *testing.T) {
	base := relayURL(t)
	ctrl := newKeypair()
	auth := newKeypair()
	// ContentAnchor without the required non-empty `label` — structurally invalid.
	bad := dfos.ServiceEntry{"id": "x", "type": "ContentAnchor", "anchor": "cv7n8vkvr64cctf3294h9k4eanhff8z"}
	token, _, _, err := dfos.SignIdentityCreateWithServices(
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{auth.mk},
		[]dfos.MultikeyPublicKey{},
		[]dfos.ServiceEntry{bad},
		ctrl.keyID,
		ctrl.priv,
	)
	if err != nil {
		t.Fatalf("SignIdentityCreateWithServices (bad entry): %v", err)
	}

	res := postOperations(t, base, []string{token})
	var body struct {
		Results []struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	b := readBody(t, res)
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatalf("decode /operations response: %v (body: %s)", err, b)
	}
	if len(body.Results) != 1 {
		t.Fatalf("expected 1 result, got %d (body: %s)", len(body.Results), b)
	}
	if body.Results[0].Status != "rejected" {
		t.Fatalf("expected invalid ContentAnchor (missing label) to be rejected, got status %q (body: %s)",
			body.Results[0].Status, b)
	}
}

func TestCountersignRelationRoundTrip(t *testing.T) {
	base := relayURL(t)
	author := createIdentity(t, base)
	cc := createContent(t, base, author)

	witness := createIdentity(t, base)
	witnessKid := witness.did + "#" + witness.auth.keyID
	const relation = "witnessed"
	csToken, _, err := dfos.SignCountersignWithRelation(witness.did, cc.genCID, relation, witnessKid, witness.auth.priv)
	if err != nil {
		t.Fatalf("SignCountersignWithRelation: %v", err)
	}
	postOperations(t, base, []string{csToken})

	var csResult struct {
		Countersignatures []string `json:"countersignatures"`
	}
	resp := getJSON(t, base+"/countersignatures/"+cc.genCID, &csResult)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /countersignatures/%s: status %d", cc.genCID, resp.StatusCode)
	}
	if len(csResult.Countersignatures) != 1 {
		t.Fatalf("expected 1 countersignature, got %d", len(csResult.Countersignatures))
	}

	// the relation rides inside the served countersign JWS — decode and assert.
	payload, err := dfos.PayloadFromJWS(csResult.Countersignatures[0])
	if err != nil {
		t.Fatalf("PayloadFromJWS: %v", err)
	}
	if got, _ := payload["relation"].(string); got != relation {
		t.Fatalf("served countersignature relation = %q, want %q (payload: %+v)", got, relation, payload)
	}
}
