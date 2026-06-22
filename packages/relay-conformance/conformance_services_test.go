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
	resp := getJSON(t, base+"/proof/v1/identities/"+did, &chain)
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

// repeatA returns a string of n 'a' bytes — used to build over-length field
// values that pass every check except the one under test.
func repeatA(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

// assertServicesRejected signs a genesis carrying the given services set and
// asserts the relay rejects it on ingest. The signing helper is permissive (it
// encodes whatever it is handed); the bounds are a relay/verifier obligation, so
// the malformed op reaches the wire and must come back `rejected`.
func assertServicesRejected(t *testing.T, base, what string, services []dfos.ServiceEntry) {
	t.Helper()
	ctrl := newKeypair()
	auth := newKeypair()
	token, _, _, err := dfos.SignIdentityCreateWithServices(
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{auth.mk},
		[]dfos.MultikeyPublicKey{},
		services,
		ctrl.keyID,
		ctrl.priv,
	)
	if err != nil {
		t.Fatalf("%s: SignIdentityCreateWithServices: %v", what, err)
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
		t.Fatalf("%s: decode /operations response: %v (body: %s)", what, err, b)
	}
	if len(body.Results) != 1 {
		t.Fatalf("%s: expected 1 result, got %d (body: %s)", what, len(body.Results), b)
	}
	if body.Results[0].Status != "rejected" {
		t.Fatalf("%s: expected rejected, got %q (body: %s)", what, body.Results[0].Status, b)
	}
}

// assertServicesAccepted is the positive-control counterpart to
// assertServicesRejected: it signs a genesis carrying the given services and
// asserts the relay accepts it ("new"). Pairing an at-/just-under-bound
// acceptance with each rejection proves the boundary is where we claim it is.
func assertServicesAccepted(t *testing.T, base, what string, services []dfos.ServiceEntry) {
	t.Helper()
	ctrl := newKeypair()
	auth := newKeypair()
	token, _, _, err := dfos.SignIdentityCreateWithServices(
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{auth.mk},
		[]dfos.MultikeyPublicKey{},
		services,
		ctrl.keyID,
		ctrl.priv,
	)
	if err != nil {
		t.Fatalf("%s: SignIdentityCreateWithServices: %v", what, err)
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
		t.Fatalf("%s: decode /operations response: %v (body: %s)", what, err, b)
	}
	if len(body.Results) != 1 {
		t.Fatalf("%s: expected 1 result, got %d (body: %s)", what, len(body.Results), b)
	}
	if body.Results[0].Status != "new" {
		t.Fatalf("%s: expected new, got %q (body: %s)", what, body.Results[0].Status, b)
	}
}

// TestServicesBoundsRejected drives every normative services bound (PROTOCOL.md
// §Bounds, L573-583). Each case is constructed to pass every check except the one
// under test, so a `rejected` result pins exactly that bound. These hold against
// both the Go and TS relays — the limit constants are mirrored across impls.
func TestServicesBoundsRejected(t *testing.T) {
	base := relayURL(t)

	t.Run("too many entries (>256)", func(t *testing.T) {
		// 257 entries, each small (rejected by the cardinality cap, not the byte
		// cap — 257 tiny entries stay well under 32768 bytes). Unique 2-char ids.
		svcs := make([]dfos.ServiceEntry, 257)
		for i := range svcs {
			id := string(rune('a'+i/26)) + string(rune('a'+i%26))
			svcs[i] = relaySvc(id, "https://r.example.com")
		}
		assertServicesRejected(t, base, "257 entries", svcs)
	})

	t.Run("duplicate ids", func(t *testing.T) {
		assertServicesRejected(t, base, "duplicate id", []dfos.ServiceEntry{
			relaySvc("dup", "https://a.example.com"),
			relaySvc("dup", "https://b.example.com"),
		})
	})

	t.Run("empty id", func(t *testing.T) {
		assertServicesRejected(t, base, "empty id", []dfos.ServiceEntry{
			relaySvc("", "https://a.example.com"),
		})
	})

	// Per-field length caps were removed (no length zoo): id/type/endpoint/label
	// are bounded only by the aggregate byte cap below + the op-size cap. So an
	// over-length single field is NOT rejected on its own — only the aggregate is.
	t.Run("oversized CBOR array (>32768 bytes)", func(t *testing.T) {
		// One entry with a giant (~33 KB) endpoint — individually valid (non-empty)
		// but pushing the CBOR array past the 32768-byte cap. The only bound that
		// can reject this is the array byte cap.
		svcs := []dfos.ServiceEntry{relaySvc("relay", "https://"+repeatA(33000))}
		assertServicesRejected(t, base, "oversized CBOR", svcs)
	})

	t.Run("CBOR array just under 32768 bytes (positive control)", func(t *testing.T) {
		// Positive control pinning the byte boundary: a single entry whose
		// canonical-CBOR encoding lands a few bytes UNDER 32768 is accepted. The
		// single-entry envelope is a fixed 38 bytes (array+map+id/type keys+values+
		// endpoint header), so an endpoint of "https://"+32714×'a' (len 32722)
		// encodes to 32760 bytes < 32768. One byte more on the endpoint flips it
		// over, proving the bound is exactly 32768 — not merely "~33KB is rejected".
		svcs := []dfos.ServiceEntry{relaySvc("relay", "https://"+repeatA(32714))}
		assertServicesAccepted(t, base, "just-under CBOR", svcs)
	})
}

// TestServicesUnknownTypePreserved asserts an unrecognized service type is
// accepted (open namespace) and round-trips verbatim — including its non-core
// fields — through verified state. (PROTOCOL.md L583: preserve + ignore.)
func TestServicesUnknownTypePreserved(t *testing.T) {
	base := relayURL(t)
	id := createIdentityWithServices(t, base, []dfos.ServiceEntry{
		{"id": "exp", "type": "ExperimentalService", "foo": "bar", "n": "42"},
	})
	svcs := fetchServices(t, base, id.did)
	if len(svcs) != 1 {
		t.Fatalf("expected 1 projected service, got %d: %+v", len(svcs), svcs)
	}
	e := findSvc(svcs, "exp")
	if e == nil || svcField(e, "type") != "ExperimentalService" {
		t.Fatalf("unknown-type entry not served: %+v", e)
	}
	if svcField(e, "foo") != "bar" || svcField(e, "n") != "42" {
		t.Fatalf("unknown-type entry non-core fields not preserved verbatim: %+v", e)
	}
}

// TestServicesDeleteCarriesForward asserts a delete carries the last services set
// unchanged into terminal state — the set is not cleared by deletion.
// (PROTOCOL.md L588-589.)
func TestServicesDeleteCarriesForward(t *testing.T) {
	base := relayURL(t)
	id := createIdentityWithServices(t, base, []dfos.ServiceEntry{
		relaySvc("relay", "https://relay.dfos.com"),
	})
	if got := fetchServices(t, base, id.did); len(got) != 1 {
		t.Fatalf("genesis services not as expected: %+v", got)
	}

	ctrlKid := id.did + "#" + id.controller.keyID
	delToken, _, err := dfos.SignIdentityDelete(id.genCID, ctrlKid, id.controller.priv)
	if err != nil {
		t.Fatalf("SignIdentityDelete: %v", err)
	}
	if res := postOperations(t, base, []string{delToken}); res.StatusCode != 200 {
		body := readBody(t, res)
		t.Fatalf("delete identity: status %d, body: %s", res.StatusCode, body)
	} else {
		res.Body.Close()
	}

	// terminal state MUST still carry the pre-delete services set.
	got := fetchServices(t, base, id.did)
	if len(got) != 1 || findSvc(got, "relay") == nil {
		t.Fatalf("delete did not carry services set forward: %+v", got)
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
	resp := getJSON(t, base+"/proof/v1/countersignatures/"+cc.genCID, &csResult)
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
