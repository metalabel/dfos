// `key=` on /index/v0/identities — the reverse lookup "which identities has
// this key ever been declared by."
//
// This is the SIBLING of `signerKey=` on /index/v0/operations
// (conformance_index_operations_signer_key_test.go), and the two are one class:
// both match a multibase public key BYTE-FOR-BYTE against strings the chains
// declared, both are opaque (no format validation, no 400), and both are
// actor-axis, proof-tier filters computed from accepted, signature-verified
// operations alone. Where they differ is the axis: `key=` answers "which chains
// declared this key", `signerKey=` answers "which operations did it sign".
//
// The contract these tests pin, from WEB-RELAY's identities section:
//
//   - HAS-EVER-DECLARED, not current state. Any accepted genesis or update that
//     ever declared the key matches, whether or not a later update rotated it
//     out. Audit and key-loss recovery both need the full declaration history —
//     a holder rediscovering identities from a restored key may hold exactly the
//     keys later updates removed.
//   - No key-class column: `authKeys`, `assertKeys`, and `controllerKeys` are
//     all matched, and which array carried the key is the chain's answer.
//   - A DELETED identity still matches; the row carries `isDeleted` and a
//     consumer that does not want it filters client-side.
//   - The value is opaque: a string no operation ever declared matches nothing.
package conformance

import (
	"net/url"
	"sort"
	"strings"
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

type indexIdentityRowBody struct {
	DID       string `json:"did"`
	IsDeleted bool   `json:"isDeleted"`
}

// requireIdentityKeyFilter skips when the target relay does not implement
// `key=`. Behavioral, for the same reason as the `signerKey=` probe: an
// unrecognized filter on this route is silently dropped rather than rejected, so
// only a question whose sole correct answer is the empty page distinguishes
// "unsupported" from "matched nothing".
func requireIdentityKeyFilter(t *testing.T, base string) {
	t.Helper()
	var unfiltered struct {
		Identities []indexIdentityRowBody `json:"identities"`
	}
	resp := getJSON(t, base+"/index/v0/identities?limit=1", &unfiltered)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /index/v0/identities: status %d", resp.StatusCode)
	}
	if len(unfiltered.Identities) == 0 {
		t.Skip("relay's identity index is empty — no corpus to probe key= against")
	}

	var probe struct {
		Identities []indexIdentityRowBody `json:"identities"`
	}
	route := base + "/index/v0/identities?limit=1&key=" +
		url.QueryEscape("conformance-probe-that-is-not-a-public-key !")
	resp = getJSON(t, route, &probe)
	skipIndex501(t, resp.StatusCode)
	if resp.StatusCode != 200 {
		t.Fatalf("key= probe: status %d, want 200 (the value is opaque — there is no format to 400 on)", resp.StatusCode)
	}
	if len(probe.Identities) != 0 {
		t.Skip("relay does not implement key= on /index/v0/identities (an unmatchable value returned rows) — skipping")
	}
}

// identitiesMatching returns the DIDs a /index/v0/identities query pages back,
// sorted, so multi-row assertions are order-independent.
func identitiesMatching(t *testing.T, base, query string) []string {
	t.Helper()
	rows := identityRowsMatching(t, base, query)
	dids := make([]string, 0, len(rows))
	for _, row := range rows {
		dids = append(dids, row.DID)
	}
	sort.Strings(dids)
	return dids
}

func identityRowsMatching(t *testing.T, base, query string) []indexIdentityRowBody {
	t.Helper()
	var body struct {
		Identities []indexIdentityRowBody `json:"identities"`
	}
	route := base + "/index/v0/identities?" + query + "&limit=1000"
	resp := getJSON(t, route, &body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: status %d", route, resp.StatusCode)
	}
	return body.Identities
}

func keyParam(publicKeyMultibase string) string {
	return "key=" + url.QueryEscape(publicKeyMultibase)
}

// TestIndexIdentitiesKeyMatchesEveryKeyArray covers the no-key-class rule: a key
// declared in ANY of the three arrays resolves the chain that declared it, and
// the filter does not leak chains that declared a different key.
func TestIndexIdentitiesKeyMatchesEveryKeyArray(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)

	// One identity carrying a DISTINCT key in each array — the shape that
	// separates "matches every array" from "matches whichever array the
	// implementation happened to index".
	controller := newKeypair()
	auth := newKeypair()
	assert := newKeypair()
	token, did, _, err := dfos.SignIdentityCreate(
		[]dfos.MultikeyPublicKey{controller.mk},
		[]dfos.MultikeyPublicKey{auth.mk},
		[]dfos.MultikeyPublicKey{assert.mk},
		controller.keyID, controller.priv,
	)
	if err != nil {
		t.Fatalf("SignIdentityCreate: %v", err)
	}
	res := postOperations(t, base, []string{token})
	if res.StatusCode != 200 {
		t.Fatalf("create identity: status %d, body: %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()

	other := createIdentity(t, base)
	requireIdentityKeyFilter(t, base)

	for name, kp := range map[string]keypair{
		"controllerKeys": controller,
		"authKeys":       auth,
		"assertKeys":     assert,
	} {
		got := identitiesMatching(t, base, keyParam(kp.mk.PublicKeyMultibase))
		if len(got) != 1 || got[0] != did {
			t.Fatalf("key=<%s key> = %v, want exactly [%s] — every key array is matched, with no key-class column", name, got, did)
		}
	}

	// A different chain's key does not resolve this one.
	if got := identitiesMatching(t, base, keyParam(other.auth.mk.PublicKeyMultibase)); contains(got, did) {
		t.Fatalf("key=<another chain's key> leaked %s (rows: %v)", did, got)
	}

	// ANDs with did=: one key may match many chains, and `did=` narrows it. Here
	// the composition is asserted on the honest-empty side too — the pair
	// (this chain's key, the other chain's DID) matches nothing.
	composed := identitiesMatching(t, base, keyParam(auth.mk.PublicKeyMultibase)+"&did="+url.QueryEscape(did))
	if len(composed) != 1 || composed[0] != did {
		t.Fatalf("key=<auth>&did=<self> = %v, want [%s]", composed, did)
	}
	if got := identitiesMatching(t, base, keyParam(auth.mk.PublicKeyMultibase)+"&did="+url.QueryEscape(other.did)); len(got) != 0 {
		t.Fatalf("key=<auth>&did=<other> = %v, want an empty page", got)
	}
}

// TestIndexIdentitiesKeyIsHasEverDeclared pins the history semantics: a key a
// later update rotates out KEEPS matching, and a deleted chain KEEPS matching
// (carrying isDeleted). Both are the cases a current-state implementation gets
// wrong, and both are exactly the cases key-loss recovery depends on.
func TestIndexIdentitiesKeyIsHasEverDeclared(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	id := createIdentity(t, base)
	requireIdentityKeyFilter(t, base)

	rotatedOut := id.auth
	replacement := newKeypair()
	controllerKid := id.did + "#" + id.controller.keyID
	rotateToken, rotateCID, err := dfos.SignIdentityUpdate(
		id.genCID,
		[]dfos.MultikeyPublicKey{id.controller.mk},
		[]dfos.MultikeyPublicKey{replacement.mk},
		[]dfos.MultikeyPublicKey{},
		controllerKid, id.controller.priv,
	)
	if err != nil {
		t.Fatalf("SignIdentityUpdate: %v", err)
	}
	res := postOperations(t, base, []string{rotateToken})
	if res.StatusCode != 200 {
		t.Fatalf("rotate: status %d, body: %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()

	// HAS-EVER-DECLARED: the rotated-out key is gone from head state and still
	// resolves the chain. The replacement resolves it too.
	if got := identitiesMatching(t, base, keyParam(rotatedOut.mk.PublicKeyMultibase)); len(got) != 1 || got[0] != id.did {
		t.Fatalf("key=<rotated-out> = %v, want [%s] — the filter is has-ever-declared, not current state", got, id.did)
	}
	if got := identitiesMatching(t, base, keyParam(replacement.mk.PublicKeyMultibase)); len(got) != 1 || got[0] != id.did {
		t.Fatalf("key=<replacement> = %v, want [%s]", got, id.did)
	}

	// DELETION removes nothing from the reverse index; the row records it.
	deleteToken, _, err := dfos.SignIdentityDelete(rotateCID, controllerKid, id.controller.priv)
	if err != nil {
		t.Fatalf("SignIdentityDelete: %v", err)
	}
	res = postOperations(t, base, []string{deleteToken})
	if res.StatusCode != 200 {
		t.Fatalf("delete: status %d, body: %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()

	rows := identityRowsMatching(t, base, keyParam(rotatedOut.mk.PublicKeyMultibase))
	if len(rows) != 1 || rows[0].DID != id.did {
		t.Fatalf("key=<rotated-out> after deletion = %+v, want the row for %s", rows, id.did)
	}
	if !rows[0].IsDeleted {
		t.Fatalf("key=<rotated-out> row for a deleted chain reports isDeleted=false: %+v — the route defines no isDeleted filter, so the field is how a consumer knows", rows[0])
	}
}

// TestIndexIdentitiesKeyIsOpaque pins the byte-match posture — the property that
// makes `key=` and `signerKey=` interoperable — and the no-400 rule.
func TestIndexIdentitiesKeyIsOpaque(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	id := createIdentity(t, base)
	requireIdentityKeyFilter(t, base)

	// AS DECLARED, byte for byte: the exact string the genesis carried is the
	// string the filter matches. A relay that re-encoded the key into its own
	// canonical rendering would fail here, and would also hand back a value that
	// appears nowhere in the chain a client can fetch and verify for itself.
	declared := id.auth.mk.PublicKeyMultibase
	if got := identitiesMatching(t, base, keyParam(declared)); len(got) != 1 || got[0] != id.did {
		t.Fatalf("key=%q = %v, want [%s] — the value matched is the string the chain declared", declared, got, id.did)
	}

	for _, garbage := range []string{
		"not-a-multibase-key !",
		id.did,                        // a valid DID
		id.did + "#" + id.auth.keyID,  // a valid kid
		strings.ToUpper(declared),     // the right key, wrong bytes
		"z" + strings.Repeat("0", 44), // multibase-SHAPED, declared by nothing
	} {
		route := base + "/index/v0/identities?" + keyParam(garbage)
		var body struct {
			Identities []indexIdentityRowBody `json:"identities"`
			Error      string                 `json:"error"`
		}
		resp := getJSON(t, route, &body)
		if resp.StatusCode != 200 {
			t.Fatalf("key=%q: status %d (error %q), want 200 — the value is opaque bytes, not a validated format", garbage, resp.StatusCode, body.Error)
		}
		if len(body.Identities) != 0 {
			t.Fatalf("key=%q returned %d rows, want an empty page", garbage, len(body.Identities))
		}
	}
}

// THE PRESENT-BUT-EMPTY VALUE IS DELIBERATELY NOT ASSERTED HERE.
//
// Both reference relays answer `?key=` and `?signerKey=` as NO FILTER, and that
// agreement is pinned — but in the dual-relay PARITY harness (parity_test.go,
// "key-addressed filters" → "an empty value is no filter at all"), not in this
// suite.
//
// The line is which contract each suite speaks for. WEB-RELAY says the value is
// matched as an opaque string with no format validation; it is SILENT on whether
// a present-but-empty parameter is a filter at all, so the posture is a twin
// consistency decision rather than something the spec requires. This file gates
// THIRD-PARTY relays, and gating an external implementation on an unstated
// posture would make the suite assert more than the specification it conforms
// to. The parity harness gates OUR two relays against each other, which is
// exactly the right place for a decision whose only warrant is "these two must
// not answer one question two ways."
//
// Banked follow-up: if the spec later gains the one clause — a present-but-empty
// value applies no filter, on both key-addressed filters — this case promotes
// back into this suite unchanged.
