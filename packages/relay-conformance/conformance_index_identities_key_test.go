// `key=` on /index/v0/identities — the reverse lookup "which identities has this
// key ever been PROVED into."
//
// This is the SIBLING of `signerKey=` on /index/v0/operations
// (conformance_index_operations_signer_key_test.go), and the two are one class:
// both match a multibase public key BYTE-FOR-BYTE against strings the chains
// declared, both are opaque (no format validation, no 400), both are actor-axis,
// proof-tier filters computed from accepted, signature-verified operations alone,
// and both are has-ever-PROVED. Where they differ is the axis: `key=` answers
// "which chains proved this key", `signerKey=` answers "which operations did it
// sign".
//
// WHY PROVED AND NOT DECLARED — the whole reason this filter has a rule at all.
// This index is the ONE-KEY-ONE-DID ORACLE: a holder asks it before signing a key
// proof and REFUSES when some chain already holds the key, because proving one
// key into two chains publishes an irreversible public link between those two
// identities (KEY-PROOF.md, Holder Obligations). An index of DECLARATIONS would
// therefore be a burn weapon. Nothing structural stops anyone from writing anyone
// else's public key into their own chain — and if that listing indexed, every
// future ceremony for the key's true holder would refuse, forever, on evidence
// the attacker manufactured for free. A declaration publishes no cross-DID link;
// only a proof does. So only a proof enters the oracle, and a hostile listing is
// void: never effective, never indexed, never a burn.
//
// The contract these tests pin, from WEB-RELAY's identities section:
//
//   - HAS-EVER-PROVED, not current state. Any accepted operation that ever
//     proved the key into the chain matches, whether or not a later update
//     rotated it out. Audit and key-loss recovery both need the full possession
//     history — a holder rediscovering identities from a restored key may hold
//     exactly the keys later updates removed — and possession, once demonstrated,
//     does not become untrue.
//   - A DECLARATION IS NOT A MATCH. A chain that lists a key no envelope ever
//     proved resolves nothing, ever. This is the burn defense, and it is the
//     single most important assertion in this file.
//   - No key-class column: `authKeys`, `assertKeys`, and `controllerKeys` are
//     all matched, and which array carried the key is the chain's answer.
//   - A DELETED identity still matches; the row carries `isDeleted` and a
//     consumer that does not want it filters client-side.
//   - The value is opaque: a string no operation ever proved matches nothing.
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
// PROVED into ANY of the three roles resolves the chain that proved it, and the
// filter does not leak chains that proved a different key.
//
// The fixture is the two-operation shape the protocol now requires. A genesis
// declares exactly ONE key, in all three roles, because its own signature is that
// key's possession proof and one signature demonstrates possession of one key. A
// distinct key per role is therefore reached the ordinary way: a single-key
// genesis, then an update that introduces the other three, each carrying its own
// envelope naming exactly the role it gains. That is not a workaround for the
// rule — it is the rule, and it is also the only shape that distinguishes
// "matches every role" from "matches whichever array the implementation happened
// to index".
func TestIndexIdentitiesKeyMatchesEveryKeyArray(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)

	id := createIdentity(t, base)
	auth := newKeypair()
	assert := newKeypair()
	controller := newKeypair()

	token, _ := signIdentityUpdateWithProofs(t, id.genCID,
		[]dfos.MultikeyPublicKey{id.controller.mk, controller.mk},
		[]dfos.MultikeyPublicKey{id.controller.mk, auth.mk},
		[]dfos.MultikeyPublicKey{id.controller.mk, assert.mk},
		[]string{
			keyProof(t, auth.priv, id.did, id.genCID, "auth"),
			keyProof(t, assert.priv, id.did, id.genCID, "assert"),
			keyProof(t, controller.priv, id.did, id.genCID, "controller"),
		},
		id.did+"#"+id.controller.keyID, id.controller.priv)
	postOperationsAccepted(t, base, []string{token})

	other := createIdentity(t, base)
	requireIdentityKeyFilter(t, base)

	for name, kp := range map[string]keypair{
		"controllerKeys": controller,
		"authKeys":       auth,
		"assertKeys":     assert,
	} {
		got := identitiesMatching(t, base, keyParam(kp.mk.PublicKeyMultibase))
		if len(got) != 1 || got[0] != id.did {
			t.Fatalf("key=<%s key> = %v, want exactly [%s] — every key array is matched, with no key-class column", name, got, id.did)
		}
	}

	// A different chain's key does not resolve this one.
	if got := identitiesMatching(t, base, keyParam(other.auth.mk.PublicKeyMultibase)); contains(got, id.did) {
		t.Fatalf("key=<another chain's key> leaked %s (rows: %v)", id.did, got)
	}

	// ANDs with did=: one key may match many chains, and `did=` narrows it. Here
	// the composition is asserted on the honest-empty side too — the pair
	// (this chain's key, the other chain's DID) matches nothing.
	composed := identitiesMatching(t, base, keyParam(auth.mk.PublicKeyMultibase)+"&did="+url.QueryEscape(id.did))
	if len(composed) != 1 || composed[0] != id.did {
		t.Fatalf("key=<auth>&did=<self> = %v, want [%s]", composed, id.did)
	}
	if got := identitiesMatching(t, base, keyParam(auth.mk.PublicKeyMultibase)+"&did="+url.QueryEscape(other.did)); len(got) != 0 {
		t.Fatalf("key=<auth>&did=<other> = %v, want an empty page", got)
	}
}

// TestIndexIdentitiesKeyIgnoresUnprovedDeclarations IS THE BURN DEFENSE, and it
// is the assertion this file exists for.
//
// A chain writes a key it does not hold into its own key arrays with no
// possession envelope. Anyone can do this to anyone — a public key is public —
// and under a has-ever-DECLARED index it would be catastrophic: the true holder's
// key would light up the one-key-one-DID oracle against a chain they never
// touched, and every future key-add ceremony for that key would refuse, forever,
// with no way to undo it.
//
// So the listing must resolve NOTHING. The key is void in the listing chain:
// declared, never effective, never indexed. And the proof that it was never
// burned is the second half — the key's actual holder then proves it into their
// OWN chain, and the filter returns that chain and only that chain.
func TestIndexIdentitiesKeyIgnoresUnprovedDeclarations(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)

	// The key the attack targets. It belongs to nobody yet; what matters is that
	// the hostile chain below cannot produce its signature.
	victim := newKeypair()

	// The HOSTILE LISTING: a chain declares the key in all three roles and carries
	// no envelope, because it holds no envelope to carry. The operation is
	// perfectly valid — void is a resolution verdict, not an ingest one — and it
	// sequences like any other.
	attacker := createIdentity(t, base)
	hostile, _ := signIdentityUpdateWithProofs(t, attacker.genCID,
		[]dfos.MultikeyPublicKey{attacker.controller.mk, victim.mk},
		[]dfos.MultikeyPublicKey{attacker.controller.mk, victim.mk},
		[]dfos.MultikeyPublicKey{attacker.controller.mk, victim.mk},
		nil,
		attacker.did+"#"+attacker.controller.keyID, attacker.controller.priv)
	postOperationsAccepted(t, base, []string{hostile})

	requireIdentityKeyFilter(t, base)

	// The listing indexes NOTHING. Not the attacker's chain, not anything.
	if got := identitiesMatching(t, base, keyParam(victim.mk.PublicKeyMultibase)); len(got) != 0 {
		t.Fatalf("key=<declared-but-never-proved> = %v, want an empty page — a chain that merely LISTS a key it does not hold must not enter the one-key-one-DID oracle, or a stranger can burn any key by writing it down", got)
	}

	// The attacker's OWN genesis key, which the genesis signature proved, is
	// indexed exactly as before — the refusal above is about possession and
	// nothing else.
	if got := identitiesMatching(t, base, keyParam(attacker.controller.mk.PublicKeyMultibase)); len(got) != 1 || got[0] != attacker.did {
		t.Fatalf("key=<attacker's proved genesis key> = %v, want [%s]", got, attacker.did)
	}

	// AND THE KEY WAS NEVER BURNED. Its real holder proves it into their own
	// chain, and the filter answers with that chain — only that chain.
	holder := createIdentity(t, base)
	introduceKey(t, base, &holder, victim)

	got := identitiesMatching(t, base, keyParam(victim.mk.PublicKeyMultibase))
	if len(got) != 1 || got[0] != holder.did {
		t.Fatalf("key=<now-proved> = %v, want exactly [%s] — the hostile listing must not appear beside the real one, or the burn succeeded partially", got, holder.did)
	}
}

// TestIndexIdentitiesKeyIsHasEverProved pins the history semantics: a key a later
// update rotates out KEEPS matching, and deleting the chain does not erase the
// deletion from the index — the row records it. Both are the cases a current-state
// implementation gets wrong, and both are exactly the cases key-loss recovery
// depends on — possession, once demonstrated, does not become untrue.
//
// The deletion half pins BOTH resolution shapes unconditionally. WEB-RELAY.md's
// discovery-vs-resolution rule lets a relay omit deleted identities from the
// DISCOVERY shapes of this route (the bare listing, the walks, nameContains,
// hasPublicProfile) — and requires `did=` AND `key=` to return them carrying
// isDeleted. `key=` is not a convenience here: key-loss recovery starts from a
// restored seed holding no DID, and mint-time burn checking refuses a key that
// already proves somewhere. A hidden sealed row tells a returning holder their
// identity never existed, and tells a minter that a spent key is free.
func TestIndexIdentitiesKeyIsHasEverProved(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	id := createIdentity(t, base)
	requireIdentityKeyFilter(t, base)

	// The genesis key is proved by the genesis signature itself.
	rotatedOut := id.controller
	replacement := newKeypair()
	controllerKid := id.did + "#" + id.controller.keyID
	// A WHOLE rotation carrying the replacement's envelope. Whole because genesis
	// declared one key in all three roles, so a narrower update would leave the old
	// key current in the roles it did not touch; with the envelope because an
	// unproved replacement would be void, and the assertion below would be testing
	// the wrong thing.
	rotateToken, rotateCID := signIdentityUpdateWithProofs(t, id.genCID,
		[]dfos.MultikeyPublicKey{replacement.mk},
		[]dfos.MultikeyPublicKey{replacement.mk},
		[]dfos.MultikeyPublicKey{replacement.mk},
		[]string{keyProof(t, replacement.priv, id.did, id.genCID)},
		controllerKid, id.controller.priv)
	postOperationsAccepted(t, base, []string{rotateToken})

	// HAS-EVER-PROVED: the rotated-out key is gone from head state and still
	// resolves the chain. The replacement resolves it too.
	if got := identitiesMatching(t, base, keyParam(rotatedOut.mk.PublicKeyMultibase)); len(got) != 1 || got[0] != id.did {
		t.Fatalf("key=<rotated-out> = %v, want [%s] — the filter is has-ever-proved, not current state", got, id.did)
	}
	if got := identitiesMatching(t, base, keyParam(replacement.mk.PublicKeyMultibase)); len(got) != 1 || got[0] != id.did {
		t.Fatalf("key=<replacement> = %v, want [%s] — a proved introduction indexes immediately", got, id.did)
	}

	// DELETION removes nothing from the reverse index; the row records it.
	deleteToken, _, err := dfos.SignIdentityDelete(rotateCID, id.did+"#"+replacement.keyID, replacement.priv)
	if err != nil {
		t.Fatalf("SignIdentityDelete: %v", err)
	}
	postOperationsAccepted(t, base, []string{deleteToken})

	// RESOLUTION 1 — `key=`. The has-ever-proved lookup MUST still answer with the
	// sealed chain. This is the assertion the recovery and burn-check paths rest
	// on, and neither has a DID to fall back to.
	rows := identityRowsMatching(t, base, keyParam(rotatedOut.mk.PublicKeyMultibase))
	if len(rows) != 1 || rows[0].DID != id.did {
		t.Fatalf("key=<rotated-out> after deletion = %+v, want the row for %s — `key=` is a resolution shape and MUST return a deleted identity", rows, id.did)
	}
	if !rows[0].IsDeleted {
		t.Fatalf("key=<rotated-out> row for a deleted chain reports isDeleted=false: %+v — the route defines no isDeleted filter, so the field is how a consumer knows", rows[0])
	}

	// RESOLUTION 2 — `did=`. The identifier itself, same MUST.
	resolved := identityRowsMatching(t, base, "did="+url.QueryEscape(id.did))
	if len(resolved) != 1 || resolved[0].DID != id.did {
		t.Fatalf("did=<deleted chain> = %+v, want the row for %s — `did=` is a resolution shape and MUST return a deleted identity", resolved, id.did)
	}
	if !resolved[0].IsDeleted {
		t.Fatalf("did=<deleted chain> row reports isDeleted=false: %+v — the field is how a consumer knows", resolved[0])
	}

	// PRECEDENCE — a discovery-shaped filter riding along does NOT convert a
	// resolution back into a discovery. The sealed chain published no profile, so
	// `hasPublicProfile=false` is the filter it satisfies; the row MUST survive it.
	// If a relay reapplied its deleted-exclusion whenever any other filter was
	// present, the resolution guarantee would evaporate exactly when a caller
	// narrowed a lookup they already held the identifier for.
	narrowed := identityRowsMatching(t, base, "did="+url.QueryEscape(id.did)+"&hasPublicProfile=false")
	if len(narrowed) != 1 || narrowed[0].DID != id.did || !narrowed[0].IsDeleted {
		t.Fatalf("did=<deleted chain>&hasPublicProfile=false = %+v, want the sealed row for %s — `did=` makes the request a resolution whatever else it carries", narrowed, id.did)
	}

	// DISCOVERY — here, and only here, either behavior is conformant. A relay that
	// lists deleted identities returns the row and it MUST carry isDeleted; a
	// relay that omits them does not return it. What is never conformant is a
	// sealed row presented as live, so that is what this asserts.
	for _, row := range identityRowsMatching(t, base, "hasPublicProfile=false") {
		if row.DID == id.did && !row.IsDeleted {
			t.Fatalf("hasPublicProfile=false listed the deleted chain %s as live: %+v", id.did, row)
		}
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
	// string the filter matches. (Declared is how the value is SPELLED; proved is
	// which values are present at all — the two rules are about different things
	// and the genesis key satisfies both.) A relay that re-encoded the key into its
	// own canonical rendering would fail here, and would also hand back a value
	// that appears nowhere in the chain a client can fetch and verify for itself.
	declared := id.auth.mk.PublicKeyMultibase
	if got := identitiesMatching(t, base, keyParam(declared)); len(got) != 1 || got[0] != id.did {
		t.Fatalf("key=%q = %v, want [%s] — the value matched is the string the chain declared", declared, got, id.did)
	}

	for _, garbage := range []string{
		"not-a-multibase-key !",
		id.did,                        // a valid DID
		id.did + "#" + id.auth.keyID,  // a valid kid
		strings.ToUpper(declared),     // the right key, wrong bytes
		"z" + strings.Repeat("0", 44), // multibase-SHAPED, proved by nothing
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
