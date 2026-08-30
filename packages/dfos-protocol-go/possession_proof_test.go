package dfos

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
)

// POSSESSION PROOFS ON THE IDENTITY CHAIN — the bimodal rule, and void semantics.
//
// Byte-twin of dfos-protocol/tests/possession-proof.spec.ts, case for case.
//
// The claim this file exists to hold: a key-role membership is EFFECTIVE only if
// possession admitted it, and everything else about the chain is unmoved. Every
// negative below produces a chain that VERIFIES — the operations are valid, the
// CIDs stand, a relay sequences them — and a key that does not resolve.
//
// Read the assertions in pairs. Each case checks Declared still carries the
// membership, VoidKeys names it, and the effective array does not. Those three
// together are the whole of "void": the chain said it, nobody proved it, no
// consumer sees it.

// -----------------------------------------------------------------------------
// fixtures
// -----------------------------------------------------------------------------

// possessionKey bundles one keypair with the Multikey the chain declares for it.
type possessionKey struct {
	priv  ed25519.PrivateKey
	mk    MultikeyPublicKey
	keyID string
}

func newPossessionKey(t *testing.T) possessionKey {
	t.Helper()
	priv, _, mk, keyID := testKeys(t)
	return possessionKey{priv: priv, mk: mk, keyID: keyID}
}

func possessionTS(minute int) string {
	return fmt.Sprintf("2026-03-07T00:%02d:00.000Z", minute)
}

// possessionGenesis mints a single-key genesis and the state it verifies to.
type possessionChain struct {
	key   possessionKey
	jws   string
	cid   string
	did   string
	state IdentityState
	// createdAt of the genesis operation.
	createdAt string
}

func newPossessionGenesis(t *testing.T) possessionChain {
	t.Helper()
	k := newPossessionKey(t)
	createdAt := possessionTS(0)
	jws, did, cid := testSignIdentityGenesis(t, k.mk, k.keyID, k.priv, createdAt)
	result, err := VerifyIdentityChain([]string{jws})
	if err != nil {
		t.Fatalf("genesis: %v", err)
	}
	return possessionChain{key: k, jws: jws, cid: cid, did: did, state: result.State, createdAt: createdAt}
}

func keysOf(k ...possessionKey) []MultikeyPublicKey {
	out := make([]MultikeyPublicKey, len(k))
	for i, key := range k {
		out[i] = key.mk
	}
	return out
}

func effectiveRole(state IdentityState, role KeyRole) []MultikeyPublicKey {
	switch role {
	case "auth":
		return state.AuthKeys
	case "assert":
		return state.AssertKeys
	case "controller":
		return state.ControllerKeys
	}
	return nil
}

func isEffective(state IdentityState, key MultikeyPublicKey, role KeyRole) bool {
	for _, k := range effectiveRole(state, role) {
		if k.ID == key.ID {
			return true
		}
	}
	return false
}

func isDeclared(state IdentityState, key MultikeyPublicKey, role KeyRole) bool {
	for _, k := range declaredRoleKeys(state.Declared, role) {
		if k.ID == key.ID {
			return true
		}
	}
	return false
}

func isVoid(state IdentityState, key MultikeyPublicKey, role KeyRole) bool {
	for _, v := range state.VoidKeys {
		if v.Key.ID == key.ID && v.Role == role {
			return true
		}
	}
	return false
}

// expectVoid is the assertion every negative case makes: declared, void, and NOT
// effective — on a chain that verified.
func expectVoid(t *testing.T, state IdentityState, key MultikeyPublicKey, roles ...KeyRole) {
	t.Helper()
	for _, role := range roles {
		if !isDeclared(state, key, role) {
			t.Fatalf("%s: expected the membership to still be DECLARED", role)
		}
		if !isVoid(state, key, role) {
			t.Fatalf("%s: expected the membership on the void list", role)
		}
		if isEffective(state, key, role) {
			t.Fatalf("%s: expected the membership to be absent from effective state", role)
		}
	}
}

func expectProved(t *testing.T, state IdentityState, key MultikeyPublicKey, roles ...KeyRole) {
	t.Helper()
	for _, role := range roles {
		if !isDeclared(state, key, role) {
			t.Fatalf("%s: expected the membership to be DECLARED", role)
		}
		if !isEffective(state, key, role) {
			t.Fatalf("%s: expected the membership to be EFFECTIVE", role)
		}
		if isVoid(state, key, role) {
			t.Fatalf("%s: expected the membership NOT to be void", role)
		}
	}
}

// expectSameKeyState compares two key states role by role, entry by entry — the
// Go stand-in for the TS suite's structural toEqual on a DeclaredKeyState.
func expectSameKeyState(t *testing.T, label string, got, want DeclaredKeyState) {
	t.Helper()
	for _, role := range KeyRoles {
		gotKeys := declaredRoleKeys(got, role)
		wantKeys := declaredRoleKeys(want, role)
		if len(gotKeys) != len(wantKeys) {
			t.Fatalf("%s %s: %d entries vs %d", label, role, len(gotKeys), len(wantKeys))
		}
		for i := range gotKeys {
			if gotKeys[i] != wantKeys[i] {
				t.Fatalf("%s %s[%d]: %+v vs %+v", label, role, i, gotKeys[i], wantKeys[i])
			}
		}
	}
}

func mustVerifyChain(t *testing.T, log ...string) IdentityState {
	t.Helper()
	result, err := VerifyIdentityChain(log)
	if err != nil {
		t.Fatalf("VerifyIdentityChain: %v", err)
	}
	return result.State
}

// -----------------------------------------------------------------------------
// the positive ceremony
// -----------------------------------------------------------------------------

func TestPossessionAdmitsARotationProvedAtTheCurrentHead(t *testing.T) {
	g := newPossessionGenesis(t)
	rotated := newPossessionKey(t)
	rot, _ := testSignIdentityUpdateWithProofs(t, g.did,
		keysOf(rotated), keysOf(rotated), keysOf(rotated),
		[]string{testKeyProof(t, rotated.priv, g.did, g.cid)},
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))

	state := mustVerifyChain(t, g.jws, rot)
	expectProved(t, state, rotated.mk, KeyRoles...)
	if len(state.VoidKeys) != 0 {
		t.Fatalf("void keys: %+v", state.VoidKeys)
	}
	// The genesis key is gone from BOTH states — a removal is a removal.
	if isDeclared(state, g.key.mk, "controller") || isEffective(state, g.key.mk, "controller") {
		t.Fatalf("the rotated-out genesis key survived")
	}
}

func TestPossessionProvesSeveralRolesWithOneEnvelope(t *testing.T) {
	g := newPossessionGenesis(t)
	a := newPossessionKey(t)
	b := newPossessionKey(t)
	// The genesis key stays a controller (a replay, no proof needed); `a` joins all
	// three roles on one envelope; `b` joins auth only.
	op, _ := testSignIdentityUpdateWithProofs(t, g.did,
		keysOf(g.key, a), keysOf(g.key, a, b), keysOf(g.key, a),
		[]string{
			testKeyProof(t, a.priv, g.did, g.cid),
			testKeyProof(t, b.priv, g.did, g.cid, "auth"),
		},
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))

	state := mustVerifyChain(t, g.jws, op)
	expectProved(t, state, a.mk, KeyRoles...)
	expectProved(t, state, b.mk, "auth")
	expectProved(t, state, g.key.mk, KeyRoles...)
	if len(state.VoidKeys) != 0 {
		t.Fatalf("void keys: %+v", state.VoidKeys)
	}
}

// TestPossessionDoesNotReplayProofsForward: a later update that only repeats keys
// carries none. Proved-ness is INHERITED, which is what keeps proofs from
// accumulating in a chain.
func TestPossessionDoesNotReplayProofsForward(t *testing.T) {
	g := newPossessionGenesis(t)
	rotated := newPossessionKey(t)
	rot, rotCID := testSignIdentityUpdateWithProofs(t, g.did,
		keysOf(rotated), keysOf(rotated), keysOf(rotated),
		[]string{testKeyProof(t, rotated.priv, g.did, g.cid)},
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))

	// The same keys, no envelopes at all.
	later, _ := testSignIdentityUpdate(t, g.did,
		keysOf(rotated), keysOf(rotated), keysOf(rotated),
		rotated.keyID, rotated.priv, rotCID, possessionTS(2))

	_, payload, err := DecodeJWSUnsafe(later)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, present := payload["keyProofs"]; present {
		t.Fatalf("the replaying update carried envelopes it does not need")
	}

	state := mustVerifyChain(t, g.jws, rot, later)
	expectProved(t, state, rotated.mk, KeyRoles...)
	if len(state.VoidKeys) != 0 {
		t.Fatalf("void keys: %+v", state.VoidKeys)
	}
}

// -----------------------------------------------------------------------------
// void semantics
// -----------------------------------------------------------------------------

// TestPossessionVoidsAnIntroductionWithNoEnvelope is the door-3 claim: an
// unproved introduction is not an invalid operation.
func TestPossessionVoidsAnIntroductionWithNoEnvelope(t *testing.T) {
	g := newPossessionGenesis(t)
	added := newPossessionKey(t)
	op, opCID := testSignIdentityUpdate(t, g.did,
		keysOf(g.key), keysOf(g.key, added), keysOf(g.key),
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))

	// THE CHAIN VERIFIES.
	state := mustVerifyChain(t, g.jws, op)
	if state.DID != g.did {
		t.Fatalf("did: %s", state.DID)
	}
	expectVoid(t, state, added.mk, "auth")
	if len(state.VoidKeys) != 1 {
		t.Fatalf("void keys: %+v", state.VoidKeys)
	}
	if state.VoidKeys[0].OperationCID != opCID {
		t.Fatalf("void operationCID: %s want %s", state.VoidKeys[0].OperationCID, opCID)
	}
	// ...and the genesis key, proved by signing genesis, is untouched.
	expectProved(t, state, g.key.mk, KeyRoles...)
}

// TestPossessionVoidsAnEnvelopeBoundToTheWrongHead is the standing-consent case.
func TestPossessionVoidsAnEnvelopeBoundToTheWrongHead(t *testing.T) {
	g := newPossessionGenesis(t)
	filler, fillerCID := testSignIdentityUpdate(t, g.did,
		keysOf(g.key), keysOf(g.key), keysOf(g.key),
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))

	added := newPossessionKey(t)
	// The envelope names GENESIS as its head; the operation carrying it builds on
	// `filler`. An envelope minted one operation ago is already dead.
	stale := testKeyProof(t, added.priv, g.did, g.cid)
	op, _ := testSignIdentityUpdateWithProofs(t, g.did,
		keysOf(g.key), keysOf(g.key, added), keysOf(g.key),
		[]string{stale},
		g.key.keyID, g.key.priv, fillerCID, possessionTS(2))
	expectVoid(t, mustVerifyChain(t, g.jws, filler, op), added.mk, "auth")

	// The SAME key, the SAME operation position, with a correctly-headed envelope:
	// proved. So the refusal is the head binding and nothing else.
	fresh, _ := testSignIdentityUpdateWithProofs(t, g.did,
		keysOf(g.key), keysOf(g.key, added), keysOf(g.key),
		[]string{testKeyProof(t, added.priv, g.did, fillerCID)},
		g.key.keyID, g.key.priv, fillerCID, possessionTS(2))
	expectProved(t, mustVerifyChain(t, g.jws, filler, fresh), added.mk, "auth")
}

func TestPossessionVoidsAnEnvelopeBoundToAnotherChain(t *testing.T) {
	g := newPossessionGenesis(t)
	other := newPossessionGenesis(t)
	added := newPossessionKey(t)
	// Real key, real signature, right head shape — wrong identity.
	op, _ := testSignIdentityUpdateWithProofs(t, g.did,
		keysOf(g.key), keysOf(g.key, added), keysOf(g.key),
		[]string{testKeyProof(t, added.priv, other.did, g.cid)},
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))

	expectVoid(t, mustVerifyChain(t, g.jws, op), added.mk, "auth")
}

func TestPossessionVoidsOnlyTheRolesTheEnvelopeDoesNotCover(t *testing.T) {
	g := newPossessionGenesis(t)
	added := newPossessionKey(t)
	// Consent to auth alone. The other two memberships are declared with no
	// consent behind them.
	op, _ := testSignIdentityUpdateWithProofs(t, g.did,
		keysOf(g.key, added), keysOf(g.key, added), keysOf(g.key, added),
		[]string{testKeyProof(t, added.priv, g.did, g.cid, "auth")},
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))

	state := mustVerifyChain(t, g.jws, op)
	expectProved(t, state, added.mk, "auth")
	expectVoid(t, state, added.mk, "assert", "controller")
}

// TestPossessionVoidsAPromotionWithNoFreshEnvelope: holding auth is not consent
// to hold control, so the promotion is its own introduction and needs its own
// envelope.
func TestPossessionVoidsAPromotionWithNoFreshEnvelope(t *testing.T) {
	g := newPossessionGenesis(t)
	added := newPossessionKey(t)
	join, joinCID := testSignIdentityUpdateWithProofs(t, g.did,
		keysOf(g.key), keysOf(g.key, added), keysOf(g.key),
		[]string{testKeyProof(t, added.priv, g.did, g.cid, "auth")},
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))

	// The controller quietly promotes it to controller.
	promote, _ := testSignIdentityUpdate(t, g.did,
		keysOf(g.key, added), keysOf(g.key, added), keysOf(g.key),
		g.key.keyID, g.key.priv, joinCID, possessionTS(2))

	state := mustVerifyChain(t, g.jws, join, promote)
	expectProved(t, state, added.mk, "auth")
	expectVoid(t, state, added.mk, "controller")
}

// TestPossessionVoidsAReAddAfterRemoval: the re-add REPLAYS the original envelope
// verbatim. It is a real signature by the real key that really consented once —
// bound to a head two operations back. Consent does not stand.
func TestPossessionVoidsAReAddAfterRemoval(t *testing.T) {
	g := newPossessionGenesis(t)
	added := newPossessionKey(t)
	firstEnvelope := testKeyProof(t, added.priv, g.did, g.cid, "auth")

	join, joinCID := testSignIdentityUpdateWithProofs(t, g.did,
		keysOf(g.key), keysOf(g.key, added), keysOf(g.key),
		[]string{firstEnvelope},
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))
	remove, removeCID := testSignIdentityUpdate(t, g.did,
		keysOf(g.key), keysOf(g.key), keysOf(g.key),
		g.key.keyID, g.key.priv, joinCID, possessionTS(2))
	readd, _ := testSignIdentityUpdateWithProofs(t, g.did,
		keysOf(g.key), keysOf(g.key, added), keysOf(g.key),
		[]string{firstEnvelope},
		g.key.keyID, g.key.priv, removeCID, possessionTS(3))

	expectVoid(t, mustVerifyChain(t, g.jws, join, remove, readd), added.mk, "auth")
}

// TestPossessionClimbsBackOutOfVoid: the membership is still declared at the next
// operation, so it is still an introduction there — and an envelope headed at THAT
// operation's parent rescues it. Void is a state, not a mark.
func TestPossessionClimbsBackOutOfVoid(t *testing.T) {
	g := newPossessionGenesis(t)
	added := newPossessionKey(t)
	unproved, unprovedCID := testSignIdentityUpdate(t, g.did,
		keysOf(g.key), keysOf(g.key, added), keysOf(g.key),
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))
	rescue, _ := testSignIdentityUpdateWithProofs(t, g.did,
		keysOf(g.key), keysOf(g.key, added), keysOf(g.key),
		[]string{testKeyProof(t, added.priv, g.did, unprovedCID, "auth")},
		g.key.keyID, g.key.priv, unprovedCID, possessionTS(2))

	expectVoid(t, mustVerifyChain(t, g.jws, unproved), added.mk, "auth")
	expectProved(t, mustVerifyChain(t, g.jws, unproved, rescue), added.mk, "auth")
}

// -----------------------------------------------------------------------------
// has-ever-proved
// -----------------------------------------------------------------------------

func provedRoleIDs(state IdentityState, role KeyRole) []string {
	keys := declaredRoleKeys(state.ProvedKeys, role)
	ids := make([]string, len(keys))
	for i, k := range keys {
		ids[i] = k.ID
	}
	return ids
}

func containsID(ids []string, id string) bool {
	for _, candidate := range ids {
		if candidate == id {
			return true
		}
	}
	return false
}

// TestPossessionKeepsAProvedKeyForeverAndNeverAdmitsAVoidOne is the load-bearing
// has-ever-proved case. The key= reverse index and historical key resolution both
// read ProvedKeys, and both are wrong under either of the two obvious shortcuts:
// reading current effective state loses a rotated-out key that was genuinely
// proved, and reading the raw log admits a key a stranger merely DECLARED.
func TestPossessionKeepsAProvedKeyForeverAndNeverAdmitsAVoidOne(t *testing.T) {
	g := newPossessionGenesis(t)
	rotated := newPossessionKey(t)
	neverProved := newPossessionKey(t)

	// `rotated` is proved in; `neverProved` is declared with no envelope.
	rot, rotCID := testSignIdentityUpdateWithProofs(t, g.did,
		keysOf(rotated), keysOf(rotated, neverProved), keysOf(rotated),
		[]string{testKeyProof(t, rotated.priv, g.did, g.cid)},
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))

	// A second rotation drops BOTH of them and goes to a key of its own.
	third := newPossessionKey(t)
	rot2, _ := testSignIdentityUpdateWithProofs(t, g.did,
		keysOf(third), keysOf(third), keysOf(third),
		[]string{testKeyProof(t, third.priv, g.did, rotCID)},
		rotated.keyID, rotated.priv, rotCID, possessionTS(2))

	state := mustVerifyChain(t, g.jws, rot, rot2)

	// Current effective state holds only the third key...
	effectiveAuth := effectiveRole(state, "auth")
	if len(effectiveAuth) != 1 || effectiveAuth[0].ID != third.mk.ID {
		t.Fatalf("effective auth keys: %+v", effectiveAuth)
	}
	// ...while has-ever-proved holds all three keys that were ever proved in.
	provedAuth := provedRoleIDs(state, "auth")
	for _, want := range []possessionKey{g.key, rotated, third} {
		if !containsID(provedAuth, want.mk.ID) {
			t.Fatalf("proved auth keys %v missing %s", provedAuth, want.mk.ID)
		}
	}
	// The declared-but-never-proved key is absent. A stranger cannot burn a key by
	// writing it into their own chain.
	if containsID(provedAuth, neverProved.mk.ID) {
		t.Fatalf("a never-proved declaration entered the has-ever-proved union: %v", provedAuth)
	}
	// The union is per role: `neverProved` was only ever declared into auth, and
	// the three real keys were proved into all three roles.
	for _, role := range []KeyRole{"assert", "controller"} {
		ids := provedRoleIDs(state, role)
		if containsID(ids, neverProved.mk.ID) {
			t.Fatalf("%s: never-proved key present: %v", role, ids)
		}
		if !containsID(ids, g.key.mk.ID) || !containsID(ids, rotated.mk.ID) || !containsID(ids, third.mk.ID) {
			t.Fatalf("%s: proved history is incomplete: %v", role, ids)
		}
	}
}

func TestPossessionProvedKeysAgreeBetweenReplayAndExtension(t *testing.T) {
	g := newPossessionGenesis(t)
	rotated := newPossessionKey(t)
	rot, _ := testSignIdentityUpdateWithProofs(t, g.did,
		keysOf(rotated), keysOf(rotated), keysOf(rotated),
		[]string{testKeyProof(t, rotated.priv, g.did, g.cid)},
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))

	replayed := mustVerifyChain(t, g.jws, rot)
	extended, err := VerifyIdentityExtension(g.state, g.cid, g.createdAt, rot)
	if err != nil {
		t.Fatalf("VerifyIdentityExtension: %v", err)
	}
	expectSameKeyState(t, "provedKeys", extended.State.ProvedKeys, replayed.ProvedKeys)
}

// TestPossessionProvedKeysCarryAcrossDeleteAndRestore: neither operation
// introduces anything, so the has-ever-proved union travels forward untouched.
func TestPossessionProvedKeysCarryAcrossDeleteAndRestore(t *testing.T) {
	g := newPossessionGenesis(t)
	del, delCID := testSignIdentityDelete(t, g.did, g.key.keyID, g.key.priv, g.cid, possessionTS(1))
	restore, _ := testSignIdentityRestore(t, g.did, g.key.keyID, g.key.priv, delCID, possessionTS(2))

	replayed := mustVerifyChain(t, g.jws, del, restore)
	if !containsID(provedRoleIDs(replayed, "controller"), g.key.mk.ID) {
		t.Fatalf("replay lost the genesis key from the proved union")
	}

	afterDelete, err := VerifyIdentityExtension(g.state, g.cid, g.createdAt, del)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	afterRestore, err := VerifyIdentityExtension(afterDelete.State, afterDelete.HeadCID, afterDelete.LastCreatedAt, restore)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	expectSameKeyState(t, "provedKeys", afterRestore.State.ProvedKeys, replayed.ProvedKeys)
}

// -----------------------------------------------------------------------------
// what proof status does NOT touch
// -----------------------------------------------------------------------------

// TestPossessionAdmitsASignatureFromAVoidControllerKey is the load-bearing
// separation. A relay must be able to decide whether an operation is admissible
// without weighing possession evidence, or two relays could disagree about
// whether an operation exists at all.
func TestPossessionAdmitsASignatureFromAVoidControllerKey(t *testing.T) {
	g := newPossessionGenesis(t)
	unproved := newPossessionKey(t)
	promote, promoteCID := testSignIdentityUpdate(t, g.did,
		keysOf(g.key, unproved), keysOf(g.key), keysOf(g.key),
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))
	expectVoid(t, mustVerifyChain(t, g.jws, promote), unproved.mk, "controller")

	// ...and it signs the next operation anyway, because DECLARED state admits it.
	next, _ := testSignIdentityUpdate(t, g.did,
		keysOf(g.key, unproved), keysOf(g.key), keysOf(g.key),
		unproved.keyID, unproved.priv, promoteCID, possessionTS(2))

	state := mustVerifyChain(t, g.jws, promote, next)
	if state.IsDeleted {
		t.Fatalf("unexpectedly deleted")
	}
	// The key signed a valid operation and still does not resolve. Both are true
	// at once, and that is the design.
	expectVoid(t, state, unproved.mk, "controller")
}

func TestPossessionCarriesBothKeyStatesAcrossDeleteAndRestore(t *testing.T) {
	g := newPossessionGenesis(t)
	added := newPossessionKey(t)
	op, opCID := testSignIdentityUpdate(t, g.did,
		keysOf(g.key), keysOf(g.key, added), keysOf(g.key),
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))
	del, delCID := testSignIdentityDelete(t, g.did, g.key.keyID, g.key.priv, opCID, possessionTS(2))
	restore, _ := testSignIdentityRestore(t, g.did, g.key.keyID, g.key.priv, delCID, possessionTS(3))

	state := mustVerifyChain(t, g.jws, op, del, restore)
	if state.IsDeleted {
		t.Fatalf("unexpectedly deleted")
	}
	expectVoid(t, state, added.mk, "auth")
	expectProved(t, state, g.key.mk, KeyRoles...)
}

// -----------------------------------------------------------------------------
// carriage
// -----------------------------------------------------------------------------

// signIdentityOpWithStrayProof signs a create/delete/restore carrying a keyProofs
// member — the shape the carriage gate refuses.
func signIdentityOpWithStrayProof(t *testing.T, payload map[string]any, kid string, priv ed25519.PrivateKey, proof string) string {
	t.Helper()
	payload["keyProofs"] = []string{proof}
	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		t.Fatal(err)
	}
	header := JWSHeader{Alg: "EdDSA", Typ: "did:dfos:identity-op", Kid: kid, CID: cidStr}
	token, err := CreateJWS(header, payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestPossessionRejectsKeyProofsOnCreateDeleteAndRestore(t *testing.T) {
	g := newPossessionGenesis(t)
	stray := testKeyProof(t, g.key.priv, g.did, g.cid)

	// create
	k := newPossessionKey(t)
	badGenesis := signIdentityOpWithStrayProof(t, map[string]any{
		"version":        int64(1),
		"type":           "create",
		"authKeys":       keysOf(k),
		"assertKeys":     keysOf(k),
		"controllerKeys": keysOf(k),
		"createdAt":      possessionTS(0),
	}, k.keyID, k.priv, stray)
	if _, err := VerifyIdentityChain([]string{badGenesis}); err == nil ||
		!strings.Contains(err.Error(), "keyProofs is valid on update only") {
		t.Fatalf("create carriage: %v", err)
	}

	// delete
	badDelete := signIdentityOpWithStrayProof(t, map[string]any{
		"version":              int64(1),
		"type":                 "delete",
		"previousOperationCID": g.cid,
		"createdAt":            possessionTS(1),
	}, g.did+"#"+g.key.keyID, g.key.priv, stray)
	if _, err := VerifyIdentityChain([]string{g.jws, badDelete}); err == nil ||
		!strings.Contains(err.Error(), "keyProofs is valid on update only") {
		t.Fatalf("delete carriage: %v", err)
	}

	// restore — which needs a real delete in front of it, since restore is only
	// ever valid immediately after one.
	cleanDelete, cleanDeleteCID := testSignIdentityDelete(t, g.did, g.key.keyID, g.key.priv, g.cid, possessionTS(1))
	badRestore := signIdentityOpWithStrayProof(t, map[string]any{
		"version":              int64(1),
		"type":                 "restore",
		"previousOperationCID": cleanDeleteCID,
		"createdAt":            possessionTS(2),
	}, g.did+"#"+g.key.keyID, g.key.priv, stray)
	if _, err := VerifyIdentityChain([]string{g.jws, cleanDelete, badRestore}); err == nil ||
		!strings.Contains(err.Error(), "keyProofs is valid on update only") {
		t.Fatalf("restore carriage: %v", err)
	}
}

// TestPossessionRejectsAMultiKeyGenesis pins the single-key genesis rule — the one
// key rule in the chain that is a REJECT rather than a void, because nothing
// precedes genesis to be a prevCID and no later operation could rescue a second
// key declared there.
func TestPossessionRejectsAMultiKeyGenesis(t *testing.T) {
	k := newPossessionKey(t)
	other := newPossessionKey(t)
	one := keysOf(k)

	for label, arrays := range map[string][3][]MultikeyPublicKey{
		"no controller key":       {{}, one, one},
		"no auth key":             {one, {}, one},
		"no assert key":           {one, one, {}},
		"two controller keys":     {keysOf(k, other), one, one},
		"a different key in auth": {one, keysOf(other), one},
	} {
		jws, _, _ := testSignIdentityGenesisRaw(t, arrays[0], arrays[1], arrays[2], k.keyID, k.priv, possessionTS(0))
		_, err := VerifyIdentityChain([]string{jws})
		if err == nil {
			t.Fatalf("%s: expected a rejection", label)
		}
		if !strings.Contains(err.Error(), "exactly one key") && !strings.Contains(err.Error(), "SAME key") {
			t.Fatalf("%s: %v", label, err)
		}
	}
}

func TestPossessionRejectsMoreKeyProofsThanTheCap(t *testing.T) {
	g := newPossessionGenesis(t)
	added := newPossessionKey(t)
	proofs := make([]string, MaxKeyProofs+1)
	for i := range proofs {
		proofs[i] = testKeyProof(t, added.priv, g.did, g.cid, "auth")
	}
	op, _ := testSignIdentityUpdateWithProofs(t, g.did,
		keysOf(g.key), keysOf(g.key, added), keysOf(g.key), proofs,
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))
	if _, err := VerifyIdentityChain([]string{g.jws, op}); err == nil ||
		!strings.Contains(err.Error(), "keyProofs exceeds max count") {
		t.Fatalf("cap: %v", err)
	}
}

// -----------------------------------------------------------------------------
// the O(1) extension verifier agrees with full replay
// -----------------------------------------------------------------------------

func TestPossessionExtensionAgreesWithFullReplay(t *testing.T) {
	g := newPossessionGenesis(t)
	proved := newPossessionKey(t)
	unproved := newPossessionKey(t)
	op, opCID := testSignIdentityUpdateWithProofs(t, g.did,
		keysOf(g.key), keysOf(g.key, proved, unproved), keysOf(g.key),
		[]string{testKeyProof(t, proved.priv, g.did, g.cid, "auth")},
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))

	replayed := mustVerifyChain(t, g.jws, op)
	extended, err := VerifyIdentityExtension(g.state, g.cid, g.createdAt, op)
	if err != nil {
		t.Fatalf("VerifyIdentityExtension: %v", err)
	}
	if extended.HeadCID != opCID {
		t.Fatalf("head: %s want %s", extended.HeadCID, opCID)
	}
	expectSameKeyState(t, "effective", DeclaredKeyState{
		AuthKeys:       extended.State.AuthKeys,
		AssertKeys:     extended.State.AssertKeys,
		ControllerKeys: extended.State.ControllerKeys,
	}, DeclaredKeyState{
		AuthKeys:       replayed.AuthKeys,
		AssertKeys:     replayed.AssertKeys,
		ControllerKeys: replayed.ControllerKeys,
	})
	expectSameKeyState(t, "declared", extended.State.Declared, replayed.Declared)
	expectSameKeyState(t, "provedKeys", extended.State.ProvedKeys, replayed.ProvedKeys)
	if len(extended.State.VoidKeys) != len(replayed.VoidKeys) {
		t.Fatalf("void list: %+v vs %+v", extended.State.VoidKeys, replayed.VoidKeys)
	}
	for i := range extended.State.VoidKeys {
		if extended.State.VoidKeys[i] != replayed.VoidKeys[i] {
			t.Fatalf("void[%d]: %+v vs %+v", i, extended.State.VoidKeys[i], replayed.VoidKeys[i])
		}
	}
	expectProved(t, extended.State, proved.mk, "auth")
	expectVoid(t, extended.State, unproved.mk, "auth")
}

// TestPossessionExtensionAdmitsAVoidControllerSigner: the extension verifier
// resolves the signer against DECLARED state too, so a key that is void for
// `controller` still signs.
func TestPossessionExtensionAdmitsAVoidControllerSigner(t *testing.T) {
	g := newPossessionGenesis(t)
	unproved := newPossessionKey(t)
	promote, promoteCID := testSignIdentityUpdate(t, g.did,
		keysOf(g.key, unproved), keysOf(g.key), keysOf(g.key),
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))
	promoted, err := VerifyIdentityExtension(g.state, g.cid, g.createdAt, promote)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	expectVoid(t, promoted.State, unproved.mk, "controller")
	if isEffective(promoted.State, unproved.mk, "controller") {
		t.Fatalf("a void key entered effective state")
	}

	next, _ := testSignIdentityUpdate(t, g.did,
		keysOf(g.key, unproved), keysOf(g.key), keysOf(g.key),
		unproved.keyID, unproved.priv, promoteCID, possessionTS(2))
	if _, err := VerifyIdentityExtension(promoted.State, promoted.HeadCID, promoted.LastCreatedAt, next); err != nil {
		t.Fatalf("a void controller key was refused as a signer: %v", err)
	}
}

// TestPossessionExtensionFallsBackToEffectiveWhenDeclaredIsAbsent pins the
// hand-built-state reading: an absent Declared is read as "the effective arrays
// are also the declared arrays", which is exactly true for a chain with no void
// memberships.
func TestPossessionExtensionFallsBackToEffectiveWhenDeclaredIsAbsent(t *testing.T) {
	g := newPossessionGenesis(t)
	handBuilt := g.state
	handBuilt.Declared = DeclaredKeyState{}
	handBuilt.VoidKeys = nil

	added := newPossessionKey(t)
	op, _ := testSignIdentityUpdateWithProofs(t, g.did,
		keysOf(g.key), keysOf(g.key, added), keysOf(g.key),
		[]string{testKeyProof(t, added.priv, g.did, g.cid, "auth")},
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))

	extended, err := VerifyIdentityExtension(handBuilt, g.cid, g.createdAt, op)
	if err != nil {
		t.Fatalf("VerifyIdentityExtension: %v", err)
	}
	expectProved(t, extended.State, added.mk, "auth")
}

func TestPossessionExtensionRejectsKeyProofsOnDelete(t *testing.T) {
	g := newPossessionGenesis(t)
	stray := testKeyProof(t, g.key.priv, g.did, g.cid)
	signed := signIdentityOpWithStrayProof(t, map[string]any{
		"version":              int64(1),
		"type":                 "delete",
		"previousOperationCID": g.cid,
		"createdAt":            possessionTS(1),
	}, g.did+"#"+g.key.keyID, g.key.priv, stray)

	if _, err := VerifyIdentityExtension(g.state, g.cid, g.createdAt, signed); err == nil ||
		!strings.Contains(err.Error(), "keyProofs is valid on update only") {
		t.Fatalf("delete extension carriage: %v", err)
	}
}

// TestPossessionExtensionCarriesStateAcrossDeleteAndRestore mirrors the full-replay
// case: neither operation introduces anything, so both key states and the void
// list travel forward untouched.
func TestPossessionExtensionCarriesStateAcrossDeleteAndRestore(t *testing.T) {
	g := newPossessionGenesis(t)
	added := newPossessionKey(t)
	op, _ := testSignIdentityUpdate(t, g.did,
		keysOf(g.key), keysOf(g.key, added), keysOf(g.key),
		g.key.keyID, g.key.priv, g.cid, possessionTS(1))
	afterUpdate, err := VerifyIdentityExtension(g.state, g.cid, g.createdAt, op)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	expectVoid(t, afterUpdate.State, added.mk, "auth")

	del, _ := testSignIdentityDelete(t, g.did, g.key.keyID, g.key.priv, afterUpdate.HeadCID, possessionTS(2))
	afterDelete, err := VerifyIdentityExtension(afterUpdate.State, afterUpdate.HeadCID, afterUpdate.LastCreatedAt, del)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !afterDelete.State.IsDeleted {
		t.Fatalf("expected deleted")
	}
	expectVoid(t, afterDelete.State, added.mk, "auth")

	restore, _ := testSignIdentityRestore(t, g.did, g.key.keyID, g.key.priv, afterDelete.HeadCID, possessionTS(3))
	afterRestore, err := VerifyIdentityExtension(afterDelete.State, afterDelete.HeadCID, afterDelete.LastCreatedAt, restore)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if afterRestore.State.IsDeleted {
		t.Fatalf("expected restored")
	}
	expectVoid(t, afterRestore.State, added.mk, "auth")
	expectProved(t, afterRestore.State, g.key.mk, KeyRoles...)
}
