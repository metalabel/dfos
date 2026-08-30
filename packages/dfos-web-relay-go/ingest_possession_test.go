package relay

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// POSSESSION PROOFS AT THE RELAY BOUNDARY.
//
// Two claims live here, and they pull in opposite directions on purpose:
//
//  1. INGEST NEVER WEIGHS POSSESSION. An update introducing a key with no proof
//     is a structurally valid operation: it sequences, it gets a CID, it lands in
//     the log. This is load-bearing — a relay whose accept/reject verdict
//     depended on possession evidence could disagree with another relay about
//     whether an operation EXISTS, and two relays disagreeing about existence is
//     the one divergence a gossip layer cannot heal.
//  2. RESOLUTION ALWAYS DOES. The key that unproved operation introduced is void:
//     absent from effective state, named on voidKeys, absent from the DID
//     document, and absent from the `key=` reverse index.
//
// Together they are the whole of "void rather than reject": the operation is
// real and the membership is not.

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// keyProofTestAudience is any lowercase authority. The chain walk deliberately
// does NOT check audience — it is fixed transport the signature covers, evidence
// of which ceremony this was, not a gate a replayer is positioned to run — so
// the value only has to satisfy the payload grammar.
const keyProofTestAudience = "relay.test"

// testKeyProof mints one possession envelope for a candidate key joining `did`
// at head `prevCID`. With no roles named it consents to all three, which is the
// ordinary rotation shape.
func testKeyProof(t *testing.T, priv ed25519.PrivateKey, did, prevCID string, roles ...dfos.KeyRole) string {
	t.Helper()
	if len(roles) == 0 {
		roles = dfos.KeyRoles
	}
	roleSet, err := dfos.SerializeRoleSet(roles)
	if err != nil {
		t.Fatalf("SerializeRoleSet: %v", err)
	}
	proof, _, err := dfos.SignKeyProof(dfos.SignKeyProofInput{
		Typ:        dfos.KeyAddJWSTyp,
		Nonce:      "nonce-" + prevCID,
		Audience:   keyProofTestAudience,
		DID:        did,
		RoleSet:    roleSet,
		PrevCID:    prevCID,
		PrivateKey: priv,
	})
	if err != nil {
		t.Fatalf("SignKeyProof: %v", err)
	}
	return proof
}

// signIdentityUpdateWithKeyProofs signs an identity update carrying possession
// envelopes.
//
// Hand-rolled because the protocol library exposes no producer for this shape:
// the carriage is a payload member on the operation, not an argument to a
// signer, so the payload is assembled here from the same exported primitives the
// verifier reads it back with. An empty proof list omits the member entirely,
// which is exactly what SignIdentityUpdate emits.
func signIdentityUpdateWithKeyProofs(
	t *testing.T,
	previousCID string,
	controllerKeys, authKeys, assertKeys []dfos.MultikeyPublicKey,
	keyProofs []string,
	kid string,
	privateKey ed25519.PrivateKey,
) (jwsToken string, operationCID string) {
	t.Helper()
	if authKeys == nil {
		authKeys = []dfos.MultikeyPublicKey{}
	}
	if assertKeys == nil {
		assertKeys = []dfos.MultikeyPublicKey{}
	}
	if controllerKeys == nil {
		controllerKeys = []dfos.MultikeyPublicKey{}
	}
	// The createdAt is BORROWED from the library's own clock — mint a throwaway
	// update through the exported signer and read its timestamp back — rather than
	// taken from time.Now(). The library's source is a process-wide monotonic
	// counter that runs ahead of the wall clock whenever operations are minted in
	// a burst, so a wall-clock stamp can land behind an operation signed
	// microseconds earlier and be refused as non-monotonic.
	// The prior state handed over is the operation's OWN arrays, so the signer's
	// writer door sees no introduction and lets the throwaway through. That is
	// honest rather than a dodge: this call exists only to read a timestamp back
	// out, and the operation it produces is discarded unsigned-for.
	clockPrior := dfos.IdentityState{
		DID:            kid[:strings.Index(kid, "#")],
		AuthKeys:       authKeys,
		AssertKeys:     assertKeys,
		ControllerKeys: controllerKeys,
	}
	throwaway, _, err := dfos.SignIdentityUpdate(
		clockPrior, previousCID, controllerKeys, authKeys, assertKeys, nil, kid, privateKey)
	if err != nil {
		t.Fatalf("SignIdentityUpdate (clock): %v", err)
	}
	_, throwawayPayload, err := dfos.DecodeJWSUnsafe(throwaway)
	if err != nil {
		t.Fatalf("DecodeJWSUnsafe (clock): %v", err)
	}
	createdAt, _ := throwawayPayload["createdAt"].(string)
	if createdAt == "" {
		t.Fatal("could not borrow a protocol timestamp")
	}

	payload := map[string]any{
		"version":              1,
		"type":                 "update",
		"previousOperationCID": previousCID,
		"authKeys":             authKeys,
		"assertKeys":           assertKeys,
		"controllerKeys":       controllerKeys,
		"createdAt":            createdAt,
	}
	if len(keyProofs) > 0 {
		payload["keyProofs"] = keyProofs
	}
	_, _, cid, errCID := dfos.DagCborCID(payload)
	if errCID != nil {
		t.Fatalf("DagCborCID: %v", errCID)
	}
	token, errJWS := dfos.CreateJWS(dfos.JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:identity-op",
		Kid: kid,
		CID: cid,
	}, payload, privateKey)
	if errJWS != nil {
		t.Fatalf("CreateJWS: %v", errJWS)
	}
	return token, cid
}

// introduceKeyWithoutProof ingests an update that adds `added` to the identity's
// auth keys and carries NO possession envelope. Returns the operation's CID.
func introduceKeyWithoutProof(t *testing.T, r *Relay, id testIdentity, added dfos.MultikeyPublicKey) string {
	t.Helper()
	time.Sleep(2 * time.Millisecond)
	token, opCID := signIdentityUpdateWithKeyProofs(t, id.opCID,
		[]dfos.MultikeyPublicKey{id.controller.mk},
		[]dfos.MultikeyPublicKey{id.auth.mk, added},
		[]dfos.MultikeyPublicKey{id.controller.mk},
		nil,
		id.did+"#"+id.controller.keyID, id.controller.priv)
	result := r.Ingest([]string{token})[0]
	if result.Status != "new" {
		t.Fatalf("an unproved introduction must still SEQUENCE: status %q err %q", result.Status, result.Error)
	}
	if result.CID != opCID {
		t.Fatalf("cid = %s, want %s", result.CID, opCID)
	}
	return opCID
}

// ---------------------------------------------------------------------------
// 1. no ingest-reject creep
// ---------------------------------------------------------------------------

// TestIngestSequencesAnUnprovedKeyIntroduction is the regression pin: possession
// evidence must never reach the accept/reject verdict. The operation is
// accepted, is in the log, and the key it introduced is void — declared, listed
// on voidKeys, and absent from effective state.
func TestIngestSequencesAnUnprovedKeyIntroduction(t *testing.T) {
	r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	id := createTestIdentity(t)
	if res := r.Ingest([]string{id.token})[0]; res.Status != "new" {
		t.Fatalf("ingest genesis: %s (%s)", res.Status, res.Error)
	}

	added := newTestKeypair()
	opCID := introduceKeyWithoutProof(t, r, id, added.mk)

	// The operation EXISTS: stored, and on the relay's operation log.
	op, err := r.readStore.GetOperation(opCID)
	if err != nil || op == nil {
		t.Fatalf("the accepted operation is not stored: %v", err)
	}
	if op.ChainType != "identity" || op.ChainID != id.did {
		t.Fatalf("stored operation = %+v, want an identity op on %s", op, id.did)
	}
	if !relayLogContainsCID(t, r, opCID) {
		t.Fatalf("the accepted operation is missing from the operation log")
	}

	chain, err := r.readStore.GetIdentityChain(id.did)
	if err != nil || chain == nil {
		t.Fatalf("chain: %v", err)
	}
	if chain.HeadCID != opCID {
		t.Fatalf("head = %s, want the unproved update %s", chain.HeadCID, opCID)
	}

	// ...and the membership does NOT.
	for _, k := range keysInKeyState(effectiveKeyState(chain.State)) {
		if k.ID == added.keyID {
			t.Fatalf("the unproved key entered effective state: %+v", chain.State)
		}
	}
	voided := false
	for _, v := range chain.State.VoidKeys {
		if v.Key.ID == added.keyID && v.Role == "auth" {
			voided = true
			if v.OperationCID != opCID {
				t.Fatalf("void operationCID = %s, want %s", v.OperationCID, opCID)
			}
		}
	}
	if !voided {
		t.Fatalf("voidKeys = %+v, want the unproved auth membership named", chain.State.VoidKeys)
	}
	// The chain still SAYS it — void is a resolution verdict, not a rewrite.
	declared := false
	for _, k := range chain.State.Declared.AuthKeys {
		if k.ID == added.keyID {
			declared = true
		}
	}
	if !declared {
		t.Fatalf("declared auth keys = %+v, want the introduced key still declared", chain.State.Declared.AuthKeys)
	}
	// Never proved, so never in the has-ever-proved union.
	if _, ok := findKeyInKeyState(chain.State.ProvedKeys, added.keyID); ok {
		t.Fatalf("the unproved key entered ProvedKeys: %+v", chain.State.ProvedKeys)
	}
}

// A key introduced WITH an envelope is the same operation shape and the opposite
// verdict — so the void above is the possession fold and not the carriage.
func TestIngestAdmitsAProvedKeyIntroduction(t *testing.T) {
	r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	id := createTestIdentity(t)
	if res := r.Ingest([]string{id.token})[0]; res.Status != "new" {
		t.Fatalf("ingest genesis: %s (%s)", res.Status, res.Error)
	}

	added := newTestKeypair()
	time.Sleep(2 * time.Millisecond)
	token, _ := signIdentityUpdateWithKeyProofs(t, id.opCID,
		[]dfos.MultikeyPublicKey{id.controller.mk},
		[]dfos.MultikeyPublicKey{id.auth.mk, added.mk},
		[]dfos.MultikeyPublicKey{id.controller.mk},
		[]string{testKeyProof(t, added.priv, id.did, id.opCID, "auth")},
		id.did+"#"+id.controller.keyID, id.controller.priv)
	if res := r.Ingest([]string{token})[0]; res.Status != "new" {
		t.Fatalf("ingest proved introduction: %s (%s)", res.Status, res.Error)
	}

	chain, _ := r.readStore.GetIdentityChain(id.did)
	if len(chain.State.VoidKeys) != 0 {
		t.Fatalf("voidKeys = %+v, want none", chain.State.VoidKeys)
	}
	if _, ok := findKeyInKeyState(effectiveKeyState(chain.State), added.keyID); !ok {
		t.Fatalf("the proved key is not effective: %+v", chain.State)
	}
	if _, ok := findKeyInKeyState(chain.State.ProvedKeys, added.keyID); !ok {
		t.Fatalf("the proved key is not in ProvedKeys: %+v", chain.State.ProvedKeys)
	}
}

// ---------------------------------------------------------------------------
// 2. a void key resolves nowhere
// ---------------------------------------------------------------------------

// A void key must not appear in any verification relationship of the DID
// document. A verification method is a standing claim that this key speaks for
// this DID, which is exactly the claim no proof was offered for.
func TestVoidKeyNeverEntersTheDidDocument(t *testing.T) {
	r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	id := createTestIdentity(t)
	if res := r.Ingest([]string{id.token})[0]; res.Status != "new" {
		t.Fatalf("ingest genesis: %s (%s)", res.Status, res.Error)
	}
	added := newTestKeypair()
	introduceKeyWithoutProof(t, r, id, added.mk)

	chain, _ := r.readStore.GetIdentityChain(id.did)
	doc, ok := identityToDidDocument(chain.State).(didDocument)
	if !ok {
		t.Fatalf("expected a live DID document, got %T", identityToDidDocument(chain.State))
	}
	voidURL := id.did + "#" + added.keyID
	for _, vm := range doc.VerificationMethod {
		if vm.ID == voidURL {
			t.Fatalf("the void key is a verification method: %+v", doc.VerificationMethod)
		}
	}
	for label, ids := range map[string][]string{
		"authentication":       doc.Authentication,
		"assertionMethod":      doc.AssertionMethod,
		"capabilityInvocation": doc.CapabilityInvocation,
	} {
		for _, id := range ids {
			if id == voidURL {
				t.Fatalf("the void key is in %s: %v", label, ids)
			}
		}
	}
	// The genesis key, proved by signing genesis, is present in all three.
	livingURL := id.did + "#" + id.controller.keyID
	for label, ids := range map[string][]string{
		"authentication":       doc.Authentication,
		"assertionMethod":      doc.AssertionMethod,
		"capabilityInvocation": doc.CapabilityInvocation,
	} {
		found := false
		for _, id := range ids {
			if id == livingURL {
				found = true
			}
		}
		if !found {
			t.Fatalf("the proved genesis key is missing from %s: %v", label, ids)
		}
	}
}

// A void key must not resolve for verification either — not on the historical
// resolver (has-ever-proved) and not on the current one (effective).
func TestVoidKeyResolvesOnNeitherResolver(t *testing.T) {
	store := NewMemoryStore()
	r, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	id := createTestIdentity(t)
	if res := r.Ingest([]string{id.token})[0]; res.Status != "new" {
		t.Fatalf("ingest genesis: %s (%s)", res.Status, res.Error)
	}
	added := newTestKeypair()
	introduceKeyWithoutProof(t, r, id, added.mk)

	voidKid := id.did + "#" + added.keyID
	if _, err := CreateKeyResolver(store)(voidKid); err == nil {
		t.Fatal("the historical resolver resolved a key no proof ever admitted")
	}
	if _, err := CreateCurrentKeyResolver(store)(voidKid); err == nil {
		t.Fatal("the current resolver resolved a key no proof ever admitted")
	}
	// The genesis key still resolves on both — the refusal is possession and
	// nothing else.
	livingKid := id.did + "#" + id.controller.keyID
	if _, err := CreateKeyResolver(store)(livingKid); err != nil {
		t.Fatalf("historical resolver on the genesis key: %v", err)
	}
	if _, err := CreateCurrentKeyResolver(store)(livingKid); err != nil {
		t.Fatalf("current resolver on the genesis key: %v", err)
	}
}

// The historical resolver is HAS-EVER-PROVED, not current-state: a key that was
// proved into the chain and later rotated out still resolves, because possession
// does not become untrue.
func TestHistoricalResolverKeepsAProvedRotatedOutKey(t *testing.T) {
	store := NewMemoryStore()
	r, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	id := createTestIdentity(t)
	if res := r.Ingest([]string{id.token})[0]; res.Status != "new" {
		t.Fatalf("ingest genesis: %s (%s)", res.Status, res.Error)
	}
	rotated, _ := rotateExistingTestIdentity(t, r, id)

	rotatedOutKid := id.did + "#" + id.auth.keyID
	if _, err := CreateKeyResolver(store)(rotatedOutKid); err != nil {
		t.Fatalf("historical resolver dropped a proved rotated-out key: %v", err)
	}
	if _, err := CreateCurrentKeyResolver(store)(rotatedOutKid); err == nil {
		t.Fatal("the current resolver kept a rotated-out key")
	}
	if _, err := CreateCurrentKeyResolver(store)(id.did + "#" + rotated.keyID); err != nil {
		t.Fatalf("current resolver on the rotated-in key: %v", err)
	}
}

// The identity route's `state` is the protocol library's IdentityState verbatim,
// which is how the two reference relays stay identical without either restating
// the member list. The three key arrays mean EFFECTIVE state, and voidKeys names
// the membership that is missing from them — the only surface where a controller
// can discover that a key they added does not resolve.
func TestIdentityRouteServesEffectiveKeysAndVoidKeys(t *testing.T) {
	r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	id := createTestIdentity(t)
	if res := r.Ingest([]string{id.token})[0]; res.Status != "new" {
		t.Fatalf("ingest genesis: %s (%s)", res.Status, res.Error)
	}
	added := newTestKeypair()
	opCID := introduceKeyWithoutProof(t, r, id, added.mk)

	status, body, raw := getIndexJSONBody(t, r.Handler(), proofBasePath+"/identities/"+id.did)
	if status != 200 {
		t.Fatalf("GET identity = %d (%s)", status, raw)
	}
	state, ok := body["state"].(map[string]any)
	if !ok {
		t.Fatalf("state missing from %s", raw)
	}

	multibasesOf := func(member string) []string {
		out := []string{}
		for _, raw := range state[member].([]any) {
			out = append(out, raw.(map[string]any)["publicKeyMultibase"].(string))
		}
		return out
	}
	for _, member := range []string{"authKeys", "assertKeys", "controllerKeys"} {
		for _, mb := range multibasesOf(member) {
			if mb == added.mk.PublicKeyMultibase {
				t.Fatalf("%s carries the void key: %s", member, raw)
			}
		}
	}
	if got := multibasesOf("authKeys"); len(got) != 1 || got[0] != id.auth.mk.PublicKeyMultibase {
		t.Fatalf("authKeys = %v, want only the proved genesis key", got)
	}

	voids, ok := state["voidKeys"].([]any)
	if !ok || len(voids) != 1 {
		t.Fatalf("voidKeys = %v, want the one unproved membership (%s)", state["voidKeys"], raw)
	}
	void := voids[0].(map[string]any)
	if void["role"] != "auth" || void["operationCID"] != opCID {
		t.Fatalf("voidKeys[0] = %v, want the auth membership introduced by %s", void, opCID)
	}
	if void["key"].(map[string]any)["publicKeyMultibase"] != added.mk.PublicKeyMultibase {
		t.Fatalf("voidKeys[0].key = %v, want the unproved key", void["key"])
	}

	// declared still SAYS it, and provedKeys never did.
	declared := state["declared"].(map[string]any)
	declaredAuth := []string{}
	for _, raw := range declared["authKeys"].([]any) {
		declaredAuth = append(declaredAuth, raw.(map[string]any)["publicKeyMultibase"].(string))
	}
	if len(declaredAuth) != 2 {
		t.Fatalf("declared.authKeys = %v, want both the genesis key and the unproved one", declaredAuth)
	}
	proved := state["provedKeys"].(map[string]any)
	for _, raw := range proved["authKeys"].([]any) {
		if raw.(map[string]any)["publicKeyMultibase"] == added.mk.PublicKeyMultibase {
			t.Fatalf("provedKeys carries a key no proof admitted: %v", proved)
		}
	}
}

// relayLogContainsCID reports whether the relay's operation log carries a CID.
func relayLogContainsCID(t *testing.T, r *Relay, cid string) bool {
	t.Helper()
	entries, _, err := r.readStore.ReadLog("", 1000)
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	for _, entry := range entries {
		if entry.CID == cid {
			return true
		}
	}
	return false
}
