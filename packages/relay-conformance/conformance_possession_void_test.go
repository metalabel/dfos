// KEY POSSESSION AT THE RELAY BOUNDARY — the void semantics, over the wire.
//
// PROTOCOL.md → Key Possession says an identity `update` that INTRODUCES a key
// (one not in the prior EFFECTIVE state for that role) must carry a possession
// proof: a compact KEY-PROOF JWS, signed by the introduced key itself, binding
// the chain's `did`, a canonical `roleSet`, and the carrying operation's
// `previousOperationCID`. An introduction with no valid proof is **void**.
//
// VOID IS NOT INVALID, and the whole of this file is that distinction:
//
//  1. INGEST NEVER WEIGHS POSSESSION. An update introducing an unproved key is a
//     structurally valid operation: it sequences, it gets a CID, it lands in the
//     log and it becomes the chain head. This is load-bearing — a relay whose
//     accept/reject verdict depended on possession evidence could disagree with
//     another relay about whether an operation EXISTS, and two relays disagreeing
//     about existence is the one divergence a gossip layer cannot heal. A relay
//     that rejects an unproved introduction is NON-CONFORMANT, and it will look
//     conformant on every other test in this suite.
//
//  2. RESOLUTION ALWAYS DOES. The key that operation introduced is absent from
//     the identity route's effective key arrays, named on `voidKeys`, absent from
//     every verification relationship of the DID document, and absent from the
//     `key=` reverse index.
//
// Together: the operation is real and the membership is not.
package conformance

import (
	"encoding/json"
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// identityKeyState is the served identity route's `state`, read for the members
// the possession fold governs. It is the protocol library's IdentityState
// verbatim on both reference relays, which is how the two stay identical without
// either restating the member list.
type identityKeyState struct {
	AuthKeys       []dfos.MultikeyPublicKey `json:"authKeys"`
	AssertKeys     []dfos.MultikeyPublicKey `json:"assertKeys"`
	ControllerKeys []dfos.MultikeyPublicKey `json:"controllerKeys"`
	Declared       struct {
		AuthKeys       []dfos.MultikeyPublicKey `json:"authKeys"`
		AssertKeys     []dfos.MultikeyPublicKey `json:"assertKeys"`
		ControllerKeys []dfos.MultikeyPublicKey `json:"controllerKeys"`
	} `json:"declared"`
	VoidKeys []struct {
		Key          dfos.MultikeyPublicKey `json:"key"`
		Role         string                 `json:"role"`
		OperationCID string                 `json:"operationCID"`
	} `json:"voidKeys"`
	ProvedKeys struct {
		AuthKeys       []dfos.MultikeyPublicKey `json:"authKeys"`
		AssertKeys     []dfos.MultikeyPublicKey `json:"assertKeys"`
		ControllerKeys []dfos.MultikeyPublicKey `json:"controllerKeys"`
	} `json:"provedKeys"`
}

// fetchIdentityKeyState reads the served state and the head CID for one chain.
func fetchIdentityKeyState(t *testing.T, base, did string) (identityKeyState, string) {
	t.Helper()
	var body struct {
		HeadCID string           `json:"headCID"`
		State   identityKeyState `json:"state"`
	}
	route := base + "/proof/v1/identities/" + did
	resp := getJSON(t, route, &body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: status %d", route, resp.StatusCode)
	}
	return body.State, body.HeadCID
}

func multibasesOf(keys []dfos.MultikeyPublicKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.PublicKeyMultibase)
	}
	return out
}

// introduceKeyUnproved ingests an update adding `added` to the chain's auth keys
// with NO possession envelope, and asserts the relay SEQUENCED it. Returns the
// operation's CID and advances id.headCID.
func introduceKeyUnproved(t *testing.T, base string, id *identity, added keypair) string {
	t.Helper()
	token, opCID := signIdentityUpdateWithProofs(t, id.headCID,
		[]dfos.MultikeyPublicKey{id.controller.mk},
		[]dfos.MultikeyPublicKey{id.controller.mk, added.mk},
		[]dfos.MultikeyPublicKey{id.controller.mk},
		nil,
		id.did+"#"+id.controller.keyID, id.controller.priv)

	res := postOperations(t, base, []string{token})
	body := readBody(t, res)
	if res.StatusCode != 200 {
		t.Fatalf("an unproved introduction must still be ACCEPTED at the transport: status %d, body: %s", res.StatusCode, body)
	}
	var parsed struct {
		Results []struct {
			Status string `json:"status"`
			CID    string `json:"cid"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("parse ingest verdicts: %v (body: %s)", err, body)
	}
	if len(parsed.Results) != 1 {
		t.Fatalf("expected one verdict, got %d (body: %s)", len(parsed.Results), body)
	}
	if parsed.Results[0].Status != "new" {
		t.Fatalf("an unproved key introduction must SEQUENCE, not be rejected: status=%q error=%q.\n"+
			"Possession evidence must never reach a relay's accept/reject verdict — a relay whose "+
			"verdict depends on it can disagree with another relay about whether an operation exists, "+
			"which is the one divergence a gossip layer cannot heal. The key is excluded at "+
			"RESOLUTION (voidKeys), never at ingest.",
			parsed.Results[0].Status, parsed.Results[0].Error)
	}
	if parsed.Results[0].CID != opCID {
		t.Fatalf("ingest reported cid %s, want %s", parsed.Results[0].CID, opCID)
	}
	id.headCID = opCID
	return opCID
}

// TestUnprovedKeyIntroductionIsSequencedAndVoid is the no-ingest-reject rule and
// the resolution verdict in one pass: the operation exists and the membership
// does not.
func TestUnprovedKeyIntroductionIsSequencedAndVoid(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	added := newKeypair()
	opCID := introduceKeyUnproved(t, base, &id, added)

	// THE OPERATION EXISTS. It is fetchable by CID and it is the chain head.
	if resp := getJSON(t, base+"/proof/v1/operations/"+opCID, nil); resp.StatusCode != 200 {
		t.Fatalf("GET /operations/%s: status %d — the accepted operation is not served", opCID, resp.StatusCode)
	}
	state, headCID := fetchIdentityKeyState(t, base, id.did)
	if headCID != opCID {
		t.Fatalf("headCID = %s, want the unproved update %s — the operation was accepted, so it is the head", headCID, opCID)
	}

	// ...AND THE MEMBERSHIP DOES NOT. The key is in no effective role array.
	for member, keys := range map[string][]dfos.MultikeyPublicKey{
		"authKeys":       state.AuthKeys,
		"assertKeys":     state.AssertKeys,
		"controllerKeys": state.ControllerKeys,
	} {
		if contains(multibasesOf(keys), added.mk.PublicKeyMultibase) {
			t.Fatalf("%s carries the unproved key %v — the three key arrays are EFFECTIVE state, and a void membership is exactly what effective state excludes",
				member, multibasesOf(keys))
		}
	}
	if got := multibasesOf(state.AuthKeys); len(got) != 1 || got[0] != id.controller.mk.PublicKeyMultibase {
		t.Fatalf("authKeys = %v, want only the genesis key (proved by the genesis signature)", got)
	}

	// It is named on voidKeys, with its role and the operation that declared it.
	// This is the ONLY surface on which a controller who introduced a key without
	// a proof can discover that their chain verifies and their key does not work.
	if len(state.VoidKeys) != 1 {
		t.Fatalf("voidKeys = %+v, want exactly the one unproved auth membership", state.VoidKeys)
	}
	void := state.VoidKeys[0]
	if void.Key.PublicKeyMultibase != added.mk.PublicKeyMultibase {
		t.Fatalf("voidKeys[0].key = %+v, want the unproved key", void.Key)
	}
	if void.Role != "auth" {
		t.Fatalf("voidKeys[0].role = %q, want \"auth\" — void is computed per ROLE, not per key", void.Role)
	}
	if void.OperationCID != opCID {
		t.Fatalf("voidKeys[0].operationCID = %q, want the introducing operation %s", void.OperationCID, opCID)
	}

	// The chain still SAYS it: void is a resolution verdict, never a rewrite of
	// what the controller wrote.
	if !contains(multibasesOf(state.Declared.AuthKeys), added.mk.PublicKeyMultibase) {
		t.Fatalf("declared.authKeys = %v, want the introduced key still declared — the operation is not edited, it is read differently",
			multibasesOf(state.Declared.AuthKeys))
	}
	// ...and provedKeys never did.
	if contains(multibasesOf(state.ProvedKeys.AuthKeys), added.mk.PublicKeyMultibase) {
		t.Fatalf("provedKeys.authKeys = %v carries a key no envelope admitted", multibasesOf(state.ProvedKeys.AuthKeys))
	}
}

// TestVoidKeyIsInNoVerificationMethod pins the DID-document half. A verification
// method is a standing public claim that this key speaks for this DID — which is
// precisely the claim no envelope was offered for — so a void key must appear in
// no verification method and in no verification relationship.
func TestVoidKeyIsInNoVerificationMethod(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	added := newKeypair()
	introduceKeyUnproved(t, base, &id, added)

	var doc struct {
		VerificationMethod []struct {
			ID                 string `json:"id"`
			PublicKeyMultibase string `json:"publicKeyMultibase"`
		} `json:"verificationMethod"`
		Authentication       []string `json:"authentication"`
		AssertionMethod      []string `json:"assertionMethod"`
		CapabilityInvocation []string `json:"capabilityInvocation"`
	}
	var envelope struct {
		DidDocument json.RawMessage `json:"didDocument"`
	}
	route := base + "/1.0/identifiers/" + id.did
	resp := getJSON(t, route, &envelope)
	if resp.StatusCode == 404 {
		t.Skip("relay does not serve the universal DID resolver route — skipping")
	}
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: status %d", route, resp.StatusCode)
	}
	if len(envelope.DidDocument) == 0 {
		t.Fatalf("GET %s: no didDocument in the resolution envelope", route)
	}
	if err := json.Unmarshal(envelope.DidDocument, &doc); err != nil {
		t.Fatalf("decode didDocument: %v", err)
	}

	voidURL := id.did + "#" + added.keyID
	for _, vm := range doc.VerificationMethod {
		if vm.ID == voidURL || vm.PublicKeyMultibase == added.mk.PublicKeyMultibase {
			t.Fatalf("the void key is a verification method (%+v) — a verification method claims the key speaks for the DID, which is the claim no proof was offered for", vm)
		}
	}
	for label, ids := range map[string][]string{
		"authentication":       doc.Authentication,
		"assertionMethod":      doc.AssertionMethod,
		"capabilityInvocation": doc.CapabilityInvocation,
	} {
		if contains(ids, voidURL) {
			t.Fatalf("the void key is in %s: %v", label, ids)
		}
	}

	// POSITIVE CONTROL: the genesis key, proved by the genesis signature, IS in
	// all three relationships — so the exclusion above is possession and not a
	// projection that simply drops keys.
	livingURL := id.did + "#" + id.controller.keyID
	for label, ids := range map[string][]string{
		"authentication":       doc.Authentication,
		"assertionMethod":      doc.AssertionMethod,
		"capabilityInvocation": doc.CapabilityInvocation,
	} {
		if !contains(ids, livingURL) {
			t.Fatalf("the proved genesis key is missing from %s: %v", label, ids)
		}
	}
}

// TestProvedKeyIntroductionLandsEverywhere is the counterpart control: the SAME
// operation shape with a valid envelope produces the opposite verdict at every
// surface the void tests check. Without this pairing, a relay that simply dropped
// every introduced key would pass the two tests above.
func TestProvedKeyIntroductionLandsEverywhere(t *testing.T) {
	base := relayURL(t)
	requireIndexCapability(t, base)
	id := createIdentity(t, base)

	added := newKeypair()
	opCID := introduceKey(t, base, &id, added, "auth")

	state, headCID := fetchIdentityKeyState(t, base, id.did)
	if headCID != opCID {
		t.Fatalf("headCID = %s, want the proved update %s", headCID, opCID)
	}
	if !contains(multibasesOf(state.AuthKeys), added.mk.PublicKeyMultibase) {
		t.Fatalf("authKeys = %v, want the proved key to be EFFECTIVE", multibasesOf(state.AuthKeys))
	}
	if len(state.VoidKeys) != 0 {
		t.Fatalf("voidKeys = %+v, want none — every membership this chain declares is proved", state.VoidKeys)
	}
	if !contains(multibasesOf(state.ProvedKeys.AuthKeys), added.mk.PublicKeyMultibase) {
		t.Fatalf("provedKeys.authKeys = %v, want the proved key", multibasesOf(state.ProvedKeys.AuthKeys))
	}

	// ...and it enters the `key=` reverse index, which the void key never does.
	requireIdentityKeyFilter(t, base)
	if got := identitiesMatching(t, base, keyParam(added.mk.PublicKeyMultibase)); len(got) != 1 || got[0] != id.did {
		t.Fatalf("key=<proved> = %v, want [%s] — a proved introduction indexes; see TestIndexIdentitiesKeyIgnoresUnprovedDeclarations for the half that must not", got, id.did)
	}
}
