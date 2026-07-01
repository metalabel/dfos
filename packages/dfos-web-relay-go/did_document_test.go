package relay

// Fast, harness-free unit coverage of the DID-core projection (did_document.go)
// against hand-built state. The dual-relay parity harness proves TS≡Go on the
// wire; these give a red bar independent of harness spin-up (they run under the
// existing `go test -race ./...` CI job).

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

func mk(id, mb string) dfos.MultikeyPublicKey {
	return dfos.MultikeyPublicKey{ID: id, Type: "Multikey", PublicKeyMultibase: mb}
}

// marshalMap round-trips a projection value through JSON so we can assert on the
// exact key set + values the wire sees (structs → maps).
func marshalMap(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

// A single key shared across all three roles must dedup to ONE verification
// method but still appear in all three FULL per-role relationship arrays.
func TestProjection_SharedKeyDedupsVMButKeepsRoleArrays(t *testing.T) {
	did := "did:dfos:2222222222222222222222222222222"
	k := mk("key_a", "z6MkShared")
	state := dfos.IdentityState{
		DID:            did,
		AuthKeys:       []dfos.MultikeyPublicKey{k},
		AssertKeys:     []dfos.MultikeyPublicKey{k},
		ControllerKeys: []dfos.MultikeyPublicKey{k},
		Services:       nil,
	}
	m := marshalMap(t, identityToDidDocument(state))

	vms, _ := m["verificationMethod"].([]any)
	if len(vms) != 1 {
		t.Fatalf("expected 1 deduped VM, got %d", len(vms))
	}
	wantURL := did + "#key_a"
	for _, role := range []string{"authentication", "assertionMethod", "capabilityInvocation"} {
		arr, ok := m[role].([]any)
		if !ok || len(arr) != 1 || arr[0] != wantURL {
			t.Fatalf("role %s = %v, want [%s]", role, m[role], wantURL)
		}
	}
	if _, present := m["service"]; present {
		t.Fatalf("service must be omitted when empty, got %v", m["service"])
	}
	if m["controller"] != did {
		t.Fatalf("controller = %v, want %s", m["controller"], did)
	}
	ctx, _ := m["@context"].([]any)
	if len(ctx) != 2 || ctx[0] != "https://www.w3.org/ns/did/v1" || ctx[1] != "https://w3id.org/security/multikey/v1" {
		t.Fatalf("@context = %v", m["@context"])
	}
}

// Distinct keys across roles → first-seen order auth→assert→controller preserved
// in the deduped verificationMethod array.
func TestProjection_VMFirstSeenOrder(t *testing.T) {
	did := "did:dfos:2222222222222222222222222222222"
	ka, kb, kc := mk("key_a", "zA"), mk("key_b", "zB"), mk("key_c", "zC")
	state := dfos.IdentityState{
		DID:            did,
		AuthKeys:       []dfos.MultikeyPublicKey{ka},
		AssertKeys:     []dfos.MultikeyPublicKey{kb},
		ControllerKeys: []dfos.MultikeyPublicKey{kc},
	}
	m := marshalMap(t, identityToDidDocument(state))
	vms, _ := m["verificationMethod"].([]any)
	if len(vms) != 3 {
		t.Fatalf("expected 3 VMs, got %d", len(vms))
	}
	want := []string{did + "#key_a", did + "#key_b", did + "#key_c"}
	for i, w := range want {
		vm, _ := vms[i].(map[string]any)
		if vm["id"] != w || vm["type"] != "Multikey" || vm["controller"] != did {
			t.Fatalf("vm[%d] = %v, want id=%s", i, vm, w)
		}
	}
}

// Services: order preserved; DfosRelay → serviceEndpoint(endpoint); ContentAnchor
// → serviceEndpoint(anchor)+label; unknown type → verbatim (envelope + extras,
// type intact, id re-anchored).
func TestProjection_ServiceShapes(t *testing.T) {
	did := "did:dfos:2222222222222222222222222222222"
	state := dfos.IdentityState{
		DID:            did,
		AuthKeys:       []dfos.MultikeyPublicKey{mk("key_a", "zA")},
		AssertKeys:     []dfos.MultikeyPublicKey{},
		ControllerKeys: []dfos.MultikeyPublicKey{mk("key_a", "zA")},
		Services: []dfos.ServiceEntry{
			{"id": "svc_relay", "type": "DfosRelay", "endpoint": "https://relay.example"},
			{"id": "svc_anchor", "type": "ContentAnchor", "label": "pinned", "anchor": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			{"id": "svc_x", "type": "CustomThing", "foo": "bar", "nested": map[string]any{"k": "v"}},
		},
	}
	m := marshalMap(t, identityToDidDocument(state))
	svc, _ := m["service"].([]any)
	if len(svc) != 3 {
		t.Fatalf("expected 3 services, got %d", len(svc))
	}

	relaySvc, _ := svc[0].(map[string]any)
	if relaySvc["id"] != did+"#svc_relay" || relaySvc["type"] != "DfosRelay" || relaySvc["serviceEndpoint"] != "https://relay.example" {
		t.Fatalf("DfosRelay projection wrong: %v", relaySvc)
	}
	if _, hasLabel := relaySvc["label"]; hasLabel {
		t.Fatalf("DfosRelay must not carry label: %v", relaySvc)
	}

	anchor, _ := svc[1].(map[string]any)
	if anchor["id"] != did+"#svc_anchor" || anchor["type"] != "ContentAnchor" ||
		anchor["serviceEndpoint"] != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || anchor["label"] != "pinned" {
		t.Fatalf("ContentAnchor projection wrong: %v", anchor)
	}

	unknown, _ := svc[2].(map[string]any)
	if unknown["id"] != did+"#svc_x" || unknown["type"] != "CustomThing" ||
		unknown["foo"] != "bar" {
		t.Fatalf("unknown-type projection wrong: %v", unknown)
	}
	nested, _ := unknown["nested"].(map[string]any)
	if nested["k"] != "v" {
		t.Fatalf("unknown-type must preserve nested extras verbatim: %v", unknown)
	}
}

// Deactivated identity → exactly {@context,id,controller,verificationMethod:[]},
// with NO relationships and NO service. Envelope reports deactivated:true.
func TestProjection_Deactivated(t *testing.T) {
	did := "did:dfos:2222222222222222222222222222222"
	state := dfos.IdentityState{
		DID:            did,
		IsDeleted:      true,
		AuthKeys:       []dfos.MultikeyPublicKey{mk("key_a", "zA")},
		ControllerKeys: []dfos.MultikeyPublicKey{mk("key_a", "zA")},
		Services:       []dfos.ServiceEntry{{"id": "svc", "type": "DfosRelay", "endpoint": "https://x"}},
	}
	m := marshalMap(t, identityToDidDocument(state))
	wantKeys := map[string]bool{"@context": true, "id": true, "controller": true, "verificationMethod": true}
	for k := range m {
		if !wantKeys[k] {
			t.Fatalf("deactivated doc has unexpected key %q: %v", k, m)
		}
	}
	if len(m) != len(wantKeys) {
		t.Fatalf("deactivated doc key set = %v, want exactly %v", m, wantKeys)
	}
	vms, _ := m["verificationMethod"].([]any)
	if vms == nil || len(vms) != 0 {
		t.Fatalf("deactivated verificationMethod must be [], got %v", m["verificationMethod"])
	}
}

// Envelope: created present when genesis carries createdAt, absent otherwise;
// updated = lastCreatedAt; deactivated + operationCount reflect chain state.
func TestResolveEnvelope_CreatedAndMetadata(t *testing.T) {
	did := "did:dfos:2222222222222222222222222222222"
	// build a real genesis token so DecodeJWSUnsafe finds createdAt
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 9
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	keyID := "key_env000000000000000000000000"
	genesisKey := dfos.NewMultikeyPublicKey(keyID, pub)
	genesis, gDID, _, err := dfos.SignIdentityCreate(
		[]dfos.MultikeyPublicKey{genesisKey},
		[]dfos.MultikeyPublicKey{genesisKey},
		[]dfos.MultikeyPublicKey{genesisKey},
		keyID, priv,
	)
	if err != nil {
		t.Fatalf("SignIdentityCreate: %v", err)
	}
	_ = did
	_, payload, _ := dfos.DecodeJWSUnsafe(genesis)
	wantCreated, _ := payload["createdAt"].(string)

	chain := &StoredIdentityChain{
		DID:           gDID,
		Log:           []string{genesis},
		HeadCID:       "cid_head",
		LastCreatedAt: "2025-06-01T00:00:00.000Z",
		State: dfos.IdentityState{
			DID:            gDID,
			AuthKeys:       []dfos.MultikeyPublicKey{mk(keyID, "zA")},
			AssertKeys:     []dfos.MultikeyPublicKey{},
			ControllerKeys: []dfos.MultikeyPublicKey{mk(keyID, "zA")},
		},
	}
	res := resolveDidDocument(chain)
	if res.Context != "https://w3id.org/did-resolution/v1" {
		t.Fatalf("envelope @context = %q", res.Context)
	}
	if res.DidResolutionMetadata.ContentType != "application/did+ld+json" {
		t.Fatalf("contentType = %q", res.DidResolutionMetadata.ContentType)
	}
	if res.DidDocumentMetadata.Created == nil || *res.DidDocumentMetadata.Created != wantCreated {
		t.Fatalf("created = %v, want %q", res.DidDocumentMetadata.Created, wantCreated)
	}
	if res.DidDocumentMetadata.Updated != "2025-06-01T00:00:00.000Z" {
		t.Fatalf("updated = %q", res.DidDocumentMetadata.Updated)
	}
	if res.DidDocumentMetadata.OperationCount != 1 || res.DidDocumentMetadata.Deactivated {
		t.Fatalf("operationCount/deactivated wrong: %+v", res.DidDocumentMetadata)
	}

	// empty log → created omitted
	emptyChain := &StoredIdentityChain{DID: did, Log: []string{}, State: dfos.IdentityState{DID: did}}
	if resolveDidDocument(emptyChain).DidDocumentMetadata.Created != nil {
		t.Fatalf("created must be nil for empty log")
	}
}
