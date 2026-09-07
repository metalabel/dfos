package dfos

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
)

// Wire agreement, continued — the SHAPE gates. Every case here is one payload
// or header whose members Go read differently from the TS reference: a claim
// resolved by case fold instead of by exact key, a field coerced from the wrong
// type instead of rejected, a required member skipped because it was absent.
// Same contract as agreement_test.go, one level in from the signature.

// ---------------------------------------------------------------------------
// Credential claims decode BY EXACT KEY (the header rule, one level down)
// ---------------------------------------------------------------------------

// signRawCredential signs a credential over exactly this payload TEXT, with a
// header whose cid commits to the same members — so a payload no marshaller
// would produce (a case-variant claim) reaches the verifier intact.
func signRawCredential(t *testing.T, payload map[string]any, payloadText, kid string, priv ed25519.PrivateKey) string {
	t.Helper()
	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		t.Fatal(err)
	}
	headerText := fmt.Sprintf(`{"alg":"EdDSA","typ":"did:dfos:credential","kid":%q,"cid":%q}`, kid, cidStr)
	return signRawText(t, headerText, payloadText, priv)
}

const testCredentialIss = "did:dfos:pf6zdt96e4d9ap4v4pt3z2b3vk9av9r"

func TestCredentialClaimsDecodeByExactKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	kid := testCredentialIss + "#key1"

	// exp:1 is long past; EXP:2000000000 is far future. encoding/json resolves a
	// key to a struct field by exact tag first and then by case fold, per key in
	// document order, so the later EXP OVERWROTE Exp and Go accepted. TypeScript
	// reads payload.exp by exact key, sees 1, and rejects as expired. The
	// raw-payload CID check cannot see the difference — it commits to both
	// members — and the duplicate-key scan cannot either.
	payload := map[string]any{
		"version": int64(1), "type": "DFOSCredential",
		"iss": testCredentialIss, "aud": "*",
		"att": []any{map[string]any{"resource": "chain:abc", "action": "read"}},
		"exp": int64(1), "EXP": int64(2000000000), "iat": int64(1),
	}
	payloadText := fmt.Sprintf(
		`{"version":1,"type":"DFOSCredential","iss":%q,"aud":"*","att":[{"resource":"chain:abc","action":"read"}],"exp":1,"EXP":2000000000,"iat":1}`,
		testCredentialIss)
	token := signRawCredential(t, payload, payloadText, kid, priv)

	if _, err := VerifyCredentialAt(token, pub, "", "read", 1800000000); err == nil ||
		!strings.Contains(err.Error(), "credential expired") {
		t.Fatalf("a case-variant EXP must not override exp: %v", err)
	}

	// the same claim spelled correctly still verifies, so the gate is the
	// SPELLING and not the presence of an extension member
	live := map[string]any{
		"version": int64(1), "type": "DFOSCredential",
		"iss": testCredentialIss, "aud": "*",
		"att": []any{map[string]any{"resource": "chain:abc", "action": "read"}},
		"exp": int64(2000000000), "iat": int64(1),
	}
	liveText := fmt.Sprintf(
		`{"version":1,"type":"DFOSCredential","iss":%q,"aud":"*","att":[{"resource":"chain:abc","action":"read"}],"exp":2000000000,"iat":1}`,
		testCredentialIss)
	if _, err := VerifyCredentialAt(signRawCredential(t, live, liveText, kid, priv), pub, "", "read", 1800000000); err != nil {
		t.Fatalf("a well-formed credential must still verify: %v", err)
	}
}

func TestCredentialAttEntriesDecodeByExactKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	kid := testCredentialIss + "#key1"

	// One level down: a mis-cased ACTION must not fold onto the entry's action
	// and grant write, which the exact-key TS schema never reads.
	payload := map[string]any{
		"version": int64(1), "type": "DFOSCredential",
		"iss": testCredentialIss, "aud": "*",
		"att": []any{map[string]any{"resource": "chain:abc", "action": "read", "ACTION": "write"}},
		"exp": int64(2000000000), "iat": int64(1),
	}
	payloadText := fmt.Sprintf(
		`{"version":1,"type":"DFOSCredential","iss":%q,"aud":"*","att":[{"resource":"chain:abc","action":"read","ACTION":"write"}],"exp":2000000000,"iat":1}`,
		testCredentialIss)
	token := signRawCredential(t, payload, payloadText, kid, priv)

	if _, err := VerifyCredentialAt(token, pub, "", "write", 1800000000); err == nil {
		t.Fatal("a case-variant ACTION must not grant write")
	}
	vc, err := VerifyCredentialAt(token, pub, "", "read", 1800000000)
	if err != nil {
		t.Fatalf("the exact-key action must still grant read: %v", err)
	}
	if vc.Att[0].Action != "read" {
		t.Fatalf("att action: got %q", vc.Att[0].Action)
	}
}

func TestVerifyCredentialRejectsWrongLengthKeyWithoutPanicking(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	kid := testCredentialIss + "#key1"
	payload := map[string]any{
		"version": int64(1), "type": "DFOSCredential",
		"iss": testCredentialIss, "aud": "*",
		"att": []any{map[string]any{"resource": "chain:abc", "action": "read"}},
		"exp": int64(2000000000), "iat": int64(1),
	}
	payloadText := fmt.Sprintf(
		`{"version":1,"type":"DFOSCredential","iss":%q,"aud":"*","att":[{"resource":"chain:abc","action":"read"}],"exp":2000000000,"iat":1}`,
		testCredentialIss)
	token := signRawCredential(t, payload, payloadText, kid, priv)

	// a resolver can hand back a nil or short key without erroring, and
	// ed25519.Verify panics on either — VerifyJWS guards, this path did not
	for _, key := range []ed25519.PublicKey{nil, make([]byte, 5)} {
		if _, err := VerifyCredentialAt(token, key, "", "read", 1800000000); err == nil {
			t.Fatalf("expected a length error for a %d-byte public key, got none", len(key))
		}
	}
	if _, err := VerifyCredentialAt(token, pub, "", "read", 1800000000); err != nil {
		t.Fatalf("a well-formed credential must still verify: %v", err)
	}
}

// ---------------------------------------------------------------------------
// A key declaration's fields are validated, never coerced
// ---------------------------------------------------------------------------

// multikeyMap is a MultikeyPublicKey as it travels on the wire.
func multikeyMap(k MultikeyPublicKey) map[string]any {
	return map[string]any{"id": k.ID, "type": k.Type, "publicKeyMultibase": k.PublicKeyMultibase}
}

// testSignIdentityOpRaw signs an identity operation whose payload members are
// exactly as given.
func testSignIdentityOpRaw(t *testing.T, payload map[string]any, kid string, priv ed25519.PrivateKey) string {
	t.Helper()
	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := CreateJWS(JWSHeader{Alg: "EdDSA", Typ: "did:dfos:identity-op", Kid: kid, CID: cidStr}, payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestMultikeyFieldsAreNotCoercedFromTheWrongType(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	genJWS, did, genCID := testSignIdentityGenesis(t, NewMultikeyPublicKey(keyID, pub), keyID, priv, "2026-03-07T00:00:00.000Z")
	if _, err := VerifyIdentityChain([]string{genJWS}); err != nil {
		t.Fatal(err)
	}
	genesisKey := NewMultikeyPublicKey(keyID, pub)

	// A wrong-typed id or publicKeyMultibase used to become "" via a comma-ok
	// assertion. The declaration then folded to a VOID membership and the whole
	// operation verified, where TS rejects the operation outright. Voiding an
	// unproved membership is not a licence to skip field validation.
	for name, bad := range map[string]map[string]any{
		"id number":                 {"id": int64(42), "type": "Multikey", "publicKeyMultibase": genesisKey.PublicKeyMultibase},
		"id null":                   {"id": nil, "type": "Multikey", "publicKeyMultibase": genesisKey.PublicKeyMultibase},
		"id absent":                 {"type": "Multikey", "publicKeyMultibase": genesisKey.PublicKeyMultibase},
		"publicKeyMultibase null":   {"id": "key-x", "type": "Multikey", "publicKeyMultibase": nil},
		"publicKeyMultibase object": {"id": "key-x", "type": "Multikey", "publicKeyMultibase": map[string]any{"a": int64(1)}},
		"publicKeyMultibase absent": {"id": "key-x", "type": "Multikey"},
		"publicKeyMultibase number": {"id": "key-x", "type": "Multikey", "publicKeyMultibase": int64(7)},
	} {
		payload := map[string]any{
			"version": int64(1), "type": "update", "did": did,
			"previousOperationCID": genCID,
			"authKeys":             []any{multikeyMap(genesisKey), bad},
			"assertKeys":           []any{multikeyMap(genesisKey)},
			"controllerKeys":       []any{multikeyMap(genesisKey)},
			"createdAt":            "2026-03-07T00:01:00.000Z",
		}
		token := testSignIdentityOpRaw(t, payload, did+"#"+keyID, priv)
		if _, err := VerifyIdentityChain([]string{genJWS, token}); err == nil {
			t.Errorf("%s: a malformed key declaration must reject the operation, not void it", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Content CID fields: presence and non-emptiness, not merely type
// ---------------------------------------------------------------------------

func TestContentCIDFieldsRequirePresenceAndNonEmptiness(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	genJWS, did, _ := testSignIdentityGenesis(t, NewMultikeyPublicKey(keyID, pub), keyID, priv, "2026-03-07T00:00:00.000Z")
	if _, err := VerifyIdentityChain([]string{genJWS}); err != nil {
		t.Fatal(err)
	}
	kid := did + "#" + keyID
	resolver := func(string, string) (ed25519.PublicKey, error) { return pub, nil }
	docCID, _, _ := DocumentCID(map[string]any{"hello": "world"})

	goodCreate := map[string]any{
		"version": int64(1), "type": "create", "did": did,
		"documentCID": docCID, "baseDocumentCID": nil,
		"createdAt": "2026-03-07T00:00:01.000Z",
	}
	genesisJWS := testSignContentUpdateRaw(t, goodCreate, kid, priv)
	_, _, genesisCID, err := DagCborCID(goodCreate)
	if err != nil {
		t.Fatal(err)
	}

	// TS declares `baseDocumentCID: CIDString.nullable()` — required-but-nullable,
	// so an ABSENT key fails safeParse — and `CIDString` is `z.string().min(1)`,
	// so an empty string fails whether or not the field is nullable. Go type-
	// checked these and stopped there, advancing onto a head TS cannot replay.
	for name, payload := range map[string]map[string]any{
		"create without baseDocumentCID": {
			"version": int64(1), "type": "create", "did": did,
			"documentCID": docCID, "createdAt": "2026-03-07T00:00:01.000Z",
		},
		"create with empty baseDocumentCID": {
			"version": int64(1), "type": "create", "did": did,
			"documentCID": docCID, "baseDocumentCID": "",
			"createdAt": "2026-03-07T00:00:01.000Z",
		},
		"create with empty documentCID": {
			"version": int64(1), "type": "create", "did": did,
			"documentCID": "", "baseDocumentCID": nil,
			"createdAt": "2026-03-07T00:00:01.000Z",
		},
	} {
		token := testSignContentUpdateRaw(t, payload, kid, priv)
		if _, err := VerifyContentChain([]string{token}, resolver, true); err == nil {
			t.Errorf("%s: VerifyContentChain accepted it", name)
		}
	}

	priorState := ContentState{
		ContentID: "c", GenesisCID: genesisCID, HeadCID: genesisCID,
		CurrentDocumentCID: &docCID, Length: 1, CreatorDID: did,
	}
	for name, payload := range map[string]map[string]any{
		"update with empty documentCID": {
			"version": int64(1), "type": "update", "did": did,
			"previousOperationCID": genesisCID, "documentCID": "",
			"baseDocumentCID": nil, "createdAt": "2026-03-07T00:00:02.000Z",
		},
		"update with empty baseDocumentCID": {
			"version": int64(1), "type": "update", "did": did,
			"previousOperationCID": genesisCID, "documentCID": docCID,
			"baseDocumentCID": "", "createdAt": "2026-03-07T00:00:02.000Z",
		},
		"update without baseDocumentCID": {
			"version": int64(1), "type": "update", "did": did,
			"previousOperationCID": genesisCID, "documentCID": docCID,
			"createdAt": "2026-03-07T00:00:02.000Z",
		},
		"update without documentCID": {
			"version": int64(1), "type": "update", "did": did,
			"previousOperationCID": genesisCID, "baseDocumentCID": nil,
			"createdAt": "2026-03-07T00:00:02.000Z",
		},
	} {
		token := testSignContentUpdateRaw(t, payload, kid, priv)
		if _, err := VerifyContentChain([]string{genesisJWS, token}, resolver, true); err == nil {
			t.Errorf("%s: VerifyContentChain accepted it", name)
		}
		if _, err := VerifyContentExtension(priorState, "2026-03-07T00:00:01.000Z", token, resolver, true); err == nil {
			t.Errorf("%s: VerifyContentExtension accepted it", name)
		}
	}

	// and the legitimate shapes still verify
	clearJWS := testSignContentUpdateRaw(t, map[string]any{
		"version": int64(1), "type": "update", "did": did,
		"previousOperationCID": genesisCID, "documentCID": nil,
		"baseDocumentCID": nil, "createdAt": "2026-03-07T00:00:02.000Z",
	}, kid, priv)
	if _, err := VerifyContentChain([]string{genesisJWS, clearJWS}, resolver, true); err != nil {
		t.Fatalf("a null documentCID must still clear the document: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The generic JWS decoder's shape contract
// ---------------------------------------------------------------------------

func TestGenericJWSDecodeRequiresTypAndAnObjectPayload(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// absent typ: the per-field loop skipped the member and left Typ "";
	// TS's asJwsHeader requires a string typ and fails the decode outright
	noTyp := signRawText(t, `{"alg":"EdDSA","kid":"k"}`, `{"v":1}`, priv)
	if _, _, err := DecodeJWSUnsafe(noTyp); err == nil {
		t.Error("DecodeJWSUnsafe accepted a header with no typ")
	}
	if _, _, err := VerifyJWS(noTyp, pub); err == nil {
		t.Error("VerifyJWS accepted a header with no typ")
	}

	// a literal `null` payload unmarshals into map[string]any as a NIL map with
	// no error, which reads downstream as an empty object
	nullPayload := signRawText(t, `{"alg":"EdDSA","typ":"t","kid":"k"}`, `null`, priv)
	if _, _, err := DecodeJWSUnsafe(nullPayload); err == nil {
		t.Error("DecodeJWSUnsafe accepted a null payload")
	}
	if _, _, err := VerifyJWS(nullPayload, pub); err == nil {
		t.Error("VerifyJWS accepted a null payload")
	}

	// kid stays OPTIONAL, and so does cid — the families that require either
	// check it themselves
	noKid := signRawText(t, `{"alg":"EdDSA","typ":"t"}`, `{"v":1}`, priv)
	if _, _, err := DecodeJWSUnsafe(noKid); err != nil {
		t.Errorf("an absent kid must still decode: %v", err)
	}
}

// ---------------------------------------------------------------------------
// A BOM is not canonicalizable, in either language
// ---------------------------------------------------------------------------

func TestBOMPrefixedSegmentsAreRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	const bom = "\ufeff"

	bomHeader := signRawText(t, bom+`{"alg":"EdDSA","typ":"t","kid":"k"}`, `{"v":1}`, priv)
	if _, _, err := DecodeJWSUnsafe(bomHeader); err == nil {
		t.Error("DecodeJWSUnsafe accepted a BOM-prefixed header")
	}
	if _, _, err := VerifyJWS(bomHeader, pub); err == nil {
		t.Error("VerifyJWS accepted a BOM-prefixed header")
	}

	bomPayload := signRawText(t, `{"alg":"EdDSA","typ":"t","kid":"k"}`, bom+`{"v":1}`, priv)
	if _, _, err := DecodeJWSUnsafe(bomPayload); err == nil {
		t.Error("DecodeJWSUnsafe accepted a BOM-prefixed payload")
	}
	if _, _, err := VerifyJWS(bomPayload, pub); err == nil {
		t.Error("VerifyJWS accepted a BOM-prefixed payload")
	}
}
