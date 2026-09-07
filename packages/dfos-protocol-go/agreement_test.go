package dfos

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Wire agreement — the Go twin of dfos-protocol/tests/wire-agreement.spec.ts and
// canonical-encode-guards.spec.ts. Each case here is one place the two reference
// verifiers reached different verdicts (or different bytes) on the same signed
// token. Where a case cannot be a shared five-language vector without teaching
// every standalone verifier a new gate, it is pinned in both unit suites instead.

// signRawText signs a JWS over exactly this header and payload TEXT, so a
// document that no marshaller would produce (duplicate key, lone surrogate
// escape, mis-cased member) can still be handed to the verifier.
func signRawText(t *testing.T, headerText, payloadText string, priv ed25519.PrivateKey) string {
	t.Helper()
	signingInput := Base64urlEncode([]byte(headerText)) + "." + Base64urlEncode([]byte(payloadText))
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + Base64urlEncode(sig)
}

// ---------------------------------------------------------------------------
// H5 — a wrong-length key is an error, never a panic
// ---------------------------------------------------------------------------

func TestDecodeMultikeyRejectsShortKey(t *testing.T) {
	// prefix-valid (0xed01) but only 5 bytes of key material
	short := EncodeMultikey(make([]byte, 5))
	if _, err := DecodeMultikey(short); err == nil {
		t.Fatal("expected a length error for a 5-byte ed25519 key, got none")
	}
	long := EncodeMultikey(make([]byte, 64))
	if _, err := DecodeMultikey(long); err == nil {
		t.Fatal("expected a length error for a 64-byte ed25519 key, got none")
	}
	if _, err := DecodeMultikey(EncodeMultikey(make([]byte, ed25519.PublicKeySize))); err != nil {
		t.Fatalf("a 32-byte key must still decode: %v", err)
	}
}

func TestVerifyJWSRejectsWrongLengthKeyWithoutPanicking(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	token := signRawText(t, `{"alg":"EdDSA","typ":"t","kid":"k"}`, `{"v":1}`, priv)

	// ed25519.Verify panics on a wrong-size key; a bad key is an invalid input
	if _, _, err := VerifyJWS(token, ed25519.PublicKey(make([]byte, 5))); err == nil {
		t.Fatal("expected an error for a 5-byte public key, got none")
	}
	if _, _, err := VerifyJWS(token, pub); err != nil {
		t.Fatalf("a well-formed token must still verify: %v", err)
	}
}

// ---------------------------------------------------------------------------
// H6 — the protected header decodes by exact key
// ---------------------------------------------------------------------------

func TestJWSHeaderDecodesByExactKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	// encoding/json would match TYP/KID/CID case-insensitively into the struct;
	// TypeScript, reading a plain object by exact key, sees none of them
	token := signRawText(t, `{"alg":"EdDSA","TYP":"x","KID":"k","CID":"bafy"}`, `{"v":1}`, priv)
	header, _, err := DecodeJWSUnsafe(token)
	if err != nil {
		t.Fatalf("DecodeJWSUnsafe: %v", err)
	}
	if header.Typ != "" || header.Kid != "" || header.CID != "" {
		t.Fatalf("mis-cased header members must not populate typ/kid/cid: %+v", header)
	}

	exact := signRawText(t, `{"alg":"EdDSA","typ":"x","kid":"k","cid":"bafy"}`, `{"v":1}`, priv)
	header, _, err = DecodeJWSUnsafe(exact)
	if err != nil {
		t.Fatalf("DecodeJWSUnsafe: %v", err)
	}
	if header.Typ != "x" || header.Kid != "k" || header.CID != "bafy" {
		t.Fatalf("exact-key header members must populate: %+v", header)
	}
}

func TestJWSHeaderRejectsNonStringMembers(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	for _, headerText := range []string{
		`{"alg":"EdDSA","typ":"x","kid":42}`,
		`{"alg":"EdDSA","typ":null,"kid":"k"}`,
		`{"alg":"EdDSA","typ":"x","kid":"k","cid":{"a":1}}`,
	} {
		token := signRawText(t, headerText, `{"v":1}`, priv)
		if _, _, err := DecodeJWSUnsafe(token); err == nil {
			t.Errorf("%s: expected a header type error, got none", headerText)
		}
	}
}

// ---------------------------------------------------------------------------
// M5 / H1 — raw-text gates on a signed document
// ---------------------------------------------------------------------------

func TestDuplicateJSONKeysAreMalformed(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	for _, tc := range []struct{ name, header, payload string }{
		{"payload", `{"alg":"EdDSA","typ":"t","kid":"k"}`, `{"a":1,"b":2,"a":3}`},
		{"escaped", `{"alg":"EdDSA","typ":"t","kid":"k"}`, `{"a":1,"a":2}`},
		{"header", `{"alg":"EdDSA","typ":"t","kid":"k","kid":"other"}`, `{"a":1}`},
	} {
		token := signRawText(t, tc.header, tc.payload, priv)
		if _, _, err := DecodeJWSUnsafe(token); err == nil {
			t.Errorf("%s: expected a duplicate-key rejection, got none", tc.name)
		}
	}

	// sibling objects may of course repeat a member name
	ok := signRawText(t, `{"alg":"EdDSA","typ":"t","kid":"k"}`, `{"b":[{"x":1},{"x":2}],"c":{"b":1}}`, priv)
	if _, _, err := DecodeJWSUnsafe(ok); err != nil {
		t.Errorf("repeated names in sibling objects must be fine: %v", err)
	}
}

func TestLoneSurrogateEscapeIsMalformed(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	// encoding/json replaces this with U+FFFD, so the escape is only visible in
	// the raw text — and a payload carrying a literal U+FFFD is a different
	// operation that would otherwise share its CID
	bad := signRawText(t, `{"alg":"EdDSA","typ":"t","kid":"k"}`, `{"a":"\ud800"}`, priv)
	if _, _, err := DecodeJWSUnsafe(bad); err == nil {
		t.Fatal("expected a lone-surrogate rejection, got none")
	}

	good := signRawText(t, `{"alg":"EdDSA","typ":"t","kid":"k"}`, `{"a":"😀"}`, priv)
	header, payload, err := DecodeJWSUnsafe(good)
	if err != nil {
		t.Fatalf("a well-formed surrogate pair must decode: %v", err)
	}
	if payload["a"] != "😀" || header.Kid != "k" {
		t.Fatalf("unexpected decode: %v", payload["a"])
	}
}

// ---------------------------------------------------------------------------
// H1 / H3 — the canonical-value walk agrees with the TS twin
// ---------------------------------------------------------------------------

func TestAssertCanonicalValueRejectsInvalidUTF8AndSentinels(t *testing.T) {
	invalid := string([]byte{0xff, 0xfe})
	for name, v := range map[string]any{
		"string value": map[string]any{"a": invalid},
		"map key":      map[string]any{invalid: 1},
		"array":        []any{invalid},
		"sentinel":     map[string]any{"/": int64(0), "bytes": int64(0)},
		"sentinel str": map[string]any{"/": "aa", "bytes": "bb"},
		"nested":       map[string]any{"a": map[string]any{"bytes": int64(0), "/": int64(0)}},
	} {
		if err := AssertCanonicalValue(v); err == nil {
			t.Errorf("%s: expected a rejection, got none", name)
		}
	}
	for name, v := range map[string]any{
		"slash alone": map[string]any{"/": "bafyabc"},
		"bytes alone": map[string]any{"bytes": "aa"},
		"emoji":       map[string]any{"a": "😀"},
	} {
		if err := AssertCanonicalValue(v); err != nil {
			t.Errorf("%s: expected acceptance, got %v", name, err)
		}
	}
}

// ---------------------------------------------------------------------------
// H8 — absent, null, and wrong-type are three different facts
// ---------------------------------------------------------------------------

// testSignContentUpdateRaw signs an update whose payload members are exactly as
// given, so a wrongly-typed documentCID can reach the verifier.
func testSignContentUpdateRaw(t *testing.T, payload map[string]any, kid string, priv ed25519.PrivateKey) string {
	t.Helper()
	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := CreateJWS(JWSHeader{Alg: "EdDSA", Typ: "did:dfos:content-op", Kid: kid, CID: cidStr}, payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestContentUpdateRejectsNonStringDocumentCID(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	genJWS, did, _ := testSignIdentityGenesis(t, NewMultikeyPublicKey(keyID, pub), keyID, priv, "2026-03-07T00:00:00.000Z")
	if _, err := VerifyIdentityChain([]string{genJWS}); err != nil {
		t.Fatal(err)
	}
	kid := did + "#" + keyID
	resolver := func(k string, _ string) (ed25519.PublicKey, error) { return pub, nil }

	docCID, _, _ := DocumentCID(map[string]any{"hello": "world"})
	contentJWS, _, genesisCID := testSignContentGenesis(t, did, docCID, kid, priv, "2026-03-07T00:00:01.000Z")

	// a null documentCID clears the document — that is the legitimate shape
	clearJWS := testSignContentUpdateRaw(t, map[string]any{
		"version": int64(1), "type": "update", "did": did,
		"previousOperationCID": genesisCID, "documentCID": nil,
		"baseDocumentCID": nil, "createdAt": "2026-03-07T00:00:02.000Z",
	}, kid, priv)
	result, err := VerifyContentChain([]string{contentJWS, clearJWS}, resolver, true)
	if err != nil {
		t.Fatalf("a null documentCID must still clear the document: %v", err)
	}
	if result.State.CurrentDocumentCID != nil {
		t.Fatal("expected a cleared document")
	}

	// every other non-string is malformed, not a clear
	for _, bad := range []any{false, int64(0), []any{}, map[string]any{}} {
		updateJWS := testSignContentUpdateRaw(t, map[string]any{
			"version": int64(1), "type": "update", "did": did,
			"previousOperationCID": genesisCID, "documentCID": bad,
			"baseDocumentCID": nil, "createdAt": "2026-03-07T00:00:02.000Z",
		}, kid, priv)

		if _, err := VerifyContentChain([]string{contentJWS, updateJWS}, resolver, true); err == nil {
			t.Errorf("documentCID %#v: VerifyContentChain accepted it as a clear", bad)
		}

		state := ContentState{
			ContentID: "c", GenesisCID: genesisCID, HeadCID: genesisCID,
			CurrentDocumentCID: &docCID, Length: 1, CreatorDID: did,
		}
		if _, err := VerifyContentExtension(state, "2026-03-07T00:00:01.000Z", updateJWS, resolver, true); err == nil {
			t.Errorf("documentCID %#v: VerifyContentExtension accepted it as a clear", bad)
		}
	}
}

func TestContentPayloadFieldTypesAreGated(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	genJWS, did, _ := testSignIdentityGenesis(t, NewMultikeyPublicKey(keyID, pub), keyID, priv, "2026-03-07T00:00:00.000Z")
	if _, err := VerifyIdentityChain([]string{genJWS}); err != nil {
		t.Fatal(err)
	}
	kid := did + "#" + keyID
	resolver := func(k string, _ string) (ed25519.PublicKey, error) { return pub, nil }
	docCID, _, _ := DocumentCID(map[string]any{"hello": "world"})

	for name, payload := range map[string]map[string]any{
		"did": {
			"version": int64(1), "type": "create", "did": int64(7),
			"documentCID": docCID, "baseDocumentCID": nil, "createdAt": "2026-03-07T00:00:01.000Z",
		},
		"baseDocumentCID": {
			"version": int64(1), "type": "create", "did": did,
			"documentCID": docCID, "baseDocumentCID": int64(1), "createdAt": "2026-03-07T00:00:01.000Z",
		},
		"authorization": {
			"version": int64(1), "type": "create", "did": did,
			"documentCID": docCID, "baseDocumentCID": nil, "authorization": int64(1),
			"createdAt": "2026-03-07T00:00:01.000Z",
		},
	} {
		token := testSignContentUpdateRaw(t, payload, kid, priv)
		if _, err := VerifyContentChain([]string{token}, resolver, true); err == nil {
			t.Errorf("%s: expected a type rejection, got none", name)
		}
	}
}

// ---------------------------------------------------------------------------
// H11 — createdAt answers to the grammar, not just to time.Parse
// ---------------------------------------------------------------------------

func TestProtocolTimestampGrammarGate(t *testing.T) {
	// both of these time.Parse accepts against the layout and TS rejects
	for _, bad := range []string{
		"2026-03-07T5:04:05.000Z",
		"2026-03-07T00:00:00,000Z",
	} {
		if _, err := ParseProtocolTimestamp(bad); err == nil {
			t.Errorf("%s: expected a grammar rejection, got none", bad)
		}
		if err := validateCreatedAt(bad); err == nil {
			t.Errorf("%s: validateCreatedAt accepted it", bad)
		}
	}
	if _, err := ParseProtocolTimestamp("2026-03-07T05:04:05.000Z"); err != nil {
		t.Fatalf("a canonical timestamp must still parse: %v", err)
	}
}

// ---------------------------------------------------------------------------
// M1 — the authorization discount belongs to update and delete
// ---------------------------------------------------------------------------

func TestOperationSizeForCapDoesNotDiscountACreate(t *testing.T) {
	auth := strings.Repeat("a", 1024)
	full := []byte(strings.Repeat("x", 4096))

	createPayload := map[string]any{"type": "create", "authorization": auth, "other": 1}
	size, err := operationSizeForCap(createPayload, full)
	if err != nil {
		t.Fatal(err)
	}
	if size != len(full) {
		t.Fatalf("a create must count its full encoding: got %d, want %d", size, len(full))
	}

	updatePayload := map[string]any{"type": "update", "authorization": auth, "other": 1}
	size, err = operationSizeForCap(updatePayload, full)
	if err != nil {
		t.Fatal(err)
	}
	if size >= len(full) {
		t.Fatalf("an update must discount its authorization: got %d", size)
	}
}

// ---------------------------------------------------------------------------
// M8 — action canonicalization trims ASCII whitespace and nothing else
// ---------------------------------------------------------------------------

func TestParseActionsTrimsASCIIWhitespaceOnly(t *testing.T) {
	if got := ParseActions("\ufeffwrite"); !got["\ufeffwrite"] {
		t.Fatalf("U+FEFF must not be trimmed: %v", got)
	}
	if got := ParseActions(" write"); !got[" write"] {
		t.Fatalf("NBSP must not be trimmed: %v", got)
	}
	if got := ParseActions(" \t\n\v\f\rwrite \t\n\v\f\r"); !got["write"] || len(got) != 1 {
		t.Fatalf("ASCII whitespace must be trimmed: %v", got)
	}

	parent := []AttEntry{{Resource: "chain:abc", Action: "write"}}
	if IsAttenuated(parent, []AttEntry{{Resource: "chain:abc", Action: "\ufeffwrite"}}) {
		t.Fatal("a BOM-prefixed action must not be covered by a bare one")
	}
}

// ---------------------------------------------------------------------------
// H7 — an omitted `prf` is not a `prf: []`
// ---------------------------------------------------------------------------

func TestCredentialCIDCommitsToTheWireBytes(t *testing.T) {
	// the CID Go derives for a payload that omits prf must be the CID of those
	// exact members — the same one the TS verifier now derives, since neither
	// injects a schema default before hashing
	payload := map[string]any{
		"version": int64(1), "type": "DFOSCredential",
		"iss": "did:dfos:a", "aud": "did:dfos:b",
		"att": []any{map[string]any{"resource": "chain:abc", "action": "write"}},
		"exp": int64(1), "iat": int64(0),
	}
	_, _, omitted, err := DagCborCID(payload)
	if err != nil {
		t.Fatal(err)
	}
	payload["prf"] = []any{}
	_, _, withEmpty, err := DagCborCID(payload)
	if err != nil {
		t.Fatal(err)
	}
	if omitted == withEmpty {
		t.Fatal("an omitted prf and an empty prf must not share a CID")
	}

	if prf, err := ParsePrf(map[string]any{}); err != nil || prf != nil {
		t.Fatalf("an absent prf is a root credential: %v %v", prf, err)
	}
}

// a compile-time reminder that the raw scan reads the same text json.Unmarshal does
var _ = json.Unmarshal
var _ = fmt.Sprintf
