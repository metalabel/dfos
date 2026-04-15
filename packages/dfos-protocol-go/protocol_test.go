package dfos

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// ---------------------------------------------------------------------------
// Reference constants from the protocol spec test vectors
// ---------------------------------------------------------------------------

const (
	expectedMultikey1 = "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb"
	expectedGenCID    = "bafyreibanjpgcqffcfhr4sptzjfthh5szohhbo5tjfulemkw7uhden5uqy"
	expectedDID       = "did:dfos:e3vvtck42d4eacdnzvtrn6"
	expectedCBORHex   = "a66474797065666372656174656776657273696f6e0168617574684b65797381a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62696372656174656441747818323032362d30332d30375430303a30303a30302e3030305a6a6173736572744b65797381a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a626e636f6e74726f6c6c65724b65797381a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62"
	expectedCIDHex    = "01711220206a5e6140a5114f1e49f3ca4b339fb2cb8e70bbb34968b23156fd0e3237b486"

	genesisJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJjaWQiOiJiYWZ5cmVpYmFuanBnY3FmZmNmaHI0c3B0empmdGhoNXN6b2hoYm81dGpmdWxlbWt3N3VoZGVuNXVxeSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiYXV0aEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImFzc2VydEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImNvbnRyb2xsZXJLZXlzIjpbeyJpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa3J6TE1Od29KU1Y0UDNZY2NXY2J0azh2ZDlMdGdNS25MZWFETFVxTHVBU2piIn1dLCJjcmVhdGVkQXQiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.EDryDK1uvtix-17cHun9t6MacFIx2rMmMF1QLzfD5TFlSsOvMcue97pCgGn3CXeLVFtVxgpCoh0kGSXioKKzAw"

	// Number encoding test vectors
	numberTestCID      = "bafyreihp6omsp6icc6ee63ox2ovsaxm6s7ikd2a7k5eh2qz2qd5soh5bsa"
	numberTestWrongCID = "bafyreiawbms4476m5jlrmqtyvtwe5ta3eo2bh7mdprtomfgfype7j57o4q"
)

// ---------------------------------------------------------------------------
// Deterministic reference keypairs
// ---------------------------------------------------------------------------

func refKey1() (ed25519.PrivateKey, ed25519.PublicKey) {
	seed := sha256.Sum256([]byte("dfos-protocol-reference-key-1"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv, priv.Public().(ed25519.PublicKey)
}

func refKey2() (ed25519.PrivateKey, ed25519.PublicKey) {
	seed := sha256.Sum256([]byte("dfos-protocol-reference-key-2"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv, priv.Public().(ed25519.PublicKey)
}

// ---------------------------------------------------------------------------
// 1. Base64url round-trip
// ---------------------------------------------------------------------------

func TestBase64urlRoundTrip(t *testing.T) {
	inputs := [][]byte{
		{},
		{0x00},
		{0xff, 0xfe, 0xfd},
		[]byte("hello, world"),
		{0x01, 0x71, 0x12, 0x20, 0xde, 0xad, 0xbe, 0xef},
	}
	for _, in := range inputs {
		encoded := Base64urlEncode(in)
		decoded, err := Base64urlDecode(encoded)
		if err != nil {
			t.Fatalf("decode error for %x: %v", in, err)
		}
		if !bytes.Equal(in, decoded) {
			t.Fatalf("round-trip mismatch: %x -> %s -> %x", in, encoded, decoded)
		}
	}

	// Also verify string variant
	s := "test payload"
	encoded := Base64urlEncodeString(s)
	decoded, err := Base64urlDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != s {
		t.Fatalf("string round-trip: got %q, want %q", string(decoded), s)
	}
}

// ---------------------------------------------------------------------------
// 2. Multikey encode — reference vector
// ---------------------------------------------------------------------------

func TestMultikeyEncodeReference(t *testing.T) {
	_, pub1 := refKey1()
	got := EncodeMultikey(pub1)
	if got != expectedMultikey1 {
		t.Fatalf("EncodeMultikey: got %s, want %s", got, expectedMultikey1)
	}
}

// ---------------------------------------------------------------------------
// 3. Multikey decode — reference vector
// ---------------------------------------------------------------------------

func TestMultikeyDecodeReference(t *testing.T) {
	_, pub1 := refKey1()
	decoded, err := DecodeMultikey(expectedMultikey1)
	if err != nil {
		t.Fatalf("DecodeMultikey error: %v", err)
	}
	if !bytes.Equal(decoded, pub1) {
		t.Fatalf("DecodeMultikey: got %x, want %x", decoded, pub1)
	}
}

// ---------------------------------------------------------------------------
// 4. Multikey round-trip
// ---------------------------------------------------------------------------

func TestMultikeyRoundTrip(t *testing.T) {
	_, pub1 := refKey1()
	encoded := EncodeMultikey(pub1)
	decoded, err := DecodeMultikey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, pub1) {
		t.Fatal("round-trip mismatch")
	}

	// Also try with key 2
	_, pub2 := refKey2()
	encoded2 := EncodeMultikey(pub2)
	decoded2, err := DecodeMultikey(encoded2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded2, pub2) {
		t.Fatal("round-trip mismatch for key 2")
	}
}

// ---------------------------------------------------------------------------
// 5. dag-cbor CID — reference vector (genesis payload)
// ---------------------------------------------------------------------------

func TestDagCborCIDReference(t *testing.T) {
	key := map[string]any{
		"id":                 "key_r9ev34fvc23z999veaaft8",
		"type":               "Multikey",
		"publicKeyMultibase": expectedMultikey1,
	}
	payload := map[string]any{
		"version":        1,
		"type":           "create",
		"authKeys":       []any{key},
		"assertKeys":     []any{key},
		"controllerKeys": []any{key},
		"createdAt":      "2026-03-07T00:00:00.000Z",
	}

	cborBytes, cidBytes, cidStr, err := DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID error: %v", err)
	}

	gotCBOR := fmt.Sprintf("%x", cborBytes)
	if gotCBOR != expectedCBORHex {
		t.Fatalf("CBOR hex mismatch\n  got:  %s\n  want: %s", gotCBOR[:60], expectedCBORHex[:60])
	}

	gotCIDHex := fmt.Sprintf("%x", cidBytes)
	if gotCIDHex != expectedCIDHex {
		t.Fatalf("CID bytes mismatch: got %s, want %s", gotCIDHex, expectedCIDHex)
	}

	if cidStr != expectedGenCID {
		t.Fatalf("CID string mismatch: got %s, want %s", cidStr, expectedGenCID)
	}
}

// ---------------------------------------------------------------------------
// 6. DID derivation — reference vector
// ---------------------------------------------------------------------------

func TestDIDDerivation(t *testing.T) {
	cidBytes, err := hex.DecodeString(expectedCIDHex)
	if err != nil {
		t.Fatal(err)
	}
	did := DeriveDID(cidBytes)
	if did != expectedDID {
		t.Fatalf("DeriveDID: got %s, want %s", did, expectedDID)
	}
}

// ---------------------------------------------------------------------------
// 7. Content ID derivation — format check
// ---------------------------------------------------------------------------

func TestContentIDDerivation(t *testing.T) {
	cidBytes, _ := hex.DecodeString(expectedCIDHex)
	contentID := DeriveContentID(cidBytes)

	if len(contentID) != 22 {
		t.Fatalf("content ID length: got %d, want 22", len(contentID))
	}

	for _, c := range contentID {
		if !strings.ContainsRune(idAlphabet, c) {
			t.Fatalf("content ID contains invalid char %q (not in alphabet %q)", string(c), idAlphabet)
		}
	}
}

// ---------------------------------------------------------------------------
// 8. GenerateKeyID — format check
// ---------------------------------------------------------------------------

func TestGenerateKeyID(t *testing.T) {
	kid := GenerateKeyID()

	if len(kid) != 26 {
		t.Fatalf("key ID length: got %d, want 26", len(kid))
	}
	if kid[:4] != "key_" {
		t.Fatalf("key ID prefix: got %q, want \"key_\"", kid[:4])
	}

	suffix := kid[4:]
	for _, c := range suffix {
		if !strings.ContainsRune(idAlphabet, c) {
			t.Fatalf("key ID suffix contains invalid char %q", string(c))
		}
	}

	// Should be random — two calls should differ
	kid2 := GenerateKeyID()
	if kid == kid2 {
		t.Fatal("two GenerateKeyID calls returned the same value")
	}
}

// ---------------------------------------------------------------------------
// 9. JWS create + verify round-trip
// ---------------------------------------------------------------------------

func TestJWSCreateVerify(t *testing.T) {
	priv1, pub1 := refKey1()

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: "test",
		Kid: "key_test123",
	}
	payload := map[string]any{
		"foo": "bar",
		"num": 42,
	}

	token, err := CreateJWS(header, payload, priv1)
	if err != nil {
		t.Fatalf("CreateJWS: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWS should have 3 parts, got %d", len(parts))
	}

	h, p, err := VerifyJWS(token, pub1)
	if err != nil {
		t.Fatalf("VerifyJWS: %v", err)
	}
	if h.Alg != "EdDSA" {
		t.Fatalf("header alg: got %s", h.Alg)
	}
	if h.Typ != "test" {
		t.Fatalf("header typ: got %s", h.Typ)
	}
	if h.Kid != "key_test123" {
		t.Fatalf("header kid: got %s", h.Kid)
	}
	if p["foo"] != "bar" {
		t.Fatalf("payload foo: got %v", p["foo"])
	}
}

// ---------------------------------------------------------------------------
// 10. JWS verify reference genesis token
// ---------------------------------------------------------------------------

func TestJWSVerifyReference(t *testing.T) {
	_, pub1 := refKey1()

	h, p, err := VerifyJWS(genesisJWS, pub1)
	if err != nil {
		t.Fatalf("VerifyJWS genesis: %v", err)
	}
	if h.Alg != "EdDSA" {
		t.Fatal("wrong alg")
	}
	if h.Typ != "did:dfos:identity-op" {
		t.Fatalf("wrong typ: %s", h.Typ)
	}
	if h.Kid != "key_r9ev34fvc23z999veaaft8" {
		t.Fatalf("wrong kid: %s", h.Kid)
	}
	if h.CID != expectedGenCID {
		t.Fatalf("wrong cid: %s", h.CID)
	}
	if p["type"] != "create" {
		t.Fatal("wrong payload type")
	}
}

// ---------------------------------------------------------------------------
// 11. JWS verify with wrong key fails
// ---------------------------------------------------------------------------

func TestJWSVerifyWrongKey(t *testing.T) {
	_, pub2 := refKey2()

	_, _, err := VerifyJWS(genesisJWS, pub2)
	if err == nil {
		t.Fatal("expected signature verification to fail with wrong key")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 12. JWS decode unsafe — no verification
// ---------------------------------------------------------------------------

func TestJWSDecodeUnsafe(t *testing.T) {
	h, p, err := DecodeJWSUnsafe(genesisJWS)
	if err != nil {
		t.Fatalf("DecodeJWSUnsafe: %v", err)
	}
	if h.Alg != "EdDSA" {
		t.Fatal("wrong alg")
	}
	if h.Typ != "did:dfos:identity-op" {
		t.Fatalf("wrong typ: %s", h.Typ)
	}
	if h.Kid != "key_r9ev34fvc23z999veaaft8" {
		t.Fatalf("wrong kid: %s", h.Kid)
	}
	if h.CID != expectedGenCID {
		t.Fatalf("wrong cid: %s", h.CID)
	}
	if p["type"] != "create" {
		t.Fatal("wrong payload type")
	}

	// Should also work with wrong key (since we don't verify)
	// Just check it doesn't panic
	_, _, err = DecodeJWSUnsafe(genesisJWS)
	if err != nil {
		t.Fatal("DecodeJWSUnsafe should not fail")
	}
}

// ---------------------------------------------------------------------------
// 13. CreateAuthToken — create and decode
// ---------------------------------------------------------------------------

func TestCreateAuthToken(t *testing.T) {
	priv1, pub1 := refKey1()
	iss := "did:dfos:testdid"
	aud := "https://relay.example.com"
	kid := "key_test"
	ttl := 1 * time.Hour

	token, err := CreateAuthToken(iss, aud, kid, ttl, priv1)
	if err != nil {
		t.Fatalf("CreateAuthToken: %v", err)
	}

	// Verify signature
	_, p, err := VerifyJWS(token, pub1)
	if err != nil {
		t.Fatalf("VerifyJWS auth token: %v", err)
	}

	if p["iss"] != iss {
		t.Fatalf("iss: got %v, want %s", p["iss"], iss)
	}
	if p["sub"] != iss {
		t.Fatalf("sub: got %v, want %s", p["sub"], iss)
	}
	if p["aud"] != aud {
		t.Fatalf("aud: got %v, want %s", p["aud"], aud)
	}

	// Decode via JWT helper
	hm, pm, err := DecodeJWTUnsafe(token)
	if err != nil {
		t.Fatalf("DecodeJWTUnsafe: %v", err)
	}
	if hm["alg"] != "EdDSA" {
		t.Fatal("wrong alg")
	}
	if hm["typ"] != "JWT" {
		t.Fatalf("wrong typ: %s", hm["typ"])
	}
	if hm["kid"] != kid {
		t.Fatalf("wrong kid: %s", hm["kid"])
	}

	// exp should be in the future
	exp, ok := pm["exp"].(float64)
	if !ok {
		// might be int64 after normalization
		if expInt, ok2 := pm["exp"].(int64); ok2 {
			exp = float64(expInt)
		} else {
			t.Fatalf("exp type: %T", pm["exp"])
		}
	}
	if int64(exp) <= time.Now().Unix() {
		t.Fatal("exp should be in the future")
	}
}

// ---------------------------------------------------------------------------
// 14. CreateCredential — DFOS credential structure
// ---------------------------------------------------------------------------

func TestCreateCredential(t *testing.T) {
	priv1, pub1 := refKey1()
	iss := expectedDID
	sub := expectedDID
	kid := "key_r9ev34fvc23z999veaaft8"
	ttl := 24 * time.Hour
	contentID := "abc123"

	token, err := CreateCredential(iss, sub, kid, "chain:"+contentID, "read", ttl, priv1)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	// Verify signature
	_, p, err := VerifyJWS(token, pub1)
	if err != nil {
		t.Fatalf("VerifyJWS credential: %v", err)
	}

	if p["iss"] != iss {
		t.Fatalf("iss: got %v", p["iss"])
	}
	if p["aud"] != sub {
		t.Fatalf("aud: got %v, want %s", p["aud"], sub)
	}
	if p["type"] != "DFOSCredential" {
		t.Fatalf("type: got %v, want DFOSCredential", p["type"])
	}

	// Check att structure
	att, ok := p["att"].([]any)
	if !ok {
		t.Fatalf("att type: %T", p["att"])
	}
	if len(att) != 1 {
		t.Fatalf("att length: got %d, want 1", len(att))
	}
	attEntry, ok := att[0].(map[string]any)
	if !ok {
		t.Fatalf("att[0] type: %T", att[0])
	}
	if attEntry["resource"] != "chain:"+contentID {
		t.Fatalf("att[0].resource: got %v, want chain:%s", attEntry["resource"], contentID)
	}
	if attEntry["action"] != "read" {
		t.Fatalf("att[0].action: got %v, want read", attEntry["action"])
	}

	// Decode via JWT helper and verify typ
	hm, _, err := DecodeJWTUnsafe(token)
	if err != nil {
		t.Fatal(err)
	}
	if hm["typ"] != "did:dfos:credential" {
		t.Fatalf("JWT typ: got %s, want did:dfos:credential", hm["typ"])
	}
}

// ---------------------------------------------------------------------------
// 15. SignIdentityCreate — deterministic DID for same inputs
// ---------------------------------------------------------------------------

func TestSignIdentityCreate(t *testing.T) {
	priv1, pub1 := refKey1()
	kid := "key_r9ev34fvc23z999veaaft8"

	mk := NewMultikeyPublicKey(kid, pub1)

	token, did, cidStr, err := SignIdentityCreate(
		[]MultikeyPublicKey{mk},
		[]MultikeyPublicKey{mk},
		[]MultikeyPublicKey{mk},
		kid,
		priv1,
	)
	if err != nil {
		t.Fatalf("SignIdentityCreate: %v", err)
	}

	// Token should be a valid JWS
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWS parts: got %d, want 3", len(parts))
	}

	// Verify signature
	h, _, err := VerifyJWS(token, pub1)
	if err != nil {
		t.Fatalf("VerifyJWS identity create: %v", err)
	}
	if h.Typ != "did:dfos:identity-op" {
		t.Fatalf("typ: got %s", h.Typ)
	}
	if h.Alg != "EdDSA" {
		t.Fatalf("alg: got %s", h.Alg)
	}
	if h.Kid != kid {
		t.Fatalf("kid: got %s", h.Kid)
	}
	if h.CID != cidStr {
		t.Fatalf("cid mismatch: header=%s, returned=%s", h.CID, cidStr)
	}

	// DID should have correct format
	if !strings.HasPrefix(did, "did:dfos:") {
		t.Fatalf("DID prefix: %s", did)
	}
	suffix := strings.TrimPrefix(did, "did:dfos:")
	if len(suffix) != 22 {
		t.Fatalf("DID suffix length: got %d, want 22", len(suffix))
	}

	// CID should start with "b" (base32lower multibase)
	if !strings.HasPrefix(cidStr, "b") {
		t.Fatalf("CID prefix: %s", cidStr)
	}

	// Calling again should produce a different DID (different createdAt timestamp)
	// but the structure should be the same
	token2, did2, _, err := SignIdentityCreate(
		[]MultikeyPublicKey{mk},
		[]MultikeyPublicKey{mk},
		[]MultikeyPublicKey{mk},
		kid,
		priv1,
	)
	if err != nil {
		t.Fatal(err)
	}
	// Token should still be valid
	_, _, err = VerifyJWS(token2, pub1)
	if err != nil {
		t.Fatal(err)
	}
	// DID will differ because createdAt is now different
	_ = did2
}

// ---------------------------------------------------------------------------
// 16. SignContentCreate — content ID and CID
// ---------------------------------------------------------------------------

func TestSignContentCreate(t *testing.T) {
	priv2, pub2 := refKey2()
	did := expectedDID
	kid := "key_ez9a874tckr3dv933d3ckd"
	docCID := "bafyreihzwuoupfg3dxip6xmgzmxsywyi2jeoxxzbgx3zxm2in7knoi3g4"

	token, contentID, cidStr, err := SignContentCreate(did, docCID, kid, "", priv2)
	if err != nil {
		t.Fatalf("SignContentCreate: %v", err)
	}

	// Verify signature with key 2
	h, p, err := VerifyJWS(token, pub2)
	if err != nil {
		t.Fatalf("VerifyJWS content create: %v", err)
	}
	if h.Typ != "did:dfos:content-op" {
		t.Fatalf("typ: got %s", h.Typ)
	}
	if h.Kid != kid {
		t.Fatalf("kid: got %s", h.Kid)
	}
	if h.CID != cidStr {
		t.Fatalf("cid mismatch: header=%s, returned=%s", h.CID, cidStr)
	}

	// Payload checks
	if p["type"] != "create" {
		t.Fatalf("payload type: got %v", p["type"])
	}
	if p["did"] != did {
		t.Fatalf("payload did: got %v", p["did"])
	}
	if p["documentCID"] != docCID {
		t.Fatalf("payload documentCID: got %v", p["documentCID"])
	}

	// Content ID format
	if len(contentID) != 22 {
		t.Fatalf("content ID length: got %d, want 22", len(contentID))
	}
	for _, c := range contentID {
		if !strings.ContainsRune(idAlphabet, c) {
			t.Fatalf("content ID contains invalid char %q", string(c))
		}
	}
}

// ---------------------------------------------------------------------------
// 17. DocumentCID — deterministic
// ---------------------------------------------------------------------------

func TestDocumentCID(t *testing.T) {
	doc := map[string]any{
		"title":   "Hello",
		"version": 1,
	}

	cid1, cbor1, err := DocumentCID(doc)
	if err != nil {
		t.Fatalf("DocumentCID: %v", err)
	}

	// Same input should produce same output
	cid2, cbor2, err := DocumentCID(map[string]any{
		"title":   "Hello",
		"version": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cid1 != cid2 {
		t.Fatalf("non-deterministic CID: %s vs %s", cid1, cid2)
	}
	if !bytes.Equal(cbor1, cbor2) {
		t.Fatal("non-deterministic CBOR")
	}

	// Different input should produce different CID
	cid3, _, err := DocumentCID(map[string]any{
		"title":   "World",
		"version": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cid1 == cid3 {
		t.Fatal("different documents produced same CID")
	}

	// CID starts with "b" (base32lower)
	if !strings.HasPrefix(cid1, "b") {
		t.Fatalf("CID prefix: %s", cid1)
	}
}

// ---------------------------------------------------------------------------
// 19. NormalizeJSONNumbers — float64(1) → int64(1), float64(1.5) stays
// ---------------------------------------------------------------------------

func TestNormalizeJSONNumbers(t *testing.T) {
	// Whole float64 → int64
	got := NormalizeJSONNumbers(float64(1))
	if v, ok := got.(int64); !ok || v != 1 {
		t.Fatalf("float64(1) should become int64(1), got %T(%v)", got, got)
	}

	// Non-whole float64 stays
	got = NormalizeJSONNumbers(float64(1.5))
	if v, ok := got.(float64); !ok || v != 1.5 {
		t.Fatalf("float64(1.5) should stay float64(1.5), got %T(%v)", got, got)
	}

	// Nested map
	input := map[string]any{
		"version": float64(42),
		"ratio":   float64(3.14),
		"name":    "test",
	}
	result := NormalizeJSONNumbers(input).(map[string]any)
	if v, ok := result["version"].(int64); !ok || v != 42 {
		t.Fatalf("nested version: %T(%v)", result["version"], result["version"])
	}
	if v, ok := result["ratio"].(float64); !ok || v != 3.14 {
		t.Fatalf("nested ratio: %T(%v)", result["ratio"], result["ratio"])
	}
	if result["name"] != "test" {
		t.Fatal("nested string should be unchanged")
	}

	// Nested slice
	inputSlice := []any{float64(1), float64(2.5), "hello"}
	resultSlice := NormalizeJSONNumbers(inputSlice).([]any)
	if _, ok := resultSlice[0].(int64); !ok {
		t.Fatalf("slice[0]: %T", resultSlice[0])
	}
	if _, ok := resultSlice[1].(float64); !ok {
		t.Fatalf("slice[1]: %T", resultSlice[1])
	}

	// JSON round-trip scenario
	jsonStr := `{"version": 1, "type": "test"}`
	var decoded map[string]any
	json.Unmarshal([]byte(jsonStr), &decoded)
	// Before normalization, version is float64
	if _, ok := decoded["version"].(float64); !ok {
		t.Fatal("JSON should decode integers as float64")
	}
	normalized := NormalizeJSONNumbers(decoded).(map[string]any)
	if _, ok := normalized["version"].(int64); !ok {
		t.Fatal("after normalization, version should be int64")
	}
}

// ---------------------------------------------------------------------------
// 20. SignIdentityUpdate — key rotation produces valid JWS
// ---------------------------------------------------------------------------

func TestSignIdentityUpdate(t *testing.T) {
	priv1, pub1 := refKey1()
	_, pub2 := refKey2()
	kid1 := "key_r9ev34fvc23z999veaaft8"

	mk1 := NewMultikeyPublicKey(kid1, pub1)

	// first create an identity
	_, did, genCID, err := SignIdentityCreate(
		[]MultikeyPublicKey{mk1}, []MultikeyPublicKey{mk1}, nil, kid1, priv1,
	)
	if err != nil {
		t.Fatalf("SignIdentityCreate: %v", err)
	}

	// now sign an update that rotates in key2
	kid2 := "key_newkey00000000000000"
	mk2 := NewMultikeyPublicKey(kid2, pub2)
	didKid := did + "#" + kid1

	token, opCID, err := SignIdentityUpdate(
		genCID,
		[]MultikeyPublicKey{mk1}, // keep controller
		[]MultikeyPublicKey{mk2}, // rotate auth to key2
		nil,
		didKid, priv1,
	)
	if err != nil {
		t.Fatalf("SignIdentityUpdate: %v", err)
	}

	// verify signature with the signing key
	h, p, err := VerifyJWS(token, pub1)
	if err != nil {
		t.Fatalf("VerifyJWS: %v", err)
	}
	if h.Typ != "did:dfos:identity-op" {
		t.Fatalf("typ: got %s", h.Typ)
	}
	if h.CID != opCID {
		t.Fatalf("CID mismatch")
	}
	if p["type"] != "update" {
		t.Fatalf("payload type: got %v", p["type"])
	}
	if p["previousOperationCID"] != genCID {
		t.Fatalf("previousOperationCID: got %v", p["previousOperationCID"])
	}

	// verify the new auth key is in the payload
	authKeys, ok := p["authKeys"].([]any)
	if !ok || len(authKeys) != 1 {
		t.Fatal("expected 1 auth key in update payload")
	}

	// should fail verification with the wrong key
	_, _, err = VerifyJWS(token, pub2)
	if err == nil {
		t.Fatal("expected verification to fail with wrong key")
	}
}

// ---------------------------------------------------------------------------
// 21. SignIdentityDelete — terminal delete operation
// ---------------------------------------------------------------------------

func TestSignIdentityDelete(t *testing.T) {
	priv1, pub1 := refKey1()
	kid := "key_r9ev34fvc23z999veaaft8"
	mk := NewMultikeyPublicKey(kid, pub1)

	_, did, genCID, err := SignIdentityCreate(
		[]MultikeyPublicKey{mk}, []MultikeyPublicKey{mk}, nil, kid, priv1,
	)
	if err != nil {
		t.Fatal(err)
	}

	didKid := did + "#" + kid
	token, opCID, err := SignIdentityDelete(genCID, didKid, priv1)
	if err != nil {
		t.Fatalf("SignIdentityDelete: %v", err)
	}

	h, p, err := VerifyJWS(token, pub1)
	if err != nil {
		t.Fatalf("VerifyJWS: %v", err)
	}
	if h.Typ != "did:dfos:identity-op" {
		t.Fatalf("typ: got %s", h.Typ)
	}
	if h.CID != opCID {
		t.Fatalf("CID mismatch")
	}
	if p["type"] != "delete" {
		t.Fatalf("payload type: got %v", p["type"])
	}
	if p["previousOperationCID"] != genCID {
		t.Fatalf("previousOperationCID: got %v", p["previousOperationCID"])
	}

	// delete payload should NOT have key arrays
	if _, ok := p["authKeys"]; ok {
		t.Fatal("delete payload should not have authKeys")
	}
}

// ---------------------------------------------------------------------------
// 22. SignContentDelete — terminal delete operation
// ---------------------------------------------------------------------------

func TestSignContentDelete(t *testing.T) {
	priv1, pub1 := refKey1()
	did := expectedDID
	kid := did + "#key_test"
	docCID := "bafyreihzwuoupfg3dxip6xmgzmxsywyi2jeoxxzbgx3zxm2in7knoi3g4"

	_, _, genCID, err := SignContentCreate(did, docCID, kid, "", priv1)
	if err != nil {
		t.Fatal(err)
	}

	token, opCID, err := SignContentDelete(did, genCID, kid, "removing this content", "", priv1)
	if err != nil {
		t.Fatalf("SignContentDelete: %v", err)
	}

	h, p, err := VerifyJWS(token, pub1)
	if err != nil {
		t.Fatalf("VerifyJWS: %v", err)
	}
	if h.Typ != "did:dfos:content-op" {
		t.Fatalf("typ: got %s", h.Typ)
	}
	if h.CID != opCID {
		t.Fatalf("CID mismatch")
	}
	if p["type"] != "delete" {
		t.Fatalf("payload type: got %v", p["type"])
	}
	if p["previousOperationCID"] != genCID {
		t.Fatalf("previousOperationCID: got %v", p["previousOperationCID"])
	}
	if p["note"] != "removing this content" {
		t.Fatalf("note: got %v", p["note"])
	}
	if p["did"] != did {
		t.Fatalf("did: got %v", p["did"])
	}
}

// ---------------------------------------------------------------------------
// 23. SignContentUpdateWithOptions — authorization and baseDocumentCID
// ---------------------------------------------------------------------------

func TestSignContentUpdateWithOptions(t *testing.T) {
	priv1, pub1 := refKey1()
	did := expectedDID
	kid := did + "#key_test"
	docCID := "bafyreihzwuoupfg3dxip6xmgzmxsywyi2jeoxxzbgx3zxm2in7knoi3g4"

	_, _, genCID, err := SignContentCreate(did, docCID, kid, "", priv1)
	if err != nil {
		t.Fatal(err)
	}

	newDocCID := "bafyreifoo000000000000000000000000000000000000000000000000bar"
	baseCID := docCID
	authz := "eyJhbGciOiJFZERTQSJ9.fake-credential-token"

	token, opCID, err := SignContentUpdateWithOptions(did, genCID, newDocCID, kid, priv1, ContentUpdateOptions{
		Note:            "delegated update",
		BaseDocumentCID: baseCID,
		Authorization:   authz,
	})
	if err != nil {
		t.Fatalf("SignContentUpdateWithOptions: %v", err)
	}

	h, p, err := VerifyJWS(token, pub1)
	if err != nil {
		t.Fatalf("VerifyJWS: %v", err)
	}
	if h.CID != opCID {
		t.Fatal("CID mismatch")
	}
	if p["type"] != "update" {
		t.Fatalf("payload type: got %v", p["type"])
	}
	if p["baseDocumentCID"] != baseCID {
		t.Fatalf("baseDocumentCID: got %v", p["baseDocumentCID"])
	}
	if p["authorization"] != authz {
		t.Fatalf("authorization: got %v", p["authorization"])
	}
	if p["note"] != "delegated update" {
		t.Fatalf("note: got %v", p["note"])
	}
}

// ---------------------------------------------------------------------------
// 24. Number encoding CID — integer vs float produces different CIDs
// ---------------------------------------------------------------------------

func TestNumberEncodingCID(t *testing.T) {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}

	// Integer encoding → correct CID
	intPayload := map[string]any{"version": int64(1), "type": "test"}
	intCBOR, err := em.Marshal(intPayload)
	if err != nil {
		t.Fatal(err)
	}
	intCIDBytes := MakeCIDBytes(intCBOR)
	intCID := CIDToBase32(intCIDBytes)
	if intCID != numberTestCID {
		t.Fatalf("integer CID mismatch: got %s, want %s", intCID, numberTestCID)
	}

	// Float encoding → known-wrong CID
	floatPayload := map[string]any{"version": float64(1.0), "type": "test"}
	floatCBOR, err := em.Marshal(floatPayload)
	if err != nil {
		t.Fatal(err)
	}
	floatCIDBytes := MakeCIDBytes(floatCBOR)
	floatCID := CIDToBase32(floatCIDBytes)
	if floatCID != numberTestWrongCID {
		t.Fatalf("float CID mismatch: got %s, want %s", floatCID, numberTestWrongCID)
	}

	// They must differ
	if intCID == floatCID {
		t.Fatal("integer and float CIDs should differ")
	}

	// DagCborCID with normalization should produce the correct (integer) CID
	// even when given float64 input (as would come from JSON decoding)
	jsonLike := map[string]any{"version": float64(1), "type": "test"}
	_, _, normalizedCID, err := DagCborCID(jsonLike)
	if err != nil {
		t.Fatal(err)
	}
	if normalizedCID != numberTestCID {
		t.Fatalf("DagCborCID with float input should normalize to integer CID: got %s, want %s", normalizedCID, numberTestCID)
	}
}

// ---------------------------------------------------------------------------
// 25. SignCountersign — standalone witness attestation
// ---------------------------------------------------------------------------

func TestSignCountersign(t *testing.T) {
	_, _ = refKey1()
	priv2, pub2 := refKey2()

	// countersign a target CID
	witnessDID := "did:dfos:witness0000000000000"
	targetCID := "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenera6h5y"
	witnessKid := witnessDID + "#key_witness"
	csToken, csCID, err := SignCountersign(witnessDID, targetCID, witnessKid, priv2)
	if err != nil {
		t.Fatalf("SignCountersign: %v", err)
	}

	// countersign CID is distinct from target CID
	if csCID == targetCID {
		t.Fatal("countersign CID must differ from target CID")
	}

	// verify the countersignature with witness key
	h, p, err := VerifyJWS(csToken, pub2)
	if err != nil {
		t.Fatalf("VerifyJWS countersign: %v", err)
	}
	if h.Kid != witnessKid {
		t.Fatalf("kid: got %s, want %s", h.Kid, witnessKid)
	}
	if h.Typ != "did:dfos:countersign" {
		t.Fatalf("typ: got %s, want did:dfos:countersign", h.Typ)
	}
	if p["type"] != "countersign" {
		t.Fatalf("payload type: got %v", p["type"])
	}
	if p["did"] != witnessDID {
		t.Fatalf("witness DID: got %v", p["did"])
	}
	if p["targetCID"] != targetCID {
		t.Fatalf("targetCID: got %v", p["targetCID"])
	}

	// countersign should NOT verify with a different key
	_, pub1 := refKey1()
	_, _, err = VerifyJWS(csToken, pub1)
	if err == nil {
		t.Fatal("countersign should not verify with wrong key")
	}
}

// ---------------------------------------------------------------------------
// 26. SignArtifact — standalone signed document
// ---------------------------------------------------------------------------

func TestSignArtifact(t *testing.T) {
	priv1, pub1 := refKey1()
	did := expectedDID
	kid := did + "#key_r9ev34fvc23z999veaaft8"

	content := map[string]any{
		"$schema":  "test/v1",
		"title":    "Hello artifact",
		"operator": "test",
	}
	token, artifactCID, err := SignArtifact(did, content, kid, priv1)
	if err != nil {
		t.Fatalf("SignArtifact: %v", err)
	}

	if artifactCID == "" {
		t.Fatal("artifact CID is empty")
	}

	h, p, err := VerifyJWS(token, pub1)
	if err != nil {
		t.Fatalf("VerifyJWS artifact: %v", err)
	}
	if h.Typ != "did:dfos:artifact" {
		t.Fatalf("typ: got %s, want did:dfos:artifact", h.Typ)
	}
	if h.CID != artifactCID {
		t.Fatalf("header CID: got %s, want %s", h.CID, artifactCID)
	}
	if p["type"] != "artifact" {
		t.Fatalf("payload type: got %v", p["type"])
	}
	contentMap, ok := p["content"].(map[string]any)
	if !ok {
		t.Fatal("content field is not a map")
	}
	if contentMap["$schema"] != "test/v1" {
		t.Fatalf("$schema: got %v", contentMap["$schema"])
	}
}

// ---------------------------------------------------------------------------
// 27. PayloadFromJWS — extracts payload map
// ---------------------------------------------------------------------------

func TestPayloadFromJWS(t *testing.T) {
	payload, err := PayloadFromJWS(genesisJWS)
	if err != nil {
		t.Fatalf("PayloadFromJWS: %v", err)
	}
	if payload["type"] != "create" {
		t.Fatalf("payload type: got %v", payload["type"])
	}

	// invalid token
	_, err = PayloadFromJWS("not-a-token")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

// ---------------------------------------------------------------------------
// 28. SignContentUpdate — backward-compatible wrapper
// ---------------------------------------------------------------------------

func TestSignContentUpdate(t *testing.T) {
	priv1, pub1 := refKey1()
	did := expectedDID
	kid := did + "#key_test"
	docCID := "bafyreihzwuoupfg3dxip6xmgzmxsywyi2jeoxxzbgx3zxm2in7knoi3g4"

	_, _, genCID, err := SignContentCreate(did, docCID, kid, "", priv1)
	if err != nil {
		t.Fatal(err)
	}

	newDocCID := "bafyreifoo000000000000000000000000000000000000000000000000bar"
	token, opCID, err := SignContentUpdate(did, genCID, newDocCID, kid, "update note", priv1)
	if err != nil {
		t.Fatalf("SignContentUpdate: %v", err)
	}

	h, p, err := VerifyJWS(token, pub1)
	if err != nil {
		t.Fatalf("VerifyJWS: %v", err)
	}
	if h.CID != opCID {
		t.Fatal("CID mismatch")
	}
	if p["type"] != "update" {
		t.Fatalf("payload type: got %v", p["type"])
	}
	if p["note"] != "update note" {
		t.Fatalf("note: got %v", p["note"])
	}
	if p["previousOperationCID"] != genCID {
		t.Fatalf("previousOperationCID: got %v", p["previousOperationCID"])
	}
}

// ---------------------------------------------------------------------------
// 29. DeriveID — deterministic
// ---------------------------------------------------------------------------

func TestDeriveID(t *testing.T) {
	id1 := DeriveID([]byte("seed-a"))
	id2 := DeriveID([]byte("seed-a"))
	id3 := DeriveID([]byte("seed-b"))

	if id1 != id2 {
		t.Fatal("same seed should produce same ID")
	}
	if id1 == id3 {
		t.Fatal("different seeds should produce different IDs")
	}
	if len(id1) != 22 {
		t.Fatalf("ID length: got %d, want 22", len(id1))
	}
}

// ---------------------------------------------------------------------------
// 30. DecodeMultikey error cases
// ---------------------------------------------------------------------------

func TestDecodeMultikeyErrors(t *testing.T) {
	// wrong prefix
	_, err := DecodeMultikey("x6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb")
	if err == nil {
		t.Fatal("expected error for wrong prefix")
	}

	// empty
	_, err = DecodeMultikey("")
	if err == nil {
		t.Fatal("expected error for empty")
	}

	// wrong multicodec prefix (valid base58 but not ed25519-pub)
	_, err = DecodeMultikey("z111111111111111111111111111111111")
	if err == nil {
		t.Fatal("expected error for wrong multicodec")
	}
}

// ---------------------------------------------------------------------------
// 31. DecodeJWSUnsafe — error paths
// ---------------------------------------------------------------------------

func TestDecodeJWSUnsafeErrors(t *testing.T) {
	// too few parts
	_, _, err := DecodeJWSUnsafe("onlyonepart")
	if err == nil {
		t.Fatal("expected error for 1-part token")
	}

	// invalid base64 in header
	_, _, err = DecodeJWSUnsafe("!!!.valid.valid")
	if err == nil {
		t.Fatal("expected error for invalid header base64")
	}

	// invalid base64 in payload
	validHeader := Base64urlEncodeString(`{"alg":"EdDSA","typ":"test","kid":"k"}`)
	_, _, err = DecodeJWSUnsafe(validHeader + ".!!!.sig")
	if err == nil {
		t.Fatal("expected error for invalid payload base64")
	}

	// valid base64 but not valid JSON in header
	_, _, err = DecodeJWSUnsafe(Base64urlEncodeString("not json") + "." + Base64urlEncodeString("{}") + ".sig")
	if err == nil {
		t.Fatal("expected error for non-JSON header")
	}

	// valid base64 but not valid JSON in payload
	_, _, err = DecodeJWSUnsafe(validHeader + "." + Base64urlEncodeString("not json") + ".sig")
	if err == nil {
		t.Fatal("expected error for non-JSON payload")
	}
}

// ---------------------------------------------------------------------------
// 32. VerifyJWS — error paths
// ---------------------------------------------------------------------------

func TestVerifyJWSErrors(t *testing.T) {
	_, pub1 := refKey1()

	// too few parts
	_, _, err := VerifyJWS("bad", pub1)
	if err == nil {
		t.Fatal("expected error")
	}

	// invalid signature base64
	validHeader := Base64urlEncodeString(`{"alg":"EdDSA","typ":"test","kid":"k"}`)
	validPayload := Base64urlEncodeString(`{"foo":"bar"}`)
	_, _, err = VerifyJWS(validHeader+"."+validPayload+".!!!", pub1)
	if err == nil {
		t.Fatal("expected error for invalid sig base64")
	}
}

// ---------------------------------------------------------------------------
// 33. DecodeJWTUnsafe — edge cases
// ---------------------------------------------------------------------------

func TestDecodeJWTUnsafeEdgeCases(t *testing.T) {
	// valid token without cid in header
	priv1, _ := refKey1()
	token, _ := CreateAuthToken("did:dfos:test", "aud", "key_1", 1*time.Hour, priv1)
	h, p, err := DecodeJWTUnsafe(token)
	if err != nil {
		t.Fatalf("DecodeJWTUnsafe: %v", err)
	}
	if h["alg"] != "EdDSA" {
		t.Fatalf("alg: %s", h["alg"])
	}
	if _, hasCID := h["cid"]; hasCID {
		t.Fatal("JWT auth token should not have cid in header map")
	}
	if p["iss"] != "did:dfos:test" {
		t.Fatalf("iss: %v", p["iss"])
	}

	// malformed token
	_, _, err = DecodeJWTUnsafe("bad-token")
	if err == nil {
		t.Fatal("expected error for malformed token")
	}
}

// ---------------------------------------------------------------------------
// 34. VerifyCredential — additional edge cases
// ---------------------------------------------------------------------------

func TestVerifyCredentialEdgeCases(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)

	// token with only 2 parts
	_, err := VerifyCredential("a.b", nil, "", "")
	if err == nil {
		t.Fatal("expected error for 2-part token")
	}

	// token with invalid base64 header
	_, err = VerifyCredential("!!!.valid.valid", nil, "", "")
	if err == nil {
		t.Fatal("expected error for invalid header")
	}

	// credential with kid that has no # (not a DID URL)
	iss := "did:dfos:test123"
	sub := "did:dfos:sub456"
	kidNoFragment := "did:dfos:test123" // missing #key_xxx
	token, _ := CreateCredential(iss, sub, kidNoFragment, "chain:x", "read", 1*time.Hour, priv)
	_, err = VerifyCredential(token, priv.Public().(ed25519.PublicKey), sub, "read")
	if err == nil {
		t.Fatal("expected error for kid without fragment")
	}

	// credential with kid DID not matching iss
	wrongKid := "did:dfos:other#key_1"
	token2, _ := CreateCredential(iss, sub, wrongKid, "chain:x", "read", 1*time.Hour, priv)
	_, err = VerifyCredential(token2, priv.Public().(ed25519.PublicKey), sub, "read")
	if err == nil {
		t.Fatal("expected error for kid DID mismatch")
	}
}

// ---------------------------------------------------------------------------
// 35. PayloadFromJWS — round-trip
// ---------------------------------------------------------------------------

func TestPayloadFromJWSRoundTrip(t *testing.T) {
	priv1, _ := refKey1()
	kid := "key_test"
	mk := NewMultikeyPublicKey(kid, priv1.Public().(ed25519.PublicKey))

	token, _, _, err := SignIdentityCreate(
		[]MultikeyPublicKey{mk}, []MultikeyPublicKey{mk}, nil, kid, priv1,
	)
	if err != nil {
		t.Fatal(err)
	}

	payload, err := PayloadFromJWS(token)
	if err != nil {
		t.Fatalf("PayloadFromJWS: %v", err)
	}
	if payload["type"] != "create" {
		t.Fatalf("type: %v", payload["type"])
	}

	// invalid base64 in payload part
	_, err = PayloadFromJWS("valid." + Base64urlEncodeString("not json") + ".sig")
	if err == nil {
		t.Fatal("expected error for invalid JSON payload")
	}
}
