// DFOS Protocol — Independent verification in Go
//
// Verifies all deterministic reference artifacts from the TypeScript implementation.
// Uses only standard crypto + cbor + base58 libraries.
//
// Run: go test -v

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/mr-tron/base58"
)

// =============================================================================
// Constants from the reference doc
// =============================================================================

const (
	genesisJWS        = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJjaWQiOiJiYWZ5cmVpY29naHZqem52bGl1bG94eG1iZjU0dHB6cXdhaG5xcGlsazduY3hlcGppbmVkcGtnYTNuZSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiYXV0aEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImFzc2VydEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImNvbnRyb2xsZXJLZXlzIjpbeyJpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa3J6TE1Od29KU1Y0UDNZY2NXY2J0azh2ZDlMdGdNS25MZWFETFVxTHVBU2piIn1dLCJjcmVhdGVkQXQiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.TeznHnzrtKOGTr0FzkDL2z-luMWnAbKXrmDbi-Exgw_xMPCnYwGHORMjw-BM28f0RoTirIAeD7d20W5RSuGuBg"
	rotationJWS       = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciNrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0ODNubjI5enZoZSIsImNpZCI6ImJhZnlyZWliZnVoNjN1djMzaTJpNWVvb2UzYm9pdDJydXlqZWh1YnNyeWVtdXV6Nm1ydGxlajI2cmVpIn0.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoidXBkYXRlIiwicHJldmlvdXNPcGVyYXRpb25DSUQiOiJiYWZ5cmVpY29naHZqem52bGl1bG94eG1iZjU0dHB6cXdhaG5xcGlsazduY3hlcGppbmVkcGtnYTNuZSIsImF1dGhLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJhc3NlcnRLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJjb250cm9sbGVyS2V5cyI6W3siaWQiOiJrZXlfZXo5YTg3NHRja3IzZHY5MzNkM2NrZG43ejZ6cmN0OCIsInR5cGUiOiJNdWx0aWtleSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtmVWQ2NUpyQWhmZGdGdU1DY2NVOVRoUXZqQjJmSkFNVUhrdXVhakY5OTJnSyJ9XSwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowMTowMC4wMDBaIn0.7fqvWGEVYW9atA1uqpp7lIUOWp4dATLpLjOmFWzJN-8gTL-QnXDCeyGcBu5AXhHzO52fauwUavh1KrB6wBYuCw"
	contentCreateJWS  = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNvbnRlbnQtb3AiLCJraWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyI2tleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwiY2lkIjoiYmFmeXJlaWQyNmJhZ241Y2ZlZTN4cHRhZmptYmx4d3VkdzQzNXA2cms1ZzNwNGdqdGtudXlscnhzc3kifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiZGlkIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciIsImRvY3VtZW50Q0lEIjoiYmFmeXJlaWV2Y3FybXZ0ejJwaXM1dGRpenQ3c2pvdG9xcW9nbDZ2cnJxZ2E2NHcydG53a3Eycm51ZHkiLCJiYXNlRG9jdW1lbnRDSUQiOm51bGwsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDI6MDAuMDAwWiJ9.mTRCvPga89hVeu-gNowrL8TApoGJlxVQBw3CzrvEA-LxAQaSp03Uyn0JwdhPWh22UtwZTe2d27IIuJ7P-5PtAA"
	jwtToken          = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4In0.eyJpc3MiOiJkZm9zIiwic3ViIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciIsImF1ZCI6ImRmb3MtYXBpIiwiZXhwIjoxNzcyOTAyODAwLCJpYXQiOjE3NzI4OTkyMDAsImp0aSI6InNlc3Npb25fcmVmX2V4YW1wbGVfMDEifQ.VdrDMOQoFAboxK165ZDOe5YXTgILUDO_bHuGHinupqEd4dptibATmyI9YrjseMaJHS4gggzX1st9qO5eoVJdCQ"
	expectedGenCID    = "bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne"
	expectedDID       = "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr"
	expectedMultikey1 = "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb"
	expectedCBORHex   = "a66474797065666372656174656776657273696f6e0168617574684b65797381a362696478236b65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62696372656174656441747818323032362d30332d30375430303a30303a30302e3030305a6a6173736572744b65797381a362696478236b65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a626e636f6e74726f6c6c65724b65797381a362696478236b65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62"
	expectedCIDHex    = "017112204e31ea9cb6ab4516ebdd812f7937e61601db07a16afb45723d286906f5181b69"
)

const alphabet = "2346789acdefhknrtvz"

// =============================================================================
// Helpers
// =============================================================================

func b64urlDecode(s string) []byte {
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func encodeID(hashBytes []byte) string {
	result := make([]byte, 31)
	for i := 0; i < 31; i++ {
		result[i] = alphabet[hashBytes[i]%19]
	}
	return string(result)
}

func decodeMultikey(multibase string) []byte {
	if multibase[0] != 'z' {
		panic("expected base58btc prefix")
	}
	raw, err := base58.Decode(multibase[1:])
	if err != nil {
		panic(err)
	}
	if raw[0] != 0xed || raw[1] != 0x01 {
		panic("expected ed25519-pub multicodec prefix")
	}
	return raw[2:]
}

func encodeMultikey(pub []byte) string {
	raw := append([]byte{0xed, 0x01}, pub...)
	return "z" + base58.Encode(raw)
}

func makeCIDBytes(cborBytes []byte) []byte {
	digest := sha256.Sum256(cborBytes)
	cid := []byte{0x01, 0x71, 0x12, 0x20}
	return append(cid, digest[:]...)
}

func cidToBase32(cidBytes []byte) string {
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(cidBytes)
	return "b" + strings.ToLower(encoded)
}

func verifyJWS(token string, pubKey ed25519.PublicKey) (header, payload map[string]any) {
	h, p, err := verifyJWSProfiled(token, pubKey)
	if err != nil {
		panic(err)
	}
	return h, p
}

// ed25519L is the group order L, little-endian — the canonical S < L bound.
var ed25519L = []byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

// scalarIsCanonical reports whether the 32-byte little-endian scalar s is < L.
func scalarIsCanonical(s []byte) bool {
	if len(s) != 32 {
		return false
	}
	for i := 31; i >= 0; i-- {
		if s[i] < ed25519L[i] {
			return true
		}
		if s[i] > ed25519L[i] {
			return false
		}
	}
	return false // s == L is non-canonical
}

// verifyJWSProfiled applies the DFOS Signature Verification Profile (pragmatic
// v1) — alg pin, crit rejection, no header-key-trust, 64-byte signature, and
// canonical S < L — BEFORE the signature check, returning an error on any
// violation instead of panicking. Used by the reject corpus.
func verifyJWSProfiled(token string, pubKey ed25519.PublicKey) (header, payload map[string]any, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("invalid JWS format")
	}

	var h map[string]any
	if uErr := json.Unmarshal(b64urlDecode(parts[0]), &h); uErr != nil {
		return nil, nil, fmt.Errorf("decode header: %w", uErr)
	}

	// profile header gates, before any signature work
	if h["alg"] != "EdDSA" {
		return nil, nil, fmt.Errorf("unsupported algorithm: %v", h["alg"])
	}
	if _, present := h["crit"]; present {
		return nil, nil, fmt.Errorf("crit header is not supported")
	}
	if _, present := h["jwk"]; present {
		return nil, nil, fmt.Errorf("jwk header is not allowed")
	}
	if _, present := h["x5c"]; present {
		return nil, nil, fmt.Errorf("x5c header is not allowed")
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	sig := b64urlDecode(parts[2])

	// length + canonical-scalar gates
	if len(sig) != 64 {
		return nil, nil, fmt.Errorf("signature must be 64 bytes, got %d", len(sig))
	}
	if !scalarIsCanonical(sig[32:64]) {
		return nil, nil, fmt.Errorf("non-canonical signature scalar (S >= L)")
	}

	if !ed25519.Verify(pubKey, signingInput, sig) {
		return nil, nil, fmt.Errorf("signature verification failed")
	}

	var p map[string]any
	json.Unmarshal(b64urlDecode(parts[1]), &p)
	return h, p, nil
}

// dagCborEncode encodes a value in dag-cbor canonical form.
// dag-cbor sorts map keys by encoded byte length first, then lexicographic.
func dagCborEncode(v any) []byte {
	// Use cbor library with canonical map key sorting matching dag-cbor
	em, _ := cbor.CanonicalEncOptions().EncMode()
	b, err := em.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// dagCborEncodeJSON encodes a JSON-like map preserving dag-cbor canonical key ordering.
// We need to manually sort keys by their CBOR-encoded byte length (dag-cbor rule).
func dagCborEncodeJSON(data map[string]any) []byte {
	// dag-cbor uses length-first sorting: shorter keys before longer, then lexicographic
	type kv struct {
		key string
		val any
	}
	var pairs []kv
	for k, v := range data {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if len(pairs[i].key) != len(pairs[j].key) {
			return len(pairs[i].key) < len(pairs[j].key)
		}
		return pairs[i].key < pairs[j].key
	})

	// Encode manually using cbor library with correct ordering
	em, _ := cbor.CoreDetEncOptions().EncMode()
	b, err := em.Marshal(data)
	if err != nil {
		panic(fmt.Sprintf("cbor encode failed: %v", err))
	}
	return b
}

// =============================================================================
// Tests
// =============================================================================

func TestKeyDerivation(t *testing.T) {
	seed1 := sha256.Sum256([]byte("dfos-protocol-reference-key-1"))
	priv1 := ed25519.NewKeyFromSeed(seed1[:])
	pub1 := priv1.Public().(ed25519.PublicKey)

	if fmt.Sprintf("%x", seed1[:]) != "132d4bebdb6e62359afb930fe15d756a92ad96e6b0d47619988f5a1a55272aac" {
		t.Fatal("Key 1 seed mismatch")
	}
	if fmt.Sprintf("%x", []byte(pub1)) != "ba421e272fad4f941c221e47f87d9253bdc04f7d4ad2625ae667ab9f0688ce32" {
		t.Fatal("Key 1 public mismatch")
	}

	seed2 := sha256.Sum256([]byte("dfos-protocol-reference-key-2"))
	priv2 := ed25519.NewKeyFromSeed(seed2[:])
	pub2 := priv2.Public().(ed25519.PublicKey)

	if fmt.Sprintf("%x", seed2[:]) != "384f5626906db84f6a773ec46475ff2d4458e92dd4dd13fe03dbb7510f4ca2a8" {
		t.Fatal("Key 2 seed mismatch")
	}
	if fmt.Sprintf("%x", []byte(pub2)) != "0f350f994f94d675f04a325bd316ebedd740ca206eaaf609bdb641b5faa0f78c" {
		t.Fatal("Key 2 public mismatch")
	}
}

func TestMultikeyEncoding(t *testing.T) {
	seed1 := sha256.Sum256([]byte("dfos-protocol-reference-key-1"))
	pub1 := ed25519.NewKeyFromSeed(seed1[:]).Public().(ed25519.PublicKey)

	encoded := encodeMultikey(pub1)
	if encoded != expectedMultikey1 {
		t.Fatalf("multikey encode: got %s, want %s", encoded, expectedMultikey1)
	}

	decoded := decodeMultikey(expectedMultikey1)
	if !bytes.Equal(decoded, pub1) {
		t.Fatal("multikey decode mismatch")
	}
}

func TestDagCborEncoding(t *testing.T) {
	// Build the genesis payload as a map matching the reference
	key := map[string]any{
		"id":                 "key_r9ev34fvc23z999veaaft83nn29zvhe",
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

	cborBytes := dagCborEncodeJSON(payload)
	got := fmt.Sprintf("%x", cborBytes)
	if got != expectedCBORHex {
		t.Fatalf("CBOR mismatch\ngot:  %s...\nwant: %s...", got[:60], expectedCBORHex[:60])
	}
}

func TestCIDDerivation(t *testing.T) {
	cborBytes, _ := hexDecode(expectedCBORHex)
	cidBytes := makeCIDBytes(cborBytes)
	got := fmt.Sprintf("%x", cidBytes)
	if got != expectedCIDHex {
		t.Fatalf("CID bytes mismatch: got %s", got)
	}

	cidStr := cidToBase32(cidBytes)
	if cidStr != expectedGenCID {
		t.Fatalf("CID string mismatch: got %s, want %s", cidStr, expectedGenCID)
	}
}

func TestDIDDerivation(t *testing.T) {
	cidBytes, _ := hexDecode(expectedCIDHex)
	didHash := sha256.Sum256(cidBytes)
	suffix := encodeID(didHash[:])
	if suffix != "cnnnft9f8a2rn938d6nkz38r847v2kr" {
		t.Fatalf("DID suffix mismatch: got %s", suffix)
	}
	did := "did:dfos:" + suffix
	if did != expectedDID {
		t.Fatalf("DID mismatch: got %s", did)
	}
}

func TestJWSGenesisVerification(t *testing.T) {
	seed1 := sha256.Sum256([]byte("dfos-protocol-reference-key-1"))
	pub1 := ed25519.NewKeyFromSeed(seed1[:]).Public().(ed25519.PublicKey)

	header, payload := verifyJWS(genesisJWS, pub1)
	if header["alg"] != "EdDSA" {
		t.Fatal("wrong alg")
	}
	if header["typ"] != "did:dfos:identity-op" {
		t.Fatal("wrong typ")
	}
	if header["kid"] != "key_r9ev34fvc23z999veaaft83nn29zvhe" {
		t.Fatal("wrong kid")
	}
	if header["cid"] != expectedGenCID {
		t.Fatalf("wrong cid: %s", header["cid"])
	}
	if payload["type"] != "create" {
		t.Fatal("wrong payload type")
	}
}

func TestJWSRotationVerification(t *testing.T) {
	seed1 := sha256.Sum256([]byte("dfos-protocol-reference-key-1"))
	pub1 := ed25519.NewKeyFromSeed(seed1[:]).Public().(ed25519.PublicKey)

	header, payload := verifyJWS(rotationJWS, pub1)
	if header["kid"] != expectedDID+"#key_r9ev34fvc23z999veaaft83nn29zvhe" {
		t.Fatalf("wrong kid: %s", header["kid"])
	}
	if header["cid"] != "bafyreibfuh63uv33i2i5eooe3boit2ruyjehubsryemuuz6mrtlej26rei" {
		t.Fatalf("wrong cid: %s", header["cid"])
	}
	if payload["type"] != "update" {
		t.Fatal("wrong type")
	}
}

func TestJWSContentCreateVerification(t *testing.T) {
	seed2 := sha256.Sum256([]byte("dfos-protocol-reference-key-2"))
	pub2 := ed25519.NewKeyFromSeed(seed2[:]).Public().(ed25519.PublicKey)

	header, _ := verifyJWS(contentCreateJWS, pub2)
	if header["typ"] != "did:dfos:content-op" {
		t.Fatal("wrong typ")
	}
	if header["kid"] != expectedDID+"#key_ez9a874tckr3dv933d3ckdn7z6zrct8" {
		t.Fatal("wrong kid")
	}
	if header["cid"] != "bafyreid26bagn5cfee3xptafjmblxwudw435p6rk5g3p4gjtknuylrxssy" {
		t.Fatalf("wrong cid: %s", header["cid"])
	}
}

func TestJWTVerification(t *testing.T) {
	seed2 := sha256.Sum256([]byte("dfos-protocol-reference-key-2"))
	pub2 := ed25519.NewKeyFromSeed(seed2[:]).Public().(ed25519.PublicKey)

	header, payload := verifyJWS(jwtToken, pub2)
	if header["alg"] != "EdDSA" {
		t.Fatal("wrong alg")
	}
	if payload["sub"] != expectedDID {
		t.Fatal("wrong sub")
	}
	if payload["iss"] != "dfos" {
		t.Fatal("wrong iss")
	}
}

func hexDecode(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		fmt.Sscanf(s[i:i+2], "%02x", &b[i/2])
	}
	return b, nil
}

// =============================================================================
// Services-genesis and credential tests
// =============================================================================

const (
	// servicesGenesisJWS is the canonical services-genesis identity-op: a create
	// op carrying a full-state services array (relay locator + content/artifact
	// anchors). Signed by reference key 1. Sourced from
	// packages/dfos-protocol/examples/identity-services.json chain[0].
	servicesGenesisJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJjaWQiOiJiYWZ5cmVpZGkzcXBzM3F0dHFwMjJtM3kzM2JkYmYyaXlrYnE1cjQ1ampod2EzN21nZXNvdjdzZGd6ZSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiYXV0aEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImFzc2VydEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImNvbnRyb2xsZXJLZXlzIjpbeyJpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa3J6TE1Od29KU1Y0UDNZY2NXY2J0azh2ZDlMdGdNS25MZWFETFVxTHVBU2piIn1dLCJzZXJ2aWNlcyI6W3siaWQiOiJyZWxheSIsInR5cGUiOiJEZm9zUmVsYXkiLCJlbmRwb2ludCI6Imh0dHBzOi8vcmVsYXkuZGZvcy5jb20ifSx7ImlkIjoicHJvZmlsZSIsInR5cGUiOiJDb250ZW50QW5jaG9yIiwibGFiZWwiOiJwcm9maWxlIiwiYW5jaG9yIjoiY3Y3bjh2a3ZyNjRjY3RmMzI5NGg5azRlYW5oZmY4eiJ9LHsiaWQiOiJhdmF0YXIiLCJ0eXBlIjoiQ29udGVudEFuY2hvciIsImxhYmVsIjoiYXZhdGFyIiwiYW5jaG9yIjoiYmFmeXJlaWV2Y3FybXZ0ejJwaXM1dGRpenQ3c2pvdG9xcW9nbDZ2cnJxZ2E2NHcydG53a3Eycm51ZHkifV0sImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDU6MDAuMDAwWiJ9.HCzVJXcUzL62lxtC8omBlit1JNSWk4b4kQKjjjWT00honzZ9-k3dKusIRuhTV6gjT1M74bLVZYUxPb8kJvhHAw"
	expectedServicesGenCID = "bafyreidi3qps3qttqp22m3y33bdbf2iykbq5r45jjhwa37mgesov7sdgze"
	expectedServicesDID    = "did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar"
	broadWriteVC           = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNyZWRlbnRpYWwiLCJraWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyI2tleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwiY2lkIjoiYmFmeXJlaWZ5aW5ieGhicml0NTZtM2FhdjY2bXc0eGQ2YWRxamFzdmNmaG11NjZnNnRudXFncnljbG0ifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiREZPU0NyZWRlbnRpYWwiLCJpc3MiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyIiwiYXVkIjoiZGlkOmRmb3M6OTRhaDc5NjNuMjIzazhjOTg4NGhoMjdla2g0Mm5lYSIsImF0dCI6W3sicmVzb3VyY2UiOiJjaGFpbjoqIiwiYWN0aW9uIjoid3JpdGUifV0sInByZiI6W10sImV4cCI6MTc5ODc2MTYwMCwiaWF0IjoxNzcyODQxNjAwfQ.A-EygURAN2bALVwI2AZKFEuy30ZnWJFBaD4jCTf1d7A90rYELStjTWJ1iI7OulihTCfaVtlvj5HtX6Dwv1VxAg"
	readVC            = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNyZWRlbnRpYWwiLCJraWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyI2tleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwiY2lkIjoiYmFmeXJlaWN0aGNiaXp4dmdlbXN4djdrc2NvbzdhcGllYWFsM2Z5ZTM3bzQ1Zmt5a25lN2I0aG9icmEifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiREZPU0NyZWRlbnRpYWwiLCJpc3MiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyIiwiYXVkIjoiZGlkOmRmb3M6OTRhaDc5NjNuMjIzazhjOTg4NGhoMjdla2g0Mm5lYSIsImF0dCI6W3sicmVzb3VyY2UiOiJjaGFpbjoqIiwiYWN0aW9uIjoicmVhZCJ9XSwicHJmIjpbXSwiZXhwIjoxNzk4NzYxNjAwLCJpYXQiOjE3NzI4NDE2MDB9.UvTItuWFriA39FZIdB5TuXa_b07eyNLc-iR0cej2litSkjBYAZaLlDJUmyDQ-3dB7TmNVXDbB3SMbpvLnWW9Dw"
)

// normalizeNumbers recursively converts whole float64 values (as produced by
// json.Unmarshal) to int64 so the canonical CBOR encoding uses integer major
// types. Matches the production number-normalization step before CID derivation.
func normalizeNumbers(v any) any {
	switch val := v.(type) {
	case map[string]any:
		for k, vv := range val {
			val[k] = normalizeNumbers(vv)
		}
		return val
	case []any:
		for i, vv := range val {
			val[i] = normalizeNumbers(vv)
		}
		return val
	case float64:
		if val == float64(int64(val)) {
			return int64(val)
		}
		return val
	default:
		return val
	}
}

// TestServicesGenesisVerification verifies the canonical services-genesis
// identity-op: signature check with reference key 1, then an independent
// recomputation of the operation CID over the decoded payload (services fields
// ride along in the payload map — no services-validation logic required here),
// asserting it equals the JWS header cid and that the derived DID matches.
func TestServicesGenesisVerification(t *testing.T) {
	seed1 := sha256.Sum256([]byte("dfos-protocol-reference-key-1"))
	pub1 := ed25519.NewKeyFromSeed(seed1[:]).Public().(ed25519.PublicKey)

	header, payload := verifyJWS(servicesGenesisJWS, pub1)
	if header["typ"] != "did:dfos:identity-op" {
		t.Fatalf("wrong typ: %s", header["typ"])
	}
	if header["kid"] != "key_r9ev34fvc23z999veaaft83nn29zvhe" {
		t.Fatalf("wrong kid: %s", header["kid"])
	}
	if header["cid"] != expectedServicesGenCID {
		t.Fatalf("wrong cid: %s", header["cid"])
	}
	if payload["type"] != "create" {
		t.Fatalf("wrong payload type: %s", payload["type"])
	}

	// Recompute the operation CID over the decoded payload and assert it matches
	// the value committed in the JWS header.
	normalizeNumbers(payload)
	cborBytes := dagCborEncodeJSON(payload)
	cidStr := cidToBase32(makeCIDBytes(cborBytes))
	if cidStr != expectedServicesGenCID {
		t.Fatalf("recomputed CID mismatch: got %s, want %s", cidStr, expectedServicesGenCID)
	}

	// Derive the DID from the operation CID bytes and assert it matches.
	cidBytes := makeCIDBytes(cborBytes)
	didHash := sha256.Sum256(cidBytes)
	did := "did:dfos:" + encodeID(didHash[:])
	if did != expectedServicesDID {
		t.Fatalf("DID mismatch: got %s, want %s", did, expectedServicesDID)
	}
}

func TestWriteCredentialVerification(t *testing.T) {
	seed1 := sha256.Sum256([]byte("dfos-protocol-reference-key-1"))
	pub1 := ed25519.NewKeyFromSeed(seed1[:]).Public().(ed25519.PublicKey)

	header, payload := verifyJWS(broadWriteVC, pub1)
	if header["typ"] != "did:dfos:credential" {
		t.Fatalf("wrong typ: %s", header["typ"])
	}
	if header["kid"] != expectedDID+"#key_r9ev34fvc23z999veaaft83nn29zvhe" {
		t.Fatalf("wrong kid: %s", header["kid"])
	}
	if payload["type"] != "DFOSCredential" {
		t.Fatalf("wrong type: %s", payload["type"])
	}
	if payload["iss"] != expectedDID {
		t.Fatalf("wrong iss: %s", payload["iss"])
	}
	if payload["aud"] != "did:dfos:94ah7963n223k8c9884hh27ekh42nea" {
		t.Fatalf("wrong aud: %s", payload["aud"])
	}
	att := payload["att"].([]any)
	attEntry := att[0].(map[string]any)
	if attEntry["resource"] != "chain:*" {
		t.Fatalf("wrong att resource: %s", attEntry["resource"])
	}
	if attEntry["action"] != "write" {
		t.Fatalf("wrong att action: %s", attEntry["action"])
	}
}

func TestReadCredentialVerification(t *testing.T) {
	seed1 := sha256.Sum256([]byte("dfos-protocol-reference-key-1"))
	pub1 := ed25519.NewKeyFromSeed(seed1[:]).Public().(ed25519.PublicKey)

	header, payload := verifyJWS(readVC, pub1)
	if header["typ"] != "did:dfos:credential" {
		t.Fatalf("wrong typ: %s", header["typ"])
	}
	if header["kid"] != expectedDID+"#key_r9ev34fvc23z999veaaft83nn29zvhe" {
		t.Fatalf("wrong kid: %s", header["kid"])
	}
	if payload["type"] != "DFOSCredential" {
		t.Fatalf("wrong type: %s", payload["type"])
	}
	if payload["iss"] != expectedDID {
		t.Fatalf("wrong iss: %s", payload["iss"])
	}
	if payload["aud"] != "did:dfos:94ah7963n223k8c9884hh27ekh42nea" {
		t.Fatalf("wrong aud: %s", payload["aud"])
	}
	att := payload["att"].([]any)
	attEntry := att[0].(map[string]any)
	if attEntry["resource"] != "chain:*" {
		t.Fatalf("wrong att resource: %s", attEntry["resource"])
	}
	if attEntry["action"] != "read" {
		t.Fatalf("wrong att action: %s", attEntry["action"])
	}
}

// =============================================================================
// Number encoding determinism tests
// =============================================================================

const (
	// Test vector: {"version": 1, "type": "test"} with integer encoding
	numberTestCBOR = "a2647479706564746573746776657273696f6e01"
	numberTestCID  = "bafyreihp6omsp6icc6ee63ox2ovsaxm6s7ikd2a7k5eh2qz2qd5soh5bsa"
	// Wrong CID that would result from float encoding of version: 1.0
	numberTestWrongCID = "bafyreiawbms4476m5jlrmqtyvtwe5ta3eo2bh7mdprtomfgfype7j57o4q"
)

func TestNumberEncodingDeterminism(t *testing.T) {
	// Encode with explicit integer type — this should always be correct
	em, _ := cbor.CoreDetEncOptions().EncMode()
	payload := map[string]any{"version": int64(1), "type": "test"}
	cborBytes, err := em.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	got := fmt.Sprintf("%x", cborBytes)
	if got != numberTestCBOR {
		t.Fatalf("CBOR mismatch:\n  got:  %s\n  want: %s", got, numberTestCBOR)
	}

	cidBytes := makeCIDBytes(cborBytes)
	cidStr := cidToBase32(cidBytes)
	if cidStr != numberTestCID {
		t.Fatalf("CID mismatch: got %s, want %s", cidStr, numberTestCID)
	}
}

func TestNumberEncodingFromJSON(t *testing.T) {
	// Simulate the JSON round-trip that catches the float64 trap:
	// JSON decode → map[string]any → CBOR encode → CID
	// In Go, json.Unmarshal decodes 1 as float64(1), not int(1).
	// Implementations MUST normalize before CBOR encoding.
	jsonInput := `{"version": 1, "type": "test"}`
	var decoded map[string]any
	if err := json.Unmarshal([]byte(jsonInput), &decoded); err != nil {
		t.Fatal(err)
	}

	// Before normalization: version is float64
	if _, isFloat := decoded["version"].(float64); !isFloat {
		t.Log("Note: this language does not decode JSON integers as float64 — normalization may not be needed")
	}

	// Normalize: convert whole float64s to int64
	for k, v := range decoded {
		if f, ok := v.(float64); ok && f == float64(int64(f)) {
			decoded[k] = int64(f)
		}
	}

	em, _ := cbor.CoreDetEncOptions().EncMode()
	cborBytes, err := em.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}

	cidBytes := makeCIDBytes(cborBytes)
	cidStr := cidToBase32(cidBytes)
	if cidStr != numberTestCID {
		t.Fatalf("CID after JSON round-trip: got %s, want %s (did you normalize float64 → int64?)", cidStr, numberTestCID)
	}

	// Verify we did NOT get the wrong (float) CID
	if cidStr == numberTestWrongCID {
		t.Fatal("CID matches the WRONG float-encoding CID — number normalization is broken")
	}
}

func TestNumberEncodingFloatProducesWrongCID(t *testing.T) {
	// Explicitly verify that float encoding produces the known-wrong CID.
	// This confirms our test vector is correct and the trap is real.
	em, _ := cbor.CoreDetEncOptions().EncMode()
	payload := map[string]any{"version": float64(1.0), "type": "test"}
	cborBytes, err := em.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	cidBytes := makeCIDBytes(cborBytes)
	cidStr := cidToBase32(cidBytes)
	if cidStr != numberTestWrongCID {
		t.Fatalf("Float CID mismatch: got %s, want %s", cidStr, numberTestWrongCID)
	}
	if cidStr == numberTestCID {
		t.Fatal("Float encoding should NOT produce the correct CID")
	}
}

// =============================================================================
// Reject corpus — every conformant verifier MUST reject all of these.
// Byte-identical inputs across all five language suites.
// =============================================================================

const rejectPub1Hex = "ba421e272fad4f941c221e47f87d9253bdc04f7d4ad2625ae667ab9f0688ce32"

var rejectVectors = map[string]string{
	"RV-LEN-SHORT":        "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2",
	"RV-LEN-LONG":         "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQA",
	"RV-S-NONCANON-PLUSL": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAFq4vaNrS7wPMIBVCWm3qp0JC5obhbU0QOP589IkS2GQ",
	"RV-S-NONCANON-FF":    "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAD__________________________________________w",
	"RV-ALG-NONE":         "eyJhbGciOiJub25lIiwidHlwIjoiZGlkOmRmb3M6cmVqZWN0LXZlY3RvciIsImtpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4In0.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ",
	"RV-ALG-CASE":         "eyJhbGciOiJlZGRzYSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ",
	"RV-CRIT-PRESENT":     "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCIsImNyaXQiOlsiZXhwIl19.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ",
	"RV-HEADER-KEY-TRUST": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkFBQUEifX0.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ",
	"RV-SIG-BITFLIP":      "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CA",
}

func TestRejectCorpus(t *testing.T) {
	pub := ed25519.PublicKey(mustHex(rejectPub1Hex))
	for name, token := range rejectVectors {
		if _, _, err := verifyJWSProfiled(token, pub); err == nil {
			t.Errorf("%s: expected rejection, got accept", name)
		}
	}
}

func mustHex(s string) []byte {
	b, _ := hexDecode(s)
	return b
}

// =============================================================================
// WP-0 number-policy vectors. CIDs are byte-identical across all five suites.
// =============================================================================

const maxSafeCanonicalInteger = 9007199254740991 // 2^53 - 1

// assertCanonicalNumbers rejects NaN, ±Inf, non-integers, and integers outside
// ±(2^53-1). Mirrors the production AssertCanonicalNumbers.
func assertCanonicalNumbers(v any) error {
	switch val := v.(type) {
	case map[string]any:
		for _, vv := range val {
			if err := assertCanonicalNumbers(vv); err != nil {
				return err
			}
		}
	case []any:
		for _, vv := range val {
			if err := assertCanonicalNumbers(vv); err != nil {
				return err
			}
		}
	case float64:
		if math.IsNaN(val) || math.IsInf(val, 0) {
			return fmt.Errorf("non-finite")
		}
		if val != math.Trunc(val) {
			return fmt.Errorf("non-integer")
		}
		if val > maxSafeCanonicalInteger || val < -maxSafeCanonicalInteger {
			return fmt.Errorf("out of safe range")
		}
	case int64:
		if val > maxSafeCanonicalInteger || val < -maxSafeCanonicalInteger {
			return fmt.Errorf("out of safe range")
		}
	}
	return nil
}

func numberCID(v any) (string, error) {
	if err := assertCanonicalNumbers(v); err != nil {
		return "", err
	}
	em, _ := cbor.CoreDetEncOptions().EncMode()
	cborBytes, err := em.Marshal(v)
	if err != nil {
		return "", err
	}
	return cidToBase32(makeCIDBytes(cborBytes)), nil
}

func TestNumberPolicyAcceptMaxSafe(t *testing.T) {
	cid, err := numberCID(map[string]any{"n": int64(maxSafeCanonicalInteger)})
	if err != nil {
		t.Fatalf("2^53-1 must be accepted: %v", err)
	}
	if cid != "bafyreieak45zq2337oaadtvk2vwtdqfvfg26hd7olnf275qiv5hrh3vywq" {
		t.Fatalf("max-safe CID mismatch: got %s", cid)
	}
}

func TestNumberPolicyRejects(t *testing.T) {
	rejects := map[string]any{
		"2^53": float64(9007199254740992),
		"1.5":  float64(1.5),
		"NaN":  math.NaN(),
		"+Inf": math.Inf(1),
		"-Inf": math.Inf(-1),
	}
	for name, bad := range rejects {
		if _, err := numberCID(map[string]any{"x": bad}); err == nil {
			t.Errorf("%s: expected rejection, got accept", name)
		}
	}
}

func TestNumberPolicyNullVector(t *testing.T) {
	nullVec := map[string]any{"documentCID": nil, "note": nil, "prf": []any{}}
	cid, err := numberCID(nullVec)
	if err != nil {
		t.Fatalf("null vector must encode: %v", err)
	}
	if cid != "bafyreign22f4jiww2ywlssx7r2l76z32suj5ufvwl354hsp4xrm26cw7ue" {
		t.Fatalf("null vector CID mismatch: got %s", cid)
	}
}
