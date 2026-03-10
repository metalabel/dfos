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
	genesisJWS       = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJjaWQiOiJiYWZ5cmVpYmFuanBnY3FmZmNmaHI0c3B0empmdGhoNXN6b2hoYm81dGpmdWxlbWt3N3VoZGVuNXVxeSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiYXV0aEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImFzc2VydEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImNvbnRyb2xsZXJLZXlzIjpbeyJpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa3J6TE1Od29KU1Y0UDNZY2NXY2J0azh2ZDlMdGdNS25MZWFETFVxTHVBU2piIn1dLCJjcmVhdGVkQXQiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.EDryDK1uvtix-17cHun9t6MacFIx2rMmMF1QLzfD5TFlSsOvMcue97pCgGn3CXeLVFtVxgpCoh0kGSXioKKzAw"
	rotationJWS       = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiNrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCIsImNpZCI6ImJhZnlyZWljeW00Y3lpZWRubGQ3M3NtYngzMnN6YWVpN3hkdWxxbjRnM3N0ZTVlMncydWxhanIzb3FtIn0.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoidXBkYXRlIiwicHJldmlvdXNPcGVyYXRpb25DSUQiOiJiYWZ5cmVpYmFuanBnY3FmZmNmaHI0c3B0empmdGhoNXN6b2hoYm81dGpmdWxlbWt3N3VoZGVuNXVxeSIsImF1dGhLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJhc3NlcnRLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJjb250cm9sbGVyS2V5cyI6W3siaWQiOiJrZXlfZXo5YTg3NHRja3IzZHY5MzNkM2NrZCIsInR5cGUiOiJNdWx0aWtleSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtmVWQ2NUpyQWhmZGdGdU1DY2NVOVRoUXZqQjJmSkFNVUhrdXVhakY5OTJnSyJ9XSwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowMTowMC4wMDBaIn0.MScuoBlgOK3j5QX9tFcw1ou0o4LgJziGJEsZ5pvqiBr1SagAyAv5h-wajQhtg8IP7dLlM0U4leW2iRra945cDg"
	contentCreateJWS  = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNvbnRlbnQtb3AiLCJraWQiOiJkaWQ6ZGZvczplM3Z2dGNrNDJkNGVhY2RuenZ0cm42I2tleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIiwiY2lkIjoiYmFmeXJlaWE1ejd6eGtuYWU1ZHM3MmV1aWh1ZjJyZzNpeGw2dDRmYnpqZWZoY29nZzNucXBweW9ncXUifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiZG9jdW1lbnRDSUQiOiJiYWZ5cmVpZnB2d3Vhcm1sNjJzZm9nZHBpMnZsbHR2ZzJldjZvNHh0dzc0emZ1ZDdjcGtnNzQyNnpuZSIsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDI6MDAuMDAwWiIsIm5vdGUiOm51bGx9.t_DDkJ_TmNekIGUFO22G-W78QoE4XTg9LKQ4gzAQHaK3B6491Tir9b-wtp-hcwmENu2Hqnieqv5ASiqfFrEbDw"
	jwtToken          = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIn0.eyJpc3MiOiJkZm9zIiwic3ViIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsImF1ZCI6ImRmb3MtYXBpIiwiZXhwIjoxNzcyOTAyODAwLCJpYXQiOjE3NzI4OTkyMDAsImp0aSI6InNlc3Npb25fcmVmX2V4YW1wbGVfMDEifQ.zhKeXJHHF7a1-MwF4QoUTRptCplAwh20-rLnuWGDFT6uJheN4E_SA5NhqvMNflLHxd7h97gdaVnMZGE67SXEBA"
	expectedGenCID    = "bafyreibanjpgcqffcfhr4sptzjfthh5szohhbo5tjfulemkw7uhden5uqy"
	expectedDID       = "did:dfos:e3vvtck42d4eacdnzvtrn6"
	expectedMultikey1 = "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb"
	expectedCBORHex   = "a66474797065666372656174656776657273696f6e0168617574684b65797381a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62696372656174656441747818323032362d30332d30375430303a30303a30302e3030305a6a6173736572744b65797381a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a626e636f6e74726f6c6c65724b65797381a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62"
	expectedCIDHex    = "01711220206a5e6140a5114f1e49f3ca4b339fb2cb8e70bbb34968b23156fd0e3237b486"
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
	result := make([]byte, 22)
	for i := 0; i < 22; i++ {
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
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		panic("invalid JWS format")
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	sig := b64urlDecode(parts[2])
	if !ed25519.Verify(pubKey, signingInput, sig) {
		panic("signature verification failed")
	}
	json.Unmarshal(b64urlDecode(parts[0]), &header)
	json.Unmarshal(b64urlDecode(parts[1]), &payload)
	return
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
	if suffix != "e3vvtck42d4eacdnzvtrn6" {
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
	if header["kid"] != "key_r9ev34fvc23z999veaaft8" {
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
	if header["kid"] != expectedDID+"#key_r9ev34fvc23z999veaaft8" {
		t.Fatalf("wrong kid: %s", header["kid"])
	}
	if header["cid"] != "bafyreicym4cyiednld73smbx32szaei7xdulqn4g3ste5e2w2ulajr3oqm" {
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
	if header["kid"] != expectedDID+"#key_ez9a874tckr3dv933d3ckd" {
		t.Fatal("wrong kid")
	}
	if header["cid"] != "bafyreia5z7zxknae5ds72euihuf2rg3ixl6t4fbzjefhcogg3nqppyogqu" {
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
