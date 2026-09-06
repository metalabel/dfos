// DFOS Protocol — Independent verification in Go
//
// Verifies all deterministic reference artifacts from the protocol specification.
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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/mr-tron/base58"
)

// =============================================================================
// Shared reference vectors
// =============================================================================
//
// Every expected value below is read from ../vectors.json — the one artifact
// all five suites share, generated from the protocol's fixed seeds by
// packages/dfos-protocol/tests/protocol-reference.spec.ts, which asserts the
// checked-in file is byte-identical to a fresh generation.
//
// Reading a JSON fixture is not a library import. This suite still uses only
// the language's native Ed25519, CBOR and SHA-256, and a third party can run it
// with nothing but this file and vectors.json.

type vectorEntry struct {
	ID          string         `json:"id"`
	Description string         `json:"description"`
	Values      map[string]any `json:"values"`
}

var vectorsByID = loadVectors()

func loadVectors() map[string]map[string]any {
	raw, err := os.ReadFile(filepath.Join("..", "vectors.json"))
	if err != nil {
		panic(fmt.Sprintf("read vectors.json: %v", err))
	}
	var file struct {
		Vectors []vectorEntry `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		panic(fmt.Sprintf("parse vectors.json: %v", err))
	}
	byID := make(map[string]map[string]any, len(file.Vectors))
	for _, v := range file.Vectors {
		byID[v.ID] = v.Values
	}
	return byID
}

// vecAny returns one field of one vector.
func vecAny(id, field string) any {
	values, ok := vectorsByID[id]
	if !ok {
		panic(fmt.Sprintf("vectors.json has no vector %q", id))
	}
	value, ok := values[field]
	if !ok {
		panic(fmt.Sprintf("vectors.json %s has no field %s", id, field))
	}
	return value
}

// vec returns one string field of one vector.
func vec(id, field string) string {
	s, ok := vecAny(id, field).(string)
	if !ok {
		panic(fmt.Sprintf("vectors.json %s.%s is not a string", id, field))
	}
	return s
}

// vecMap returns one object field of one vector with JSON numbers normalized to
// integers, so a dag-cbor re-encode uses integer major types.
func vecMap(id, field string) map[string]any {
	m, ok := vecAny(id, field).(map[string]any)
	if !ok {
		panic(fmt.Sprintf("vectors.json %s.%s is not an object", id, field))
	}
	return normalizeNumbers(m).(map[string]any)
}

// vecStringMap returns one string→string map field of one vector.
func vecStringMap(id, field string) map[string]string {
	m, ok := vecAny(id, field).(map[string]any)
	if !ok {
		panic(fmt.Sprintf("vectors.json %s.%s is not an object", id, field))
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			panic(fmt.Sprintf("vectors.json %s.%s.%s is not a string", id, field, k))
		}
		out[k] = s
	}
	return out
}

// vecStrings returns one string-array field of one vector.
func vecStrings(id, field string) []string {
	arr, ok := vecAny(id, field).([]any)
	if !ok {
		panic(fmt.Sprintf("vectors.json %s.%s is not an array", id, field))
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		s, ok := v.(string)
		if !ok {
			panic(fmt.Sprintf("vectors.json %s.%s is not a string array", id, field))
		}
		out = append(out, s)
	}
	return out
}

// =============================================================================
// Constants from the reference doc
// =============================================================================

var (
	expectedGenCID    = vec("identity-genesis", "cid")
	expectedDID       = vec("identity-genesis", "did")
	expectedMultikey1 = vec("key-1", "multikey")
	expectedMultikey2 = vec("key-2", "multikey")

	genesisJWS       = vec("identity-genesis", "jws")
	rotationJWS      = vec("identity-rotation", "jws")
	deleteJWS        = vec("identity-delete", "jws")
	restoreJWS       = vec("identity-restore", "jws")
	contentCreateJWS = vec("content-create", "jws")
	jwtToken         = vec("jwt", "token")

	// The possession proof the rotation carries. The envelope's payload is
	// CLOSED: exactly seven members, in exactly one order — and the octets are
	// the only serialization those members are ever signed as. The envelope is
	// signed by key 2 (the key being introduced) while the operation carrying it
	// is signed by key 1.
	keyProofRoleSet          = vec("key-proof", "roleSet")
	keyProofCanonicalPayload = vec("key-proof", "canonicalPayload")

	expectedCBORHex = vec("identity-genesis", "cborHex")
	expectedCIDHex  = vec("identity-genesis", "cidBytesHex")
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

	if fmt.Sprintf("%x", seed1[:]) != vec("key-1", "privateKeyHex") {
		t.Fatal("Key 1 seed mismatch")
	}
	if fmt.Sprintf("%x", []byte(pub1)) != vec("key-1", "publicKeyHex") {
		t.Fatal("Key 1 public mismatch")
	}

	seed2 := sha256.Sum256([]byte("dfos-protocol-reference-key-2"))
	priv2 := ed25519.NewKeyFromSeed(seed2[:])
	pub2 := priv2.Public().(ed25519.PublicKey)

	if fmt.Sprintf("%x", seed2[:]) != vec("key-2", "privateKeyHex") {
		t.Fatal("Key 2 seed mismatch")
	}
	if fmt.Sprintf("%x", []byte(pub2)) != vec("key-2", "publicKeyHex") {
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
	// The genesis payload is the shared vector, not a local transcription.
	cborBytes := dagCborEncodeJSON(vecMap("identity-genesis", "payload"))
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
	did := "did:dfos:" + encodeID(didHash[:])
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
	if header["kid"] != vec("identity-genesis", "kid") {
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
	if header["kid"] != vec("identity-rotation", "kid") {
		t.Fatalf("wrong kid: %s", header["kid"])
	}
	if header["cid"] != vec("identity-rotation", "cid") {
		t.Fatalf("wrong cid: %s", header["cid"])
	}
	if payload["type"] != "update" {
		t.Fatal("wrong type")
	}
}

// keyProofMembers is the canonical member order — the ONLY order these bytes are
// ever emitted in.
var keyProofMembers = vecStrings("key-proof", "members")

// TestKeyProofCarriedByRotation verifies the possession proof embedded in the
// rotation operation. The OPERATION is signed by key 1; the envelope inside it
// is signed by key 2 — the key being introduced — against the key named in the
// envelope's own payload. That circularity is the possession proof. The payload
// is closed: exactly seven members, one order, one serialization.
func TestKeyProofCarriedByRotation(t *testing.T) {
	seed1 := sha256.Sum256([]byte("dfos-protocol-reference-key-1"))
	pub1 := ed25519.NewKeyFromSeed(seed1[:]).Public().(ed25519.PublicKey)
	seed2 := sha256.Sum256([]byte("dfos-protocol-reference-key-2"))
	pub2 := ed25519.NewKeyFromSeed(seed2[:]).Public().(ed25519.PublicKey)

	_, payload := verifyJWS(rotationJWS, pub1)
	proofs, ok := payload["keyProofs"].([]any)
	if !ok || len(proofs) != 1 {
		t.Fatalf("rotation must carry exactly one key proof, got %+v", payload["keyProofs"])
	}
	envelope, ok := proofs[0].(string)
	if !ok {
		t.Fatal("key proof must be a compact JWS string")
	}

	parts := strings.Split(envelope, ".")
	if len(parts) != 3 {
		t.Fatalf("key proof must have three parts, got %d", len(parts))
	}

	headerText := string(b64urlDecode(parts[0]))
	payloadText := string(b64urlDecode(parts[1]))

	var header map[string]any
	if err := json.Unmarshal([]byte(headerText), &header); err != nil {
		t.Fatalf("decode key proof header: %v", err)
	}
	if header["alg"] != "EdDSA" {
		t.Fatalf("wrong key proof alg: %v", header["alg"])
	}
	if header["typ"] != "did:dfos:key-add" {
		t.Fatalf("wrong key proof typ: %v", header["typ"])
	}
	if len(header) != 2 {
		t.Fatalf("key proof header must be exactly {alg, typ}, got %d members", len(header))
	}

	// The load-bearing check: the presented octets ARE the canonical
	// serialization. Same property the rest of this family asserts — the bytes
	// bind the verifier, not only the signer.
	if payloadText != keyProofCanonicalPayload {
		t.Fatalf("key proof payload is not the canonical serialization\ngot:  %s\nwant: %s", payloadText, keyProofCanonicalPayload)
	}

	var proof map[string]any
	if err := json.Unmarshal([]byte(payloadText), &proof); err != nil {
		t.Fatalf("decode key proof payload: %v", err)
	}
	if len(proof) != 7 {
		t.Fatalf("key proof payload must have exactly 7 members, got %d", len(proof))
	}

	cursor := -1
	for _, member := range keyProofMembers {
		at := strings.Index(payloadText, `"`+member+`":`)
		if at <= cursor {
			t.Fatalf("key proof member %q is out of canonical order", member)
		}
		cursor = at
	}

	if proof["did"] != expectedDID {
		t.Fatalf("wrong key proof did: %v", proof["did"])
	}
	if proof["prevCID"] != expectedGenCID {
		t.Fatalf("wrong key proof prevCID: %v", proof["prevCID"])
	}
	if proof["roleSet"] != keyProofRoleSet {
		t.Fatalf("wrong key proof roleSet: %v", proof["roleSet"])
	}
	if proof["publicKeyMultibase"] != expectedMultikey2 {
		t.Fatalf("wrong key proof publicKeyMultibase: %v", proof["publicKeyMultibase"])
	}

	// The signature verifies against the key the payload itself names — there is
	// no resolver seam here.
	proofPub := decodeMultikey(proof["publicKeyMultibase"].(string))
	if !bytes.Equal(proofPub, pub2) {
		t.Fatal("key proof key is not reference key 2")
	}
	sig := b64urlDecode(parts[2])
	if len(sig) != 64 {
		t.Fatalf("key proof signature must be 64 bytes, got %d", len(sig))
	}
	if !scalarIsCanonical(sig[32:64]) {
		t.Fatal("non-canonical key proof signature scalar (S >= L)")
	}
	if !ed25519.Verify(ed25519.PublicKey(proofPub), []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("key proof signature verification failed under its own named key")
	}
}

func TestJWSDeleteRestoreVerification(t *testing.T) {
	seed2 := sha256.Sum256([]byte("dfos-protocol-reference-key-2"))
	pub2 := ed25519.NewKeyFromSeed(seed2[:]).Public().(ed25519.PublicKey)

	deleteHeader, deletePayload := verifyJWS(deleteJWS, pub2)
	if deletePayload["type"] != "delete" || deletePayload["previousOperationCID"] != vec("identity-delete", "previousOperationCID") {
		t.Fatalf("wrong delete payload: %+v", deletePayload)
	}
	deletePayload["version"] = int64(1)
	if cidToBase32(makeCIDBytes(dagCborEncodeJSON(deletePayload))) != deleteHeader["cid"] || deleteHeader["cid"] != vec("identity-delete", "cid") {
		t.Fatalf("wrong delete CID: %s", deleteHeader["cid"])
	}

	restoreHeader, restorePayload := verifyJWS(restoreJWS, pub2)
	if restorePayload["type"] != "restore" || restorePayload["previousOperationCID"] != deleteHeader["cid"] {
		t.Fatalf("wrong restore payload: %+v", restorePayload)
	}
	restorePayload["version"] = int64(1)
	if cidToBase32(makeCIDBytes(dagCborEncodeJSON(restorePayload))) != restoreHeader["cid"] || restoreHeader["cid"] != vec("identity-restore", "cid") {
		t.Fatalf("wrong restore CID: %s", restoreHeader["cid"])
	}
}

func TestJWSContentCreateVerification(t *testing.T) {
	seed2 := sha256.Sum256([]byte("dfos-protocol-reference-key-2"))
	pub2 := ed25519.NewKeyFromSeed(seed2[:]).Public().(ed25519.PublicKey)

	header, payload := verifyJWS(contentCreateJWS, pub2)
	if header["typ"] != vec("content-create", "typ") {
		t.Fatal("wrong typ")
	}
	if header["kid"] != vec("content-create", "kid") {
		t.Fatal("wrong kid")
	}
	if header["cid"] != vec("content-create", "cid") {
		t.Fatalf("wrong cid: %s", header["cid"])
	}
	if payload["documentCID"] != vec("content-create", "documentCID") {
		t.Fatalf("wrong documentCID: %s", payload["documentCID"])
	}
}

// TestDocumentCID re-derives the CID of the content document the create
// operation commits to. The document itself is the shared vector: encode it as
// canonical dag-cbor and the published CID must come back out.
func TestDocumentCID(t *testing.T) {
	document := vecMap("document", "value")
	cid := cidToBase32(makeCIDBytes(dagCborEncodeJSON(document)))
	if cid != vec("document", "cid") {
		t.Fatalf("document CID mismatch: got %s, want %s", cid, vec("document", "cid"))
	}
}

func TestJWTVerification(t *testing.T) {
	seed2 := sha256.Sum256([]byte("dfos-protocol-reference-key-2"))
	pub2 := ed25519.NewKeyFromSeed(seed2[:]).Public().(ed25519.PublicKey)

	header, payload := verifyJWS(jwtToken, pub2)
	if header["alg"] != "EdDSA" {
		t.Fatal("wrong alg")
	}
	if payload["sub"] != vec("jwt", "sub") {
		t.Fatal("wrong sub")
	}
	if payload["iss"] != vec("jwt", "iss") {
		t.Fatal("wrong iss")
	}
	if payload["aud"] != vec("jwt", "aud") {
		t.Fatal("wrong aud")
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

// The canonical services-genesis identity-op is a create op carrying a
// full-state services array (relay locator + content/artifact anchors), signed
// by reference key 1, alongside the two credential vectors it shares a DID with.
var (
	servicesGenesisJWS     = vec("services-genesis", "jws")
	expectedServicesGenCID = vec("services-genesis", "cid")
	expectedServicesDID    = vec("services-genesis", "did")
	broadWriteVC           = vec("credential-write", "jws")
	readVC                 = vec("credential-read", "jws")
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
	if header["kid"] != vec("services-genesis", "kid") {
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

	assertCredential(t, broadWriteVC, pub1, "credential-write")
}

func TestReadCredentialVerification(t *testing.T) {
	seed1 := sha256.Sum256([]byte("dfos-protocol-reference-key-1"))
	pub1 := ed25519.NewKeyFromSeed(seed1[:]).Public().(ed25519.PublicKey)

	assertCredential(t, readVC, pub1, "credential-read")
}

// assertCredential checks one credential JWS against the shared vector of the
// given id: signature under the issuer key, then every published header and
// payload field.
func assertCredential(t *testing.T, token string, pub ed25519.PublicKey, id string) {
	t.Helper()
	header, payload := verifyJWS(token, pub)
	if header["typ"] != vec(id, "typ") {
		t.Fatalf("wrong typ: %s", header["typ"])
	}
	if header["kid"] != vec(id, "kid") {
		t.Fatalf("wrong kid: %s", header["kid"])
	}
	if header["cid"] != vec(id, "cid") {
		t.Fatalf("wrong cid: %s", header["cid"])
	}
	if payload["type"] != "DFOSCredential" {
		t.Fatalf("wrong type: %s", payload["type"])
	}
	if payload["iss"] != vec(id, "iss") {
		t.Fatalf("wrong iss: %s", payload["iss"])
	}
	if payload["aud"] != vec(id, "aud") {
		t.Fatalf("wrong aud: %s", payload["aud"])
	}
	attEntry := payload["att"].([]any)[0].(map[string]any)
	if attEntry["resource"] != vec(id, "resource") {
		t.Fatalf("wrong att resource: %s", attEntry["resource"])
	}
	if attEntry["action"] != vec(id, "action") {
		t.Fatalf("wrong att action: %s", attEntry["action"])
	}
}

// =============================================================================
// Number encoding determinism tests
// =============================================================================

var (
	// Test vector: {"version": 1, "type": "test"} with integer encoding
	numberTestCBOR = vec("number-integer", "cborHex")
	numberTestCID  = vec("number-integer", "cid")
	// The CID that results from float encoding of version: 1.0 — the answer a
	// conforming encoder must never produce.
	numberTestWrongCID = vec("number-integer", "floatCid")
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

	// The float serialization is itself a shared vector: these are the exact
	// bytes a conforming encoder must never emit.
	if got := fmt.Sprintf("%x", cborBytes); got != vec("number-integer", "floatCborHex") {
		t.Fatalf("Float CBOR mismatch: got %s, want %s", got, vec("number-integer", "floatCborHex"))
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

var rejectPub1Hex = vec("reject-corpus", "publicKeyHex")

var rejectVectors = vecStringMap("reject-corpus", "tokens")

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
	cid, err := numberCID(vecMap("number-max-safe", "value"))
	if err != nil {
		t.Fatalf("2^53-1 must be accepted: %v", err)
	}
	if cid != vec("number-max-safe", "cid") {
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
	cid, err := numberCID(vecMap("number-null-vector", "value"))
	if err != nil {
		t.Fatalf("null vector must encode: %v", err)
	}
	if cid != vec("number-null-vector", "cid") {
		t.Fatalf("null vector CID mismatch: got %s", cid)
	}
}
