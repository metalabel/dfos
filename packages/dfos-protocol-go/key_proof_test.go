package dfos

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// KEY-PROOF — byte contract + envelope verification.
//
// The cross-language vector set. Every literal in this block is pinned
// byte-identically in dfos-protocol/tests/key-proof.spec.ts — if one side moves,
// both suites go red rather than the two signers silently forking. The claim the
// vectors make is stronger than "same canonical bytes": the SIGNED envelope is
// pinned too, so keyProofVectorJWS below IS the string TypeScript emits, and
// verifying it here is verifying a TS-signed proof in Go.
//
// Step 6 (nonce bookkeeping) is the CALLER's and is therefore untestable here —
// VerifyKeyProof performs steps 1–5 and 7.

const keyProofVectorNonce = "nonce-key-proof-vector-0001"
const keyProofVectorAudience = "keys.dfos.com"
const keyProofVectorTimestamp = "2026-03-07T00:00:00.000Z"
const keyProofVectorUnix = int64(1772841600)
const keyProofVectorMultibase = "z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2"
const keyProofOtherMultibase = "z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG"

const keyProofVectorCanonical = `{"nonce":"nonce-key-proof-vector-0001","audience":"keys.dfos.com","publicKeyMultibase":"z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2","timestamp":"2026-03-07T00:00:00.000Z"}`
const keyProofVectorJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1hZGQifQ.eyJub25jZSI6Im5vbmNlLWtleS1wcm9vZi12ZWN0b3ItMDAwMSIsImF1ZGllbmNlIjoia2V5cy5kZm9zLmNvbSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtoRndYTkZXb3NMZXVndlNmNHdjTDl0M3V1Ulh1ZUdTRlRSZ1N2SGhXajVHMiIsInRpbWVzdGFtcCI6IjIwMjYtMDMtMDdUMDA6MDA6MDAuMDAwWiJ9.r7fDOdNq04g6BDaQpeuVbQ0mvcJ3OV2fBkNqd7kNKkZLRFnoa5ktLZDs-Ef-qqFRqwpK0bbUT827Fv7A5ZPICA"

// The SAME fixture under a second purpose — the proof that typ is a parameter.
const keyProofVectorOtherTyp = "did:dfos:key-proof-vector-other"
const keyProofVectorOtherTypJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1wcm9vZi12ZWN0b3Itb3RoZXIifQ.eyJub25jZSI6Im5vbmNlLWtleS1wcm9vZi12ZWN0b3ItMDAwMSIsImF1ZGllbmNlIjoia2V5cy5kZm9zLmNvbSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtoRndYTkZXb3NMZXVndlNmNHdjTDl0M3V1Ulh1ZUdTRlRSZ1N2SGhXajVHMiIsInRpbWVzdGFtcCI6IjIwMjYtMDMtMDdUMDA6MDA6MDAuMDAwWiJ9.NMNjktabEWgXRhP28Jh2hLl7s6ATWD4liXvS_nw85HwvnLu14HEl6NINtuTSO2O2dBW7tPOcnJrvFSrnrzPRDA"

// The same members signed by the OTHER key, naming the OTHER key.
const keyProofVectorOtherKeyJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1hZGQifQ.eyJub25jZSI6Im5vbmNlLWtleS1wcm9vZi12ZWN0b3ItMDAwMSIsImF1ZGllbmNlIjoia2V5cy5kZm9zLmNvbSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtneGoyUjNITHRRUnBQbnZmdnB1S0VjZVNxZjN0WkhCamRtWjNmRnozSkhHRyIsInRpbWVzdGFtcCI6IjIwMjYtMDMtMDdUMDA6MDA6MDAuMDAwWiJ9.p1pM7ycrLvynxbrHSCAJZiWIw5RufHWnnQa-ewpj8SbOI55o01IfV2-SO4rs28SqTa40WeLQovyE4TqI1_PQDQ"

// keyProofVectorKey is the fixed seed both languages use: bytes 0x20..0x3f.
func keyProofVectorKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(0x20 + i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// keyProofOtherKey is a SECOND fixed seed, bytes 0x40..0x5f — the wrong-signer
// negative.
func keyProofOtherKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(0x40 + i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func keyProofVectorPayload() KeyProofPayload {
	return KeyProofPayload{
		Nonce:              keyProofVectorNonce,
		Audience:           keyProofVectorAudience,
		PublicKeyMultibase: keyProofVectorMultibase,
		Timestamp:          keyProofVectorTimestamp,
	}
}

func keyProofVectorExpect() KeyProofExpectations {
	return KeyProofExpectations{Typ: KeyAddJWSTyp, Audience: keyProofVectorAudience}
}

func keyProofVectorNow() time.Time { return time.Unix(keyProofVectorUnix, 0).UTC() }

// forgeKeyProof hand-assembles a signed envelope from arbitrary header and
// payload values, so the negative cases can produce artifacts SignKeyProof would
// never emit. The signature is always REAL — every rejection below is therefore a
// rejection by the gate under test, not an accidental signature failure.
func forgeKeyProof(t *testing.T, header map[string]any, payload any, key ed25519.PrivateKey) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	signingInput := Base64urlEncode(headerJSON) + "." + Base64urlEncode(payloadJSON)
	return signingInput + "." + Base64urlEncode(ed25519.Sign(key, []byte(signingInput)))
}

func keyProofHeader() map[string]any {
	return map[string]any{"alg": "EdDSA", "typ": KeyAddJWSTyp}
}

// reasonOf extracts the failing step from a rejection, and fails the test if the
// error is not a key-proof verdict at all.
func keyProofReason(t *testing.T, err error) KeyProofFailureReason {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a rejection, got nil")
	}
	if !errors.Is(err, ErrKeyProofInvalid) {
		t.Fatalf("expected ErrKeyProofInvalid, got %v", err)
	}
	var verdict *KeyProofError
	if !errors.As(err, &verdict) {
		t.Fatalf("expected a *KeyProofError, got %v", err)
	}
	return verdict.Reason
}

// -----------------------------------------------------------------------------
// byte contract
// -----------------------------------------------------------------------------

func TestKeyProofSharedCanonicalAndSignedVectors(t *testing.T) {
	canonical, err := KeyProofSigningInput(keyProofVectorPayload())
	if err != nil {
		t.Fatalf("KeyProofSigningInput: %v", err)
	}
	if string(canonical) != keyProofVectorCanonical {
		t.Fatalf("canonical bytes:\n got %s\nwant %s", canonical, keyProofVectorCanonical)
	}

	proof, payload, err := SignKeyProof(KeyAddJWSTyp, keyProofVectorNonce, keyProofVectorAudience,
		keyProofVectorKey(), KeyProofOptions{Timestamp: keyProofVectorTimestamp})
	if err != nil {
		t.Fatalf("SignKeyProof: %v", err)
	}
	if payload.PublicKeyMultibase != keyProofVectorMultibase {
		t.Fatalf("derived multibase: got %s want %s", payload.PublicKeyMultibase, keyProofVectorMultibase)
	}
	if proof != keyProofVectorJWS {
		t.Fatalf("signed vector:\n got %s\nwant %s", proof, keyProofVectorJWS)
	}
	// The emitted payload segment IS the signing input. That equivalence is the
	// whole reason there is one byte contract and not two.
	if got := strings.Split(proof, ".")[1]; got != Base64urlEncode(canonical) {
		t.Fatalf("payload segment is not the signing input: %s", got)
	}
}

func TestKeyProofHeaderIsExactlyAlgAndTyp(t *testing.T) {
	headerBytes, err := Base64urlDecode(strings.Split(keyProofVectorJWS, ".")[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if string(headerBytes) != `{"alg":"EdDSA","typ":"did:dfos:key-add"}` {
		t.Fatalf("protected header: %s", headerBytes)
	}
}

func TestKeyProofTypIsAParameter(t *testing.T) {
	proof, _, err := SignKeyProof(keyProofVectorOtherTyp, keyProofVectorNonce, keyProofVectorAudience,
		keyProofVectorKey(), KeyProofOptions{Timestamp: keyProofVectorTimestamp})
	if err != nil {
		t.Fatalf("SignKeyProof: %v", err)
	}
	if proof != keyProofVectorOtherTypJWS {
		t.Fatalf("second-purpose vector:\n got %s\nwant %s", proof, keyProofVectorOtherTypJWS)
	}
	// Same payload segment as the key-add vector: only the header differs.
	if strings.Split(proof, ".")[1] != strings.Split(keyProofVectorJWS, ".")[1] {
		t.Fatalf("payload segment differs across purposes")
	}
}

func TestKeyProofFloorNormalizesTimestamp(t *testing.T) {
	proof, payload, err := SignKeyProof(KeyAddJWSTyp, keyProofVectorNonce, keyProofVectorAudience,
		keyProofVectorKey(), KeyProofOptions{Timestamp: "2026-03-07T00:00:00.987Z"})
	if err != nil {
		t.Fatalf("SignKeyProof: %v", err)
	}
	if payload.Timestamp != keyProofVectorTimestamp || proof != keyProofVectorJWS {
		t.Fatalf("millisecond-bearing override was not floored: %s", payload.Timestamp)
	}

	proof, payload, err = SignKeyProof(KeyAddJWSTyp, keyProofVectorNonce, keyProofVectorAudience,
		keyProofVectorKey(), KeyProofOptions{Now: time.Unix(keyProofVectorUnix, 654_000_000).UTC()})
	if err != nil {
		t.Fatalf("SignKeyProof: %v", err)
	}
	if payload.Timestamp != keyProofVectorTimestamp || proof != keyProofVectorJWS {
		t.Fatalf("default timestamp was not floored: %s", payload.Timestamp)
	}
}

func TestKeyProofRefusesATimestampOverrideOutsideTheGrammar(t *testing.T) {
	// The same six spellings the TS twin refuses. Each one is a case where a
	// lenient parser on one side would floor something the other side would not.
	for _, timestamp := range []string{
		"2026-03-07T00:00:00Z",          // no fraction
		"2026-03-07T00:00:00.12Z",       // two digits
		"2026-03-07T00:00:00.000+00:00", // numeric offset
		"2026-03-07T00:00:00.000",       // no zone
		"2026-02-30T00:00:00.000Z",      // not a calendar date
		"yesterday",
	} {
		if _, _, err := SignKeyProof(KeyAddJWSTyp, keyProofVectorNonce, keyProofVectorAudience,
			keyProofVectorKey(), KeyProofOptions{Timestamp: timestamp}); err == nil {
			t.Fatalf("%q: expected a rejection", timestamp)
		}
	}
}

func TestKeyProofSigningInputRefusesAnInadmissiblePayload(t *testing.T) {
	for name, payload := range map[string]KeyProofPayload{
		"uppercase audience": {Nonce: "n", Audience: "KEYS.DFOS.COM", PublicKeyMultibase: keyProofVectorMultibase, Timestamp: keyProofVectorTimestamp},
		"scheme in audience": {Nonce: "n", Audience: "https://keys.dfos.com", PublicKeyMultibase: keyProofVectorMultibase, Timestamp: keyProofVectorTimestamp},
		"path in audience":   {Nonce: "n", Audience: "keys.dfos.com/complete", PublicKeyMultibase: keyProofVectorMultibase, Timestamp: keyProofVectorTimestamp},
		"unfloored":          {Nonce: "n", Audience: keyProofVectorAudience, PublicKeyMultibase: keyProofVectorMultibase, Timestamp: "2026-03-07T00:00:00.987Z"},
		"no fraction":        {Nonce: "n", Audience: keyProofVectorAudience, PublicKeyMultibase: keyProofVectorMultibase, Timestamp: "2026-03-07T00:00:00Z"},
		"empty nonce":        {Nonce: "", Audience: keyProofVectorAudience, PublicKeyMultibase: keyProofVectorMultibase, Timestamp: keyProofVectorTimestamp},
	} {
		if _, err := KeyProofSigningInput(payload); err == nil {
			t.Fatalf("%s: expected a rejection", name)
		}
	}
}

func TestKeyProofRefusesToSignOverTheCap(t *testing.T) {
	if _, _, err := SignKeyProof(KeyAddJWSTyp, strings.Repeat("n", MaxKeyProofSize),
		keyProofVectorAudience, keyProofVectorKey(), KeyProofOptions{Timestamp: keyProofVectorTimestamp}); err == nil {
		t.Fatalf("expected an over-cap rejection")
	}
}

// -----------------------------------------------------------------------------
// verification — steps 1–5 and 7
// -----------------------------------------------------------------------------

func TestVerifyKeyProofAcceptsTheTypeScriptSignedVector(t *testing.T) {
	verified, err := VerifyKeyProof(keyProofVectorJWS, keyProofVectorExpect(), keyProofVectorNow())
	if err != nil {
		t.Fatalf("VerifyKeyProof: %v", err)
	}
	if verified.Payload != keyProofVectorPayload() {
		t.Fatalf("payload: %+v", verified.Payload)
	}
	if verified.Typ != KeyAddJWSTyp || verified.Now != keyProofVectorUnix {
		t.Fatalf("typ/now: %s %d", verified.Typ, verified.Now)
	}
	// Step 6 is the caller's: this is the value it check-and-deletes against.
	if verified.Payload.Nonce != keyProofVectorNonce {
		t.Fatalf("nonce not handed back: %s", verified.Payload.Nonce)
	}

	expect := keyProofVectorExpect()
	expect.Typ = keyProofVectorOtherTyp
	if _, err := VerifyKeyProof(keyProofVectorOtherTypJWS, expect, keyProofVectorNow()); err != nil {
		t.Fatalf("second-purpose vector: %v", err)
	}
}

func TestVerifyKeyProofSizeCap(t *testing.T) {
	if reason := keyProofReason(t, mustFailKeyProof(t, strings.Repeat("a", MaxKeyProofSize+1))); reason != KeyProofFailureSize {
		t.Fatalf("reason: %s", reason)
	}
	huge := map[string]any{
		"nonce": strings.Repeat("n", MaxKeyProofSize), "audience": keyProofVectorAudience,
		"publicKeyMultibase": keyProofVectorMultibase, "timestamp": keyProofVectorTimestamp,
	}
	oversize := forgeKeyProof(t, keyProofHeader(), huge, keyProofVectorKey())
	if reason := keyProofReason(t, mustFailKeyProof(t, oversize)); reason != KeyProofFailureSize {
		t.Fatalf("reason: %s", reason)
	}
}

func TestVerifyKeyProofRejectsAPresentKid(t *testing.T) {
	header := keyProofHeader()
	header["kid"] = "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae#key_0"
	proof := forgeKeyProof(t, header, keyProofVectorPayload2(), keyProofVectorKey())
	err := mustFailKeyProof(t, proof)
	if reason := keyProofReason(t, err); reason != KeyProofFailureHeader {
		t.Fatalf("reason: %s", reason)
	}
	if !strings.Contains(err.Error(), "kid must be absent") {
		t.Fatalf("message: %v", err)
	}
}

func TestVerifyKeyProofRejectsCritAndEmbeddedKeys(t *testing.T) {
	header := keyProofHeader()
	header["crit"] = []string{"b64"}
	if reason := keyProofReason(t, mustFailKeyProof(t,
		forgeKeyProof(t, header, keyProofVectorPayload2(), keyProofVectorKey()))); reason != KeyProofFailureHeader {
		t.Fatalf("crit reason: %s", reason)
	}

	for _, member := range []string{"jwk", "jku", "x5c", "x5u"} {
		header := keyProofHeader()
		header[member] = "https://evil.example/key"
		err := mustFailKeyProof(t, forgeKeyProof(t, header, keyProofVectorPayload2(), keyProofVectorKey()))
		if reason := keyProofReason(t, err); reason != KeyProofFailureHeader {
			t.Fatalf("%s reason: %s", member, reason)
		}
		if !strings.Contains(err.Error(), member) {
			t.Fatalf("%s message: %v", member, err)
		}
	}
}

func TestVerifyKeyProofTypGateIsAbsoluteInBothDirections(t *testing.T) {
	expect := keyProofVectorExpect()
	expect.Typ = keyProofVectorOtherTyp
	if _, err := VerifyKeyProof(keyProofVectorJWS, expect, keyProofVectorNow()); err == nil {
		t.Fatalf("a key-add proof passed where another purpose was required")
	} else if reason := keyProofReason(t, err); reason != KeyProofFailureHeader {
		t.Fatalf("reason: %s", reason)
	}

	if _, err := VerifyKeyProof(keyProofVectorOtherTypJWS, keyProofVectorExpect(), keyProofVectorNow()); err == nil {
		t.Fatalf("another purpose's proof passed as key-add")
	} else if reason := keyProofReason(t, err); reason != KeyProofFailureHeader {
		t.Fatalf("reason: %s", reason)
	}

	// A typ from another family is not a key proof at all.
	header := keyProofHeader()
	header["typ"] = SiwdAskJWSTyp
	if reason := keyProofReason(t, mustFailKeyProof(t,
		forgeKeyProof(t, header, keyProofVectorPayload2(), keyProofVectorKey()))); reason != KeyProofFailureHeader {
		t.Fatalf("reason: %s", reason)
	}
}

func TestVerifyKeyProofRejectsMalformedHeaders(t *testing.T) {
	header := keyProofHeader()
	header["alg"] = "none"
	if reason := keyProofReason(t, mustFailKeyProof(t,
		forgeKeyProof(t, header, keyProofVectorPayload2(), keyProofVectorKey()))); reason != KeyProofFailureHeader {
		t.Fatalf("alg reason: %s", reason)
	}
	for _, malformed := range []string{"not.a.jws.at.all", "onlyonepart", "a.b"} {
		if reason := keyProofReason(t, mustFailKeyProof(t, malformed)); reason != KeyProofFailureHeader {
			t.Fatalf("%q reason: %s", malformed, reason)
		}
	}
}

func TestVerifyKeyProofPayloadIsClosed(t *testing.T) {
	extra := keyProofVectorPayload2()
	extra["intent"] = "send all my money"
	err := mustFailKeyProof(t, forgeKeyProof(t, keyProofHeader(), extra, keyProofVectorKey()))
	if reason := keyProofReason(t, err); reason != KeyProofFailureSchema {
		t.Fatalf("reason: %s", reason)
	}
	if !strings.Contains(err.Error(), "the payload is closed") {
		t.Fatalf("message: %v", err)
	}
}

func TestVerifyKeyProofRejectsMissingAndNonStringMembers(t *testing.T) {
	for _, member := range keyProofMembers {
		partial := keyProofVectorPayload2()
		delete(partial, member)
		if reason := keyProofReason(t, mustFailKeyProof(t,
			forgeKeyProof(t, keyProofHeader(), partial, keyProofVectorKey()))); reason != KeyProofFailureSchema {
			t.Fatalf("missing %s reason: %s", member, reason)
		}
	}

	for _, value := range []any{42, nil, true, []int{}, map[string]int{"a": 1}} {
		bad := keyProofVectorPayload2()
		bad["nonce"] = value
		if reason := keyProofReason(t, mustFailKeyProof(t,
			forgeKeyProof(t, keyProofHeader(), bad, keyProofVectorKey()))); reason != KeyProofFailureSchema {
			t.Fatalf("non-string nonce %v reason: %s", value, reason)
		}
	}
	// A numeric timestamp is the case a lenient parser would coerce.
	numeric := keyProofVectorPayload2()
	numeric["timestamp"] = keyProofVectorUnix
	if reason := keyProofReason(t, mustFailKeyProof(t,
		forgeKeyProof(t, keyProofHeader(), numeric, keyProofVectorKey()))); reason != KeyProofFailureSchema {
		t.Fatalf("numeric timestamp reason: %s", reason)
	}

	for _, payload := range []any{[]int{1, 2, 3}, "a string", 7, nil} {
		if reason := keyProofReason(t, mustFailKeyProof(t,
			forgeKeyProof(t, keyProofHeader(), payload, keyProofVectorKey()))); reason != KeyProofFailureSchema {
			t.Fatalf("non-object payload %v reason: %s", payload, reason)
		}
	}
}

func TestVerifyKeyProofAudienceIsByteEquality(t *testing.T) {
	// Near-misses are misses: no port normalization, no case folding, no suffix match.
	for _, authority := range []string{"evil.example", "keys.dfos.com:443", "KEYS.DFOS.COM", "dfos.com", "a.keys.dfos.com"} {
		expect := keyProofVectorExpect()
		expect.Audience = authority
		_, err := VerifyKeyProof(keyProofVectorJWS, expect, keyProofVectorNow())
		if reason := keyProofReason(t, err); reason != KeyProofFailureAudience {
			t.Fatalf("%s reason: %s", authority, reason)
		}
	}
}

func TestVerifyKeyProofFreshnessIsSymmetric(t *testing.T) {
	edge := int64(DefaultKeyProofSkewSeconds)
	for _, offset := range []int64{-edge, 0, edge} {
		if _, err := VerifyKeyProof(keyProofVectorJWS, keyProofVectorExpect(),
			time.Unix(keyProofVectorUnix+offset, 0).UTC()); err != nil {
			t.Fatalf("offset %d: %v", offset, err)
		}
	}
	for _, offset := range []int64{-edge - 1, edge + 1, 86_400} {
		_, err := VerifyKeyProof(keyProofVectorJWS, keyProofVectorExpect(),
			time.Unix(keyProofVectorUnix+offset, 0).UTC())
		if reason := keyProofReason(t, err); reason != KeyProofFailureFreshness {
			t.Fatalf("offset %d reason: %s", offset, reason)
		}
	}

	// An explicit tighter window is honored, and an explicit 0 is not omission.
	expect := keyProofVectorExpect()
	expect.MaxSkewSeconds = Int64Ptr(30)
	_, err := VerifyKeyProof(keyProofVectorJWS, expect, time.Unix(keyProofVectorUnix+31, 0).UTC())
	if reason := keyProofReason(t, err); reason != KeyProofFailureFreshness {
		t.Fatalf("tight window reason: %s", reason)
	}
	expect.MaxSkewSeconds = Int64Ptr(0)
	if _, err := VerifyKeyProof(keyProofVectorJWS, expect, keyProofVectorNow()); err != nil {
		t.Fatalf("explicit zero window at the exact instant: %v", err)
	}
}

func TestVerifyKeyProofRefusesANegativeWindowAsMisconfiguration(t *testing.T) {
	expect := keyProofVectorExpect()
	expect.MaxSkewSeconds = Int64Ptr(-1)
	_, err := VerifyKeyProof(keyProofVectorJWS, expect, keyProofVectorNow())
	if err == nil {
		t.Fatalf("expected a rejection")
	}
	// NOT a verdict about the artifact.
	if errors.Is(err, ErrKeyProofInvalid) {
		t.Fatalf("a verifier misconfiguration was reported as an invalid proof: %v", err)
	}
}

func TestVerifyKeyProofSignatureIsSelfProving(t *testing.T) {
	// Real signature, real key — but the payload names the vector key and the
	// signature is the other key's. This is the substitution the self-proving
	// circularity exists to catch.
	mismatched := forgeKeyProof(t, keyProofHeader(), keyProofVectorPayload2(), keyProofOtherKey())
	if reason := keyProofReason(t, mustFailKeyProof(t, mismatched)); reason != KeyProofFailureSignature {
		t.Fatalf("reason: %s", reason)
	}

	// The converse is a VALID proof — it names the key that signed it.
	honest, err := VerifyKeyProof(keyProofVectorOtherKeyJWS, keyProofVectorExpect(), keyProofVectorNow())
	if err != nil {
		t.Fatalf("other-key vector: %v", err)
	}
	if honest.Payload.PublicKeyMultibase != keyProofOtherMultibase {
		t.Fatalf("multibase: %s", honest.Payload.PublicKeyMultibase)
	}
}

func TestVerifyKeyProofRejectsUndecodableKeysAndSignatures(t *testing.T) {
	for _, multibase := range []string{"zNotAMultikey", "z6Mk", "not-multibase"} {
		bad := keyProofVectorPayload2()
		bad["publicKeyMultibase"] = multibase
		if reason := keyProofReason(t, mustFailKeyProof(t,
			forgeKeyProof(t, keyProofHeader(), bad, keyProofVectorKey()))); reason != KeyProofFailureSignature {
			t.Fatalf("%s reason: %s", multibase, reason)
		}
	}

	parts := strings.Split(keyProofVectorJWS, ".")
	for _, signature := range []string{"AAAA", "", "!!!!"} {
		if reason := keyProofReason(t, mustFailKeyProof(t,
			parts[0]+"."+parts[1]+"."+signature)); reason != KeyProofFailureSignature {
			t.Fatalf("signature %q reason: %s", signature, reason)
		}
	}
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// keyProofVectorPayload2 is the vector payload as a mutable map, for the forged
// negatives.
func keyProofVectorPayload2() map[string]any {
	return map[string]any{
		"nonce":              keyProofVectorNonce,
		"audience":           keyProofVectorAudience,
		"publicKeyMultibase": keyProofVectorMultibase,
		"timestamp":          keyProofVectorTimestamp,
	}
}

func mustFailKeyProof(t *testing.T, proof string) error {
	t.Helper()
	verified, err := VerifyKeyProof(proof, keyProofVectorExpect(), keyProofVectorNow())
	if err == nil {
		t.Fatalf("expected a rejection, got %+v", verified)
	}
	return err
}
