package dfos

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
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
const keyProofVectorDID = "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae"

// keyProofVectorRoleSet is a PROPER SUBSET on purpose. The full set would make
// the walk's coverage rule and presentation-time's equality rule
// indistinguishable, and coverage-not-equality is the one place the two modes
// deliberately differ.
const keyProofVectorRoleSet = "auth,assert"
const keyProofVectorPrevCID = "bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne"
const keyProofVectorTimestamp = "2026-03-07T00:00:00.000Z"
const keyProofVectorUnix = int64(1772841600)
const keyProofVectorMultibase = "z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2"
const keyProofOtherMultibase = "z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG"

const keyProofVectorCanonical = `{"nonce":"nonce-key-proof-vector-0001","audience":"keys.dfos.com","did":"did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae","roleSet":"auth,assert","prevCID":"bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne","publicKeyMultibase":"z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2","timestamp":"2026-03-07T00:00:00.000Z"}`
const keyProofVectorJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1hZGQifQ.eyJub25jZSI6Im5vbmNlLWtleS1wcm9vZi12ZWN0b3ItMDAwMSIsImF1ZGllbmNlIjoia2V5cy5kZm9zLmNvbSIsImRpZCI6ImRpZDpkZm9zOm56a2Y4MzhlZnI0MjQ0MzNybjJyemtkdjhoN3Q5YWUiLCJyb2xlU2V0IjoiYXV0aCxhc3NlcnQiLCJwcmV2Q0lEIjoiYmFmeXJlaWNvZ2h2anpudmxpdWxveHhtYmY1NHRwenF3YWhucXBpbGs3bmN4ZXBqaW5lZHBrZ2EzbmUiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1raEZ3WE5GV29zTGV1Z3ZTZjR3Y0w5dDN1dVJYdWVHU0ZUUmdTdkhoV2o1RzIiLCJ0aW1lc3RhbXAiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.KepNMLYBmZbnB4l4rNcLOhZS-NOgQHr_a9_So0REHwzoT_jXtVF9XEEeiUNzxxSh965ZfZdNQJteK8Tf6OcuAg"

// The SAME fixture under a second purpose — the proof that typ is a parameter.
const keyProofVectorOtherTyp = "did:dfos:key-proof-vector-other"
const keyProofVectorOtherTypJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1wcm9vZi12ZWN0b3Itb3RoZXIifQ.eyJub25jZSI6Im5vbmNlLWtleS1wcm9vZi12ZWN0b3ItMDAwMSIsImF1ZGllbmNlIjoia2V5cy5kZm9zLmNvbSIsImRpZCI6ImRpZDpkZm9zOm56a2Y4MzhlZnI0MjQ0MzNybjJyemtkdjhoN3Q5YWUiLCJyb2xlU2V0IjoiYXV0aCxhc3NlcnQiLCJwcmV2Q0lEIjoiYmFmeXJlaWNvZ2h2anpudmxpdWxveHhtYmY1NHRwenF3YWhucXBpbGs3bmN4ZXBqaW5lZHBrZ2EzbmUiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1raEZ3WE5GV29zTGV1Z3ZTZjR3Y0w5dDN1dVJYdWVHU0ZUUmdTdkhoV2o1RzIiLCJ0aW1lc3RhbXAiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.KYh81pniAUn0n-ss4Z9_PJCpJkCtryCt8U3ZQhTt3zzjGRzE0v1qyarYjmMUin9eN6bJ1cMXCx6cupyUMDMcDA"

// THE MALLEABILITY NEGATIVES. Both carry the vector's exact seven members, both
// are REALLY signed by the vector key over the octets they present, and both are
// refused: the first serializes the members in reverse order, the second inserts
// insignificant whitespace. A signature covers whatever octets arrived, so the
// only thing that makes one set of members one payload string is the verifier
// recomputing the canonical signing input and byte-comparing. Pinned in
// dfos-protocol/tests/key-proof.spec.ts too — a twin that accepted either would
// be accepting bytes production refuses.
const keyProofVectorReorderedJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1hZGQifQ.eyJ0aW1lc3RhbXAiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1raEZ3WE5GV29zTGV1Z3ZTZjR3Y0w5dDN1dVJYdWVHU0ZUUmdTdkhoV2o1RzIiLCJwcmV2Q0lEIjoiYmFmeXJlaWNvZ2h2anpudmxpdWxveHhtYmY1NHRwenF3YWhucXBpbGs3bmN4ZXBqaW5lZHBrZ2EzbmUiLCJyb2xlU2V0IjoiYXV0aCxhc3NlcnQiLCJkaWQiOiJkaWQ6ZGZvczpuemtmODM4ZWZyNDI0NDMzcm4ycnprZHY4aDd0OWFlIiwiYXVkaWVuY2UiOiJrZXlzLmRmb3MuY29tIiwibm9uY2UiOiJub25jZS1rZXktcHJvb2YtdmVjdG9yLTAwMDEifQ.4qHdOCS5yAq10_XpdfBFoglwm2ZDLNooUntOyWDjcNul9M2_GbShh8JIOd5vimen0ZKUpObmFFVPlzVcmT0XDw"
const keyProofVectorSpacedJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1hZGQifQ.eyJub25jZSI6ICJub25jZS1rZXktcHJvb2YtdmVjdG9yLTAwMDEiLCAiYXVkaWVuY2UiOiAia2V5cy5kZm9zLmNvbSIsICJkaWQiOiAiZGlkOmRmb3M6bnprZjgzOGVmcjQyNDQzM3JuMnJ6a2R2OGg3dDlhZSIsICJyb2xlU2V0IjogImF1dGgsYXNzZXJ0IiwgInByZXZDSUQiOiAiYmFmeXJlaWNvZ2h2anpudmxpdWxveHhtYmY1NHRwenF3YWhucXBpbGs3bmN4ZXBqaW5lZHBrZ2EzbmUiLCAicHVibGljS2V5TXVsdGliYXNlIjogIno2TWtoRndYTkZXb3NMZXVndlNmNHdjTDl0M3V1Ulh1ZUdTRlRSZ1N2SGhXajVHMiIsICJ0aW1lc3RhbXAiOiAiMjAyNi0wMy0wN1QwMDowMDowMC4wMDBaIn0.XVCcwA2t1jpxbbotBVsOa96dQecpm0ZpymM53MrCA_r88suegEmMLxva6nVSelNipVmeBuWS7lcTFSb2dNeeDw"

// The same members signed by the OTHER key, naming the OTHER key.
const keyProofVectorOtherKeyJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1hZGQifQ.eyJub25jZSI6Im5vbmNlLWtleS1wcm9vZi12ZWN0b3ItMDAwMSIsImF1ZGllbmNlIjoia2V5cy5kZm9zLmNvbSIsImRpZCI6ImRpZDpkZm9zOm56a2Y4MzhlZnI0MjQ0MzNybjJyemtkdjhoN3Q5YWUiLCJyb2xlU2V0IjoiYXV0aCxhc3NlcnQiLCJwcmV2Q0lEIjoiYmFmeXJlaWNvZ2h2anpudmxpdWxveHhtYmY1NHRwenF3YWhucXBpbGs3bmN4ZXBqaW5lZHBrZ2EzbmUiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rZ3hqMlIzSEx0UVJwUG52ZnZwdUtFY2VTcWYzdFpIQmpkbVozZkZ6M0pIR0ciLCJ0aW1lc3RhbXAiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.Y2Wd-a7PPXpt6-hLJBRg2V9vLZwMfXa_qxv7ZxtB48OB6l9EotoKYkJhwdOLjv2Ydy-MEnkOkt4_CWEhAgJKCg"

// The same fixture consenting to ALL THREE roles. Presentation-time refuses it
// where auth,assert was asked (equality); the chain walk accepts it for any one
// of the three (coverage). One envelope, two different right answers.
const keyProofVectorFullRoleSetJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmtleS1hZGQifQ.eyJub25jZSI6Im5vbmNlLWtleS1wcm9vZi12ZWN0b3ItMDAwMSIsImF1ZGllbmNlIjoia2V5cy5kZm9zLmNvbSIsImRpZCI6ImRpZDpkZm9zOm56a2Y4MzhlZnI0MjQ0MzNybjJyemtkdjhoN3Q5YWUiLCJyb2xlU2V0IjoiYXV0aCxhc3NlcnQsY29udHJvbGxlciIsInByZXZDSUQiOiJiYWZ5cmVpY29naHZqem52bGl1bG94eG1iZjU0dHB6cXdhaG5xcGlsazduY3hlcGppbmVkcGtnYTNuZSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtoRndYTkZXb3NMZXVndlNmNHdjTDl0M3V1Ulh1ZUdTRlRSZ1N2SGhXajVHMiIsInRpbWVzdGFtcCI6IjIwMjYtMDMtMDdUMDA6MDA6MDAuMDAwWiJ9.mK04MC77zaK0oUUS68dsWbdw8IV0ES9wS9xXoxG48sk1uxvE3Tabu6kQFWsvzhgdLxvxX6VPYBiuDJHbz8M2Cg"

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
		DID:                keyProofVectorDID,
		RoleSet:            keyProofVectorRoleSet,
		PrevCID:            keyProofVectorPrevCID,
		PublicKeyMultibase: keyProofVectorMultibase,
		Timestamp:          keyProofVectorTimestamp,
	}
}

// keyProofVectorSignInput is the producer-side input the vector envelope is
// signed from.
func keyProofVectorSignInput() SignKeyProofInput {
	return SignKeyProofInput{
		Typ:        KeyAddJWSTyp,
		Nonce:      keyProofVectorNonce,
		Audience:   keyProofVectorAudience,
		DID:        keyProofVectorDID,
		RoleSet:    keyProofVectorRoleSet,
		PrevCID:    keyProofVectorPrevCID,
		PrivateKey: keyProofVectorKey(),
		Timestamp:  keyProofVectorTimestamp,
	}
}

func keyProofVectorExpect() KeyProofExpectations {
	return KeyProofExpectations{
		Typ:      KeyAddJWSTyp,
		Audience: keyProofVectorAudience,
		DID:      keyProofVectorDID,
		RoleSet:  keyProofVectorRoleSet,
		PrevCID:  keyProofVectorPrevCID,
	}
}

func keyProofWalkFor() ChainKeyProofExpectations {
	return ChainKeyProofExpectations{
		Typ:                KeyAddJWSTyp,
		DID:                keyProofVectorDID,
		PrevCID:            keyProofVectorPrevCID,
		PublicKeyMultibase: keyProofVectorMultibase,
		Role:               "auth",
	}
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
	signingInput := Base64urlEncode(headerJSON) + "." + Base64urlEncode(forgeKeyProofPayload(t, payload))
	return signingInput + "." + Base64urlEncode(ed25519.Sign(key, []byte(signingInput)))
}

// forgeKeyProofPayload serializes a forged payload map in the CANONICAL member
// order, appending any unknown member after the seven. json.Marshal would emit map
// keys ALPHABETICALLY, which is a non-canonical payload, and the verifier now
// byte-compares against the canonical bytes. Every forged negative would otherwise
// reject at the canonical-bytes gate instead of the gate it is written to
// exercise. The malleability cases are deliberately pinned envelopes, not
// forgeries, precisely so no helper's serialization choices are load-bearing for
// them.
func forgeKeyProofPayload(t *testing.T, payload any) []byte {
	t.Helper()
	members, ok := payload.(map[string]any)
	if !ok {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		return encoded
	}

	var buf bytes.Buffer
	buf.WriteByte('{')
	write := func(name string) {
		value, err := json.Marshal(members[name])
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		if buf.Len() > 1 {
			buf.WriteByte(',')
		}
		buf.WriteString(jsonStringifyString(name))
		buf.WriteByte(':')
		buf.Write(value)
	}
	for _, name := range keyProofMembers {
		if _, present := members[name]; present {
			write(name)
		}
	}
	var extra []string
	for name := range members {
		if !slices.Contains(keyProofMembers, name) {
			extra = append(extra, name)
		}
	}
	slices.Sort(extra)
	for _, name := range extra {
		write(name)
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

func keyProofHeader() map[string]any {
	return map[string]any{"alg": "EdDSA", "typ": KeyAddJWSTyp}
}

// keyProofReason extracts the failing step from a rejection, and fails the test
// if the error is not a key-proof verdict at all.
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

	proof, payload, err := SignKeyProof(keyProofVectorSignInput())
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
	input := keyProofVectorSignInput()
	input.Typ = keyProofVectorOtherTyp
	proof, _, err := SignKeyProof(input)
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

func TestKeyProofFullRoleSetVector(t *testing.T) {
	input := keyProofVectorSignInput()
	roleSet, err := SerializeRoleSet(KeyRoles)
	if err != nil {
		t.Fatalf("SerializeRoleSet: %v", err)
	}
	input.RoleSet = roleSet
	proof, _, err := SignKeyProof(input)
	if err != nil {
		t.Fatalf("SignKeyProof: %v", err)
	}
	if proof != keyProofVectorFullRoleSetJWS {
		t.Fatalf("full-role-set vector:\n got %s\nwant %s", proof, keyProofVectorFullRoleSetJWS)
	}
}

func TestKeyProofFloorNormalizesTimestamp(t *testing.T) {
	input := keyProofVectorSignInput()
	input.Timestamp = "2026-03-07T00:00:00.987Z"
	proof, payload, err := SignKeyProof(input)
	if err != nil {
		t.Fatalf("SignKeyProof: %v", err)
	}
	if payload.Timestamp != keyProofVectorTimestamp || proof != keyProofVectorJWS {
		t.Fatalf("millisecond-bearing override was not floored: %s", payload.Timestamp)
	}

	input = keyProofVectorSignInput()
	input.Timestamp = ""
	input.Now = time.Unix(keyProofVectorUnix, 654_000_000).UTC()
	proof, payload, err = SignKeyProof(input)
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
		input := keyProofVectorSignInput()
		input.Timestamp = timestamp
		if _, _, err := SignKeyProof(input); err == nil {
			t.Fatalf("%q: expected a rejection", timestamp)
		}
	}
}

func TestKeyProofSigningInputRefusesAnInadmissiblePayload(t *testing.T) {
	withField := func(mutate func(*KeyProofPayload)) KeyProofPayload {
		payload := keyProofVectorPayload()
		mutate(&payload)
		return payload
	}
	for name, payload := range map[string]KeyProofPayload{
		"uppercase audience": withField(func(p *KeyProofPayload) { p.Audience = "KEYS.DFOS.COM" }),
		"scheme in audience": withField(func(p *KeyProofPayload) { p.Audience = "https://keys.dfos.com" }),
		"path in audience":   withField(func(p *KeyProofPayload) { p.Audience = "keys.dfos.com/complete" }),
		"unfloored":          withField(func(p *KeyProofPayload) { p.Timestamp = "2026-03-07T00:00:00.987Z" }),
		"no fraction":        withField(func(p *KeyProofPayload) { p.Timestamp = "2026-03-07T00:00:00Z" }),
		"empty nonce":        withField(func(p *KeyProofPayload) { p.Nonce = "" }),
		"empty did":          withField(func(p *KeyProofPayload) { p.DID = "" }),
		"empty roleSet":      withField(func(p *KeyProofPayload) { p.RoleSet = "" }),
		"empty prevCID":      withField(func(p *KeyProofPayload) { p.PrevCID = "" }),
		"reversed roleSet":   withField(func(p *KeyProofPayload) { p.RoleSet = "assert,auth" }),
		"spaced roleSet":     withField(func(p *KeyProofPayload) { p.RoleSet = "auth, assert" }),
		"duplicate roleSet":  withField(func(p *KeyProofPayload) { p.RoleSet = "auth,auth" }),
		"unknown role":       withField(func(p *KeyProofPayload) { p.RoleSet = "auth,owner" }),
	} {
		if _, err := KeyProofSigningInput(payload); err == nil {
			t.Fatalf("%s: expected a rejection", name)
		}
	}
}

func TestKeyProofRefusesToSignOverTheCap(t *testing.T) {
	input := keyProofVectorSignInput()
	input.Nonce = strings.Repeat("n", MaxKeyProofSize)
	if _, _, err := SignKeyProof(input); err == nil {
		t.Fatalf("expected an over-cap rejection")
	}
}

// -----------------------------------------------------------------------------
// the role set
// -----------------------------------------------------------------------------

func TestSerializeRoleSetFixesTheOrder(t *testing.T) {
	for _, tc := range []struct {
		roles []KeyRole
		want  string
	}{
		{[]KeyRole{"controller", "auth"}, "auth,controller"},
		{[]KeyRole{"assert", "auth"}, "auth,assert"},
		{[]KeyRole{"controller", "assert", "auth"}, "auth,assert,controller"},
		// A set is a set: duplicates in the input collapse rather than reject.
		{[]KeyRole{"auth", "auth"}, "auth"},
		{KeyRoles, "auth,assert,controller"},
	} {
		got, err := SerializeRoleSet(tc.roles)
		if err != nil {
			t.Fatalf("%v: %v", tc.roles, err)
		}
		if got != tc.want {
			t.Fatalf("%v: got %q want %q", tc.roles, got, tc.want)
		}
	}

	if _, err := SerializeRoleSet([]KeyRole{"owner"}); err == nil {
		t.Fatalf("expected an unknown-role rejection")
	}
	if _, err := SerializeRoleSet(nil); err == nil {
		t.Fatalf("expected an empty-set rejection")
	}
}

func TestParseRoleSetAdmitsExactlyTheSevenCanonicalSpellings(t *testing.T) {
	for _, value := range []string{
		"auth",
		"assert",
		"controller",
		"auth,assert",
		"auth,controller",
		"assert,controller",
		"auth,assert,controller",
	} {
		roles, ok := ParseRoleSet(value)
		if !ok {
			t.Fatalf("%q: expected a parse", value)
		}
		roundTrip, err := SerializeRoleSet(roles)
		if err != nil {
			t.Fatalf("%q: %v", value, err)
		}
		if roundTrip != value {
			t.Fatalf("%q round-trips to %q", value, roundTrip)
		}
		if !IsCanonicalRoleSet(value) {
			t.Fatalf("%q: IsCanonicalRoleSet disagrees with ParseRoleSet", value)
		}
	}

	for _, value := range []string{
		"",                // empty
		"assert,auth",     // out of order
		"controller,auth", // out of order
		"auth, assert",    // whitespace
		" auth",           // whitespace
		"auth,",           // empty segment
		",auth",           // empty segment
		"auth,auth",       // duplicate
		"auth,owner",      // unknown role
		"owner",           // unknown role
		"AUTH",            // case
		"auth;assert",     // wrong separator
	} {
		if _, ok := ParseRoleSet(value); ok {
			t.Fatalf("%q: expected a refusal", value)
		}
		if IsCanonicalRoleSet(value) {
			t.Fatalf("%q: IsCanonicalRoleSet disagrees with ParseRoleSet", value)
		}
	}
}

func TestRoleSetCovers(t *testing.T) {
	if !RoleSetCovers("auth,assert", "auth") || !RoleSetCovers("auth,assert", "assert") {
		t.Fatalf("auth,assert should cover auth and assert")
	}
	if RoleSetCovers("auth,assert", "controller") {
		t.Fatalf("auth,assert must not cover controller")
	}
	// A non-canonical role set covers nothing — it never parsed.
	if RoleSetCovers("assert,auth", "auth") {
		t.Fatalf("a non-canonical role set must cover nothing")
	}
}

func TestVerifyKeyProofRejectsANonCanonicalRoleSetInsideTheEnvelope(t *testing.T) {
	for _, roleSet := range []string{"assert,auth", "auth, assert", "auth,auth", "auth,owner", ""} {
		payload := keyProofVectorPayloadMap()
		payload["roleSet"] = roleSet
		forged := forgeKeyProof(t, keyProofHeader(), payload, keyProofVectorKey())
		if reason := keyProofReason(t, mustFailKeyProof(t, forged)); reason != KeyProofFailureSchema {
			t.Fatalf("%q reason: %s", roleSet, reason)
		}
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
	huge := keyProofVectorPayloadMap()
	huge["nonce"] = strings.Repeat("n", MaxKeyProofSize)
	oversize := forgeKeyProof(t, keyProofHeader(), huge, keyProofVectorKey())
	if reason := keyProofReason(t, mustFailKeyProof(t, oversize)); reason != KeyProofFailureSize {
		t.Fatalf("reason: %s", reason)
	}
}

func TestVerifyKeyProofRejectsAPresentKid(t *testing.T) {
	header := keyProofHeader()
	header["kid"] = keyProofVectorDID + "#key_0"
	proof := forgeKeyProof(t, header, keyProofVectorPayloadMap(), keyProofVectorKey())
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
		forgeKeyProof(t, header, keyProofVectorPayloadMap(), keyProofVectorKey()))); reason != KeyProofFailureHeader {
		t.Fatalf("crit reason: %s", reason)
	}

	for _, member := range []string{"jwk", "jku", "x5c", "x5u"} {
		header := keyProofHeader()
		header[member] = "https://evil.example/key"
		err := mustFailKeyProof(t, forgeKeyProof(t, header, keyProofVectorPayloadMap(), keyProofVectorKey()))
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
		forgeKeyProof(t, header, keyProofVectorPayloadMap(), keyProofVectorKey()))); reason != KeyProofFailureHeader {
		t.Fatalf("reason: %s", reason)
	}
}

func TestVerifyKeyProofRejectsMalformedHeaders(t *testing.T) {
	header := keyProofHeader()
	header["alg"] = "none"
	if reason := keyProofReason(t, mustFailKeyProof(t,
		forgeKeyProof(t, header, keyProofVectorPayloadMap(), keyProofVectorKey()))); reason != KeyProofFailureHeader {
		t.Fatalf("alg reason: %s", reason)
	}
	for _, malformed := range []string{"not.a.jws.at.all", "onlyonepart", "a.b"} {
		if reason := keyProofReason(t, mustFailKeyProof(t, malformed)); reason != KeyProofFailureHeader {
			t.Fatalf("%q reason: %s", malformed, reason)
		}
	}
}

func TestVerifyKeyProofPayloadIsClosed(t *testing.T) {
	extra := keyProofVectorPayloadMap()
	extra["intent"] = "send all my money"
	err := mustFailKeyProof(t, forgeKeyProof(t, keyProofHeader(), extra, keyProofVectorKey()))
	if reason := keyProofReason(t, err); reason != KeyProofFailureSchema {
		t.Fatalf("reason: %s", reason)
	}
	if !strings.Contains(err.Error(), "the payload is closed") {
		t.Fatalf("message: %v", err)
	}
}

// TestVerifyKeyProofRejectsANonCanonicalPayload pins the malleability gate. Every
// other check passes on both fixtures — real signature by the named key, right
// typ, right audience, fresh timestamp, exactly the seven members — and what fails
// is that the presented octets are not the canonical serialization of those
// members. Left unchecked, one set of members would have unboundedly many payload
// spellings, and this package would verify payloads production's verifier refuses.
func TestVerifyKeyProofRejectsANonCanonicalPayload(t *testing.T) {
	for _, malleable := range []string{keyProofVectorReorderedJWS, keyProofVectorSpacedJWS} {
		err := mustFailKeyProof(t, malleable)
		if reason := keyProofReason(t, err); reason != KeyProofFailureSchema {
			t.Fatalf("reason: %s", reason)
		}
		if !strings.Contains(err.Error(), "canonical signing input") {
			t.Fatalf("message: %v", err)
		}

		// The members really are the vector's, and the signature really covers the
		// bytes presented — so the refusal is the canonical-bytes gate and nothing else.
		parts := strings.Split(malleable, ".")
		presented, err := Base64urlDecode(parts[1])
		if err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		var members map[string]string
		if err := json.Unmarshal(presented, &members); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		canonical, err := KeyProofSigningInput(KeyProofPayload{
			Nonce:              members["nonce"],
			Audience:           members["audience"],
			DID:                members["did"],
			RoleSet:            members["roleSet"],
			PrevCID:            members["prevCID"],
			PublicKeyMultibase: members["publicKeyMultibase"],
			Timestamp:          members["timestamp"],
		})
		if err != nil {
			t.Fatalf("KeyProofSigningInput: %v", err)
		}
		if string(canonical) != keyProofVectorCanonical {
			t.Fatalf("the fixture does not carry the vector's members: %s", canonical)
		}
		if bytes.Equal(presented, canonical) {
			t.Fatalf("the fixture is canonical after all: %s", presented)
		}
		if !ed25519.Verify(keyProofVectorKey().Public().(ed25519.PublicKey),
			[]byte(parts[0]+"."+parts[1]), mustDecodeKeyProofSignature(t, parts[2])) {
			t.Fatalf("the fixture is not signed over the bytes it presents")
		}
	}

	// ...and the canonical spelling of the same members verifies, so the gate is a
	// byte comparison and not a blanket refusal.
	if _, err := VerifyKeyProof(keyProofVectorJWS, keyProofVectorExpect(), keyProofVectorNow()); err != nil {
		t.Fatalf("canonical vector: %v", err)
	}
}

func TestVerifyKeyProofRejectsMissingAndNonStringMembers(t *testing.T) {
	for _, member := range keyProofMembers {
		partial := keyProofVectorPayloadMap()
		delete(partial, member)
		if reason := keyProofReason(t, mustFailKeyProof(t,
			forgeKeyProof(t, keyProofHeader(), partial, keyProofVectorKey()))); reason != KeyProofFailureSchema {
			t.Fatalf("missing %s reason: %s", member, reason)
		}
	}

	for _, value := range []any{42, nil, true, []int{}, map[string]int{"a": 1}} {
		bad := keyProofVectorPayloadMap()
		bad["nonce"] = value
		if reason := keyProofReason(t, mustFailKeyProof(t,
			forgeKeyProof(t, keyProofHeader(), bad, keyProofVectorKey()))); reason != KeyProofFailureSchema {
			t.Fatalf("non-string nonce %v reason: %s", value, reason)
		}
	}
	// A numeric timestamp is the case a lenient parser would coerce.
	numeric := keyProofVectorPayloadMap()
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

// keyProofCalendarCase is a spelled-correctly timestamp and the instant a
// verifier would be holding when it arrives.
type keyProofCalendarCase struct {
	timestamp string
	unix      int64
}

// TestVerifyKeyProofRejectsANonCalendarTimestamp is the twin contract's sharpest
// edge, from the verify side. time.Parse refuses 2026-02-30 outright, where
// JavaScript's Date.parse NORMALIZES it to March 2 and returns a finite number —
// so a TS verifier checking only finiteness VERIFIED a correctly-signed proof
// this one rejects, which is the one thing two byte-twins may never do. The four
// fixtures below are pinned identically in dfos-protocol/tests/key-proof.spec.ts.
func TestVerifyKeyProofRejectsANonCalendarTimestamp(t *testing.T) {
	for _, tc := range []keyProofCalendarCase{
		{"2026-02-30T00:00:00.000Z", 1772409600}, // February has no 30th
		{"2027-02-29T00:00:00.000Z", 1803859200}, // 2027 is not a leap year
	} {
		payload := keyProofVectorPayloadMap()
		payload["timestamp"] = tc.timestamp
		proof := forgeKeyProof(t, keyProofHeader(), payload, keyProofVectorKey())
		_, err := VerifyKeyProof(proof, keyProofVectorExpect(), time.Unix(tc.unix, 0).UTC())
		if reason := keyProofReason(t, err); reason != KeyProofFailureSchema {
			t.Fatalf("%s reason: %s", tc.timestamp, reason)
		}
	}

	// ...and the neighbouring REAL dates still verify, so the gate is a calendar
	// check and not a blanket refusal of February.
	for _, tc := range []keyProofCalendarCase{
		{"2026-02-28T00:00:00.000Z", 1772236800},
		{"2028-02-29T00:00:00.000Z", 1835395200}, // 2028 IS a leap year
	} {
		payload := keyProofVectorPayloadMap()
		payload["timestamp"] = tc.timestamp
		proof := forgeKeyProof(t, keyProofHeader(), payload, keyProofVectorKey())
		if _, err := VerifyKeyProof(proof, keyProofVectorExpect(), time.Unix(tc.unix, 0).UTC()); err != nil {
			t.Fatalf("%s: expected acceptance, got %v", tc.timestamp, err)
		}
	}
}

// TestKeyProofRefusesAnEmptyPurposeOnBothSides pins the producer and verifier
// halves of one rule: the typ gate is only a gate when the expectation NAMES a
// purpose. An empty expectation byte-equals an artifact carrying "typ":"", so a
// verifier configured with one would admit an envelope scoped to no ceremony at
// all. Both refusals are MISCONFIGURATIONS rather than verdicts — a plain error,
// never wrapping ErrKeyProofInvalid, so a caller branching on Reason cannot read
// a broken deployment as a bad envelope. The TS twin pins the same pair.
func TestKeyProofRefusesAnEmptyPurposeOnBothSides(t *testing.T) {
	input := keyProofVectorSignInput()
	input.Typ = ""
	if _, _, err := SignKeyProof(input); err == nil {
		t.Fatalf("expected SignKeyProof to refuse an empty typ")
	}

	// A REAL signature over a header whose typ is the empty string — the artifact
	// an empty expectation would otherwise wave through.
	proof := forgeKeyProof(t, map[string]any{"alg": "EdDSA", "typ": ""},
		keyProofVectorPayloadMap(), keyProofVectorKey())
	expect := keyProofVectorExpect()
	expect.Typ = ""
	_, err := VerifyKeyProof(proof, expect, keyProofVectorNow())
	if err == nil {
		t.Fatalf("expected VerifyKeyProof to refuse an empty expectation")
	}
	if errors.Is(err, ErrKeyProofInvalid) {
		t.Fatalf("an empty expectation is a misconfiguration, not a proof verdict: %v", err)
	}

	// The chain walk carries the same guard.
	walk := keyProofWalkFor()
	walk.Typ = ""
	if _, err := VerifyChainKeyProof(keyProofVectorJWS, walk); err == nil {
		t.Fatalf("expected VerifyChainKeyProof to refuse an empty expectation")
	} else if errors.Is(err, ErrKeyProofInvalid) {
		t.Fatalf("an empty expectation is a misconfiguration, not a proof verdict: %v", err)
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

// TestVerifyKeyProofPositionalArms pins each of the three positional arms alone.
// Every other gate passes, so the reason names the arm — a proof collected for one
// chain, one role set, or one head is not spendable at another, and each refusal
// is separately observable.
func TestVerifyKeyProofPositionalArms(t *testing.T) {
	expect := keyProofVectorExpect()
	expect.DID = "did:dfos:someotherchain00000000000000"
	if reason := keyProofReason(t, mustFailKeyProofWith(t, keyProofVectorJWS, expect)); reason != KeyProofFailureDID {
		t.Fatalf("did reason: %s", reason)
	}

	expect = keyProofVectorExpect()
	expect.RoleSet = "auth"
	if reason := keyProofReason(t, mustFailKeyProofWith(t, keyProofVectorJWS, expect)); reason != KeyProofFailureRoleSet {
		t.Fatalf("roleSet reason: %s", reason)
	}

	expect = keyProofVectorExpect()
	expect.PrevCID = "bafyreibfuh63uv33i2i5eooe3boit2ruyjehubsryemuuz6mrtlej26rei"
	if reason := keyProofReason(t, mustFailKeyProofWith(t, keyProofVectorJWS, expect)); reason != KeyProofFailurePrevCID {
		t.Fatalf("prevCID reason: %s", reason)
	}
}

// TestVerifyKeyProofRoleSetIsEqualityNotCoverage: the holder consented to all
// three roles; the ceremony is writing two. That is the holder conceding more than
// was asked, and a completing authority has no business banking the difference.
func TestVerifyKeyProofRoleSetIsEqualityNotCoverage(t *testing.T) {
	if reason := keyProofReason(t, mustFailKeyProof(t, keyProofVectorFullRoleSetJWS)); reason != KeyProofFailureRoleSet {
		t.Fatalf("reason: %s", reason)
	}
	// Under the matching expectation the very same envelope verifies.
	expect := keyProofVectorExpect()
	expect.RoleSet = "auth,assert,controller"
	if _, err := VerifyKeyProof(keyProofVectorFullRoleSetJWS, expect, keyProofVectorNow()); err != nil {
		t.Fatalf("matching expectation: %v", err)
	}
	// ...and the chain walk reads it the OTHER way: coverage, one role at a time.
	for _, role := range KeyRoles {
		walk := keyProofWalkFor()
		walk.Role = role
		if _, err := VerifyChainKeyProof(keyProofVectorFullRoleSetJWS, walk); err != nil {
			t.Fatalf("walk %s: %v", role, err)
		}
	}
}

// TestVerifyKeyProofRefusesEmptyPositionalExpectations: an arm compared against an
// empty string binds nothing while reading as present, which is exactly the
// standing consent the members exist to close. A plain error, never a
// *KeyProofError — a broken deployment must not be mistakable for a bad envelope.
func TestVerifyKeyProofRefusesEmptyPositionalExpectations(t *testing.T) {
	cases := map[string]func(*KeyProofExpectations){
		"Audience": func(e *KeyProofExpectations) { e.Audience = "" },
		"DID":      func(e *KeyProofExpectations) { e.DID = "" },
		"PrevCID":  func(e *KeyProofExpectations) { e.PrevCID = "" },
	}
	for _, roleSet := range []string{"", "assert,auth", "auth, assert", "owner"} {
		cases["RoleSet="+roleSet] = func(e *KeyProofExpectations) { e.RoleSet = roleSet }
	}
	for name, mutate := range cases {
		expect := keyProofVectorExpect()
		mutate(&expect)
		_, err := VerifyKeyProof(keyProofVectorJWS, expect, keyProofVectorNow())
		if err == nil {
			t.Fatalf("%s: expected a rejection", name)
		}
		if errors.Is(err, ErrKeyProofInvalid) {
			t.Fatalf("%s: a misconfiguration was reported as an invalid proof: %v", name, err)
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
	mismatched := forgeKeyProof(t, keyProofHeader(), keyProofVectorPayloadMap(), keyProofOtherKey())
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

// TestVerifyKeyProofRejectsATamperedPayloadSegment: canonical bytes for a
// DIFFERENT nonce, carried under the vector's header and the vector's signature.
// Every schema gate passes; the signature is what refuses it.
func TestVerifyKeyProofRejectsATamperedPayloadSegment(t *testing.T) {
	swappedPayload := keyProofVectorPayload()
	swappedPayload.Nonce = "nonce-key-proof-vector-0002"
	canonical, err := KeyProofSigningInput(swappedPayload)
	if err != nil {
		t.Fatalf("KeyProofSigningInput: %v", err)
	}
	parts := strings.Split(keyProofVectorJWS, ".")
	swapped := parts[0] + "." + Base64urlEncode(canonical) + "." + parts[2]
	if reason := keyProofReason(t, mustFailKeyProof(t, swapped)); reason != KeyProofFailureSignature {
		t.Fatalf("reason: %s", reason)
	}
}

func TestVerifyKeyProofRejectsUndecodableKeysAndSignatures(t *testing.T) {
	for _, multibase := range []string{"zNotAMultikey", "z6Mk", "not-multibase"} {
		bad := keyProofVectorPayloadMap()
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
// chain-walk verification — the same envelope, read from a different position
// -----------------------------------------------------------------------------

func TestVerifyChainKeyProofVerifiesAPosition(t *testing.T) {
	payload, err := VerifyChainKeyProof(keyProofVectorJWS, keyProofWalkFor())
	if err != nil {
		t.Fatalf("VerifyChainKeyProof: %v", err)
	}
	if *payload != keyProofVectorPayload() {
		t.Fatalf("payload: %+v", *payload)
	}
	// The two transport members ride along, verbatim and unchecked.
	if payload.Nonce != keyProofVectorNonce || payload.Audience != keyProofVectorAudience {
		t.Fatalf("transport members did not travel: %+v", *payload)
	}
}

// TestVerifyChainKeyProofChecksNeitherFreshnessNorAudience: a DECADE past the
// timestamp. Presentation-time refuses this on freshness; the walk does not,
// because a chain that expired would be a chain no one could replay. There is no
// clock parameter and no audience parameter here at all — the absence is the
// contract.
func TestVerifyChainKeyProofChecksNeitherFreshnessNorAudience(t *testing.T) {
	if _, err := VerifyChainKeyProof(keyProofVectorJWS, keyProofWalkFor()); err != nil {
		t.Fatalf("walk: %v", err)
	}
	_, err := VerifyKeyProof(keyProofVectorJWS, keyProofVectorExpect(),
		time.Unix(keyProofVectorUnix+315_360_000, 0).UTC())
	if reason := keyProofReason(t, err); reason != KeyProofFailureFreshness {
		t.Fatalf("presentation-time reason: %s", reason)
	}
}

func TestVerifyChainKeyProofRefusesAnotherKeyChainHeadOrRole(t *testing.T) {
	// The key arm: an honest, fully valid envelope — for the other key.
	if _, err := VerifyChainKeyProof(keyProofVectorOtherKeyJWS, keyProofWalkFor()); err == nil {
		t.Fatalf("an envelope for another key was admitted")
	} else if reason := keyProofReason(t, err); reason != KeyProofFailureKey {
		t.Fatalf("key reason: %s", reason)
	}

	walk := keyProofWalkFor()
	walk.DID = "did:dfos:someotherchain00000000000000"
	if _, err := VerifyChainKeyProof(keyProofVectorJWS, walk); err == nil {
		t.Fatalf("an envelope for another chain was admitted")
	} else if reason := keyProofReason(t, err); reason != KeyProofFailureDID {
		t.Fatalf("did reason: %s", reason)
	}

	// THE STANDING-CONSENT ARM. Same key, same chain, same roles — a head that has
	// moved on. This is what makes a re-add or a promotion need a FRESH envelope.
	walk = keyProofWalkFor()
	walk.PrevCID = "bafyreibfuh63uv33i2i5eooe3boit2ruyjehubsryemuuz6mrtlej26rei"
	if _, err := VerifyChainKeyProof(keyProofVectorJWS, walk); err == nil {
		t.Fatalf("an envelope bound to another head was admitted")
	} else if reason := keyProofReason(t, err); reason != KeyProofFailurePrevCID {
		t.Fatalf("prevCID reason: %s", reason)
	}

	// Coverage: the vector consents to auth and assert, so controller is uncovered.
	walk = keyProofWalkFor()
	walk.Role = "controller"
	if _, err := VerifyChainKeyProof(keyProofVectorJWS, walk); err == nil {
		t.Fatalf("an uncovered role was admitted")
	} else if reason := keyProofReason(t, err); reason != KeyProofFailureRoleSet {
		t.Fatalf("roleSet reason: %s", reason)
	}
	for _, role := range []KeyRole{"auth", "assert"} {
		walk = keyProofWalkFor()
		walk.Role = role
		if _, err := VerifyChainKeyProof(keyProofVectorJWS, walk); err != nil {
			t.Fatalf("covered role %s: %v", role, err)
		}
	}
}

// TestVerifyChainKeyProofAppliesTheSameArtifactGates: size, header, closed schema
// and canonical bytes are properties of the artifact, not of the reader's
// position, so both modes refuse identically.
func TestVerifyChainKeyProofAppliesTheSameArtifactGates(t *testing.T) {
	failWalk := func(proof string) error {
		t.Helper()
		payload, err := VerifyChainKeyProof(proof, keyProofWalkFor())
		if err == nil {
			t.Fatalf("expected a rejection, got %+v", payload)
		}
		return err
	}

	if reason := keyProofReason(t, failWalk(strings.Repeat("a", MaxKeyProofSize+1))); reason != KeyProofFailureSize {
		t.Fatalf("size reason: %s", reason)
	}
	if reason := keyProofReason(t, failWalk(keyProofVectorOtherTypJWS)); reason != KeyProofFailureHeader {
		t.Fatalf("typ reason: %s", reason)
	}
	for _, malleable := range []string{keyProofVectorReorderedJWS, keyProofVectorSpacedJWS} {
		if reason := keyProofReason(t, failWalk(malleable)); reason != KeyProofFailureSchema {
			t.Fatalf("malleability reason: %s", reason)
		}
	}
	header := keyProofHeader()
	header["kid"] = keyProofVectorDID + "#key_0"
	if reason := keyProofReason(t, failWalk(
		forgeKeyProof(t, header, keyProofVectorPayloadMap(), keyProofVectorKey()))); reason != KeyProofFailureHeader {
		t.Fatalf("kid reason: %s", reason)
	}
	extra := keyProofVectorPayloadMap()
	extra["intent"] = "send all my money"
	if reason := keyProofReason(t, failWalk(
		forgeKeyProof(t, keyProofHeader(), extra, keyProofVectorKey()))); reason != KeyProofFailureSchema {
		t.Fatalf("closed-payload reason: %s", reason)
	}
	// ...and the signature, against the key the payload names.
	mismatched := forgeKeyProof(t, keyProofHeader(), keyProofVectorPayloadMap(), keyProofOtherKey())
	if reason := keyProofReason(t, failWalk(mismatched)); reason != KeyProofFailureSignature {
		t.Fatalf("signature reason: %s", reason)
	}
}

// TestUnsafeKeyProofSubjectIsAHintAndNothingMore pins the index hint: it reads the
// named key out of unverified bytes, and answers false when there is no string
// there. It proves nothing about the key — VerifyChainKeyProof's own key arm is
// what makes routing by this value sound.
func TestUnsafeKeyProofSubjectIsAHintAndNothingMore(t *testing.T) {
	subject, ok := UnsafeKeyProofSubject(keyProofVectorJWS)
	if !ok || subject != keyProofVectorMultibase {
		t.Fatalf("subject: %q %v", subject, ok)
	}
	// It does not verify: a proof signed by the WRONG key still names its subject.
	mismatched := forgeKeyProof(t, keyProofHeader(), keyProofVectorPayloadMap(), keyProofOtherKey())
	if subject, ok := UnsafeKeyProofSubject(mismatched); !ok || subject != keyProofVectorMultibase {
		t.Fatalf("unverified subject: %q %v", subject, ok)
	}
	for _, bad := range []string{"", "onlyonepart", "a.b", "a.!!!!.c"} {
		if _, ok := UnsafeKeyProofSubject(bad); ok {
			t.Fatalf("%q: expected no subject", bad)
		}
	}
	missing := keyProofVectorPayloadMap()
	delete(missing, "publicKeyMultibase")
	if _, ok := UnsafeKeyProofSubject(
		forgeKeyProof(t, keyProofHeader(), missing, keyProofVectorKey())); ok {
		t.Fatalf("expected no subject when the member is absent")
	}
	numeric := keyProofVectorPayloadMap()
	numeric["publicKeyMultibase"] = 7
	if _, ok := UnsafeKeyProofSubject(
		forgeKeyProof(t, keyProofHeader(), numeric, keyProofVectorKey())); ok {
		t.Fatalf("expected no subject when the member is not a string")
	}
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

// keyProofVectorPayloadMap is the vector payload as a mutable map, for the forged
// negatives.
func keyProofVectorPayloadMap() map[string]any {
	return map[string]any{
		"nonce":              keyProofVectorNonce,
		"audience":           keyProofVectorAudience,
		"did":                keyProofVectorDID,
		"roleSet":            keyProofVectorRoleSet,
		"prevCID":            keyProofVectorPrevCID,
		"publicKeyMultibase": keyProofVectorMultibase,
		"timestamp":          keyProofVectorTimestamp,
	}
}

func mustDecodeKeyProofSignature(t *testing.T, segment string) []byte {
	t.Helper()
	signature, err := Base64urlDecode(segment)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	return signature
}

func mustFailKeyProof(t *testing.T, proof string) error {
	t.Helper()
	return mustFailKeyProofWith(t, proof, keyProofVectorExpect())
}

func mustFailKeyProofWith(t *testing.T, proof string, expect KeyProofExpectations) error {
	t.Helper()
	verified, err := VerifyKeyProof(proof, expect, keyProofVectorNow())
	if err == nil {
		t.Fatalf("expected a rejection, got %+v", verified)
	}
	return err
}
