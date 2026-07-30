package dfos

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// Twin of dfos-protocol/tests/credit-claim.spec.ts. Same cases, same verdicts.

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type creditClaimant struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	did  string
	kid  string
}

func makeClaimant(seed string) creditClaimant {
	priv, pub := deriveTestKey(seed)
	did := "did:dfos:" + DeriveID([]byte(seed+"-did"))
	return creditClaimant{priv: priv, pub: pub, did: did, kid: did + "#" + "key_" + DeriveID([]byte(seed+"-key"))}
}

func deriveTestKey(seed string) (ed25519.PrivateKey, ed25519.PublicKey) {
	h := DeriveID([]byte(seed))
	s := make([]byte, ed25519.SeedSize)
	copy(s, h)
	priv := ed25519.NewKeyFromSeed(s)
	return priv, priv.Public().(ed25519.PublicKey)
}

// resolverFor resolves any kid to the given key — the claim's kid↔did check is
// what binds the key to the claimant, so the test resolver stays trivial.
func resolverFor(pub ed25519.PublicKey) KeyResolver {
	return func(kid string) (ed25519.PublicKey, error) { return pub, nil }
}

func testContentID(seed string) string {
	return DeriveID([]byte(seed))
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

func TestCreditClaimRoundTrip(t *testing.T) {
	claimant := makeClaimant("credit-claim-roundtrip")
	contentID := testContentID("chain-a")

	jwsToken, claimCID, err := SignCreditClaim(claimant.did, contentID, "photography", claimant.kid, claimant.priv)
	if err != nil {
		t.Fatalf("SignCreditClaim: %v", err)
	}
	if strings.Count(jwsToken, ".") != 2 {
		t.Fatalf("expected a 3-part JWS, got %q", jwsToken)
	}

	result, err := VerifyCreditClaim(jwsToken, resolverFor(claimant.pub))
	if err != nil {
		t.Fatalf("VerifyCreditClaim: %v", err)
	}
	if result.DID != claimant.did {
		t.Errorf("did: got %q want %q", result.DID, claimant.did)
	}
	if result.ContentID != contentID {
		t.Errorf("contentId: got %q want %q", result.ContentID, contentID)
	}
	if result.Role != "photography" {
		t.Errorf("role: got %q want %q", result.Role, "photography")
	}
	if result.ClaimCID != claimCID {
		t.Errorf("claimCID: got %q want %q", result.ClaimCID, claimCID)
	}
	if result.SignerKeyId != claimant.kid {
		t.Errorf("signerKeyId: got %q want %q", result.SignerKeyId, claimant.kid)
	}
	// millisecond-precision UTC, the one createdAt grammar. (The TS twin's signer
	// additionally zeroes the ms component; both forms are conforming and both
	// verify on either implementation — the grammar is what is normative.)
	if err := validateCreatedAt(result.CreatedAt); err != nil {
		t.Errorf("createdAt %q: %v", result.CreatedAt, err)
	}
	if result.AsOfDocumentCID != "" {
		t.Errorf("asOfDocumentCID: got %q want empty", result.AsOfDocumentCID)
	}
}

func TestCreditClaimAsOfDocumentCID(t *testing.T) {
	claimant := makeClaimant("credit-claim-asof")
	asOf := "bafyrei" + strings.Repeat("a", 52)

	jwsToken, _, err := SignCreditClaimWithAsOf(claimant.did, testContentID("chain-b"), "author", asOf, claimant.kid, claimant.priv)
	if err != nil {
		t.Fatalf("SignCreditClaimWithAsOf: %v", err)
	}

	result, err := VerifyCreditClaim(jwsToken, resolverFor(claimant.pub))
	if err != nil {
		t.Fatalf("VerifyCreditClaim: %v", err)
	}
	if result.AsOfDocumentCID != asOf {
		t.Errorf("asOfDocumentCID: got %q want %q", result.AsOfDocumentCID, asOf)
	}
}

// An empty asOfDocumentCID is omitted from the payload, so it must encode
// identically to a claim that never carried the field (CID-neutral).
func TestCreditClaimEmptyAsOfIsCIDNeutral(t *testing.T) {
	claimant := makeClaimant("credit-claim-cid-neutral")
	contentID := testContentID("chain-neutral")

	payload := map[string]any{
		"version":   1,
		"type":      "credit-claim",
		"contentId": contentID,
		"did":       claimant.did,
		"role":      "author",
		"createdAt": "2026-03-07T00:00:00.000Z",
	}
	_, _, bare, err := DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}

	payload["asOfDocumentCID"] = ""
	_, _, withEmpty, err := DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}
	if bare == withEmpty {
		t.Fatal("an empty-string asOfDocumentCID must NOT encode like an absent one — the signer omits the key entirely")
	}
}

// Cross-language byte parity. The same fixed payload is encoded in the TS twin
// (credit-claim.spec.ts, "cross-language byte parity") and MUST derive these exact
// CIDs. A divergence here means the two implementations disagree on claim bytes,
// which forks claim identity — so this literal is normative, not a snapshot to
// re-bless when it breaks.
func TestCreditClaimCIDParityVector(t *testing.T) {
	payload := map[string]any{
		"version":   1,
		"type":      "credit-claim",
		"contentId": "cv7n8vkvr64cctf3294h9k4eanhff8z",
		"did":       "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
		"role":      "photography",
		"createdAt": "2026-03-07T00:00:00.000Z",
	}
	_, _, cid, err := DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}
	if cid != creditClaimParityCID {
		t.Errorf("bare claim CID: got %q want %q", cid, creditClaimParityCID)
	}

	payload["asOfDocumentCID"] = creditClaimParityAsOf
	_, _, cidWithAsOf, err := DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}
	if cidWithAsOf != creditClaimParityAsOfCID {
		t.Errorf("asOf claim CID: got %q want %q", cidWithAsOf, creditClaimParityAsOfCID)
	}
}

const (
	creditClaimParityCID     = "bafyreih4ge62ips6u6ek3y6sg2a6xlwuciz5njqftcxfoytfius4lekohq"
	creditClaimParityAsOf    = "bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne"
	creditClaimParityAsOfCID = "bafyreihgzssoutaannyjdvnymcerl6pe5zhx5jeb576igp777so2qmdcri"
)

func TestCreditClaimRejectsKidDIDMismatch(t *testing.T) {
	claimant := makeClaimant("credit-claim-kid-claimant")
	other := makeClaimant("credit-claim-kid-other")

	// hand-build a claim signed under other's kid while naming claimant in the
	// payload — the "someone else claims your credit for you" shape
	payload := map[string]any{
		"version":   1,
		"type":      "credit-claim",
		"contentId": testContentID("chain-c"),
		"did":       claimant.did,
		"role":      "author",
		"createdAt": "2026-03-07T00:00:00.000Z",
	}
	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}
	jwsToken, err := CreateJWS(JWSHeader{Alg: "EdDSA", Typ: "did:dfos:credit-claim", Kid: other.kid, CID: cidStr}, payload, other.priv)
	if err != nil {
		t.Fatalf("CreateJWS: %v", err)
	}

	_, err = VerifyCreditClaim(jwsToken, resolverFor(other.pub))
	if err == nil || !strings.Contains(err.Error(), "kid DID does not match payload did") {
		t.Fatalf("expected kid/did mismatch rejection, got %v", err)
	}
}

func TestCreditClaimRejectsWrongSignature(t *testing.T) {
	claimant := makeClaimant("credit-claim-sig-claimant")
	impostor := makeClaimant("credit-claim-sig-impostor")

	jwsToken, _, err := SignCreditClaim(claimant.did, testContentID("chain-d"), "author", claimant.kid, claimant.priv)
	if err != nil {
		t.Fatalf("SignCreditClaim: %v", err)
	}

	_, err = VerifyCreditClaim(jwsToken, resolverFor(impostor.pub))
	if err == nil || !strings.Contains(err.Error(), "invalid credit claim signature") {
		t.Fatalf("expected signature rejection, got %v", err)
	}
}

func TestCreditClaimRejectsWrongTyp(t *testing.T) {
	claimant := makeClaimant("credit-claim-typ")

	payload := map[string]any{
		"version":   1,
		"type":      "credit-claim",
		"contentId": testContentID("chain-e"),
		"did":       claimant.did,
		"role":      "author",
		"createdAt": "2026-03-07T00:00:00.000Z",
	}
	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}
	jwsToken, err := CreateJWS(JWSHeader{Alg: "EdDSA", Typ: "did:dfos:revocation", Kid: claimant.kid, CID: cidStr}, payload, claimant.priv)
	if err != nil {
		t.Fatalf("CreateJWS: %v", err)
	}

	_, err = VerifyCreditClaim(jwsToken, resolverFor(claimant.pub))
	if err == nil || !strings.Contains(err.Error(), "invalid credit claim typ") {
		t.Fatalf("expected typ rejection, got %v", err)
	}
}

func TestCreditClaimRejectsCIDMismatch(t *testing.T) {
	claimant := makeClaimant("credit-claim-cid")

	payload := map[string]any{
		"version":   1,
		"type":      "credit-claim",
		"contentId": testContentID("chain-f"),
		"did":       claimant.did,
		"role":      "author",
		"createdAt": "2026-03-07T00:00:00.000Z",
	}
	// sign a header carrying the CID of a DIFFERENT payload — the signature is
	// valid over these exact bytes, so only CID re-derivation catches it
	decoy := map[string]any{}
	for k, v := range payload {
		decoy[k] = v
	}
	decoy["role"] = "editor"
	_, _, decoyCID, err := DagCborCID(decoy)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}
	jwsToken, err := CreateJWS(JWSHeader{Alg: "EdDSA", Typ: "did:dfos:credit-claim", Kid: claimant.kid, CID: decoyCID}, payload, claimant.priv)
	if err != nil {
		t.Fatalf("CreateJWS: %v", err)
	}

	_, err = VerifyCreditClaim(jwsToken, resolverFor(claimant.pub))
	if err == nil || !strings.Contains(err.Error(), "credit claim cid mismatch") {
		t.Fatalf("expected cid mismatch rejection, got %v", err)
	}
}

func TestCreditClaimRejectsOversizedToken(t *testing.T) {
	claimant := makeClaimant("credit-claim-size")

	// role carries no separate length cap — the aggregate token cap is the single
	// byte arbiter, so an oversized role is what trips it
	jwsToken, _, err := SignCreditClaim(claimant.did, testContentID("chain-g"), strings.Repeat("x", maxCreditClaimSize+1), claimant.kid, claimant.priv)
	if err != nil {
		t.Fatalf("SignCreditClaim: %v", err)
	}
	if len(jwsToken) <= maxCreditClaimSize {
		t.Fatalf("expected an oversized token, got %d bytes", len(jwsToken))
	}

	_, err = VerifyCreditClaim(jwsToken, resolverFor(claimant.pub))
	if err == nil || !strings.Contains(err.Error(), "credit claim exceeds max size") {
		t.Fatalf("expected size rejection, got %v", err)
	}
}

func TestCreditClaimRejectsMalformedJWS(t *testing.T) {
	claimant := makeClaimant("credit-claim-malformed")

	_, err := VerifyCreditClaim("not-a-jws", resolverFor(claimant.pub))
	if err == nil || !strings.Contains(err.Error(), "failed to decode credit claim JWS") {
		t.Fatalf("expected decode rejection, got %v", err)
	}
}

func TestCreditClaimRejectsNonContentIDBinder(t *testing.T) {
	claimant := makeClaimant("credit-claim-binder-shape")

	// an artifact CID is immutable and chainless — it can never host a credits
	// slot, so it is not a legal binder
	_, _, err := SignCreditClaim(claimant.did, "bafyrei"+strings.Repeat("a", 52), "author", claimant.kid, claimant.priv)
	if err == nil || !strings.Contains(err.Error(), "contentId must be a 31-char content chain id") {
		t.Fatalf("expected binder-shape rejection, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// contentId binding (anti-replay)
// ---------------------------------------------------------------------------

func TestCreditClaimBoundAcceptsMatchingContentID(t *testing.T) {
	claimant := makeClaimant("credit-claim-bound-ok")
	contentID := testContentID("chain-h")

	jwsToken, _, err := SignCreditClaim(claimant.did, contentID, "author", claimant.kid, claimant.priv)
	if err != nil {
		t.Fatalf("SignCreditClaim: %v", err)
	}

	result, err := VerifyCreditClaimBound(jwsToken, resolverFor(claimant.pub), contentID)
	if err != nil {
		t.Fatalf("VerifyCreditClaimBound: %v", err)
	}
	if result.ContentID != contentID {
		t.Errorf("contentId: got %q want %q", result.ContentID, contentID)
	}
}

func TestCreditClaimBoundRejectsReplayIntoAnotherChain(t *testing.T) {
	claimant := makeClaimant("credit-claim-bound-replay")

	jwsToken, _, err := SignCreditClaim(claimant.did, testContentID("chain-i"), "author", claimant.kid, claimant.priv)
	if err != nil {
		t.Fatalf("SignCreditClaim: %v", err)
	}

	_, err = VerifyCreditClaimBound(jwsToken, resolverFor(claimant.pub), testContentID("chain-j"))
	if err == nil || !strings.Contains(err.Error(), "does not match expected") {
		t.Fatalf("expected binder rejection, got %v", err)
	}
}
