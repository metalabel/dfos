package dfos

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

// Twin of dfos-protocol/tests/credit-claim.spec.ts. Same cases, same verdicts.

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type creditClaimant struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	did   string
	keyID string
	kid   string
}

func makeClaimant(seed string) creditClaimant {
	priv, pub := deriveTestKey(seed)
	did := "did:dfos:" + DeriveID([]byte(seed+"-did"))
	keyID := "key_" + DeriveID([]byte(seed+"-key"))
	return creditClaimant{priv: priv, pub: pub, did: did, keyID: keyID, kid: did + "#" + keyID}
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

// failingResolver stands in for an unreachable relay.
func failingResolver() KeyResolver {
	return func(kid string) (ed25519.PublicKey, error) {
		return nil, errors.New("relay unreachable")
	}
}

func testContentID(seed string) string {
	return DeriveID([]byte(seed))
}

// signRaw builds a claim JWS from an arbitrary payload map, bypassing the signer's
// validation. Used to probe what the VERIFIER accepts for payloads a conforming
// signer would never mint.
func signRaw(t *testing.T, c creditClaimant, payload map[string]any) string {
	t.Helper()
	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}
	token, err := CreateJWS(JWSHeader{Alg: "EdDSA", Typ: "did:dfos:credit-claim", Kid: c.kid, CID: cidStr}, payload, c.priv)
	if err != nil {
		t.Fatalf("CreateJWS: %v", err)
	}
	return token
}

func basePayload(c creditClaimant, contentID string) map[string]any {
	return map[string]any{
		"version":   1,
		"type":      "credit-claim",
		"contentId": contentID,
		"did":       c.did,
		"role":      "author",
		"createdAt": "2026-03-07T00:00:00.000Z",
	}
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

func TestCreditClaimRoundTrip(t *testing.T) {
	claimant := makeClaimant("credit-claim-roundtrip")
	contentID := testContentID("chain-a")

	jwsToken, claimCID, err := SignCreditClaim(claimant.did, contentID, "photography", claimant.keyID, claimant.priv)
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
	if result.AsOfDocumentCID != "" {
		t.Errorf("asOfDocumentCID: got %q want empty", result.AsOfDocumentCID)
	}
}

// The signer derives kid from (did, keyID), so a kid↔did mismatch is
// unrepresentable at sign time — parity with the TS twin.
func TestCreditClaimSignerDerivesKid(t *testing.T) {
	claimant := makeClaimant("credit-claim-derives-kid")

	jwsToken, _, err := SignCreditClaim(claimant.did, testContentID("chain-kid"), "author", claimant.keyID, claimant.priv)
	if err != nil {
		t.Fatalf("SignCreditClaim: %v", err)
	}
	header, _, err := DecodeJWSUnsafe(jwsToken)
	if err != nil {
		t.Fatalf("DecodeJWSUnsafe: %v", err)
	}
	if header.Kid != claimant.did+"#"+claimant.keyID {
		t.Errorf("kid: got %q want %q", header.Kid, claimant.did+"#"+claimant.keyID)
	}
}

// createdAt zeroes the millisecond component, per the signRevocation convention
// the TS twin follows. A signer emitting real milliseconds would produce claims
// that differ in bytes from the TS twin for the same logical statement.
func TestCreditClaimCreatedAtIsSecondTruncated(t *testing.T) {
	claimant := makeClaimant("credit-claim-truncate")

	jwsToken, _, err := SignCreditClaim(claimant.did, testContentID("chain-trunc"), "author", claimant.keyID, claimant.priv)
	if err != nil {
		t.Fatalf("SignCreditClaim: %v", err)
	}
	result, err := VerifyCreditClaim(jwsToken, resolverFor(claimant.pub))
	if err != nil {
		t.Fatalf("VerifyCreditClaim: %v", err)
	}
	if !strings.HasSuffix(result.CreatedAt, ".000Z") {
		t.Errorf("createdAt not second-truncated: %q", result.CreatedAt)
	}
	if err := validateCreatedAt(result.CreatedAt); err != nil {
		t.Errorf("createdAt %q: %v", result.CreatedAt, err)
	}
}

// A CreatedAt override makes signing deterministic, so a previously issued
// claim's exact bytes can be re-derived rather than re-minted.
func TestCreditClaimCreatedAtOverrideIsDeterministic(t *testing.T) {
	claimant := makeClaimant("credit-claim-createdat")
	contentID := testContentID("chain-det")
	at := time.Date(2026, 3, 7, 0, 0, 0, 0, time.UTC)

	first, firstCID, err := SignCreditClaimWithOptions(claimant.did, contentID, "author", claimant.keyID, claimant.priv, CreditClaimOptions{CreatedAt: at})
	if err != nil {
		t.Fatalf("SignCreditClaimWithOptions: %v", err)
	}
	second, secondCID, err := SignCreditClaimWithOptions(claimant.did, contentID, "author", claimant.keyID, claimant.priv, CreditClaimOptions{CreatedAt: at})
	if err != nil {
		t.Fatalf("SignCreditClaimWithOptions: %v", err)
	}
	if first != second {
		t.Error("same inputs must re-derive byte-identical tokens")
	}
	if firstCID != secondCID {
		t.Errorf("claim CIDs diverged: %q vs %q", firstCID, secondCID)
	}
}

// createdAt is inside the signed payload, so it is part of the claim CID. An
// override carrying real milliseconds through on one implementation but not the
// other would fork claim identity, so BOTH signers truncate to whole seconds. The
// assertion anchors on the cross-language parity CID: signing the parity payload's
// fields with a .777 override MUST land on the same claim CID as the .000Z vector,
// which is what "the override is normalized" means. The TS twin asserts the same
// literal from the same override ("should normalize a createdAt override to whole
// seconds").
func TestCreditClaimCreatedAtOverrideIsNormalized(t *testing.T) {
	claimant := makeClaimant("credit-claim-normalize")
	at := time.Date(2026, 3, 7, 0, 0, 0, 777_000_000, time.UTC)

	_, claimCID, err := SignCreditClaimWithOptions(
		"did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
		"cv7n8vkvr64cctf3294h9k4eanhff8z",
		"photography",
		claimant.keyID,
		claimant.priv,
		CreditClaimOptions{CreatedAt: at},
	)
	if err != nil {
		t.Fatalf("SignCreditClaimWithOptions: %v", err)
	}
	if claimCID != creditClaimParityCID {
		t.Errorf("claim CID: got %q want %q — a createdAt override must be truncated to whole seconds", claimCID, creditClaimParityCID)
	}
}

func TestCreditClaimAsOfDocumentCID(t *testing.T) {
	claimant := makeClaimant("credit-claim-asof")
	asOf := "bafyrei" + strings.Repeat("a", 52)

	jwsToken, _, err := SignCreditClaimWithAsOf(claimant.did, testContentID("chain-b"), "author", asOf, claimant.keyID, claimant.priv)
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

// An empty asOf is an ERROR at sign time, not a silent omission: the
// empty-string shape is a different signed encoding from an absent field, so
// minting it would produce a claim both verifiers reject.
func TestCreditClaimSignRejectsEmptyAsOf(t *testing.T) {
	claimant := makeClaimant("credit-claim-empty-asof")

	_, _, err := SignCreditClaimWithAsOf(claimant.did, testContentID("chain-empty-asof"), "author", "", claimant.keyID, claimant.priv)
	if err == nil || !strings.Contains(err.Error(), "asOfDocumentCID must be non-empty when present") {
		t.Fatalf("expected empty-asOf rejection, got %v", err)
	}
}

// A present-but-non-string asOfDocumentCID must be REJECTED, not coerced to "".
// This is the exact payload a nullable-optional producer emits, and coercing it
// forked the verdict against the TS twin (which rejects it via zod).
func TestCreditClaimRejectsNonStringAsOf(t *testing.T) {
	claimant := makeClaimant("credit-claim-asof-types")

	for _, bad := range []any{nil, 42, "", true} {
		payload := basePayload(claimant, testContentID("chain-asof-type"))
		payload["asOfDocumentCID"] = bad
		token := signRaw(t, claimant, payload)

		_, err := VerifyCreditClaim(token, resolverFor(claimant.pub))
		if err == nil {
			t.Errorf("asOfDocumentCID=%#v: expected rejection, got nil", bad)
			continue
		}
		if !errors.Is(err, ErrCreditClaimInvalid) {
			t.Errorf("asOfDocumentCID=%#v: want ErrCreditClaimInvalid, got %v", bad, err)
		}
		if !strings.Contains(err.Error(), "asOfDocumentCID must be a non-empty string when present") {
			t.Errorf("asOfDocumentCID=%#v: unexpected message %v", bad, err)
		}
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
	// payload — the "someone else claims your credit for you" shape. The signer
	// can no longer produce this, so it must be forged directly.
	payload := basePayload(claimant, testContentID("chain-c"))
	token := signRaw(t, other, payload)

	_, err := VerifyCreditClaim(token, resolverFor(other.pub))
	if err == nil || !strings.Contains(err.Error(), "kid DID does not match payload did") {
		t.Fatalf("expected kid/did mismatch rejection, got %v", err)
	}
	if !errors.Is(err, ErrCreditClaimInvalid) {
		t.Errorf("want ErrCreditClaimInvalid, got %v", err)
	}
}

func TestCreditClaimRejectsNonDIDClaimant(t *testing.T) {
	claimant := makeClaimant("credit-claim-nondid")

	payload := basePayload(claimant, testContentID("chain-nondid"))
	payload["did"] = strings.TrimPrefix(claimant.did, "did:dfos:")
	token := signRaw(t, claimant, payload)

	_, err := VerifyCreditClaim(token, resolverFor(claimant.pub))
	if err == nil || !strings.Contains(err.Error(), "did must be a DID (did: prefix)") {
		t.Fatalf("expected non-DID rejection, got %v", err)
	}

	// and the signer refuses it too
	if _, _, err := SignCreditClaim("not-a-did", testContentID("chain-nondid2"), "author", claimant.keyID, claimant.priv); err == nil {
		t.Error("signer must refuse a non-DID claimant")
	}
}

func TestCreditClaimRejectsWrongSignature(t *testing.T) {
	claimant := makeClaimant("credit-claim-sig-claimant")
	impostor := makeClaimant("credit-claim-sig-impostor")

	jwsToken, _, err := SignCreditClaim(claimant.did, testContentID("chain-d"), "author", claimant.keyID, claimant.priv)
	if err != nil {
		t.Fatalf("SignCreditClaim: %v", err)
	}

	_, err = VerifyCreditClaim(jwsToken, resolverFor(impostor.pub))
	if err == nil || !strings.Contains(err.Error(), "invalid credit claim signature") {
		t.Fatalf("expected signature rejection, got %v", err)
	}
	if !errors.Is(err, ErrCreditClaimInvalid) {
		t.Errorf("want ErrCreditClaimInvalid, got %v", err)
	}
}

// A resolver that fails is "could not check", never "checked and failed" — a
// network failure must not be presented as a bad signature.
func TestCreditClaimResolverFailureIsUnverifiable(t *testing.T) {
	claimant := makeClaimant("credit-claim-unresolvable")

	jwsToken, _, err := SignCreditClaim(claimant.did, testContentID("chain-unres"), "author", claimant.keyID, claimant.priv)
	if err != nil {
		t.Fatalf("SignCreditClaim: %v", err)
	}

	_, err = VerifyCreditClaim(jwsToken, failingResolver())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, ErrCreditClaimUnverifiable) {
		t.Errorf("want ErrCreditClaimUnverifiable, got %v", err)
	}
	if errors.Is(err, ErrCreditClaimInvalid) {
		t.Error("a resolver failure must NOT be reported as invalid")
	}
}

func TestCreditClaimRejectsWrongTyp(t *testing.T) {
	claimant := makeClaimant("credit-claim-typ")

	payload := basePayload(claimant, testContentID("chain-e"))
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

	payload := basePayload(claimant, testContentID("chain-f"))
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

// The cap is enforced on the SIGN path too: a signer must not mint a token every
// verifier — including its own — would reject.
func TestCreditClaimSignRejectsOversizedToken(t *testing.T) {
	claimant := makeClaimant("credit-claim-size")

	// role carries no separate length cap — the aggregate token cap is the single
	// byte arbiter, so an oversized role is what trips it
	_, _, err := SignCreditClaim(claimant.did, testContentID("chain-g"), strings.Repeat("x", maxCreditClaimSize+1), claimant.keyID, claimant.priv)
	if err == nil || !strings.Contains(err.Error(), "credit claim exceeds max size") {
		t.Fatalf("expected sign-path size rejection, got %v", err)
	}
}

func TestCreditClaimVerifyRejectsOversizedToken(t *testing.T) {
	claimant := makeClaimant("credit-claim-size-verify")

	payload := basePayload(claimant, testContentID("chain-g2"))
	payload["role"] = strings.Repeat("x", maxCreditClaimSize+1)
	token := signRaw(t, claimant, payload)

	if len(token) <= maxCreditClaimSize {
		t.Fatalf("expected an oversized token, got %d bytes", len(token))
	}
	_, err := VerifyCreditClaim(token, resolverFor(claimant.pub))
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
	_, _, err := SignCreditClaim(claimant.did, "bafyrei"+strings.Repeat("a", 52), "author", claimant.keyID, claimant.priv)
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

	jwsToken, _, err := SignCreditClaim(claimant.did, contentID, "author", claimant.keyID, claimant.priv)
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

	jwsToken, _, err := SignCreditClaim(claimant.did, testContentID("chain-i"), "author", claimant.keyID, claimant.priv)
	if err != nil {
		t.Fatalf("SignCreditClaim: %v", err)
	}

	_, err = VerifyCreditClaimBound(jwsToken, resolverFor(claimant.pub), testContentID("chain-j"))
	if err == nil || !strings.Contains(err.Error(), "does not match expected") {
		t.Fatalf("expected binder rejection, got %v", err)
	}
}

// An EMPTY expectedContentID must ERROR, never silently degrade to the unbound
// form. The empty string is a zero value (unhydrated field, failed parse), and
// treating it as "no binder wanted" is how a caller that asked for bound
// semantics silently gets unbound ones — reopening cross-chain replay.
func TestCreditClaimBoundRejectsEmptyExpected(t *testing.T) {
	claimant := makeClaimant("credit-claim-bound-empty")

	jwsToken, _, err := SignCreditClaim(claimant.did, testContentID("chain-k"), "author", claimant.keyID, claimant.priv)
	if err != nil {
		t.Fatalf("SignCreditClaim: %v", err)
	}

	_, err = VerifyCreditClaimBound(jwsToken, resolverFor(claimant.pub), "")
	if err == nil {
		t.Fatal("VerifyCreditClaimBound with an empty expectedContentID must error, not skip the binder")
	}
	if !strings.Contains(err.Error(), "requires a non-empty expectedContentID") {
		t.Errorf("unexpected message: %v", err)
	}
	// fails CLOSED for consumers that map errors onto a verdict
	if !errors.Is(err, ErrCreditClaimInvalid) {
		t.Errorf("want ErrCreditClaimInvalid (fail closed), got %v", err)
	}
}

// ---------------------------------------------------------------------------
// entry verification (the full bind)
// ---------------------------------------------------------------------------

func TestVerifyCreditEntryStates(t *testing.T) {
	claimant := makeClaimant("credit-entry-states")
	contentID := testContentID("chain-entry")
	token, _, err := SignCreditClaim(claimant.did, contentID, "photography", claimant.keyID, claimant.priv)
	if err != nil {
		t.Fatalf("SignCreditClaim: %v", err)
	}
	otherChainToken, _, err := SignCreditClaim(claimant.did, testContentID("chain-other"), "photography", claimant.keyID, claimant.priv)
	if err != nil {
		t.Fatalf("SignCreditClaim: %v", err)
	}

	cases := []struct {
		name    string
		entry   map[string]any
		resolve KeyResolver
		want    CreditEntryState
	}{
		{
			name:    "claimed",
			entry:   map[string]any{"did": claimant.did, "role": "photography", "claim": token},
			resolve: resolverFor(claimant.pub),
			want:    CreditEntryClaimed,
		},
		{
			name:    "unclaimed when no claim field",
			entry:   map[string]any{"did": claimant.did, "role": "photography"},
			resolve: resolverFor(claimant.pub),
			want:    CreditEntryUnclaimed,
		},
		{
			name:    "invalid when role does not bind",
			entry:   map[string]any{"did": claimant.did, "role": "editor", "claim": token},
			resolve: resolverFor(claimant.pub),
			want:    CreditEntryInvalid,
		},
		{
			name:    "invalid when a claim-bearing entry has no role",
			entry:   map[string]any{"did": claimant.did, "claim": token},
			resolve: resolverFor(claimant.pub),
			want:    CreditEntryInvalid,
		},
		{
			name:    "invalid when did does not bind",
			entry:   map[string]any{"did": "did:dfos:someone-else", "role": "photography", "claim": token},
			resolve: resolverFor(claimant.pub),
			want:    CreditEntryInvalid,
		},
		{
			name:    "invalid when the claim belongs to another chain",
			entry:   map[string]any{"did": claimant.did, "role": "photography", "claim": otherChainToken},
			resolve: resolverFor(claimant.pub),
			want:    CreditEntryInvalid,
		},
		{
			name:    "invalid when claim is not a string",
			entry:   map[string]any{"did": claimant.did, "role": "photography", "claim": 42},
			resolve: resolverFor(claimant.pub),
			want:    CreditEntryInvalid,
		},
		{
			name:    "unverifiable when the claimant cannot be resolved",
			entry:   map[string]any{"did": claimant.did, "role": "photography", "claim": token},
			resolve: failingResolver(),
			want:    CreditEntryUnverifiable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := VerifyCreditEntry(tc.entry, tc.resolve, contentID)
			if err != nil {
				t.Fatalf("VerifyCreditEntry: %v", err)
			}
			if result.State != tc.want {
				t.Errorf("state: got %q want %q (note: %s)", result.State, tc.want, result.Note)
			}
			if tc.want == CreditEntryClaimed && result.Claim == nil {
				t.Error("a claimed entry must carry the verified claim")
			}
			if tc.want != CreditEntryClaimed && result.Claim != nil {
				t.Error("only a claimed entry may carry a verified claim")
			}
		})
	}
}

func TestVerifyCreditEntryRequiresContentID(t *testing.T) {
	claimant := makeClaimant("credit-entry-no-contentid")

	_, err := VerifyCreditEntry(map[string]any{"did": claimant.did}, resolverFor(claimant.pub), "")
	if err == nil || !strings.Contains(err.Error(), "requires the hosting chain contentID") {
		t.Fatalf("expected contentID requirement, got %v", err)
	}
}
