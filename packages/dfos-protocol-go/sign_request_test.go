package dfos

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// Twin of dfos-protocol/tests/sign-request.spec.ts. Same cases, bytes, and verdicts.

type signRequestParty struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	did   string
	keyID string
	kid   string
}

func makeSignRequestParty(seed string) signRequestParty {
	digest := sha256.Sum256([]byte(seed))
	priv := ed25519.NewKeyFromSeed(digest[:])
	pub := priv.Public().(ed25519.PublicKey)
	did := "did:dfos:" + DeriveID([]byte(seed+"-did"))
	keyID := "key_" + DeriveID([]byte(seed+"-key"))
	return signRequestParty{priv: priv, pub: pub, did: did, keyID: keyID, kid: did + "#" + keyID}
}

func signRequestResolver(party signRequestParty) KeyResolver {
	return func(kid string) (ed25519.PublicKey, error) {
		if kid != party.kid {
			return nil, errors.New("current key not found")
		}
		return party.pub, nil
	}
}

func failingSignRequestResolver() KeyResolver {
	return func(kid string) (ed25519.PublicKey, error) {
		return nil, errors.New("relay unreachable")
	}
}

func signRequestBasePayload(requester, subject signRequestParty) map[string]any {
	return map[string]any{
		"version":    1,
		"type":       "sign-request",
		"did":        requester.did,
		"subject":    subject.did,
		"payloadTyp": "did:dfos:credit-claim",
		"payload":    base64.RawURLEncoding.EncodeToString([]byte("target bytes")),
		"createdAt":  "2026-08-10T00:00:00.000Z",
		"expiresAt":  "2026-08-11T00:00:00.000Z",
	}
}

func signRequestSignRaw(t *testing.T, party signRequestParty, payload map[string]any, headerOverrides map[string]any) string {
	t.Helper()
	_, _, cid, err := DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}
	header := map[string]any{
		"alg": "EdDSA", "typ": "did:dfos:sign-request", "kid": party.kid, "cid": cid,
	}
	for key, value := range headerOverrides {
		header[key] = value
	}
	return signRequestSignArbitrary(t, party, header, payload)
}

func signRequestSignArbitrary(t *testing.T, party signRequestParty, header, payload any) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64
	signature := ed25519.Sign(party.priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signRequestVerifyAt(token string, party signRequestParty) (*VerifiedSignRequest, error) {
	return VerifySignRequest(token, signRequestResolver(party), time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC))
}

func requireSignRequestVerdict(t *testing.T, err error, target error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected verification to reject")
	}
	if !errors.Is(err, target) {
		t.Fatalf("got %v, want errors.Is(..., %v)", err, target)
	}
	other := ErrSignRequestInvalid
	if target == ErrSignRequestInvalid {
		other = ErrSignRequestUnverifiable
	}
	if errors.Is(err, other) {
		t.Fatalf("error must not also wrap the other verdict: %v", err)
	}
}

const signRequestParityClaim = `{"version":1,"type":"credit-claim","contentId":"cv7n8vkvr64cctf3294h9k4eanhff8z","did":"did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae","role":"photography","createdAt":"2026-08-10T00:00:00.000Z"}`

func TestSignRequestRoundTripAndDeterminism(t *testing.T) {
	requester := makeSignRequestParty("sign-request-roundtrip")
	subject := makeSignRequestParty("sign-request-roundtrip-subject")
	target := []byte{0, 1, 2, 127, 128, 255}
	created := time.Date(2026, 8, 10, 0, 0, 0, 777_000_000, time.UTC)
	expires := time.Date(2026, 8, 11, 0, 0, 0, 999_000_000, time.UTC)
	opts := SignRequestOptions{CreatedAt: created}

	first, firstCID, err := BuildSignRequest(requester.did, subject.did, "did:dfos:credit-claim", target, expires, requester.keyID, requester.priv, opts)
	if err != nil {
		t.Fatalf("BuildSignRequest: %v", err)
	}
	second, secondCID, err := BuildSignRequest(requester.did, subject.did, "did:dfos:credit-claim", target, expires, requester.keyID, requester.priv, opts)
	if err != nil {
		t.Fatalf("BuildSignRequest second: %v", err)
	}
	if first != second || firstCID != secondCID {
		t.Fatal("same inputs must re-derive an identical token and CID")
	}

	verified, err := signRequestVerifyAt(first, requester)
	if err != nil {
		t.Fatalf("VerifySignRequest: %v", err)
	}
	if verified.DID != requester.did || verified.Subject != subject.did || verified.PayloadTyp != "did:dfos:credit-claim" {
		t.Errorf("unexpected verified fields: %+v", verified)
	}
	if !bytes.Equal(verified.PayloadBytes, target) {
		t.Errorf("payload bytes: got %v want %v", verified.PayloadBytes, target)
	}
	if verified.CreatedAt != "2026-08-10T00:00:00.000Z" || verified.ExpiresAt != "2026-08-11T00:00:00.000Z" {
		t.Errorf("timestamps were not floor-normalized: %+v", verified)
	}
	if verified.SignerKeyID != requester.kid || verified.RequestCID != firstCID {
		t.Errorf("signer/CID did not round-trip: %+v", verified)
	}
}

func TestSignRequestCIDParityVector(t *testing.T) {
	// The TS twin (sign-request.spec.ts, cross-language parity) encodes this same
	// fixed payload and MUST derive this exact CID. A divergence forks request
	// identity — so this literal is normative, not a snapshot to re-bless.
	payload := map[string]any{
		"version":    1,
		"type":       "sign-request",
		"did":        "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
		"subject":    "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae",
		"payloadTyp": "did:dfos:credit-claim",
		"payload":    base64.RawURLEncoding.EncodeToString([]byte(signRequestParityClaim)),
		"createdAt":  "2026-08-10T00:00:00.000Z",
		"expiresAt":  "2026-08-13T00:00:00.000Z",
	}
	_, _, cid, err := DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}
	const expected = "bafyreibl3vv5shcpzvm5kyntihs5y22sxykqgju6c3iuw7hybhudktpisu"
	if cid != expected {
		t.Errorf("request CID: got %q want %q", cid, expected)
	}
}

func TestSignRequestBuildGuards(t *testing.T) {
	requester := makeSignRequestParty("sign-request-build")
	subject := makeSignRequestParty("sign-request-build-subject")
	created := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	opts := SignRequestOptions{CreatedAt: created}

	cases := []struct {
		name      string
		subject   string
		payload   []byte
		expiresAt time.Time
		message   string
	}{
		{"empty payload", subject.did, nil, created.Add(time.Hour), "non-empty"},
		{"oversized payload", subject.did, make([]byte, maxSignRequestPayloadSize+1), created.Add(time.Hour), "max decoded size"},
		{"equal timestamps", subject.did, []byte("x"), created, "strictly after"},
		{"overlong window", subject.did, []byte("x"), created.Add(7*24*time.Hour + time.Second), "604800"},
		{"oversized token", "did:" + strings.Repeat("x", maxSignRequestSize), []byte("x"), created.Add(time.Hour), "exceeds max size"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := BuildSignRequest(requester.did, tc.subject, "did:dfos:credit-claim", tc.payload, tc.expiresAt, requester.keyID, requester.priv, opts)
			if err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("got %v, want message containing %q", err, tc.message)
			}
		})
	}
}

func TestSignRequestRejectsOversizedAndMalformedJWS(t *testing.T) {
	requester := makeSignRequestParty("sign-request-malformed")
	_, err := signRequestVerifyAt(strings.Repeat("x", maxSignRequestSize+1), requester)
	requireSignRequestVerdict(t, err, ErrSignRequestInvalid)
	_, err = signRequestVerifyAt("not-a-jws", requester)
	requireSignRequestVerdict(t, err, ErrSignRequestInvalid)
}

func TestSignRequestRejectsHeaderShapesAndProfileViolations(t *testing.T) {
	requester := makeSignRequestParty("sign-request-headers")
	subject := makeSignRequestParty("sign-request-headers-subject")
	payload := signRequestBasePayload(requester, subject)
	_, _, cid, err := DagCborCID(payload)
	if err != nil {
		t.Fatal(err)
	}
	headers := []any{
		nil,
		[]any{},
		map[string]any{"alg": "EdDSA", "typ": "did:dfos:sign-request", "cid": cid},
		map[string]any{"alg": "EdDSA", "typ": "did:dfos:sign-request", "kid": 42, "cid": cid},
		map[string]any{"alg": "EdDSA", "kid": requester.kid, "cid": cid},
		map[string]any{"alg": "none", "typ": "did:dfos:sign-request", "kid": requester.kid, "cid": cid},
		map[string]any{"alg": "EdDSA", "typ": "did:dfos:sign-request", "kid": requester.kid, "cid": cid, "crit": []any{}},
		map[string]any{"alg": "EdDSA", "typ": "did:dfos:sign-request", "kid": requester.kid, "cid": cid, "jwk": map[string]any{}},
		map[string]any{"alg": "EdDSA", "typ": "did:dfos:sign-request", "kid": requester.kid, "cid": cid, "x5c": []any{}},
	}
	for _, header := range headers {
		token := signRequestSignArbitrary(t, requester, header, payload)
		_, err := signRequestVerifyAt(token, requester)
		requireSignRequestVerdict(t, err, ErrSignRequestInvalid)
	}
}

func TestSignRequestRejectsEnvelopeIntegrityFailures(t *testing.T) {
	requester := makeSignRequestParty("sign-request-integrity")
	subject := makeSignRequestParty("sign-request-integrity-subject")
	other := makeSignRequestParty("sign-request-integrity-other")
	payload := signRequestBasePayload(requester, subject)

	wrongTyp := signRequestSignRaw(t, requester, payload, map[string]any{"typ": "did:dfos:credit-claim"})
	_, err := signRequestVerifyAt(wrongTyp, requester)
	requireSignRequestVerdict(t, err, ErrSignRequestInvalid)

	wrongKid := signRequestSignRaw(t, other, payload, nil)
	_, err = VerifySignRequest(wrongKid, signRequestResolver(other), time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC))
	requireSignRequestVerdict(t, err, ErrSignRequestInvalid)

	decoy := signRequestBasePayload(requester, other)
	_, _, decoyCID, err := DagCborCID(decoy)
	if err != nil {
		t.Fatal(err)
	}
	wrongCID := signRequestSignRaw(t, requester, payload, map[string]any{"cid": decoyCID})
	_, err = signRequestVerifyAt(wrongCID, requester)
	requireSignRequestVerdict(t, err, ErrSignRequestInvalid)

	good := signRequestSignRaw(t, requester, payload, nil)
	_, err = VerifySignRequest(good, func(kid string) (ed25519.PublicKey, error) {
		return other.pub, nil
	}, time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC))
	requireSignRequestVerdict(t, err, ErrSignRequestInvalid)
}

func TestSignRequestRejectsTemporalFailures(t *testing.T) {
	requester := makeSignRequestParty("sign-request-temporal")
	subject := makeSignRequestParty("sign-request-temporal-subject")
	for _, expires := range []string{
		"2026-08-10T00:00:00.000Z",
		"2026-08-09T23:59:59.000Z",
		"2026-08-17T00:00:01.000Z",
	} {
		payload := signRequestBasePayload(requester, subject)
		payload["expiresAt"] = expires
		_, err := signRequestVerifyAt(signRequestSignRaw(t, requester, payload, nil), requester)
		requireSignRequestVerdict(t, err, ErrSignRequestInvalid)
	}

	payload := signRequestBasePayload(requester, subject)
	token := signRequestSignRaw(t, requester, payload, nil)
	expires, _ := time.Parse(protocolTimeFormat, payload["expiresAt"].(string))
	_, err := VerifySignRequest(token, signRequestResolver(requester), expires)
	requireSignRequestVerdict(t, err, ErrSignRequestInvalid)
}

func TestSignRequestRejectsTargetByteEncodings(t *testing.T) {
	requester := makeSignRequestParty("sign-request-target")
	subject := makeSignRequestParty("sign-request-target-subject")
	encodings := []string{
		"eA==",
		"eA+",
		"",
		base64.RawURLEncoding.EncodeToString(make([]byte, maxSignRequestPayloadSize+1)),
	}
	for _, encoded := range encodings {
		payload := signRequestBasePayload(requester, subject)
		payload["payload"] = encoded
		token := signRequestSignRaw(t, requester, payload, nil)
		_, err := signRequestVerifyAt(token, requester)
		requireSignRequestVerdict(t, err, ErrSignRequestInvalid)
	}
}

func TestSignRequestResolverFailureIsUnverifiable(t *testing.T) {
	requester := makeSignRequestParty("sign-request-resolver")
	subject := makeSignRequestParty("sign-request-resolver-subject")
	token := signRequestSignRaw(t, requester, signRequestBasePayload(requester, subject), nil)
	_, err := VerifySignRequest(token, failingSignRequestResolver(), time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC))
	requireSignRequestVerdict(t, err, ErrSignRequestUnverifiable)
}

func TestSignRequestCanonicalPayloadPositiveControls(t *testing.T) {
	bare := signRequestParityClaim
	withAsOf := strings.TrimSuffix(bare, "}") + `,"asOfDocumentCID":"bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne"}`
	for _, source := range []string{bare, withAsOf} {
		if err := AssertCanonicalSignRequestPayload("did:dfos:credit-claim", []byte(source), "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae"); err != nil {
			t.Errorf("canonical payload rejected: %v", err)
		}
	}
	special := strings.Replace(bare, "photography", "<photography>&é\u2028", 1)
	if err := AssertCanonicalSignRequestPayload("did:dfos:credit-claim", []byte(special), "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae"); err != nil {
		t.Errorf("canonical non-ASCII/HTML payload rejected: %v", err)
	}
	// A role legitimately carrying the six literal chars ` ` canonicalizes to
	// `\\u2028` (escaped backslash) and must round-trip — the case a blind
	// post-substitution corrupts. In this raw Go string literal `\\u2028` is the
	// JSON two-char escape for one backslash followed by u2028.
	literalEscape := strings.Replace(bare, "photography", `a\\u2028b`, 1)
	if err := AssertCanonicalSignRequestPayload("did:dfos:credit-claim", []byte(literalEscape), "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae"); err != nil {
		t.Errorf("canonical literal-escape payload rejected: %v", err)
	}
}

func TestSignRequestCanonicalPayloadLoneSurrogateRefused(t *testing.T) {
	const subject = "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae"
	// role "\ud800" is a lone surrogate; Go substitutes U+FFFD on decode so the
	// re-serialization cannot byte-match the input, and the payload is refused —
	// converging with the TS twin's explicit well-formedness rejection.
	loneSurrogate := strings.Replace(signRequestParityClaim, "photography", `\ud800`, 1)
	err := AssertCanonicalSignRequestPayload("did:dfos:credit-claim", []byte(loneSurrogate), subject)
	requireSignRequestVerdict(t, err, ErrSignRequestInvalid)
}

func TestSignRequestCanonicalPayloadAdversarialVectors(t *testing.T) {
	const subject = "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae"
	bare := signRequestParityClaim
	withAsOf := strings.TrimSuffix(bare, "}") + `,"asOfDocumentCID":"bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne"}`
	vectors := [][]byte{
		[]byte(strings.Replace(bare, `"version":1`, `"version": 1`, 1)),
		[]byte(strings.Replace(bare, `"role":"photography"`, `"role":"editor","role":"photography"`, 1)),
		[]byte(strings.Replace(bare, `"contentId":"cv7n8vkvr64cctf3294h9k4eanhff8z","did":"`+subject+`"`, `"did":"`+subject+`","contentId":"cv7n8vkvr64cctf3294h9k4eanhff8z"`, 1)),
		[]byte(strings.Replace(bare, `"version":1`, `"version":1.0`, 1)),
		[]byte(strings.Replace(bare, `"version":1`, `"version":1e0`, 1)),
		[]byte(strings.Replace(bare, "photography", `photograph\u0079`, 1)),
		[]byte(strings.TrimSuffix(bare, "}") + `,"note":"hi"}`),
		[]byte(strings.Replace(bare, ".000Z", ".123Z", 1)),
		[]byte(strings.Replace(bare, subject, "did:dfos:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1)),
		[]byte(strings.Replace(withAsOf, "bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne", "", 1)),
		[]byte(bare + "\n"),
		append([]byte{0xef, 0xbb, 0xbf}, []byte(bare)...),
		[]byte("[]"),
		[]byte("42"),
		[]byte(`"x"`),
	}
	for _, vector := range vectors {
		err := AssertCanonicalSignRequestPayload("did:dfos:credit-claim", vector, subject)
		requireSignRequestVerdict(t, err, ErrSignRequestInvalid)
	}
	err := AssertCanonicalSignRequestPayload("did:dfos:credential", []byte(bare), subject)
	requireSignRequestVerdict(t, err, ErrSignRequestInvalid)
	if !strings.Contains(err.Error(), "did:dfos:credential") {
		t.Errorf("unknown-typ message must name typ: %v", err)
	}
}

func TestSignRequestCanonicalPayloadVerifiesAsCreditClaim(t *testing.T) {
	claimant := makeSignRequestParty("sign-request-credit-e2e")
	canonical := strings.ReplaceAll(signRequestParityClaim, "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae", claimant.did)
	if err := AssertCanonicalSignRequestPayload("did:dfos:credit-claim", []byte(canonical), claimant.did); err != nil {
		t.Fatalf("canonical check: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(canonical), &payload); err != nil {
		t.Fatal(err)
	}
	NormalizeJSONNumbers(payload)
	_, _, cid, err := DagCborCID(payload)
	if err != nil {
		t.Fatal(err)
	}
	headerJSON, _ := json.Marshal(JWSHeader{Alg: "EdDSA", Typ: "did:dfos:credit-claim", Kid: claimant.kid, CID: cid})
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(canonical))
	signingInput := headerB64 + "." + payloadB64
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(claimant.priv, []byte(signingInput)))

	verified, err := VerifyCreditClaimBound(token, signRequestResolver(claimant), "cv7n8vkvr64cctf3294h9k4eanhff8z")
	if err != nil {
		t.Fatalf("VerifyCreditClaimBound: %v", err)
	}
	if verified.DID != claimant.did || verified.Role != "photography" {
		t.Errorf("unexpected verified claim: %+v", verified)
	}
}
