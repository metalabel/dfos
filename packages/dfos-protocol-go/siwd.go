package dfos

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const SiwdJWSTyp = "did:dfos:siwd"

// SiwdAskJWSTyp is the registered JWS typ of a loopback client's ask proof
// (SIWD.md §The ask proof) — distinct from SiwdJWSTyp because both artifacts
// sign the SAME canonical challenge bytes, so the typ gate is the only thing
// keeping a client's ask from presenting as a subject's sign-in, or a subject's
// sign-in from presenting as a client's ask.
const SiwdAskJWSTyp = "did:dfos:siwd-ask"

// SiwdChallenge is the closed SIWD 0.1 challenge schema. Pointer optionals
// preserve the distinction between an absent member and a present empty string,
// which is part of the canonical byte contract.
type SiwdChallenge struct {
	Domain    string
	Nonce     string
	Timestamp string
	Statement *string
	DID       *string
}

// ValidatedSiwdSignRequest is the verified courier envelope plus the strict,
// canonical challenge parse a signer renders before signing the original bytes.
type ValidatedSiwdSignRequest struct {
	*VerifiedSignRequest
	Challenge SiwdChallenge
}

func validateSiwdChallenge(challenge SiwdChallenge) error {
	if challenge.Domain == "" {
		return fmt.Errorf("invalid SIWD challenge: domain must be a non-empty string")
	}
	if challenge.Nonce == "" {
		return fmt.Errorf("invalid SIWD challenge: nonce must be a non-empty string")
	}
	if challenge.Timestamp == "" {
		return fmt.Errorf("invalid SIWD challenge: timestamp must be a non-empty string")
	}
	for _, value := range []*string{&challenge.Domain, &challenge.Nonce, &challenge.Timestamp, challenge.Statement, challenge.DID} {
		if value != nil && !utf8.ValidString(*value) {
			return fmt.Errorf("invalid SIWD challenge: string members must be valid UTF-8")
		}
	}
	if _, err := ParseProtocolTimestamp(challenge.Timestamp); err != nil || !strings.HasSuffix(challenge.Timestamp, ".000Z") {
		return fmt.Errorf("invalid SIWD challenge: timestamp must be ISO-8601 UTC whole-second .000Z")
	}
	return nil
}

// SiwdSigningInput returns the canonical bytes shared by both SIWD couriers:
// domain, nonce, timestamp, statement?, did?, with no insignificant whitespace.
func SiwdSigningInput(challenge SiwdChallenge) ([]byte, error) {
	if err := validateSiwdChallenge(challenge); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(`{"domain":`)
	b.WriteString(jsonStringifyString(challenge.Domain))
	b.WriteString(`,"nonce":`)
	b.WriteString(jsonStringifyString(challenge.Nonce))
	b.WriteString(`,"timestamp":`)
	b.WriteString(jsonStringifyString(challenge.Timestamp))
	if challenge.Statement != nil {
		b.WriteString(`,"statement":`)
		b.WriteString(jsonStringifyString(*challenge.Statement))
	}
	if challenge.DID != nil {
		b.WriteString(`,"did":`)
		b.WriteString(jsonStringifyString(*challenge.DID))
	}
	b.WriteByte('}')
	return []byte(b.String()), nil
}

// ParseSiwdChallenge applies SIGNING's WYSIWYS steps 3–5: strict UTF-8 JSON,
// closed SIWD schema, canonical re-serialization, and exact byte comparison.
func ParseSiwdChallenge(octets []byte) (SiwdChallenge, error) {
	if !utf8.Valid(octets) {
		return SiwdChallenge{}, fmt.Errorf("invalid SIWD challenge: payload is not valid UTF-8 JSON")
	}
	if bytes.HasPrefix(octets, []byte{0xef, 0xbb, 0xbf}) {
		return SiwdChallenge{}, fmt.Errorf("invalid SIWD challenge: payload must not carry a UTF-8 BOM")
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(octets, &raw); err != nil {
		return SiwdChallenge{}, fmt.Errorf("invalid SIWD challenge: payload is not valid JSON")
	}
	if raw == nil {
		return SiwdChallenge{}, fmt.Errorf("invalid SIWD challenge: expected a JSON object")
	}
	allowed := map[string]bool{"domain": true, "nonce": true, "timestamp": true, "statement": true, "did": true}
	for field := range raw {
		if !allowed[field] {
			return SiwdChallenge{}, fmt.Errorf("invalid SIWD challenge: unknown member %s", field)
		}
	}

	readRequired := func(field string) (string, error) {
		value, present := raw[field]
		if !present {
			return "", fmt.Errorf("invalid SIWD challenge: %s must be a non-empty string", field)
		}
		var parsed string
		if err := json.Unmarshal(value, &parsed); err != nil || parsed == "" {
			return "", fmt.Errorf("invalid SIWD challenge: %s must be a non-empty string", field)
		}
		return parsed, nil
	}
	domain, err := readRequired("domain")
	if err != nil {
		return SiwdChallenge{}, err
	}
	nonce, err := readRequired("nonce")
	if err != nil {
		return SiwdChallenge{}, err
	}
	timestamp, err := readRequired("timestamp")
	if err != nil {
		return SiwdChallenge{}, err
	}

	readOptional := func(field string) (*string, error) {
		value, present := raw[field]
		if !present {
			return nil, nil
		}
		var parsed string
		if err := json.Unmarshal(value, &parsed); err != nil {
			return nil, fmt.Errorf("invalid SIWD challenge: %s must be a string when present", field)
		}
		return &parsed, nil
	}
	statement, err := readOptional("statement")
	if err != nil {
		return SiwdChallenge{}, err
	}
	did, err := readOptional("did")
	if err != nil {
		return SiwdChallenge{}, err
	}

	challenge := SiwdChallenge{Domain: domain, Nonce: nonce, Timestamp: timestamp, Statement: statement, DID: did}
	canonical, err := SiwdSigningInput(challenge)
	if err != nil {
		return SiwdChallenge{}, err
	}
	if !bytes.Equal(canonical, octets) {
		return SiwdChallenge{}, fmt.Errorf("invalid SIWD challenge: payload bytes are not canonical")
	}
	return challenge, nil
}

// SignSiwdAskProof signs the ask proof a loopback client carries on its
// authorize request: a JWS over the exact canonical bytes of that request's own
// challenge, under SiwdAskJWSTyp, signed by a CURRENT auth key of the client
// identity's chain (SIWD.md §The ask proof). It is what makes a client_did on a
// loopback request mean anything — the host verifies it against the chain's
// current state before rendering any consent.
//
// BYTE-PRECISE, and assembled by hand rather than through CreateJWS for the same
// reason BuildRequestProof is: the host compares the proof's payload SEGMENT by
// string equality against its own re-derivation of
// Base64urlEncode(SiwdSigningInput(challenge)), so a construction that
// round-tripped the challenge through a JSON object would re-serialize it, and
// any spelling differing by one byte would fail that comparison while looking
// correct here.
//
// kid is the DID URL of the signing key. The host ignores it for key SELECTION
// — it tries the chain's current auth keys — but a proof naming a key it was not
// signed with is a lie the wire format has no reason to carry.
func SignSiwdAskProof(challenge SiwdChallenge, kid string, privateKey ed25519.PrivateKey) (string, error) {
	// Both halves must be present: "#x", "x#", and a bare "#" name no key, no
	// identity, or neither, and a host cannot resolve any of them to a chain.
	hashIdx := strings.Index(kid, "#")
	if hashIdx <= 0 || hashIdx == len(kid)-1 {
		return "", fmt.Errorf("invalid SIWD ask proof: kid must be a DID URL with both halves non-empty (<did>#<keyId>)")
	}
	// ed25519.Sign PANICS on a wrong-length key, and this signer is reached with
	// key material a caller loaded from a keystore or a file. A malformed key is
	// a bad input to report, never a crash to take.
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid SIWD ask proof: private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(privateKey))
	}
	payload, err := SiwdSigningInput(challenge)
	if err != nil {
		return "", err
	}
	headerJSON, err := json.Marshal(JWSHeader{Alg: "EdDSA", Typ: SiwdAskJWSTyp, Kid: kid})
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	signingInput := Base64urlEncode(headerJSON) + "." + Base64urlEncode(payload)
	return signingInput + "." + Base64urlEncode(ed25519.Sign(privateKey, []byte(signingInput))), nil
}

func validateSiwdAcceptanceWindow(acceptanceWindow time.Duration) error {
	if acceptanceWindow <= 0 || acceptanceWindow%time.Second != 0 {
		return fmt.Errorf("SIWD acceptance window must be a positive whole-second duration")
	}
	if acceptanceWindow > 7*24*time.Hour {
		return fmt.Errorf("SIWD acceptance window exceeds the sign-request 604800-second ceiling")
	}
	return nil
}

func validateSiwdOneClock(challengeTimestamp string, expiresAt time.Time, acceptanceWindow time.Duration) error {
	if err := validateSiwdAcceptanceWindow(acceptanceWindow); err != nil {
		return err
	}
	challengeTime, err := ParseProtocolTimestamp(challengeTimestamp)
	if err != nil || !strings.HasSuffix(challengeTimestamp, ".000Z") {
		return fmt.Errorf("invalid SIWD challenge: timestamp must be ISO-8601 UTC whole-second .000Z")
	}
	if expiresAt.UTC().Truncate(time.Second).After(challengeTime.Add(acceptanceWindow)) {
		return fmt.Errorf("SIWD sign request expiresAt exceeds the challenge acceptance window")
	}
	return nil
}

// BuildSiwdSignRequest composes SIWD profile B through BuildSignRequest. The
// caller must state its acceptance window; there is deliberately no default.
func BuildSiwdSignRequest(did, subject string, challenge SiwdChallenge,
	expiresAt time.Time, acceptanceWindow time.Duration, keyID string,
	privateKey ed25519.PrivateKey, opts SignRequestOptions) (jwsToken, requestCID string, err error) {
	payload, err := SiwdSigningInput(challenge)
	if err != nil {
		return "", "", err
	}
	if challenge.DID != nil && *challenge.DID != subject {
		return "", "", fmt.Errorf("SIWD challenge did does not match sign request subject")
	}
	if err := validateSiwdOneClock(challenge.Timestamp, expiresAt, acceptanceWindow); err != nil {
		return "", "", err
	}
	return BuildSignRequest(did, subject, SiwdJWSTyp, payload, expiresAt, keyID, privateKey, opts)
}

// ValidateSiwdSignRequest is the signer-side family gate: verify the envelope,
// bind its subject, typ, canonical payload bytes, semantic expiry, and optional
// challenge DID before anything is rendered or signed.
func ValidateSiwdSignRequest(jwsToken, signerDID string, acceptanceWindow time.Duration,
	resolveKey KeyResolver, now time.Time) (*ValidatedSiwdSignRequest, error) {
	if err := validateSiwdAcceptanceWindow(acceptanceWindow); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrSignRequestInvalid, err)
	}
	request, err := VerifySignRequest(jwsToken, resolveKey, now)
	if err != nil {
		return nil, err
	}
	if request.Subject != signerDID {
		return nil, fmt.Errorf("%w: SIWD sign request subject does not match signer DID", ErrSignRequestInvalid)
	}
	if request.PayloadTyp != SiwdJWSTyp {
		return nil, fmt.Errorf("%w: invalid SIWD sign request payloadTyp: %s", ErrSignRequestInvalid, request.PayloadTyp)
	}
	challenge, err := ParseSiwdChallenge(request.PayloadBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrSignRequestInvalid, err)
	}
	expiresAt, err := ParseProtocolTimestamp(request.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid SIWD sign request expiresAt", ErrSignRequestInvalid)
	}
	if err := validateSiwdOneClock(challenge.Timestamp, expiresAt, acceptanceWindow); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrSignRequestInvalid, err)
	}
	if challenge.DID != nil && *challenge.DID != signerDID {
		return nil, fmt.Errorf("%w: SIWD challenge did does not match signer DID", ErrSignRequestInvalid)
	}
	return &ValidatedSiwdSignRequest{VerifiedSignRequest: request, Challenge: challenge}, nil
}
