package dfos

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// SIGN REQUEST — the Go twin of dfos-protocol/src/chain/sign-request.ts.
//
// A requester's signed, transport-agnostic ask that one subject sign exactly
// these bytes as one named DFOS artifact type before a bounded deadline. A sign
// request is ephemeral courier-plane state, never proof-plane state.
//
// This file MUST stay in sync with the TS twin. Payload fields, validation
// ORDER, byte caps, temporal boundaries, and the canonical target serialization
// are deliberately aligned.
//
// Shape divergence from the TS twin: verification takes a KeyResolver (kid →
// public key), following every other Go verifier, while TS takes
// resolveIdentity and checks isDeleted itself. The KeyResolver passed to
// VerifySignRequest MUST implement CURRENT-STATE-ONLY resolution: it fails for
// rotated-out keys and deleted identities. Because the resolver cannot reveal
// whether failure means absent key, deleted identity, or transport outage, every
// resolver failure honestly maps to ErrSignRequestUnverifiable.

const (
	maxSignRequestSize        = 8192
	maxSignRequestPayloadSize = 4096
)

// Sentinel errors for the two consumer-visible verification verdicts. Every
// verify-path error wraps exactly one; callers branch with errors.Is, never on
// diagnostic message text.
var (
	ErrSignRequestInvalid      = errors.New("sign request invalid")
	ErrSignRequestUnverifiable = errors.New("sign request unverifiable")
)

// SignRequestOptions carries optional sign-request build inputs.
type SignRequestOptions struct {
	// CreatedAt overrides the build timestamp; zero means now. It is truncated to
	// whole seconds exactly like the TS twin's normalizeClaimCreatedAt idiom.
	CreatedAt time.Time
}

// VerifiedSignRequest is the result of sign-request verification.
type VerifiedSignRequest struct {
	DID, Subject, PayloadTyp string
	PayloadBytes             []byte
	CreatedAt, ExpiresAt     string
	SignerKeyID, RequestCID  string
}

// BuildSignRequest builds a signed request around exact target payload bytes.
// The kid is derived from did + keyID, making a requester mismatch
// unrepresentable on the build path. Both timestamps are UTC-truncated to whole
// seconds before signing.
func BuildSignRequest(did, subject, payloadTyp string, payload []byte,
	expiresAt time.Time, keyID string, privateKey ed25519.PrivateKey,
	opts SignRequestOptions) (jwsToken, requestCID string, err error) {
	if len(payload) == 0 {
		return "", "", fmt.Errorf("invalid sign request payload: target payload must be non-empty")
	}
	if len(payload) > maxSignRequestPayloadSize {
		return "", "", fmt.Errorf("sign request payload exceeds max decoded size: %d > %d", len(payload), maxSignRequestPayloadSize)
	}
	if !strings.HasPrefix(did, "did:") {
		return "", "", fmt.Errorf("invalid sign request payload: did must be a DID (did: prefix)")
	}
	if !strings.HasPrefix(subject, "did:") {
		return "", "", fmt.Errorf("invalid sign request payload: subject must be a DID (did: prefix)")
	}
	if payloadTyp == "" {
		return "", "", fmt.Errorf("invalid sign request payload: missing payloadTyp")
	}

	created := opts.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	created = created.UTC().Truncate(time.Second)
	expires := expiresAt.UTC().Truncate(time.Second)
	if err := validateSignRequestWindow(created, expires); err != nil {
		return "", "", err
	}

	payloadMap := map[string]any{
		"version":    1,
		"type":       "sign-request",
		"did":        did,
		"subject":    subject,
		"payloadTyp": payloadTyp,
		"payload":    base64.RawURLEncoding.EncodeToString(payload),
		"createdAt":  created.Format(protocolTimeFormat),
		"expiresAt":  expires.Format(protocolTimeFormat),
	}
	_, _, requestCID, err = DagCborCID(payloadMap)
	if err != nil {
		return "", "", err
	}
	jwsToken, err = CreateJWS(JWSHeader{
		Alg: "EdDSA", Typ: "did:dfos:sign-request", Kid: did + "#" + keyID, CID: requestCID,
	}, payloadMap, privateKey)
	if err != nil {
		return "", "", err
	}
	if len(jwsToken) > maxSignRequestSize {
		return "", "", fmt.Errorf("sign request exceeds max size: %d > %d", len(jwsToken), maxSignRequestSize)
	}
	return jwsToken, requestCID, nil
}

func validateSignRequestWindow(createdAt, expiresAt time.Time) error {
	if !expiresAt.After(createdAt) {
		return fmt.Errorf("sign request expiresAt must be strictly after createdAt")
	}
	if expiresAt.Sub(createdAt) > 604800*time.Second {
		return fmt.Errorf("sign request validity window exceeds 604800 seconds")
	}
	return nil
}

// VerifySignRequest verifies a sign request in SIGNING.md's exact 1–9 order.
//
// resolveKey MUST perform current-state-only resolution: rotated-out keys and
// deleted identities fail resolution. Resolver failures are unverifiable;
// checked-and-failed schema, signature, CID, and temporal conditions are invalid.
// now is the caller's wall-clock instant and is compared strictly to expiresAt.
func VerifySignRequest(jwsToken string, resolveKey KeyResolver,
	now time.Time) (result *VerifiedSignRequest, err error) {
	// An unexpected panic is inability to complete verification, never evidence
	// that the request itself is malformed.
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			err = fmt.Errorf("%w: verification could not complete: %v", ErrSignRequestUnverifiable, recovered)
		}
	}()

	// 1. Size — before any decode.
	if len(jwsToken) > maxSignRequestSize {
		return nil, fmt.Errorf("%w: sign request exceeds max size: %d > %d", ErrSignRequestInvalid, len(jwsToken), maxSignRequestSize)
	}

	// 2. Decode and profile gates. Apply the profile to raw header bytes before
	// payload schema work; DecodeJWSUnsafe then supplies typed typ/kid shape guards.
	parts := strings.Split(jwsToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: failed to decode sign request JWS", ErrSignRequestInvalid)
	}
	headerBytes, decodeErr := Base64urlDecode(parts[0])
	if decodeErr != nil {
		return nil, fmt.Errorf("%w: failed to decode sign request JWS", ErrSignRequestInvalid)
	}
	if profileErr := assertJWSProfile(headerBytes); profileErr != nil {
		return nil, fmt.Errorf("%w: %s", ErrSignRequestInvalid, profileErr)
	}
	header, payloadMap, decodeErr := DecodeJWSUnsafe(jwsToken)
	if decodeErr != nil {
		return nil, fmt.Errorf("%w: failed to decode sign request JWS", ErrSignRequestInvalid)
	}
	if header.Typ == "" || header.Kid == "" {
		return nil, fmt.Errorf("%w: sign request header must carry a string typ and kid", ErrSignRequestInvalid)
	}
	if header.Typ != "did:dfos:sign-request" {
		return nil, fmt.Errorf("%w: invalid sign request typ: %s", ErrSignRequestInvalid, header.Typ)
	}

	// 3. Envelope payload schema. Unknown top-level fields remain in payloadMap
	// and therefore in CID re-derivation, but are otherwise ignored.
	version, _ := payloadMap["version"].(int64)
	if version != 1 {
		return nil, fmt.Errorf("%w: invalid sign request payload: invalid or missing version", ErrSignRequestInvalid)
	}
	if payloadString(payloadMap, "type") != "sign-request" {
		return nil, fmt.Errorf("%w: invalid sign request payload: wrong type", ErrSignRequestInvalid)
	}
	did := payloadString(payloadMap, "did")
	if !strings.HasPrefix(did, "did:") {
		return nil, fmt.Errorf("%w: invalid sign request payload: did must be a DID (did: prefix)", ErrSignRequestInvalid)
	}
	subject := payloadString(payloadMap, "subject")
	if !strings.HasPrefix(subject, "did:") {
		return nil, fmt.Errorf("%w: invalid sign request payload: subject must be a DID (did: prefix)", ErrSignRequestInvalid)
	}
	payloadTyp := payloadString(payloadMap, "payloadTyp")
	if payloadTyp == "" {
		return nil, fmt.Errorf("%w: invalid sign request payload: missing payloadTyp", ErrSignRequestInvalid)
	}
	payloadEncoded := payloadString(payloadMap, "payload")
	if payloadEncoded == "" {
		return nil, fmt.Errorf("%w: invalid sign request payload: missing payload", ErrSignRequestInvalid)
	}
	createdAt := payloadString(payloadMap, "createdAt")
	created, parseErr := ParseProtocolTimestamp(createdAt)
	if parseErr != nil {
		return nil, fmt.Errorf("%w: invalid sign request payload: invalid createdAt format", ErrSignRequestInvalid)
	}
	expiresAt := payloadString(payloadMap, "expiresAt")
	expires, parseErr := ParseProtocolTimestamp(expiresAt)
	if parseErr != nil {
		return nil, fmt.Errorf("%w: invalid sign request payload: invalid expiresAt format", ErrSignRequestInvalid)
	}

	// 4. Exact target bytes — RawURLEncoding rejects padding and non-base64url.
	payloadBytes, decodeErr := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if decodeErr != nil {
		return nil, fmt.Errorf("%w: sign request payload must be canonical unpadded base64url", ErrSignRequestInvalid)
	}
	if base64.RawURLEncoding.EncodeToString(payloadBytes) != payloadEncoded {
		return nil, fmt.Errorf("%w: sign request payload must be canonical unpadded base64url", ErrSignRequestInvalid)
	}
	if len(payloadBytes) == 0 {
		return nil, fmt.Errorf("%w: sign request payload must decode to non-empty bytes", ErrSignRequestInvalid)
	}
	if len(payloadBytes) > maxSignRequestPayloadSize {
		return nil, fmt.Errorf("%w: sign request payload exceeds max decoded size: %d > %d", ErrSignRequestInvalid, len(payloadBytes), maxSignRequestPayloadSize)
	}

	// 5. kid ↔ requester DID.
	hashIdx := strings.Index(header.Kid, "#")
	if hashIdx < 0 {
		return nil, fmt.Errorf("%w: sign request kid must be a DID URL", ErrSignRequestInvalid)
	}
	if header.Kid[:hashIdx] != did {
		return nil, fmt.Errorf("%w: sign request kid DID does not match payload did", ErrSignRequestInvalid)
	}

	// 6–7. Current-state key resolution, then signature.
	publicKey, resolveErr := resolveKey(header.Kid)
	if resolveErr != nil {
		return nil, fmt.Errorf("%w: failed to resolve current sign request key: %s", ErrSignRequestUnverifiable, resolveErr)
	}
	if _, _, verifyErr := VerifyJWS(jwsToken, publicKey); verifyErr != nil {
		return nil, fmt.Errorf("%w: invalid sign request signature", ErrSignRequestInvalid)
	}

	// 8. CID integrity.
	_, _, requestCID, cidErr := DagCborCID(payloadMap)
	if cidErr != nil {
		return nil, fmt.Errorf("%w: failed to derive sign request CID: %s", ErrSignRequestInvalid, cidErr)
	}
	if header.CID != requestCID {
		return nil, fmt.Errorf("%w: sign request cid mismatch", ErrSignRequestInvalid)
	}

	// 9. Temporal validity.
	if windowErr := validateSignRequestWindow(created, expires); windowErr != nil {
		return nil, fmt.Errorf("%w: %s", ErrSignRequestInvalid, windowErr)
	}
	if !now.Before(expires) {
		return nil, fmt.Errorf("%w: sign request is expired", ErrSignRequestInvalid)
	}

	return &VerifiedSignRequest{
		DID: did, Subject: subject, PayloadTyp: payloadTyp,
		PayloadBytes: append([]byte(nil), payloadBytes...),
		CreatedAt:    createdAt, ExpiresAt: expiresAt,
		SignerKeyID: header.Kid, RequestCID: requestCID,
	}, nil
}

// AssertCanonicalSignRequestPayload applies SIGNING.md signer obligations 2–5
// to exact target bytes. SIGNING 0.1 implements only did:dfos:credit-claim;
// unknown payload types are refused with ErrSignRequestInvalid.
func AssertCanonicalSignRequestPayload(payloadTyp string, payload []byte,
	subject string) error {
	if payloadTyp != "did:dfos:credit-claim" {
		return fmt.Errorf("%w: unsupported sign request payloadTyp: %s", ErrSignRequestInvalid, payloadTyp)
	}
	if !utf8.Valid(payload) {
		return fmt.Errorf("%w: sign request payload is not valid UTF-8 JSON", ErrSignRequestInvalid)
	}
	if bytes.HasPrefix(payload, []byte{0xef, 0xbb, 0xbf}) {
		return fmt.Errorf("%w: sign request payload must not carry a UTF-8 BOM", ErrSignRequestInvalid)
	}

	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil || raw == nil {
		return fmt.Errorf("%w: sign request payload is not a JSON object", ErrSignRequestInvalid)
	}
	allowed := map[string]bool{
		"version": true, "type": true, "contentId": true, "did": true,
		"role": true, "createdAt": true, "asOfDocumentCID": true,
	}
	for key := range raw {
		if !allowed[key] {
			return fmt.Errorf("%w: unknown credit-claim payload field: %s", ErrSignRequestInvalid, key)
		}
	}

	version, ok := raw["version"].(float64)
	if !ok || version != 1 {
		return fmt.Errorf("%w: invalid canonical credit-claim payload: invalid or missing version", ErrSignRequestInvalid)
	}
	claimType, ok := raw["type"].(string)
	if !ok || claimType != "credit-claim" {
		return fmt.Errorf("%w: invalid canonical credit-claim payload: wrong type", ErrSignRequestInvalid)
	}
	contentID, ok := raw["contentId"].(string)
	if !ok || !contentIDAnchorRe.MatchString(contentID) {
		return fmt.Errorf("%w: invalid canonical credit-claim payload: contentId must be a 31-char content chain id", ErrSignRequestInvalid)
	}
	did, ok := raw["did"].(string)
	if !ok || !strings.HasPrefix(did, "did:") {
		return fmt.Errorf("%w: invalid canonical credit-claim payload: did must be a DID (did: prefix)", ErrSignRequestInvalid)
	}
	role, ok := raw["role"].(string)
	if !ok || role == "" {
		return fmt.Errorf("%w: invalid canonical credit-claim payload: missing role", ErrSignRequestInvalid)
	}
	createdAt, ok := raw["createdAt"].(string)
	if !ok {
		return fmt.Errorf("%w: invalid canonical credit-claim payload: missing createdAt", ErrSignRequestInvalid)
	}
	if _, err := ParseProtocolTimestamp(createdAt); err != nil {
		return fmt.Errorf("%w: invalid canonical credit-claim payload: invalid createdAt format", ErrSignRequestInvalid)
	}
	if !strings.HasSuffix(createdAt, ".000Z") {
		return fmt.Errorf("%w: credit-claim createdAt must be normalized to whole seconds", ErrSignRequestInvalid)
	}
	if did != subject {
		return fmt.Errorf("%w: credit-claim payload did does not match sign request subject", ErrSignRequestInvalid)
	}

	var asOf *string
	if value, present := raw["asOfDocumentCID"]; present {
		s, ok := value.(string)
		if !ok || s == "" {
			return fmt.Errorf("%w: credit-claim asOfDocumentCID must be non-empty when present", ErrSignRequestInvalid)
		}
		asOf = &s
	}

	canonical := struct {
		Version         int     `json:"version"`
		Type            string  `json:"type"`
		ContentID       string  `json:"contentId"`
		DID             string  `json:"did"`
		Role            string  `json:"role"`
		CreatedAt       string  `json:"createdAt"`
		AsOfDocumentCID *string `json:"asOfDocumentCID,omitempty"`
	}{1, claimType, contentID, did, role, createdAt, asOf}
	canonicalBytes, err := marshalSignRequestCanonicalJSON(canonical)
	if err != nil {
		return fmt.Errorf("%w: canonical credit-claim serialization failed: %s", ErrSignRequestUnverifiable, err)
	}
	if !bytes.Equal(canonicalBytes, payload) {
		return fmt.Errorf("%w: credit-claim payload bytes are not canonical", ErrSignRequestInvalid)
	}
	return nil
}

// marshalSignRequestCanonicalJSON matches JSON.stringify byte-for-byte. Go's
// encoder needs HTML escaping disabled and otherwise-unconditional U+2028/U+2029
// escapes restored to their UTF-8 bytes. Encoder.Encode appends one newline.
func marshalSignRequestCanonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	encoded := bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})
	encoded = bytes.ReplaceAll(encoded, []byte(`\u2028`), []byte("\u2028"))
	encoded = bytes.ReplaceAll(encoded, []byte(`\u2029`), []byte("\u2029"))
	return encoded, nil
}
