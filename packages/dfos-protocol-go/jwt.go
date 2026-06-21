package dfos

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// maxCredentialSize bounds the byte length of a credential JWS token — the
// credential's analog of maxOperationSize. Credentials are EXEMPT from the 64
// KiB operation cap (a maximum-depth 16-hop delegation chain embeds each parent
// in prf and legitimately exceeds it), so they carry their own larger ceiling.
// VALIDITY-determining: MUST match the TS reference (MAX_CREDENTIAL_SIZE).
const maxCredentialSize = 262144

// maxAttEntries bounds the number of attenuation entries per credential. A
// CARDINALITY cap (DoS pre-allocation guard), matching the TS reference
// (MAX_ATT).
const maxAttEntries = 32

// VerifiedCredential represents a successfully verified DFOS credential.
type VerifiedCredential struct {
	Iss string
	Aud string // audience DID or "*" for public
	Exp int64
	Iat int64
	Att []AttEntry // full attenuation array
	Kid string
	CID string // credential CID from header

	// Convenience fields derived from the first att entry granting a recognized
	// action. Action is the raw att action string and may be a combined grant
	// (e.g. "read,write"); callers needing set semantics should ParseActions it.
	Action    string
	ContentID string // resource ID (without "chain:" prefix)
}

// CreateAuthToken creates a DID-signed auth token JWT for relay authentication.
func CreateAuthToken(iss, aud, kid string, ttl time.Duration, privateKey ed25519.PrivateKey) (string, error) {
	now := time.Now().Unix()
	exp := now + int64(ttl.Seconds())

	header := map[string]string{
		"alg": "EdDSA",
		"typ": "JWT",
		"kid": kid,
	}
	payload := map[string]any{
		"iss": iss,
		"sub": iss,
		"aud": aud,
		"exp": exp,
		"iat": now,
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := Base64urlEncode(headerJSON)
	payloadB64 := Base64urlEncode(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	sig := ed25519.Sign(privateKey, []byte(signingInput))
	sigB64 := Base64urlEncode(sig)

	return signingInput + "." + sigB64, nil
}

// CreateCredential creates a DFOS credential (UCAN-style authorization token).
//
// The resource parameter is the full resource string (e.g., "chain:contentId",
// "chain:*"). The action is "read" or "write".
// The aud parameter is the audience DID (or "*" for public credentials).
func CreateCredential(iss, aud, kid, resource, action string, ttl time.Duration, privateKey ed25519.PrivateKey) (string, error) {
	now := time.Now().Unix()
	exp := now + int64(ttl.Seconds())

	att := []map[string]string{
		{
			"resource": resource,
			"action":   action,
		},
	}

	payload := map[string]any{
		"version": 1,
		"type":    "DFOSCredential",
		"iss":     iss,
		"aud":     aud,
		"att":     att,
		"prf":     []string{},
		"exp":     exp,
		"iat":     now,
	}

	// derive CID from dag-cbor canonical encoding
	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		return "", fmt.Errorf("DagCborCID: %w", err)
	}

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:credential",
		Kid: kid,
		CID: cidStr,
	}

	token, err := CreateJWS(header, payload, privateKey)
	if err != nil {
		return "", fmt.Errorf("CreateJWS: %w", err)
	}

	return token, nil
}

// VerifyCredential verifies a DFOS credential token. It checks the signature,
// expiration, payload structure, and optionally subject and expected action.
// Pass empty string for subject or expectedAction to skip those checks.
func VerifyCredential(token string, publicKey ed25519.PublicKey, subject string, expectedAction string) (*VerifiedCredential, error) {
	return verifyCredentialCore(token, publicKey, subject, expectedAction, time.Now().Unix())
}

// VerifyCredentialAt is like VerifyCredential but accepts a custom current
// time (unix seconds) for testing temporal checks.
func VerifyCredentialAt(token string, publicKey ed25519.PublicKey, subject string, expectedAction string, currentTime int64) (*VerifiedCredential, error) {
	return verifyCredentialCore(token, publicKey, subject, expectedAction, currentTime)
}

// verifyCredentialCore is the shared implementation for DFOS credential
// verification.
func verifyCredentialCore(token string, publicKey ed25519.PublicKey, subject string, expectedAction string, currentTime int64) (*VerifiedCredential, error) {
	// bound credential size — the credential's analog of maxOperationSize. The
	// leaf token embeds the entire nested delegation chain (each parent carried
	// in prf), so this one cap bounds the whole chain. Checked before any decode
	// or recursion as a DoS guard. Matches the TS reference (MAX_CREDENTIAL_SIZE).
	if len(token) > maxCredentialSize {
		return nil, fmt.Errorf("credential exceeds max size: %d > %d", len(token), maxCredentialSize)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	headerB64, payloadB64, signatureB64 := parts[0], parts[1], parts[2]

	// decode header and payload
	headerBytes, err := Base64urlDecode(headerB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token")
	}
	payloadBytes, err := Base64urlDecode(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token")
	}

	// apply the DFOS signature verification profile (alg pin, crit, no
	// header-key-trust) BEFORE any signature check
	if err := assertJWSProfile(headerBytes); err != nil {
		return nil, err
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
		CID string `json:"cid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to decode token")
	}

	// verify header fields
	if header.Typ != "did:dfos:credential" {
		return nil, fmt.Errorf("invalid typ: %s", header.Typ)
	}

	// verify signature
	signingInput := headerB64 + "." + payloadB64
	sigBytes, err := Base64urlDecode(signatureB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature")
	}
	if !ed25519.Verify(publicKey, []byte(signingInput), sigBytes) {
		return nil, fmt.Errorf("invalid signature")
	}

	// parse payload — DFOS credential format
	var claims struct {
		Version int64  `json:"version"`
		Type    string `json:"type"`
		Iss     string `json:"iss"`
		Aud     string `json:"aud"`
		Exp     int64  `json:"exp"`
		Iat     int64  `json:"iat"`
		Att     []struct {
			Resource string `json:"resource"`
			Action   string `json:"action"`
		} `json:"att"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("invalid credential claims: %s", err)
	}

	// validate required fields
	if claims.Iss == "" || claims.Aud == "" || claims.Exp == 0 || claims.Iat == 0 {
		return nil, fmt.Errorf("invalid credential claims: missing required fields")
	}
	if claims.Type != "DFOSCredential" {
		return nil, fmt.Errorf("invalid credential type: %s", claims.Type)
	}
	if claims.Version != 1 {
		return nil, fmt.Errorf("unsupported credential version: %d", claims.Version)
	}

	// att cardinality — a credential MUST carry 1..maxAttEntries attenuations.
	// A zero-att credential grants nothing (malformed); the upper bound is a DoS
	// pre-allocation guard. Enforced identically in the TS reference (MAX_ATT).
	if len(claims.Att) < 1 || len(claims.Att) > maxAttEntries {
		return nil, fmt.Errorf("credential att count out of bounds: %d (must be 1..%d)", len(claims.Att), maxAttEntries)
	}

	// verify CID integrity — re-derive from payload and compare to header
	headerCID := header.CID
	if headerCID == "" {
		return nil, fmt.Errorf("missing cid in credential header")
	}
	var payloadMap map[string]any
	if err := json.Unmarshal(payloadBytes, &payloadMap); err != nil {
		return nil, fmt.Errorf("failed to parse credential payload for CID derivation")
	}
	NormalizeJSONNumbers(payloadMap)
	_, _, derivedCID, err := DagCborCID(payloadMap)
	if err != nil {
		return nil, fmt.Errorf("failed to derive credential CID: %w", err)
	}
	if headerCID != derivedCID {
		return nil, fmt.Errorf("credential CID mismatch: header %s, derived %s", headerCID, derivedCID)
	}

	// verify kid is a DID URL and matches iss
	kid := header.Kid
	if kid == "" || !strings.Contains(kid, "#") {
		return nil, fmt.Errorf("credential kid must be a DID URL")
	}
	kidDID := kid[:strings.Index(kid, "#")]
	if kidDID != claims.Iss {
		return nil, fmt.Errorf("credential kid DID does not match iss")
	}

	// verify temporal validity
	if claims.Iat > currentTime {
		return nil, fmt.Errorf("credential not yet valid (iat is in the future)")
	}
	if claims.Exp <= currentTime {
		return nil, fmt.Errorf("credential expired")
	}

	// verify subject (aud) if specified
	if subject != "" && claims.Aud != subject {
		return nil, fmt.Errorf("subject mismatch: expected %s, got %s", subject, claims.Aud)
	}

	// build full att array
	att := make([]AttEntry, 0, len(claims.Att))
	for _, a := range claims.Att {
		att = append(att, AttEntry{Resource: a.Resource, Action: a.Action})
	}

	// Derive convenience fields from the first att entry that grants a recognized
	// action. Actions are comma-separated strings ("read", "write", "read,write")
	// split with ParseActions, matching IsAttenuated / matchesResource semantics.
	// These fields are best-effort metadata: the authoritative resource+action
	// check is the caller's (the relay's matchesResource), and the TS reference
	// applies no action allowlist. A credential whose att grants only unrecognized
	// actions leaves these fields empty rather than being rejected here — the
	// previous exact-match allowlist hard-rejected the spec-valid combined
	// "read,write" grant, diverging from TS.
	var action string
	var contentID string
	for _, a := range claims.Att {
		acts := ParseActions(a.Action)
		if !acts["read"] && !acts["write"] {
			continue
		}
		action = a.Action
		if a.Resource != "" {
			r := a.Resource
			if strings.HasPrefix(r, "chain:") {
				r = r[len("chain:"):]
			}
			contentID = r
		}
		break
	}

	// verify action if specified — membership test, so a combined "read,write"
	// grant satisfies an expectedAction of "read" or "write".
	if expectedAction != "" && !ParseActions(action)[expectedAction] {
		return nil, fmt.Errorf("action mismatch: expected %s, not granted by att (%q)", expectedAction, action)
	}

	return &VerifiedCredential{
		Iss:       claims.Iss,
		Aud:       claims.Aud,
		Exp:       claims.Exp,
		Iat:       claims.Iat,
		Att:       att,
		Action:    action,
		Kid:       kid,
		ContentID: contentID,
		CID:       headerCID,
	}, nil
}

// VerifiedAuthToken represents a successfully verified auth token JWT.
type VerifiedAuthToken struct {
	Iss string
	Sub string
	Kid string
	Exp int64 // expiration (unix seconds)
	Iat int64 // issued-at (unix seconds)
}

// VerifyAuthToken verifies a DID auth token JWT for relay authentication.
// Checks signature, typ=JWT, kid DID URL, audience, and temporal validity.
func VerifyAuthToken(token string, publicKey ed25519.PublicKey, audience string) (*VerifiedAuthToken, error) {
	return verifyAuthTokenCore(token, publicKey, audience, time.Now().Unix())
}

// VerifyAuthTokenAt is like VerifyAuthToken but accepts a custom current time
// (unix seconds) for testing temporal checks.
func VerifyAuthTokenAt(token string, publicKey ed25519.PublicKey, audience string, currentTime int64) (*VerifiedAuthToken, error) {
	return verifyAuthTokenCore(token, publicKey, audience, currentTime)
}

func verifyAuthTokenCore(token string, publicKey ed25519.PublicKey, audience string, currentTime int64) (*VerifiedAuthToken, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	headerBytes, err := Base64urlDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token")
	}
	payloadBytes, err := Base64urlDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token")
	}

	// apply the DFOS signature verification profile (alg pin, crit, no
	// header-key-trust) BEFORE any signature check
	if err := assertJWSProfile(headerBytes); err != nil {
		return nil, err
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to decode token")
	}

	if header.Typ != "JWT" {
		return nil, fmt.Errorf("invalid typ: %s", header.Typ)
	}

	// verify signature
	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := Base64urlDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature")
	}
	if !ed25519.Verify(publicKey, []byte(signingInput), sigBytes) {
		return nil, fmt.Errorf("invalid signature")
	}

	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		Iat int64  `json:"iat"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("invalid token claims")
	}

	if claims.Iss == "" || claims.Sub == "" || claims.Aud == "" || claims.Exp == 0 || claims.Iat == 0 {
		return nil, fmt.Errorf("missing required claims")
	}

	// verify kid is DID URL matching iss
	kid := header.Kid
	if kid == "" || !strings.Contains(kid, "#") {
		return nil, fmt.Errorf("kid must be a DID URL")
	}
	kidDID := kid[:strings.Index(kid, "#")]
	if kidDID != claims.Iss {
		return nil, fmt.Errorf("kid DID does not match iss")
	}

	// verify audience
	if claims.Aud != audience {
		return nil, fmt.Errorf("audience mismatch: expected %s, got %s", audience, claims.Aud)
	}

	// verify temporal validity
	if claims.Iat > currentTime {
		return nil, fmt.Errorf("token not yet valid")
	}
	if claims.Exp <= currentTime {
		return nil, fmt.Errorf("token expired")
	}

	return &VerifiedAuthToken{
		Iss: claims.Iss,
		Sub: claims.Sub,
		Kid: kid,
		Exp: claims.Exp,
		Iat: claims.Iat,
	}, nil
}

// DecodeJWTUnsafe decodes a JWT without verifying.
func DecodeJWTUnsafe(token string) (header map[string]string, payload map[string]any, err error) {
	h, p, err := DecodeJWSUnsafe(token)
	if err != nil {
		return nil, nil, err
	}
	hm := map[string]string{
		"alg": h.Alg,
		"typ": h.Typ,
		"kid": h.Kid,
	}
	if h.CID != "" {
		hm["cid"] = h.CID
	}
	return hm, p, nil
}
