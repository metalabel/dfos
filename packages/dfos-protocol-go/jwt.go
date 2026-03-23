package dfos

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// VerifiedCredential represents a successfully verified VC-JWT credential.
type VerifiedCredential struct {
	Iss       string
	Sub       string
	Exp       int64
	Type      string // "DFOSContentRead" or "DFOSContentWrite"
	Kid       string
	ContentID string // optional scope
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

// CreateCredential creates a VC-JWT credential (DFOSContentRead or DFOSContentWrite).
func CreateCredential(iss, sub, kid, credType string, ttl time.Duration, contentID string, privateKey ed25519.PrivateKey) (string, error) {
	now := time.Now().Unix()
	exp := now + int64(ttl.Seconds())

	header := map[string]string{
		"alg": "EdDSA",
		"typ": "vc+jwt",
		"kid": kid,
	}

	credSubject := map[string]string{}
	if contentID != "" {
		credSubject["contentId"] = contentID
	}

	payload := map[string]any{
		"iss": iss,
		"sub": sub,
		"exp": exp,
		"iat": now,
		"vc": map[string]any{
			"@context":          []string{"https://www.w3.org/ns/credentials/v2"},
			"type":              []string{"VerifiableCredential", credType},
			"credentialSubject": credSubject,
		},
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

// VerifyCredential verifies a VC-JWT credential token. It checks the signature,
// expiration, payload structure, and optionally subject and credential type.
// Pass empty string for subject or expectedType to skip those checks.
func VerifyCredential(token string, publicKey ed25519.PublicKey, subject string, expectedType string) (*VerifiedCredential, error) {
	return verifyCredentialCore(token, publicKey, subject, expectedType, time.Now().Unix())
}

// VerifyCredentialAt is like VerifyCredential but accepts a custom current time
// (unix seconds) for testing temporal checks.
func VerifyCredentialAt(token string, publicKey ed25519.PublicKey, subject string, expectedType string, currentTime int64) (*VerifiedCredential, error) {
	return verifyCredentialCore(token, publicKey, subject, expectedType, currentTime)
}

// verifyCredentialCore is the shared implementation for credential verification.
func verifyCredentialCore(token string, publicKey ed25519.PublicKey, subject string, expectedType string, currentTime int64) (*VerifiedCredential, error) {
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

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to decode token")
	}

	// verify header fields
	if header.Alg != "EdDSA" {
		return nil, fmt.Errorf("unsupported algorithm: %s", header.Alg)
	}
	if header.Typ != "vc+jwt" {
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

	// parse payload
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
		Iat int64  `json:"iat"`
		VC  struct {
			Context           []string       `json:"@context"`
			Type              []string       `json:"type"`
			CredentialSubject map[string]any `json:"credentialSubject"`
		} `json:"vc"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("invalid credential claims: %s", err)
	}

	// validate required fields
	if claims.Iss == "" || claims.Sub == "" || claims.Exp == 0 || claims.Iat == 0 {
		return nil, fmt.Errorf("invalid credential claims: missing required fields")
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

	// verify subject if specified
	if subject != "" && claims.Sub != subject {
		return nil, fmt.Errorf("subject mismatch: expected %s, got %s", subject, claims.Sub)
	}

	// extract credential type (second element after "VerifiableCredential")
	if len(claims.VC.Type) < 2 || claims.VC.Type[0] != "VerifiableCredential" {
		return nil, fmt.Errorf("invalid credential type array")
	}
	vcType := claims.VC.Type[1]

	// verify type if specified
	if expectedType != "" && vcType != expectedType {
		return nil, fmt.Errorf("type mismatch: expected %s, got %s", expectedType, vcType)
	}

	// extract optional contentId
	var contentID string
	if cid, ok := claims.VC.CredentialSubject["contentId"]; ok {
		if s, ok := cid.(string); ok {
			contentID = s
		}
	}

	return &VerifiedCredential{
		Iss:       claims.Iss,
		Sub:       claims.Sub,
		Exp:       claims.Exp,
		Type:      vcType,
		Kid:       kid,
		ContentID: contentID,
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
