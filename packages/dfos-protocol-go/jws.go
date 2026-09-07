package dfos

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
)

// JWSHeader is the protected header of a JWS token.
//
// Crit/JWK/X5C are declared so that a header carrying them is observable; the
// DFOS profile rejects all three (see assertJWSProfile). DFOS never emits them.
type JWSHeader struct {
	Alg  string          `json:"alg"`
	Typ  string          `json:"typ"`
	Kid  string          `json:"kid"`
	CID  string          `json:"cid,omitempty"`
	Crit json.RawMessage `json:"crit,omitempty"`
	JWK  json.RawMessage `json:"jwk,omitempty"`
	X5C  json.RawMessage `json:"x5c,omitempty"`
}

// CreateJWS creates a JWS compact serialization token.
func CreateJWS(header JWSHeader, payload any, privateKey ed25519.PrivateKey) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	headerB64 := Base64urlEncode(headerJSON)
	payloadB64 := Base64urlEncode(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	sig := ed25519.Sign(privateKey, []byte(signingInput))
	sigB64 := Base64urlEncode(sig)

	return signingInput + "." + sigB64, nil
}

// decodeJWSHeader decodes a protected header BY EXACT KEY.
//
// encoding/json matches an unmatched struct field case-insensitively, so a
// header spelling "KID" or "CID" populates Kid/CID exactly as the correctly
// cased member would — and kid/cid are the integrity-bearing half of the
// header, the part that says which key signed and what CID the signature
// commits to. The TypeScript reference reads its header off a plain object, by
// exact key, and would see no kid at all in that token. So this reads the header
// into a raw map and pulls each member by its exact name, the pattern
// key_proof.go and profile.go already use.
//
// A member present with a non-string value is an error rather than a silent
// zero: absent, null, and wrong-type are three different facts.
func decodeJWSHeader(headerBytes []byte) (*JWSHeader, error) {
	if err := AssertCanonicalJSONText(headerBytes); err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(headerBytes, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal header: %w", err)
	}

	header := &JWSHeader{}
	for _, field := range []struct {
		name string
		dst  *string
	}{
		{"alg", &header.Alg},
		{"typ", &header.Typ},
		{"kid", &header.Kid},
		{"cid", &header.CID},
	} {
		rawValue, present := raw[field.name]
		if !present {
			continue
		}
		// json.Unmarshal accepts a JSON null into any type as a no-op, which
		// would read as "absent" here while TypeScript rejects it outright
		if string(rawValue) == "null" {
			return nil, fmt.Errorf("header %s must be a string", field.name)
		}
		if err := json.Unmarshal(rawValue, field.dst); err != nil {
			return nil, fmt.Errorf("header %s must be a string", field.name)
		}
	}
	header.Crit = raw["crit"]
	header.JWK = raw["jwk"]
	header.X5C = raw["x5c"]

	return header, nil
}

// DecodeJWSUnsafe decodes a JWS token without verifying the signature.
func DecodeJWSUnsafe(token string) (*JWSHeader, map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("invalid JWS format: expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := Base64urlDecode(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("decode header: %w", err)
	}
	payloadBytes, err := Base64urlDecode(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("decode payload: %w", err)
	}

	header, err := decodeJWSHeader(headerBytes)
	if err != nil {
		return nil, nil, err
	}

	if err := AssertCanonicalJSONText(payloadBytes); err != nil {
		return nil, nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, fmt.Errorf("unmarshal payload: %w", err)
	}

	// normalize JSON numbers (float64 → int64 for whole numbers)
	// so CBOR encoding matches the TypeScript reference implementation
	NormalizeJSONNumbers(payload)

	return header, payload, nil
}

// VerifyJWS verifies a JWS compact serialization token and returns the header and payload.
func VerifyJWS(token string, publicKey ed25519.PublicKey) (*JWSHeader, map[string]any, error) {
	// ed25519.Verify panics on a wrong-size key. DecodeMultikey is the usual
	// source and now rejects one, but it is not the only path that can hand a
	// key here, and a bad key is an invalid input, never a crash.
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("expected a %d-byte ed25519 key, got %d bytes", ed25519.PublicKeySize, len(publicKey))
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("invalid JWS format")
	}

	headerBytes, err := Base64urlDecode(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("decode header: %w", err)
	}

	// apply the DFOS signature verification profile (alg pin, crit, no
	// header-key-trust) BEFORE any signature check
	if err := assertJWSProfile(headerBytes); err != nil {
		return nil, nil, err
	}

	// the header decodes by exact key, and its raw text is scanned for the
	// defects a decoded value cannot show — both BEFORE the signature check, so
	// an out-of-profile token is rejected whatever its signature would have done
	header, err := decodeJWSHeader(headerBytes)
	if err != nil {
		return nil, nil, err
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	sig, err := Base64urlDecode(parts[2])
	if err != nil {
		return nil, nil, fmt.Errorf("decode signature: %w", err)
	}

	if !ed25519.Verify(publicKey, signingInput, sig) {
		return nil, nil, fmt.Errorf("signature verification failed")
	}

	payloadBytes, _ := Base64urlDecode(parts[1])
	if err := AssertCanonicalJSONText(payloadBytes); err != nil {
		return nil, nil, err
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, fmt.Errorf("unmarshal payload: %w", err)
	}

	return header, payload, nil
}
