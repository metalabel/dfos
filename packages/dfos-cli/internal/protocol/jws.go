package protocol

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
)

// JWSHeader is the protected header of a JWS token.
type JWSHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
	CID string `json:"cid,omitempty"`
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

	var header JWSHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("unmarshal header: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, fmt.Errorf("unmarshal payload: %w", err)
	}

	// normalize JSON numbers (float64 → int64 for whole numbers)
	// so CBOR encoding matches the TypeScript reference implementation
	NormalizeJSONNumbers(payload)

	return &header, payload, nil
}

// VerifyJWS verifies a JWS compact serialization token and returns the header and payload.
func VerifyJWS(token string, publicKey ed25519.PublicKey) (*JWSHeader, map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("invalid JWS format")
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	sig, err := Base64urlDecode(parts[2])
	if err != nil {
		return nil, nil, fmt.Errorf("decode signature: %w", err)
	}

	if !ed25519.Verify(publicKey, signingInput, sig) {
		return nil, nil, fmt.Errorf("signature verification failed")
	}

	headerBytes, _ := Base64urlDecode(parts[0])
	payloadBytes, _ := Base64urlDecode(parts[1])

	var header JWSHeader
	json.Unmarshal(headerBytes, &header)

	var payload map[string]any
	json.Unmarshal(payloadBytes, &payload)

	return &header, payload, nil
}
