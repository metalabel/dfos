package dfos

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
)

// SignCountersignature countersigns an existing operation by re-signing the same payload.
func SignCountersignature(operationToken string, witnessKid string, privateKey ed25519.PrivateKey) (string, error) {
	// decode the original operation to get its payload
	_, payload, err := DecodeJWSUnsafe(operationToken)
	if err != nil {
		return "", fmt.Errorf("decode operation: %w", err)
	}

	// re-derive the CID from the payload
	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		return "", fmt.Errorf("derive CID: %w", err)
	}

	// determine typ from the original
	origHeader, _, _ := DecodeJWSUnsafe(operationToken)
	typ := origHeader.Typ

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: typ,
		Kid: witnessKid,
		CID: cidStr,
	}

	return CreateJWS(header, payload, privateKey)
}

// SignBeaconCountersignature countersigns a beacon by re-signing its payload.
func SignBeaconCountersignature(beaconPayload map[string]any, witnessKid string, privateKey ed25519.PrivateKey) (string, error) {
	_, _, cidStr, err := DagCborCID(beaconPayload)
	if err != nil {
		return "", fmt.Errorf("derive CID: %w", err)
	}

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:beacon",
		Kid: witnessKid,
		CID: cidStr,
	}

	return CreateJWS(header, beaconPayload, privateKey)
}

// PayloadFromJWS extracts the raw payload map from a JWS token.
func PayloadFromJWS(token string) (map[string]any, error) {
	parts := splitJWS(token)
	if parts == nil {
		return nil, fmt.Errorf("invalid JWS format")
	}
	payloadBytes, err := Base64urlDecode(parts[1])
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func splitJWS(token string) []string {
	parts := make([]string, 0, 3)
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	if len(parts) != 3 {
		return nil
	}
	return parts
}
