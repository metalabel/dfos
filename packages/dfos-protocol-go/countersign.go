package dfos

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
)

// SignCountersign signs a standalone countersignature attesting to a target operation by CID.
// Returns the JWS token and the countersign's own CID (distinct from the target).
func SignCountersign(witnessDID, targetCID, kid string, privateKey ed25519.PrivateKey) (jwsToken string, countersignCID string, err error) {
	now := protocolTimestamp()

	payload := map[string]any{
		"version":   1,
		"type":      "countersign",
		"did":       witnessDID,
		"targetCID": targetCID,
		"createdAt": now.Format("2006-01-02T15:04:05.000Z"),
	}

	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		return "", "", err
	}

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:countersign",
		Kid: kid,
		CID: cidStr,
	}

	jwsToken, err = CreateJWS(header, payload, privateKey)
	if err != nil {
		return "", "", err
	}

	return jwsToken, cidStr, nil
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
