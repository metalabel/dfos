package dfos

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

// SignArtifact signs a standalone artifact — an inline structured document with a $schema discriminator.
// Returns the JWS token and the artifact's CID.
func SignArtifact(did string, content map[string]any, kid string, privateKey ed25519.PrivateKey) (jwsToken string, artifactCID string, err error) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	payload := map[string]any{
		"version":   1,
		"type":      "artifact",
		"did":       did,
		"content":   content,
		"createdAt": now.Format("2006-01-02T15:04:05.000Z"),
	}

	cborBytes, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		return "", "", err
	}
	if len(cborBytes) > 16384 {
		return "", "", fmt.Errorf("artifact payload exceeds max size: %d > 16384", len(cborBytes))
	}

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:artifact",
		Kid: kid,
		CID: cidStr,
	}

	jwsToken, err = CreateJWS(header, payload, privateKey)
	if err != nil {
		return "", "", err
	}

	return jwsToken, cidStr, nil
}
