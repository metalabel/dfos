package dfos

import (
	"crypto/ed25519"
)

// SignBeacon signs a beacon announcement.
func SignBeacon(did, manifestContentId, kid string, privateKey ed25519.PrivateKey) (jwsToken string, beaconCID string, err error) {
	now := protocolTimestamp()

	payload := map[string]any{
		"version":           int64(1),
		"type":              "beacon",
		"did":               did,
		"manifestContentId": manifestContentId,
		"createdAt":         now.Format("2006-01-02T15:04:05.000Z"),
	}

	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		return "", "", err
	}

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:beacon",
		Kid: kid,
		CID: cidStr,
	}

	jwsToken, err = CreateJWS(header, payload, privateKey)
	if err != nil {
		return "", "", err
	}

	return jwsToken, cidStr, nil
}
