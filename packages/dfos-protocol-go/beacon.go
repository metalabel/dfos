package dfos

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"sort"
	"time"
)

// SignBeacon signs a beacon announcement.
func SignBeacon(did, merkleRoot, kid string, privateKey ed25519.PrivateKey) (jwsToken string, beaconCID string, err error) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	payload := map[string]any{
		"version":    1,
		"type":       "beacon",
		"did":        did,
		"merkleRoot": merkleRoot,
		"createdAt":  now.Format("2006-01-02T15:04:05.000Z"),
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

// BuildMerkleRoot builds a merkle tree from a list of content IDs and returns the hex root.
func BuildMerkleRoot(contentIDs []string) string {
	if len(contentIDs) == 0 {
		return fmt.Sprintf("%064x", 0)
	}

	sorted := make([]string, len(contentIDs))
	copy(sorted, contentIDs)
	sort.Strings(sorted)

	leaves := make([][]byte, len(sorted))
	for i, id := range sorted {
		h := sha256.Sum256([]byte(id))
		leaves[i] = h[:]
	}

	level := leaves
	for len(level) > 1 {
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				h := sha256.Sum256(append(level[i], level[i+1]...))
				next = append(next, h[:])
			} else {
				next = append(next, level[i])
			}
		}
		level = next
	}

	return fmt.Sprintf("%x", level[0])
}
