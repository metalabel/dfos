package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// BootstrapRelayIdentity generates a JIT relay identity and profile artifact,
// ingests both into the store, and returns the relay identity.
func BootstrapRelayIdentity(store Store) (*RelayIdentity, error) {
	// generate keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}

	keyID := dfos.GenerateKeyID()
	mk := dfos.NewMultikeyPublicKey(keyID, pub)

	// sign identity genesis
	identityJWS, did, _, err := dfos.SignIdentityCreate(
		[]dfos.MultikeyPublicKey{mk}, // controller
		[]dfos.MultikeyPublicKey{mk}, // auth
		[]dfos.MultikeyPublicKey{mk}, // assert
		keyID,
		priv,
	)
	if err != nil {
		return nil, fmt.Errorf("sign identity genesis: %w", err)
	}

	// ingest identity genesis to derive the DID
	results := IngestOperations([]string{identityJWS}, store)
	if len(results) == 0 || results[0].Status != "accepted" || results[0].ChainID == "" {
		errMsg := "unknown"
		if len(results) > 0 && results[0].Error != "" {
			errMsg = results[0].Error
		}
		return nil, fmt.Errorf("bootstrap relay identity: %s", errMsg)
	}

	// sign profile artifact
	kid := did + "#" + keyID
	content := map[string]any{
		"$schema": "https://schemas.dfos.com/profile/v1",
		"name":    "DFOS Relay",
	}
	profileArtifactJWS, _, err := dfos.SignArtifact(did, content, kid, priv)
	if err != nil {
		return nil, fmt.Errorf("sign profile artifact: %w", err)
	}

	// ingest profile artifact
	artResults := IngestOperations([]string{profileArtifactJWS}, store)
	if len(artResults) == 0 || artResults[0].Status != "accepted" {
		errMsg := "unknown"
		if len(artResults) > 0 && artResults[0].Error != "" {
			errMsg = artResults[0].Error
		}
		return nil, fmt.Errorf("ingest relay profile artifact: %s", errMsg)
	}

	return &RelayIdentity{
		DID:                did,
		ProfileArtifactJWS: profileArtifactJWS,
	}, nil
}
