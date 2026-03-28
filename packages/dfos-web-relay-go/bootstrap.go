package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// ProfileConfig holds the relay's profile fields. If empty, defaults are used.
type ProfileConfig struct {
	Name        string
	Description string
}

// BootstrapRelayIdentity generates a JIT relay identity and profile artifact,
// ingests both into the store, and returns the relay identity.
func BootstrapRelayIdentity(store Store) (*RelayIdentity, error) {
	return bootstrapRelay(store, nil, nil, ProfileConfig{})
}

// BootstrapRelayIdentityWithProfile generates a JIT relay identity with a
// custom profile, ingests both into the store, and returns the relay identity.
func BootstrapRelayIdentityWithProfile(store Store, profile ProfileConfig) (*RelayIdentity, error) {
	return bootstrapRelay(store, nil, nil, profile)
}

// BootstrapRelayIdentityFromKey creates a relay identity from an existing
// private key and key ID, signs a profile artifact, ingests both, and returns
// the relay identity. Used for persistent bootstrap where keys are loaded from
// storage.
func BootstrapRelayIdentityFromKey(store Store, priv ed25519.PrivateKey, keyID string, profile ProfileConfig) (*RelayIdentity, error) {
	pub := priv.Public().(ed25519.PublicKey)
	return bootstrapRelay(store, priv, &keyMaterial{pub: pub, keyID: keyID}, profile)
}

// RebootstrapProfile signs a fresh profile artifact for an existing relay
// identity. The identity chain is already in the store — this only produces a
// new profile artifact (e.g. after RELAY_NAME changes between restarts).
func RebootstrapProfile(store Store, priv ed25519.PrivateKey, keyID, did string, profile ProfileConfig) (*RelayIdentity, error) {
	kid := did + "#" + keyID
	content := map[string]any{
		"$schema": "https://schemas.dfos.com/profile/v1",
		"name":    profile.Name,
	}
	if content["name"] == "" {
		content["name"] = "DFOS Relay"
	}
	if profile.Description != "" {
		content["description"] = profile.Description
	}

	profileArtifactJWS, _, err := dfos.SignArtifact(did, content, kid, priv)
	if err != nil {
		return nil, fmt.Errorf("sign profile artifact: %w", err)
	}

	// ingest profile artifact (new artifact each boot — immutable, append-only)
	artResults := IngestOperations([]string{profileArtifactJWS}, store)
	if len(artResults) == 0 || artResults[0].Status == "rejected" {
		errMsg := "unknown"
		if len(artResults) > 0 && artResults[0].Error != "" {
			errMsg = artResults[0].Error
		}
		return nil, fmt.Errorf("ingest relay profile artifact: %s", errMsg)
	}

	return &RelayIdentity{
		DID:                did,
		ProfileArtifactJWS: profileArtifactJWS,
		PrivateKey:         priv,
		KeyID:              keyID,
	}, nil
}

type keyMaterial struct {
	pub   ed25519.PublicKey
	keyID string
}

func bootstrapRelay(store Store, priv ed25519.PrivateKey, existing *keyMaterial, profile ProfileConfig) (*RelayIdentity, error) {
	var pub ed25519.PublicKey
	var keyID string
	var err error

	if existing != nil {
		pub = existing.pub
		keyID = existing.keyID
	} else {
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate keypair: %w", err)
		}
		keyID = dfos.GenerateKeyID()
	}

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

	// ingest identity genesis — may return duplicate if key was reloaded
	results := IngestOperations([]string{identityJWS}, store)
	if len(results) == 0 || results[0].Status == "rejected" {
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
		"name":    profile.Name,
	}
	if content["name"] == "" {
		content["name"] = "DFOS Relay"
	}
	if profile.Description != "" {
		content["description"] = profile.Description
	}

	profileArtifactJWS, _, err := dfos.SignArtifact(did, content, kid, priv)
	if err != nil {
		return nil, fmt.Errorf("sign profile artifact: %w", err)
	}

	// ingest profile artifact
	artResults := IngestOperations([]string{profileArtifactJWS}, store)
	if len(artResults) == 0 || artResults[0].Status == "rejected" {
		errMsg := "unknown"
		if len(artResults) > 0 && artResults[0].Error != "" {
			errMsg = artResults[0].Error
		}
		return nil, fmt.Errorf("ingest relay profile artifact: %s", errMsg)
	}

	return &RelayIdentity{
		DID:                did,
		ProfileArtifactJWS: profileArtifactJWS,
		PrivateKey:         priv,
		KeyID:              keyID,
	}, nil
}
