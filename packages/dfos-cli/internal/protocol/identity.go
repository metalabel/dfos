package protocol

import (
	"crypto/ed25519"
	"time"
)

// MultikeyPublicKey represents a public key in Multikey format.
type MultikeyPublicKey struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

// IdentityState represents the verified state of an identity chain.
type IdentityState struct {
	DID            string              `json:"did"`
	IsDeleted      bool                `json:"isDeleted"`
	AuthKeys       []MultikeyPublicKey `json:"authKeys"`
	AssertKeys     []MultikeyPublicKey `json:"assertKeys"`
	ControllerKeys []MultikeyPublicKey `json:"controllerKeys"`
}

// NewMultikeyPublicKey creates a MultikeyPublicKey from an ed25519 public key.
func NewMultikeyPublicKey(keyID string, pubKey ed25519.PublicKey) MultikeyPublicKey {
	return MultikeyPublicKey{
		ID:                 keyID,
		Type:               "Multikey",
		PublicKeyMultibase: EncodeMultikey(pubKey),
	}
}

// SignIdentityCreate signs an identity genesis (create) operation.
// Returns the JWS token and derived DID.
func SignIdentityCreate(controllerKeys, authKeys, assertKeys []MultikeyPublicKey, signerKeyID string, privateKey ed25519.PrivateKey) (jwsToken string, did string, operationCID string, err error) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	// ensure empty slices instead of nil (JSON null vs [])
	if authKeys == nil {
		authKeys = []MultikeyPublicKey{}
	}
	if assertKeys == nil {
		assertKeys = []MultikeyPublicKey{}
	}
	if controllerKeys == nil {
		controllerKeys = []MultikeyPublicKey{}
	}

	payload := map[string]any{
		"version":        1,
		"type":           "create",
		"authKeys":       authKeys,
		"assertKeys":     assertKeys,
		"controllerKeys": controllerKeys,
		"createdAt":      now.Format("2006-01-02T15:04:05.000Z"),
	}

	_, cidBytes, cidStr, err := DagCborCID(payload)
	if err != nil {
		return "", "", "", err
	}

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:identity-op",
		Kid: signerKeyID, // bare key ID for genesis
		CID: cidStr,
	}

	jwsToken, err = CreateJWS(header, payload, privateKey)
	if err != nil {
		return "", "", "", err
	}

	did = DeriveDID(cidBytes)
	return jwsToken, did, cidStr, nil
}
