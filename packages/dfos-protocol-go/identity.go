package dfos

import "crypto/ed25519"

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
	now := protocolTimestamp()

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

// SignIdentityUpdate signs an identity update operation (key rotation).
// The signer must use a current controller key. kid must be a DID URL
// (e.g., "did:dfos:xxx#key_yyy").
func SignIdentityUpdate(previousCID string, controllerKeys, authKeys, assertKeys []MultikeyPublicKey, kid string, privateKey ed25519.PrivateKey) (jwsToken string, operationCID string, err error) {
	now := protocolTimestamp()

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
		"version":              1,
		"type":                 "update",
		"previousOperationCID": previousCID,
		"authKeys":             authKeys,
		"assertKeys":           assertKeys,
		"controllerKeys":       controllerKeys,
		"createdAt":            now.Format("2006-01-02T15:04:05.000Z"),
	}

	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		return "", "", err
	}

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:identity-op",
		Kid: kid,
		CID: cidStr,
	}

	jwsToken, err = CreateJWS(header, payload, privateKey)
	if err != nil {
		return "", "", err
	}

	return jwsToken, cidStr, nil
}

// SignIdentityDelete signs an identity delete operation (permanent destruction).
// The signer must use a current controller key.
func SignIdentityDelete(previousCID, kid string, privateKey ed25519.PrivateKey) (jwsToken string, operationCID string, err error) {
	now := protocolTimestamp()

	payload := map[string]any{
		"version":              1,
		"type":                 "delete",
		"previousOperationCID": previousCID,
		"createdAt":            now.Format("2006-01-02T15:04:05.000Z"),
	}

	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		return "", "", err
	}

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:identity-op",
		Kid: kid,
		CID: cidStr,
	}

	jwsToken, err = CreateJWS(header, payload, privateKey)
	if err != nil {
		return "", "", err
	}

	return jwsToken, cidStr, nil
}
