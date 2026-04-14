package dfos

import (
	"fmt"
	"strings"
)

// VerifiedRevocationResult is the result of revocation verification.
type VerifiedRevocationResult struct {
	// The issuer DID that revoked the credential
	DID string
	// CID of the revoked credential
	CredentialCID string
	// Timestamp of the revocation
	CreatedAt string
	// kid from the JWS header
	SignerKeyId string
	// CID of the revocation artifact itself
	RevocationCID string
}

// VerifyRevocation verifies a revocation JWS — signature, CID, payload
// schema, signer match.
func VerifyRevocation(jwsToken string, resolveKey KeyResolver) (*VerifiedRevocationResult, error) {
	return verifyRevocationCore(jwsToken, resolveKey)
}

// VerifyRevocationAt is an alias for VerifyRevocation. Revocations have no
// temporal validity window (they are permanent), so there is no custom time
// parameter. Provided for API consistency with other verify functions.
func VerifyRevocationAt(jwsToken string, resolveKey KeyResolver) (*VerifiedRevocationResult, error) {
	return verifyRevocationCore(jwsToken, resolveKey)
}

func verifyRevocationCore(jwsToken string, resolveKey KeyResolver) (*VerifiedRevocationResult, error) {
	header, payload, err := DecodeJWSUnsafe(jwsToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode revocation JWS")
	}

	// verify typ
	if header.Typ != "did:dfos:revocation" {
		return nil, fmt.Errorf("invalid revocation typ: %s", header.Typ)
	}

	// validate payload
	version, _ := payload["version"].(int64)
	if version != 1 {
		return nil, fmt.Errorf("invalid revocation payload: invalid or missing version")
	}
	if payloadString(payload, "type") != "revocation" {
		return nil, fmt.Errorf("invalid revocation payload: wrong type")
	}
	did := payloadString(payload, "did")
	if did == "" {
		return nil, fmt.Errorf("invalid revocation payload: missing did")
	}
	credentialCID := payloadString(payload, "credentialCID")
	if credentialCID == "" {
		return nil, fmt.Errorf("invalid revocation payload: missing credentialCID")
	}
	createdAt := payloadString(payload, "createdAt")
	if err := validateCreatedAt(createdAt); err != nil {
		return nil, fmt.Errorf("invalid revocation payload: %w", err)
	}

	// verify kid DID matches payload did (only the issuer can revoke)
	kid := header.Kid
	hashIdx := strings.Index(kid, "#")
	if hashIdx < 0 {
		return nil, fmt.Errorf("revocation kid must be a DID URL")
	}
	kidDid := kid[:hashIdx]
	if kidDid != did {
		return nil, fmt.Errorf("revocation kid DID does not match payload did")
	}

	// verify signature
	publicKey, err := resolveKey(kid)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve revocation key: %w", err)
	}
	if _, _, err := VerifyJWS(jwsToken, publicKey); err != nil {
		return nil, fmt.Errorf("invalid revocation signature")
	}

	// verify CID
	_, _, revocationCID, err := DagCborCID(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to derive revocation CID: %w", err)
	}
	if header.CID == "" {
		return nil, fmt.Errorf("missing cid in revocation header")
	}
	if header.CID != revocationCID {
		return nil, fmt.Errorf("revocation cid mismatch")
	}

	return &VerifiedRevocationResult{
		DID:           did,
		CredentialCID: credentialCID,
		CreatedAt:     createdAt,
		SignerKeyId:   kid,
		RevocationCID: revocationCID,
	}, nil
}
