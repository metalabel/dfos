package relay

import (
	"strings"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// AuthenticateRequest extracts a Bearer token from the Authorization header,
// resolves the signing key from stored identity chains, and verifies the token
// against the relay's DID as audience.
//
// Uses current-state key resolution only — rotated-out keys are rejected.
// Returns nil if authentication fails for any reason.
func AuthenticateRequest(authHeader string, relayDID string, store Store) *dfos.VerifiedAuthToken {
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return nil
	}

	token := authHeader[7:]
	if token == "" {
		return nil
	}

	// decode JWS header to extract kid
	header, _, err := dfos.DecodeJWSUnsafe(token)
	if err != nil || header == nil {
		return nil
	}

	kid := header.Kid
	if kid == "" || !strings.Contains(kid, "#") {
		return nil
	}

	resolveKey := CreateCurrentKeyResolver(store)

	publicKey, err := resolveKey(kid)
	if err != nil {
		return nil
	}

	result, err := dfos.VerifyAuthToken(token, publicKey, relayDID)
	if err != nil {
		return nil
	}

	return result
}
