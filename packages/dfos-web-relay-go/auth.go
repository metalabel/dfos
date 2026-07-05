package relay

import (
	"fmt"
	"strings"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// DefaultMaxAuthTokenTTL bounds the lifetime (exp-iat) the relay honors on a
// self-signed auth token. Auth tokens are ephemeral (the spec describes them as
// "minutes"); this ceiling caps a buggy or malicious signer minting an
// effectively-permanent bearer token. It applies ONLY to auth tokens — DFOS
// credentials (read/write/standing) are verified on a separate path
// (verifyCredentialForAccess) and never reach AuthenticateRequest, so their
// hours-to-months lifetimes are unaffected. A value <= 0 disables the ceiling.
const DefaultMaxAuthTokenTTL = 24 * time.Hour

// AuthenticateRequest extracts a Bearer token from the Authorization header,
// resolves the signing key from stored identity chains, and verifies the token
// against the relay's DID as audience.
//
// Uses current-state key resolution only — rotated-out keys are rejected. The
// token's declared lifetime (exp-iat) must not exceed maxAuthTokenTTL (pass <= 0
// to disable). Returns nil if authentication fails for any reason.
func AuthenticateRequest(authHeader string, relayDID string, store Store, maxAuthTokenTTL time.Duration) *dfos.VerifiedAuthToken {
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

	// enforce the auth-token lifetime ceiling (auth tokens only — credentials are
	// verified on a different path and never reach here).
	if maxAuthTokenTTL > 0 && result.Exp-result.Iat > int64(maxAuthTokenTTL.Seconds()) {
		return nil
	}

	return result
}

// ---------------------------------------------------------------------------
// public standing auth
// ---------------------------------------------------------------------------

// hasPublicStandingAuth checks if a valid public standing credential exists
// for the given content. Verifies expiry and revocation.
//
// Store-scoped (mirrors the TS twin hasPublicStandingAuth(contentId, action,
// store)): the HTTP read path passes r.readStore (never races on the ingestion
// tx); ingest-time index maintenance passes the ingestion store so the recompute
// sees the same within-batch uncommitted writes the op just made.
func hasPublicStandingAuth(contentID string, action string, store Store) bool {
	resource := "chain:" + contentID
	publicCreds, _ := store.GetPublicCredentials(resource)
	resolveKey := CreateKeyResolver(store)

	chain, _ := store.GetContentChain(contentID)
	if chain == nil {
		return false
	}

	for _, credJws := range publicCreds {
		if err := verifyCredentialForAccess(credJws, resolveKey, resource, action, chain.State.CreatorDID, "", store); err == nil {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// content access verification
// ---------------------------------------------------------------------------

// verifyContentAccess checks whether a requester has access to a resource.
// Returns "" if access is granted, or an error message string if denied.
//
// Checks in order:
// 1. Creator always has access
// 2. Stored public credentials (standing authorization)
// 3. Per-request credential (X-Credential header)
func (r *Relay) verifyContentAccess(requesterDID string, creatorDID string, requestedResource string, action string, credentialJWS string) string {
	// 1. creator always has access
	if requesterDID != "" && requesterDID == creatorDID {
		return ""
	}

	// readStore: key resolution runs on the HTTP read path, never races on tx.
	store := r.readStore
	resolveKey := CreateKeyResolver(store)

	// 2. check stored public credentials
	publicCreds, _ := store.GetPublicCredentials(requestedResource)
	for _, credJws := range publicCreds {
		if err := verifyCredentialForAccess(credJws, resolveKey, requestedResource, action, creatorDID, "", store); err == nil {
			return ""
		}
	}

	// 3. check per-request credential
	if credentialJWS != "" {
		if err := verifyCredentialForAccess(credentialJWS, resolveKey, requestedResource, action, creatorDID, requesterDID, store); err != nil {
			return err.Error()
		}
		return ""
	}

	return "read credential required"
}

// verifyCredentialForAccess verifies a single credential for resource access.
// It verifies the signature, checks revocation, checks resource+action match,
// and verifies the delegation chain.
//
// For public credentials (aud="*"), requesterDID can be empty.
// For per-request credentials, requesterDID is checked against aud.
func verifyCredentialForAccess(credJws string, resolveKey dfos.KeyResolver, requestedResource string, action string, creatorDID string, requesterDID string, store Store) error {
	// decode to get kid and raw payload
	header, payload, err := dfos.DecodeJWSUnsafe(credJws)
	if err != nil || header == nil {
		return fmt.Errorf("invalid credential format")
	}

	kid := header.Kid
	if kid == "" || !strings.Contains(kid, "#") {
		return fmt.Errorf("credential kid must be a DID URL")
	}

	issuerDID := kid[:strings.Index(kid, "#")]

	// check issuer identity is not deleted
	issuerIdentity, _ := store.GetIdentityChain(issuerDID)
	if issuerIdentity != nil && issuerIdentity.State.IsDeleted {
		return fmt.Errorf("credential issuer identity is deleted")
	}

	// resolve signing key and verify credential signature + structure
	publicKey, err := resolveKey(kid)
	if err != nil {
		return fmt.Errorf("failed to resolve credential key: %v", err)
	}

	// VerifyCredential checks signature, CID integrity, temporal validity, kid
	// We pass empty string for subject to skip audience check (we do it manually)
	// and empty string for expectedType to accept any action type
	verified, err := dfos.VerifyCredential(credJws, publicKey, "", "")
	if err != nil {
		return err
	}

	// check leaf revocation
	revoked, _ := store.IsCredentialRevoked(verified.Iss, verified.CID)
	if revoked {
		return fmt.Errorf("credential is revoked")
	}

	// parse att from raw payload for resource matching and delegation
	att := dfos.ParseAtt(payload)

	// check resource + action match
	if !matchesResource(att, requestedResource, action) {
		return fmt.Errorf("credential does not cover requested resource")
	}

	// for per-request credentials, check audience
	if requesterDID != "" {
		aud, _ := payload["aud"].(string)
		if aud != "*" && aud != requesterDID {
			return fmt.Errorf("credential audience does not match requester")
		}
	}

	// verify delegation chain — shared with the write path via the protocol
	// library's linear (single-parent) walk. The relay no longer maintains its
	// own copy: the previous copy unioned the att of ALL parents and recursed
	// only through parents[0], which let a self-issued secondary parent contribute
	// scope never rooted at the creator (a multi-parent authority-escalation the
	// library walk and the TS stack reject). Closures bind the read-store
	// revocation + issuer-deletion checks; leaf revocation/deletion is checked
	// above (the walk covers parents only).
	prf, err := dfos.ParsePrf(payload)
	if err != nil {
		return fmt.Errorf("credential prf invalid: %v", err)
	}
	isRevoked := func(issuerDID, credentialCID string) (bool, error) {
		revoked, _ := store.IsCredentialRevoked(issuerDID, credentialCID)
		return revoked, nil
	}
	isDeleted := func(did string) (bool, error) {
		idc, _ := store.GetIdentityChain(did)
		return idc != nil && idc.State.IsDeleted, nil
	}
	if err := dfos.VerifyDelegationChain(credJws, verified, att, prf, resolveKey, creatorDID, isRevoked, isDeleted); err != nil {
		return err
	}

	return nil
}

// ---------------------------------------------------------------------------
// resource matching
// ---------------------------------------------------------------------------

// matchesResource checks if an att array covers a requested resource+action.
func matchesResource(att []dfos.AttEntry, resource string, action string) bool {
	reqType, reqID, ok := dfos.ParseResource(resource)
	if !ok {
		return false
	}
	reqActions := dfos.ParseActions(action)

	for _, entry := range att {
		entryType, entryID, ok := dfos.ParseResource(entry.Resource)
		if !ok {
			continue
		}
		entryActions := dfos.ParseActions(entry.Action)

		// check action coverage — all requested actions must be in entry actions
		actionsCovered := true
		for a := range reqActions {
			if !entryActions[a] {
				actionsCovered = false
				break
			}
		}
		if !actionsCovered {
			continue
		}

		// chain:* covers any chain: request
		if entryType == "chain" && entryID == "*" && reqType == "chain" {
			return true
		}

		// exact resource match
		if entryType == reqType && entryID == reqID {
			return true
		}

	}

	return false
}
