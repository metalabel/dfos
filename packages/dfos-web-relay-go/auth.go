package relay

import (
	"encoding/json"
	"fmt"
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

	resolveKey := CreateKeyResolver(r.store)

	// 2. check stored public credentials
	publicCreds, _ := r.store.GetPublicCredentials(requestedResource)
	for _, credJws := range publicCreds {
		if err := r.verifyCredentialForAccess(credJws, resolveKey, requestedResource, action, creatorDID, ""); err == nil {
			return ""
		}
	}

	// 3. check per-request credential
	if credentialJWS != "" {
		if err := r.verifyCredentialForAccess(credentialJWS, resolveKey, requestedResource, action, creatorDID, requesterDID); err != nil {
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
func (r *Relay) verifyCredentialForAccess(credJws string, resolveKey dfos.KeyResolver, requestedResource string, action string, creatorDID string, requesterDID string) error {
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
	issuerIdentity, _ := r.store.GetIdentityChain(issuerDID)
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
	revoked, _ := r.store.IsCredentialRevoked(verified.Iss, verified.CID)
	if revoked {
		return fmt.Errorf("credential is revoked")
	}

	// parse att from raw payload for resource matching and delegation
	att := dfos.ParseAtt(payload)

	// check resource + action match (with manifest transitive lookup)
	if !r.matchesResource(att, requestedResource, action) {
		return fmt.Errorf("credential does not cover requested resource")
	}

	// for per-request credentials, check audience
	if requesterDID != "" {
		aud, _ := payload["aud"].(string)
		if aud != "*" && aud != requesterDID {
			return fmt.Errorf("credential audience does not match requester")
		}
	}

	// verify delegation chain
	prf := dfos.ParsePrf(payload)
	if err := r.verifyDelegationChain(credJws, prf, att, verified, resolveKey, creatorDID, 0); err != nil {
		return err
	}

	return nil
}

// ---------------------------------------------------------------------------
// delegation chain
// ---------------------------------------------------------------------------

// verifyDelegationChain walks the prf array recursively, verifying each parent
// credential's signature, revocation status, audience linkage, monotonic
// attenuation, and expiry bounds. The chain must root at creatorDID.
func (r *Relay) verifyDelegationChain(childJws string, prf []string, childAtt []dfos.AttEntry, child *dfos.VerifiedCredential, resolveKey dfos.KeyResolver, creatorDID string, depth int) error {
	if depth > 16 {
		return fmt.Errorf("delegation chain too deep (max 16 hops)")
	}

	// no parents — this is the root credential, issuer must be creator
	if len(prf) == 0 {
		if child.Iss != creatorDID {
			return fmt.Errorf("delegation chain root issuer %s does not match expected root %s", child.Iss, creatorDID)
		}
		return nil
	}

	type verifiedParent struct {
		jws      string
		verified *dfos.VerifiedCredential
		att      []dfos.AttEntry
		prf      []string
		aud      string
		exp      int64
	}

	var parents []verifiedParent
	for _, parentJws := range prf {
		pHeader, pPayload, err := dfos.DecodeJWSUnsafe(parentJws)
		if err != nil || pHeader == nil {
			return fmt.Errorf("failed to decode parent credential in delegation chain")
		}

		pKid := pHeader.Kid
		if pKid == "" || !strings.Contains(pKid, "#") {
			return fmt.Errorf("parent credential kid must be a DID URL")
		}

		parentIssuerDID := pKid[:strings.Index(pKid, "#")]

		// check parent issuer identity is not deleted
		parentIdentity, _ := r.store.GetIdentityChain(parentIssuerDID)
		if parentIdentity != nil && parentIdentity.State.IsDeleted {
			return fmt.Errorf("parent credential issuer identity is deleted")
		}

		pKey, err := resolveKey(pKid)
		if err != nil {
			return fmt.Errorf("failed to resolve parent credential key: %v", err)
		}

		pVerified, err := dfos.VerifyCredential(parentJws, pKey, "", "")
		if err != nil {
			return fmt.Errorf("parent credential verification failed: %v", err)
		}

		// check revocation at every level
		prevoked, _ := r.store.IsCredentialRevoked(pVerified.Iss, pVerified.CID)
		if prevoked {
			return fmt.Errorf("parent credential in delegation chain is revoked")
		}

		pAud, _ := pPayload["aud"].(string)
		parents = append(parents, verifiedParent{
			jws:      parentJws,
			verified: pVerified,
			att:      dfos.ParseAtt(pPayload),
			prf:      dfos.ParsePrf(pPayload),
			aud:      pAud,
			exp:      pVerified.Exp,
		})
	}

	// child's issuer must be the audience of at least one parent
	hasMatchingParent := false
	for _, p := range parents {
		if p.aud == "*" || p.aud == child.Iss {
			hasMatchingParent = true
			break
		}
	}
	if !hasMatchingParent {
		return fmt.Errorf("delegation gap: no parent credential has audience matching child issuer %s", child.Iss)
	}

	// child's exp must not exceed any parent's exp
	for _, p := range parents {
		if child.Exp > p.exp {
			return fmt.Errorf("delegation chain: child credential expiry exceeds parent expiry")
		}
	}

	// child's att must be attenuated from the union of all parents' att
	var parentAttUnion []dfos.AttEntry
	for _, p := range parents {
		parentAttUnion = append(parentAttUnion, p.att...)
	}
	if !dfos.IsAttenuated(parentAttUnion, childAtt) {
		return fmt.Errorf("delegation chain: child credential scope exceeds parent scope")
	}

	// recurse into the first parent (all parents verified above)
	first := parents[0]
	return r.verifyDelegationChain(first.jws, first.prf, first.att, first.verified, resolveKey, creatorDID, depth+1)
}

// ---------------------------------------------------------------------------
// resource matching
// ---------------------------------------------------------------------------

// matchesResource checks if an att array covers a requested resource+action.
// Handles manifest transitive lookup for manifest: → chain: coverage.
func (r *Relay) matchesResource(att []dfos.AttEntry, resource string, action string) bool {
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

		// manifest covers chain transitively
		if entryType == "manifest" && reqType == "chain" {
			indexed := r.manifestLookup(entryID)
			for _, id := range indexed {
				if id == reqID {
					return true
				}
			}
		}
	}

	return false
}

// manifestLookup resolves which contentIds a manifest indexes by reading its
// head document blob and extracting entries values.
func (r *Relay) manifestLookup(manifestContentID string) []string {
	chain, err := r.store.GetContentChain(manifestContentID)
	if err != nil || chain == nil {
		return nil
	}
	if chain.State.CurrentDocumentCID == nil {
		return nil
	}
	docCID := *chain.State.CurrentDocumentCID

	blob, _ := r.store.GetBlob(BlobKey{CreatorDID: chain.State.CreatorDID, DocumentCID: docCID})
	if blob == nil {
		return nil
	}

	var doc map[string]any
	if err := json.Unmarshal(blob, &doc); err != nil {
		return nil
	}

	entries, ok := doc["entries"]
	if !ok {
		return nil
	}
	entriesMap, ok := entries.(map[string]any)
	if !ok {
		return nil
	}

	var result []string
	for _, v := range entriesMap {
		s, ok := v.(string)
		if !ok {
			continue
		}
		// contentId references are 22-char bare hashes, not DIDs or CIDs
		if strings.HasPrefix(s, "did:") || strings.HasPrefix(s, "bafyrei") {
			continue
		}
		result = append(result, s)
	}
	return result
}

