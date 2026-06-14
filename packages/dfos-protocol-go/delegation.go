package dfos

import (
	"fmt"
	"strings"
)

// AttEntry is a resource + action pair parsed from a credential payload.
type AttEntry struct {
	Resource string
	Action   string
}

// ParseAtt extracts the att array from a raw credential payload.
func ParseAtt(payload map[string]any) []AttEntry {
	attRaw, ok := payload["att"].([]any)
	if !ok {
		return nil
	}
	var result []AttEntry
	for _, item := range attRaw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		resource, _ := m["resource"].(string)
		action, _ := m["action"].(string)
		if resource != "" && action != "" {
			result = append(result, AttEntry{Resource: resource, Action: action})
		}
	}
	return result
}

// ParsePrf extracts the prf array from a raw credential payload.
//
// It HARD-REJECTS any prf element that is not a non-empty string, returning an
// error rather than silently filtering. The TS twin rejects such a credential
// at decode (the strictObject schema parses prf as z.array(z.string()) and
// MAX_PRF=1 bounds the length), so a prf like ["<parent>", ""] is REJECTED by
// TS. The previous Go implementation filtered the empty/non-string element,
// dropping the array to length 1, which slipped past the multi-parent length
// gate (delegation.go len(childPrf)>1, verify.go) and ACCEPTED a byte-identical
// credential that TS rejects — a real twin divergence. Surfacing the error at
// both call sites (parentPrf in this file, childPrf in verify.go) makes Go
// reject in lockstep with TS: Go has no schema layer, so this validating decode
// IS the gate.
func ParsePrf(payload map[string]any) ([]string, error) {
	prfRaw, ok := payload["prf"]
	if !ok {
		return nil, nil
	}
	prfArr, ok := prfRaw.([]any)
	if !ok {
		return nil, fmt.Errorf("credential prf must be an array")
	}
	result := make([]string, 0, len(prfArr))
	for _, item := range prfArr {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("credential prf must contain only strings")
		}
		if s == "" {
			return nil, fmt.Errorf("credential prf must not contain empty strings")
		}
		result = append(result, s)
	}
	return result, nil
}

// ParseResource splits a resource string into type and id (e.g., "chain:abc" → "chain", "abc").
func ParseResource(resource string) (string, string, bool) {
	idx := strings.Index(resource, ":")
	if idx < 0 {
		return "", "", false
	}
	return resource[:idx], resource[idx+1:], true
}

// ParseActions splits a comma-separated action string into a set.
func ParseActions(action string) map[string]bool {
	result := make(map[string]bool)
	for _, a := range strings.Split(action, ",") {
		a = strings.TrimSpace(a)
		if a != "" {
			result[a] = true
		}
	}
	return result
}

// IsAttenuated checks if childAtt is a valid attenuation of parentAtt.
// Every entry in childAtt must be covered by at least one entry in parentAtt.
func IsAttenuated(parentAtt []AttEntry, childAtt []AttEntry) bool {
	for _, child := range childAtt {
		childType, childID, ok := ParseResource(child.Resource)
		if !ok {
			return false
		}
		childActions := ParseActions(child.Action)

		covered := false
		for _, parent := range parentAtt {
			parentType, parentID, ok := ParseResource(parent.Resource)
			if !ok {
				continue
			}
			parentActions := ParseActions(parent.Action)

			// check action coverage — child actions must be subset of parent actions
			actionOK := true
			for a := range childActions {
				if !parentActions[a] {
					actionOK = false
					break
				}
			}
			if !actionOK {
				continue
			}

			// check resource coverage
			if parentType == "chain" && parentID == "*" && childType == "chain" {
				// chain:* covers any chain resource: chain:X, chain:*
				covered = true
				break
			} else if childType == "chain" && childID == "*" {
				// chain:* can only be covered by chain:* (checked above)
				continue
			} else if childType == "chain" && parentType == "chain" {
				if childID == parentID {
					covered = true
					break
				}
			}
			// chain:* NOT covered by chain:X (widening — invalid)
		}

		if !covered {
			return false
		}
	}
	return true
}

// VerifyDelegationChain is the exported entrypoint for verifying a credential's
// delegation chain. The relay read / per-request-credential path calls this
// directly; the write path reaches the same walk via content authorization. Both
// relay surfaces therefore share ONE implementation instead of maintaining
// divergent copies (a divergent relay copy is exactly how a multi-parent
// authority-escalation slipped past one surface but not the other).
//
// Pass nil for isRevoked or isDeleted to skip that store-backed check.
func VerifyDelegationChain(childToken string, childVC *VerifiedCredential, childAtt []AttEntry, childPrf []string, resolveKey KeyResolver, rootDID string, isRevoked RevocationChecker, isDeleted IdentityDeletedChecker) error {
	return verifyDelegationChain(childToken, childVC, childAtt, childPrf, resolveKey, rootDID, isRevoked, isDeleted, 0)
}

// verifyDelegationChain verifies a DFOS credential's delegation chain.
// Walks the prf array recursively, verifying each parent credential's
// signature, audience linkage, expiry bounds, and monotonic attenuation.
// The chain must root at rootDID.
//
// The optional isRevoked callback checks revocation at each parent level, and
// the optional isDeleted callback gates each parent's issuer identity. Pass nil
// for either to skip that check (the protocol layer is store-agnostic; the
// relay supplies these closures at the call boundary).
func verifyDelegationChain(childToken string, childVC *VerifiedCredential, childAtt []AttEntry, childPrf []string, resolveKey KeyResolver, rootDID string, isRevoked RevocationChecker, isDeleted IdentityDeletedChecker, depth int) error {
	if depth > 16 {
		return fmt.Errorf("delegation chain too deep (max 16 hops)")
	}

	// no parents — this is the root credential, issuer must be the root DID
	if len(childPrf) == 0 {
		if childVC.Iss != rootDID {
			return fmt.Errorf("delegation chain root issuer %s does not match expected root %s", childVC.Iss, rootDID)
		}
		return nil
	}

	// DFOS delegation is LINEAR: exactly one parent per hop. Multi-parent
	// proofs are rejected. A union-of-authority model (att taken from the union
	// of all parents, but the root walk continuing only through the first
	// parent) let a self-issued secondary parent contribute scope that was
	// never rooted at rootDID — an authority-escalation. Linear delegation
	// removes the class entirely.
	if len(childPrf) > 1 {
		return fmt.Errorf("delegation chain: multi-parent credentials are not supported (prf must have at most one entry)")
	}

	// verify the single parent credential
	parentJws := childPrf[0]
	pHeader, pPayload, err := DecodeJWSUnsafe(parentJws)
	if err != nil || pHeader == nil {
		return fmt.Errorf("failed to decode parent credential in delegation chain")
	}

	pKid := pHeader.Kid
	if pKid == "" || !strings.Contains(pKid, "#") {
		return fmt.Errorf("parent credential kid must be a DID URL")
	}

	// parent issuer-isDeleted gate (mirrors read-path auth.go:231-234)
	parentIssuerDID := pKid[:strings.Index(pKid, "#")]
	if isDeleted != nil {
		deleted, err := isDeleted(parentIssuerDID)
		if err != nil {
			return fmt.Errorf("parent issuer delete-check failed: %v", err)
		}
		if deleted {
			return fmt.Errorf("parent credential issuer identity is deleted")
		}
	}

	pKey, err := resolveKey(pKid)
	if err != nil {
		return fmt.Errorf("failed to resolve parent credential key: %v", err)
	}

	pVerified, err := VerifyCredential(parentJws, pKey, "", "")
	if err != nil {
		return fmt.Errorf("parent credential verification failed: %v", err)
	}

	// check revocation at every level
	if isRevoked != nil {
		revoked, err := isRevoked(pVerified.Iss, pVerified.CID)
		if err != nil {
			return fmt.Errorf("revocation check failed: %v", err)
		}
		if revoked {
			return fmt.Errorf("parent credential in delegation chain is revoked")
		}
	}

	pAud, _ := pPayload["aud"].(string)
	parentAtt := ParseAtt(pPayload)
	parentPrf, err := ParsePrf(pPayload)
	if err != nil {
		return fmt.Errorf("parent credential prf invalid: %v", err)
	}

	// child's issuer must be the parent's audience
	if pAud != "*" && pAud != childVC.Iss {
		return fmt.Errorf("delegation gap: parent credential audience %s does not match child issuer %s", pAud, childVC.Iss)
	}

	// child's exp must not exceed the parent's exp
	if childVC.Exp > pVerified.Exp {
		return fmt.Errorf("delegation chain: child credential expiry exceeds parent expiry")
	}

	// child's att must be attenuated from the parent's att
	if !IsAttenuated(parentAtt, childAtt) {
		return fmt.Errorf("delegation chain: child credential scope exceeds parent scope")
	}

	// continue walking through the parent
	return verifyDelegationChain(parentJws, pVerified, parentAtt, parentPrf, resolveKey, rootDID, isRevoked, isDeleted, depth+1)
}
