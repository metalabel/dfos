package dfos

import (
	"fmt"
	"strings"
)

// attEntry is a resource + action pair parsed from a credential payload.
type attEntry struct {
	Resource string
	Action   string
}

// parseAtt extracts the att array from a raw credential payload.
func parseAtt(payload map[string]any) []attEntry {
	attRaw, ok := payload["att"].([]any)
	if !ok {
		return nil
	}
	var result []attEntry
	for _, item := range attRaw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		resource, _ := m["resource"].(string)
		action, _ := m["action"].(string)
		if resource != "" && action != "" {
			result = append(result, attEntry{Resource: resource, Action: action})
		}
	}
	return result
}

// parsePrf extracts the prf array from a raw credential payload.
func parsePrf(payload map[string]any) []string {
	prfRaw, ok := payload["prf"].([]any)
	if !ok {
		return nil
	}
	var result []string
	for _, item := range prfRaw {
		s, ok := item.(string)
		if ok && s != "" {
			result = append(result, s)
		}
	}
	return result
}

// parseResource splits a resource string into type and id (e.g., "chain:abc" → "chain", "abc").
func parseResource(resource string) (string, string, bool) {
	idx := strings.Index(resource, ":")
	if idx < 0 {
		return "", "", false
	}
	return resource[:idx], resource[idx+1:], true
}

// parseActions splits a comma-separated action string into a set.
func parseActions(action string) map[string]bool {
	result := make(map[string]bool)
	for _, a := range strings.Split(action, ",") {
		a = strings.TrimSpace(a)
		if a != "" {
			result[a] = true
		}
	}
	return result
}

// isAttenuated checks if childAtt is a valid attenuation of parentAtt.
// Every entry in childAtt must be covered by at least one entry in parentAtt.
func isAttenuated(parentAtt []attEntry, childAtt []attEntry) bool {
	for _, child := range childAtt {
		childType, childID, ok := parseResource(child.Resource)
		if !ok {
			return false
		}
		childActions := parseActions(child.Action)

		covered := false
		for _, parent := range parentAtt {
			parentType, parentID, ok := parseResource(parent.Resource)
			if !ok {
				continue
			}
			parentActions := parseActions(parent.Action)

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
			if parentType == "chain" && parentID == "*" {
				// chain:* covers everything: chain:X, chain:*, manifest:M
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
			} else if childType == "chain" && parentType == "manifest" {
				// narrowing from manifest — valid structurally
				covered = true
				break
			} else if childType == "manifest" && parentType == "manifest" {
				if childID == parentID {
					covered = true
					break
				}
			}
			// manifest:M NOT covered by chain:X (widening — invalid)
			// chain:* NOT covered by chain:X or manifest:M (widening — invalid)
		}

		if !covered {
			return false
		}
	}
	return true
}

// VerifyDelegationChain verifies a DFOS credential's delegation chain.
// Walks the prf array recursively, verifying each parent credential's
// signature, audience linkage, expiry bounds, and monotonic attenuation.
// The chain must root at rootDID.
//
// The optional isRevoked callback checks revocation at each level. Pass nil
// to skip revocation checks (useful at the protocol layer where revocation
// state may not be available).
func VerifyDelegationChain(childToken string, childVC *VerifiedCredential, childAtt []attEntry, childPrf []string, resolveKey KeyResolver, rootDID string, isRevoked func(issuerDID, credentialCID string) (bool, error), depth int) error {
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

	type verifiedParent struct {
		jws      string
		verified *VerifiedCredential
		att      []attEntry
		prf      []string
		aud      string
		exp      int64
	}

	var parents []verifiedParent
	for _, parentJws := range childPrf {
		pHeader, pPayload, err := DecodeJWSUnsafe(parentJws)
		if err != nil || pHeader == nil {
			return fmt.Errorf("failed to decode parent credential in delegation chain")
		}

		pKid := pHeader.Kid
		if pKid == "" || !strings.Contains(pKid, "#") {
			return fmt.Errorf("parent credential kid must be a DID URL")
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
		parents = append(parents, verifiedParent{
			jws:      parentJws,
			verified: pVerified,
			att:      parseAtt(pPayload),
			prf:      parsePrf(pPayload),
			aud:      pAud,
			exp:      pVerified.Exp,
		})
	}

	// child's issuer must be the audience of at least one parent
	hasMatchingParent := false
	for _, p := range parents {
		if p.aud == "*" || p.aud == childVC.Iss {
			hasMatchingParent = true
			break
		}
	}
	if !hasMatchingParent {
		return fmt.Errorf("delegation gap: no parent credential has audience matching child issuer %s", childVC.Iss)
	}

	// child's exp must not exceed any parent's exp
	for _, p := range parents {
		if childVC.Exp > p.exp {
			return fmt.Errorf("delegation chain: child credential expiry exceeds parent expiry")
		}
	}

	// child's att must be attenuated from the union of all parents' att
	var parentAttUnion []attEntry
	for _, p := range parents {
		parentAttUnion = append(parentAttUnion, p.att...)
	}
	if !isAttenuated(parentAttUnion, childAtt) {
		return fmt.Errorf("delegation chain: child credential scope exceeds parent scope")
	}

	// recurse into the first parent (all parents verified above)
	first := parents[0]
	return VerifyDelegationChain(first.jws, first.verified, first.att, first.prf, resolveKey, rootDID, isRevoked, depth+1)
}
