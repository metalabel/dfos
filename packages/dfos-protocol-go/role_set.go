package dfos

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// THE ROLE SET — THE CANONICAL SPELLING OF "WHICH ROLES THIS PROOF COVERS".
//
// Byte-twin of dfos-protocol/src/key-proof/role-set.ts.
//
// A key proof binds a candidate key to a POSITION in a chain, and a position has
// a role. roleSet is the member that carries that: the subset of the closed set
// {auth, assert, controller} the envelope consents to, serialized ONE way and
// only one way — the subset in the fixed order auth,assert,controller,
// comma-joined, no whitespace, no duplicates, never empty.
//
// WHY A STRING AND NOT AN ARRAY. The member lives inside the CLOSED payload whose
// canonical bytes are recomputed and byte-compared by the verifier (see
// key_proof.go). Every member of that payload is a string, so the byte contract
// has exactly one shape to pin per language. An array member would need its own
// canonicalization rule — element order, empty-array handling, nesting — layered
// on top of the one this file already fixes.
//
// WHY THE ORDER IS FIXED RATHER THAN SORTED-AT-SERIALIZE. auth,assert,controller
// is the declaration order of the three key arrays on an identity operation, not
// an alphabetical accident. A verifier reading the string sees the same order it
// reads the chain in.
//
// ANY OTHER BYTE FORM IS A SCHEMA REJECT — the same class as a member-order
// violation, and for the same reason: assert,auth and auth,assert name the same
// set, so admitting both would mean one role set has more than one payload
// spelling and the payload stops being a function of its members.

// KeyRole is one role a key can hold in an identity chain.
type KeyRole string

// KeyRoles is the CLOSED role set. Membership in an identity operation's
// authKeys, assertKeys and controllerKeys arrays respectively — the three
// positions a key can hold in a chain, and the only three a proof can consent to.
//
// THIS ORDER IS THE CANONICAL SERIALIZATION ORDER. It is not sorted; it is the
// order the roles appear in an identity operation.
var KeyRoles = []KeyRole{"auth", "assert", "controller"}

func isKeyRole(value KeyRole) bool { return slices.Contains(KeyRoles, value) }

// SerializeRoleSet serializes a set of roles to its ONE canonical spelling.
// Duplicates in the input collapse (a set is a set); an unknown role or an empty
// result errors, because neither can be signed.
//
// This is the producer half. ParseRoleSet is the verifier half, and the two are
// inverses on exactly the canonical strings.
func SerializeRoleSet(roles []KeyRole) (string, error) {
	present := make(map[KeyRole]bool, len(KeyRoles))
	for _, role := range roles {
		if !isKeyRole(role) {
			return "", fmt.Errorf("invalid role set: unknown role %q", string(role))
		}
		present[role] = true
	}
	if len(present) == 0 {
		return "", errors.New("invalid role set: must name at least one role")
	}
	parts := make([]string, 0, len(present))
	for _, role := range KeyRoles {
		if present[role] {
			parts = append(parts, string(role))
		}
	}
	return strings.Join(parts, ","), nil
}

// ParseRoleSet parses a role set from its canonical spelling. The second return
// is false when the bytes are not that spelling — false rather than an error so
// the caller raises the failure in ITS OWN vocabulary: a schema rejection inside
// key-proof verification, a void membership inside the identity walk.
//
// THE PARSE IS THE CANONICALITY CHECK. It is strict in every direction at once:
// an unknown role, a duplicate, a member out of the fixed order, any whitespace
// (" auth" is not "auth"), an empty segment, and the empty string all return
// false. There is no lenient mode and no normalization — a producer that meant
// auth,assert must spell it auth,assert.
func ParseRoleSet(value string) ([]KeyRole, bool) {
	parts := strings.Split(value, ",")
	roles := make([]KeyRole, 0, len(parts))
	seen := make(map[KeyRole]bool, len(parts))
	for _, part := range parts {
		role := KeyRole(part)
		if !isKeyRole(role) || seen[role] {
			return nil, false
		}
		seen[role] = true
		roles = append(roles, role)
	}
	// The order gate. Everything above admits assert,auth; only this refuses it.
	ordered := make([]KeyRole, 0, len(seen))
	for _, role := range KeyRoles {
		if seen[role] {
			ordered = append(ordered, role)
		}
	}
	if !slices.Equal(roles, ordered) {
		return nil, false
	}
	return roles, true
}

// IsCanonicalRoleSet reports whether value is exactly the canonical spelling of
// the set it names.
func IsCanonicalRoleSet(value string) bool {
	_, ok := ParseRoleSet(value)
	return ok
}

// RoleSetCovers reports whether this role set covers role — the question the
// CHAIN WALK asks: an introduction of key K to role R is proved only by an
// envelope whose role set includes R. A non-canonical role set covers nothing —
// it never parsed.
func RoleSetCovers(value string, role KeyRole) bool {
	roles, ok := ParseRoleSet(value)
	return ok && slices.Contains(roles, role)
}
