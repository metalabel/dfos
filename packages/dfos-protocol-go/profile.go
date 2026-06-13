package dfos

import (
	"encoding/json"
	"fmt"
)

// assertJWSProfile applies the DFOS Signature Verification Profile (pragmatic
// v1) to a raw protected header (the base64url-decoded header JSON bytes). It
// MUST be called BEFORE any signature check on every verification path so that
// an out-of-profile token is rejected regardless of whether its signature
// would have verified. See PROTOCOL.md "Signature Verification Profile".
//
//  1. alg pinning      — alg MUST equal the exact string "EdDSA"
//  2. crit rejection   — a "crit" member MUST be absent (DFOS emits none)
//  3. no header-key-trust — jwk / x5c (or any embedded key) MUST be absent;
//     the key is resolved from kid against the identity chain
//
// The canonical-scalar (S < L) gate is enforced by crypto/ed25519, which
// rejects non-canonical S, so it is not duplicated here.
//
// Plain json.Unmarshal into a typed header struct silently drops crit/jwk/x5c,
// so this re-decodes the header into a map to observe their presence.
func assertJWSProfile(headerBytes []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(headerBytes, &raw); err != nil {
		return fmt.Errorf("failed to decode header")
	}

	// 1. alg pinning — exact string "EdDSA"
	algRaw, ok := raw["alg"]
	if !ok {
		return fmt.Errorf("unsupported algorithm: missing alg")
	}
	var alg string
	if err := json.Unmarshal(algRaw, &alg); err != nil || alg != "EdDSA" {
		return fmt.Errorf("unsupported algorithm: %s", string(algRaw))
	}

	// 2. crit — reject any protected header carrying a crit member
	if _, present := raw["crit"]; present {
		return fmt.Errorf("crit header is not supported")
	}

	// 3. no header-key-trust — reject embedded key material
	if _, present := raw["jwk"]; present {
		return fmt.Errorf("jwk header is not allowed (key is resolved from kid)")
	}
	if _, present := raw["x5c"]; present {
		return fmt.Errorf("x5c header is not allowed (key is resolved from kid)")
	}

	return nil
}
