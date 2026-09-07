package dfos

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// maxCredentialSize bounds the byte length of a credential JWS token — the
// credential's analog of maxOperationSize. Credentials are EXEMPT from the 64
// KiB operation cap (a maximum-depth 16-credential delegation chain embeds each parent
// in prf and legitimately exceeds it), so they carry their own larger ceiling.
// VALIDITY-determining: MUST match the TS reference (MAX_CREDENTIAL_SIZE).
const maxCredentialSize = 262144

// maxAttEntries bounds the number of attenuation entries per credential. A
// CARDINALITY cap (DoS pre-allocation guard), matching the TS reference
// (MAX_ATT).
const maxAttEntries = 32

// VerifiedCredential represents a successfully verified DFOS credential.
type VerifiedCredential struct {
	Iss string
	Aud string // audience DID or "*" for public
	Exp int64
	Iat int64
	Att []AttEntry // full attenuation array
	Kid string
	CID string // credential CID from header

	// Convenience fields derived from the first att entry granting a recognized
	// action. Action is the raw att action string and may be a combined grant
	// (e.g. "read,write"); callers needing set semantics should ParseActions it.
	Action    string
	ContentID string // resource ID (without "chain:" prefix)
}

// CreateCredential creates a DFOS credential (UCAN-style authorization token).
//
// The resource parameter is the full resource string (e.g., "chain:contentId",
// "chain:*"). The action is "read" or "write".
// The aud parameter is the audience DID (or "*" for public credentials).
func CreateCredential(iss, aud, kid, resource, action string, ttl time.Duration, privateKey ed25519.PrivateKey) (string, error) {
	now := time.Now().Unix()
	exp := now + int64(ttl.Seconds())

	att := []map[string]string{
		{
			"resource": resource,
			"action":   action,
		},
	}

	payload := map[string]any{
		"version": 1,
		"type":    "DFOSCredential",
		"iss":     iss,
		"aud":     aud,
		"att":     att,
		"prf":     []string{},
		"exp":     exp,
		"iat":     now,
	}

	// derive CID from dag-cbor canonical encoding
	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		return "", fmt.Errorf("DagCborCID: %w", err)
	}

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:credential",
		Kid: kid,
		CID: cidStr,
	}

	token, err := CreateJWS(header, payload, privateKey)
	if err != nil {
		return "", fmt.Errorf("CreateJWS: %w", err)
	}

	return token, nil
}

// VerifyCredential verifies a DFOS credential token against an ephemeral basis:
// the wall clock. It checks the signature, expiration, payload structure, and
// optionally subject and expected action. Pass empty string for subject or
// expectedAction to skip those checks.
func VerifyCredential(token string, publicKey ed25519.PublicKey, subject string, expectedAction string) (*VerifiedCredential, error) {
	return verifyCredentialCore(token, publicKey, subject, expectedAction, time.Now().Unix())
}

// VerifyCredentialAt is like VerifyCredential but takes the basis directly as
// integer Unix seconds.
func VerifyCredentialAt(token string, publicKey ed25519.PublicKey, subject string, expectedAction string, currentTime int64) (*VerifiedCredential, error) {
	return verifyCredentialCore(token, publicKey, subject, expectedAction, currentTime)
}

// VerifyCredentialAtBasis is VerifyCredentialAt taking the basis in the
// createdAt grammar, which is the form a committed artifact carries. An empty
// basis is ephemeral and falls to the wall clock.
//
// The conversion truncates to whole seconds and never rounds (PROTOCOL, Time
// basis): rounding up would move the basis into the second after the one the
// operation was signed in, and two implementations disagreeing by one second on
// the exp boundary fork authorization.
func VerifyCredentialAtBasis(token string, publicKey ed25519.PublicKey, subject string, expectedAction string, basis string) (*VerifiedCredential, error) {
	if basis == "" {
		return VerifyCredential(token, publicKey, subject, expectedAction)
	}
	seconds, err := BasisUnixSeconds(basis)
	if err != nil {
		return nil, err
	}
	return verifyCredentialCore(token, publicKey, subject, expectedAction, seconds)
}

// BasisUnixSeconds converts a basis in the createdAt grammar to the integer Unix
// seconds that exp and revocation compare against, truncating the millisecond
// remainder.
func BasisUnixSeconds(basis string) (int64, error) {
	parsed, err := time.Parse(protocolTimeFormat, basis)
	if err != nil {
		return 0, fmt.Errorf("invalid basis time: %w", err)
	}
	return parsed.Unix(), nil
}

// credentialClaims is the decoded DFOS credential payload. It carries no struct
// tags on purpose: nothing unmarshals INTO it, decodeCredentialClaims fills it
// member by member.
type credentialClaims struct {
	Version int64
	Type    string
	Iss     string
	Aud     string
	Exp     int64
	Iat     int64
	Att     []AttEntry
}

// decodeCredentialClaims decodes the credential payload BY EXACT KEY, for the
// same reason decodeJWSHeader decodes the protected header that way.
//
// encoding/json resolves a JSON key to a struct field by exact tag match first
// and then by case-insensitive fold, per key, in document order — so a payload
// spelling `"exp":1,"EXP":2000000000` overwrites Exp with the second value. The
// TS reference reads `payload.exp` off a plain object by exact key and sees an
// unrecognized extension member it preserves and ignores, so the two verifiers
// disagree about when the credential expires on identical signed bytes. The
// raw-payload CID check cannot catch it (both members are committed) and the
// duplicate-key scan cannot either ("exp" and "EXP" are different strings).
//
// A member present with a wrong-typed value is an error rather than a silent
// zero: absent and wrong-type are two different facts.
func decodeCredentialClaims(payloadBytes []byte) (*credentialClaims, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payloadBytes, &raw); err != nil {
		return nil, fmt.Errorf("invalid credential claims: %s", err)
	}

	claims := &credentialClaims{}
	for _, member := range []struct {
		name string
		dst  any
	}{
		{"version", &claims.Version},
		{"type", &claims.Type},
		{"iss", &claims.Iss},
		{"aud", &claims.Aud},
		{"exp", &claims.Exp},
		{"iat", &claims.Iat},
	} {
		if err := decodeClaimMember(raw, member.name, member.dst); err != nil {
			return nil, err
		}
	}

	// att entries carry the same hazard one level down: an entry spelling
	// "RESOURCE" would fold onto Resource in a struct decode.
	if rawAtt, present := raw["att"]; present && string(rawAtt) != "null" {
		var entries []map[string]json.RawMessage
		if err := json.Unmarshal(rawAtt, &entries); err != nil {
			return nil, fmt.Errorf("invalid credential claims: att must be an array of objects")
		}
		claims.Att = make([]AttEntry, len(entries))
		for i, entry := range entries {
			if err := decodeClaimMember(entry, "resource", &claims.Att[i].Resource); err != nil {
				return nil, err
			}
			if err := decodeClaimMember(entry, "action", &claims.Att[i].Action); err != nil {
				return nil, err
			}
		}
	}

	return claims, nil
}

// decodeClaimMember reads one member by its exact name. Absent (or JSON null,
// which unmarshals into any destination as a no-op) leaves the zero value for
// the required-field checks to catch; present-but-wrong-type is an error.
func decodeClaimMember(raw map[string]json.RawMessage, name string, dst any) error {
	rawValue, present := raw[name]
	if !present {
		return nil
	}
	if err := json.Unmarshal(rawValue, dst); err != nil {
		return fmt.Errorf("invalid credential claims: %s has the wrong type", name)
	}
	return nil
}

// verifyCredentialCore is the shared implementation for DFOS credential
// verification.
func verifyCredentialCore(token string, publicKey ed25519.PublicKey, subject string, expectedAction string, currentTime int64) (*VerifiedCredential, error) {
	// bound credential size — the credential's analog of maxOperationSize. The
	// leaf token embeds the entire nested delegation chain (each parent carried
	// in prf), so this one cap bounds the whole chain. Checked before any decode
	// or recursion as a DoS guard. Matches the TS reference (MAX_CREDENTIAL_SIZE).
	if len(token) > maxCredentialSize {
		return nil, fmt.Errorf("credential exceeds max size: %d > %d", len(token), maxCredentialSize)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	headerB64, payloadB64, signatureB64 := parts[0], parts[1], parts[2]

	// decode header and payload
	headerBytes, err := Base64urlDecode(headerB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token")
	}
	payloadBytes, err := Base64urlDecode(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token")
	}

	// apply the DFOS signature verification profile (alg pin, crit, no
	// header-key-trust) BEFORE any signature check
	if err := assertJWSProfile(headerBytes); err != nil {
		return nil, err
	}

	// by exact key — see decodeJWSHeader on why a struct decode is not enough
	header, err := decodeJWSHeader(headerBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token")
	}
	if err := AssertCanonicalJSONText(payloadBytes); err != nil {
		return nil, err
	}

	// verify header fields
	if header.Typ != "did:dfos:credential" {
		return nil, fmt.Errorf("invalid typ: %s", header.Typ)
	}

	// verify signature
	signingInput := headerB64 + "." + payloadB64
	sigBytes, err := Base64urlDecode(signatureB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature")
	}
	// ed25519.Verify panics on a wrong-size key, and a resolver can hand one here
	// without erroring. Same guard, same text as VerifyJWS: a bad key is an
	// invalid input, never a crash.
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected a %d-byte ed25519 key, got %d bytes", ed25519.PublicKeySize, len(publicKey))
	}
	if !ed25519.Verify(publicKey, []byte(signingInput), sigBytes) {
		return nil, fmt.Errorf("invalid signature")
	}

	// parse payload — DFOS credential format, BY EXACT KEY
	claims, err := decodeCredentialClaims(payloadBytes)
	if err != nil {
		return nil, err
	}

	// validate required fields
	if claims.Iss == "" || claims.Aud == "" || claims.Exp == 0 || claims.Iat == 0 {
		return nil, fmt.Errorf("invalid credential claims: missing required fields")
	}
	if claims.Type != "DFOSCredential" {
		return nil, fmt.Errorf("invalid credential type: %s", claims.Type)
	}
	if claims.Version != 1 {
		return nil, fmt.Errorf("unsupported credential version: %d", claims.Version)
	}

	// att cardinality — a credential MUST carry 1..maxAttEntries attenuations.
	// A zero-att credential grants nothing (malformed); the upper bound is a DoS
	// pre-allocation guard. Enforced identically in the TS reference (MAX_ATT).
	if len(claims.Att) < 1 || len(claims.Att) > maxAttEntries {
		return nil, fmt.Errorf("credential att count out of bounds: %d (must be 1..%d)", len(claims.Att), maxAttEntries)
	}

	// verify CID integrity — re-derive from payload and compare to header
	headerCID := header.CID
	if headerCID == "" {
		return nil, fmt.Errorf("missing cid in credential header")
	}
	var payloadMap map[string]any
	if err := json.Unmarshal(payloadBytes, &payloadMap); err != nil {
		return nil, fmt.Errorf("failed to parse credential payload for CID derivation")
	}
	NormalizeJSONNumbers(payloadMap)
	_, _, derivedCID, err := DagCborCID(payloadMap)
	if err != nil {
		return nil, fmt.Errorf("failed to derive credential CID: %w", err)
	}
	if headerCID != derivedCID {
		return nil, fmt.Errorf("credential CID mismatch: header %s, derived %s", headerCID, derivedCID)
	}

	// verify kid is a DID URL and matches iss
	kid := header.Kid
	if kid == "" || !strings.Contains(kid, "#") {
		return nil, fmt.Errorf("credential kid must be a DID URL")
	}
	kidDID := kid[:strings.Index(kid, "#")]
	if kidDID != claims.Iss {
		return nil, fmt.Errorf("credential kid DID does not match iss")
	}

	// Temporal validity against the one basis. iat is informational: a credential
	// dated after the basis is not a rejection, because the basis, not the
	// issuer's clock, decides when authority applies.
	if claims.Exp <= currentTime {
		return nil, fmt.Errorf("credential expired")
	}

	// verify subject (aud) if specified
	if subject != "" && claims.Aud != subject {
		return nil, fmt.Errorf("subject mismatch: expected %s, got %s", subject, claims.Aud)
	}

	// the full att array, as decoded
	att := claims.Att

	// Derive convenience fields from the first att entry that grants a recognized
	// action. Actions are comma-separated strings ("read", "write", "read,write")
	// split with ParseActions, matching IsAttenuated / matchesResource semantics.
	// These fields are best-effort metadata: the authoritative resource+action
	// check is the caller's (the relay's matchesResource), and the TS reference
	// applies no action allowlist. A credential whose att grants only unrecognized
	// actions leaves these fields empty rather than being rejected here — the
	// previous exact-match allowlist hard-rejected the spec-valid combined
	// "read,write" grant, diverging from TS.
	var action string
	var contentID string
	for _, a := range claims.Att {
		acts := ParseActions(a.Action)
		if !acts["read"] && !acts["write"] {
			continue
		}
		action = a.Action
		if a.Resource != "" {
			r := a.Resource
			if strings.HasPrefix(r, "chain:") {
				r = r[len("chain:"):]
			}
			contentID = r
		}
		break
	}

	// verify action if specified — membership test, so a combined "read,write"
	// grant satisfies an expectedAction of "read" or "write".
	if expectedAction != "" && !ParseActions(action)[expectedAction] {
		return nil, fmt.Errorf("action mismatch: expected %s, not granted by att (%q)", expectedAction, action)
	}

	return &VerifiedCredential{
		Iss:       claims.Iss,
		Aud:       claims.Aud,
		Exp:       claims.Exp,
		Iat:       claims.Iat,
		Att:       att,
		Action:    action,
		Kid:       kid,
		ContentID: contentID,
		CID:       headerCID,
	}, nil
}

// DecodeJWTUnsafe decodes a JWT without verifying.
func DecodeJWTUnsafe(token string) (header map[string]string, payload map[string]any, err error) {
	h, p, err := DecodeJWSUnsafe(token)
	if err != nil {
		return nil, nil, err
	}
	hm := map[string]string{
		"alg": h.Alg,
		"typ": h.Typ,
		"kid": h.Kid,
	}
	if h.CID != "" {
		hm["cid"] = h.CID
	}
	return hm, p, nil
}
