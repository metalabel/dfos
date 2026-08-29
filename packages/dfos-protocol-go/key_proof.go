package dfos

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// KEY PROOF — the Go byte-twin of dfos-protocol/src/key-proof/key-proof.ts.
//
// A KEY PROOF is a compact JWS over exactly four members — {nonce, audience,
// publicKeyMultibase, timestamp} — signed by the candidate key ITSELF, scoped by
// a registered typ to exactly one ceremony purpose. It proves one fact: the named
// key was held, and consented to this ceremony at this verifier, inside this
// window. It never conveys intent, content, or authority. See specs/KEY-PROOF.md.
//
// THREE THINGS ARE STRUCTURALLY DIFFERENT FROM THE API-AUTH ENVELOPES in this
// package, and each one is load-bearing:
//
//  1. NO kid. The candidate key is in no chain, so there is no DID URL to name;
//     the verification key rides in the SIGNED PAYLOAD. A present kid REJECTS.
//     This is why the header is hand-rolled rather than marshalled from
//     JWSHeader, whose Kid field has no omitempty and would emit "kid":"".
//  2. THE PAYLOAD IS CLOSED. Unlike API-AUTH's MUST-ignore-unknown envelope, an
//     extra member REJECTS. There is deliberately no room to smuggle intent.
//  3. NO RESOLVER SEAM. The signature verifies against the payload's own
//     publicKeyMultibase. That circularity IS the proof.
//
// STEP 6 IS NOT HERE. KEY-PROOF.md's verification algorithm has seven steps;
// VerifyKeyProof performs 1–5 and 7. Step 6 — the nonce MUST be one this verifier
// minted, for this ceremony, not yet consumed, checked and consumed ATOMICALLY —
// is the CALLER'S, because only the caller holds the store the check-and-delete
// runs against. A verified proof hands back its payload so the caller can do
// exactly that. A deployment that skips step 6 has a replayable proof for the
// length of its freshness window.
//
// This file MUST stay in sync with the TS twin. The canonical signing input is
// hand-rolled with jsonStringifyString rather than encoding/json for the same
// reason api_auth.go hand-rolls its own: encoding/json HTML-escapes &, < and >,
// which would silently fork the signed bytes away from what JavaScript's
// JSON.stringify emits. The cross-language vector set lives in key_proof_test.go
// and dfos-protocol/tests/key-proof.spec.ts, pinned byte-identically.

// KeyAddJWSTyp is the first registered purpose in KEY-PROOF.md's purpose
// registry: the candidate key presents for addition to a ceremony-named
// identity's authKeys/assertKeys sets.
//
// The typ is a PARAMETER everywhere in this file, not a constant baked into the
// algorithm — the grammar and the verification steps are identical for every
// registered row, and a new purpose lands by registering a value, never by
// minting an envelope. This constant is the one row that exists.
const KeyAddJWSTyp = "did:dfos:key-add"

const (
	// MaxKeyProofSize bounds the serialized envelope, checked BEFORE any decode.
	MaxKeyProofSize = 4096
	// DefaultKeyProofSkewSeconds is the RECOMMENDED acceptance window, in seconds,
	// EITHER SIDE of the verifier's clock — matching a ceremony's own lifetime.
	DefaultKeyProofSkewSeconds = 300
)

// ErrKeyProofInvalid is the single consumer-visible verdict: the envelope was
// checked and failed. Callers branch with errors.Is, never on message text; a
// caller that wants the failing STEP reads KeyProofError.Reason.
//
// There is no unverifiable tier and no config tier, because there is nothing to
// resolve: this verifier touches no network and no store. The one caller mistake
// that is not a verdict about the artifact — a negative skew — is returned as a
// plain error rather than wrapped here.
var ErrKeyProofInvalid = errors.New("key proof invalid")

// KeyProofFailureReason names the verification step a failure arose in. Byte-twin
// of the TS KeyProofVerifyError.reason union.
type KeyProofFailureReason string

const (
	KeyProofFailureSize      KeyProofFailureReason = "size"
	KeyProofFailureHeader    KeyProofFailureReason = "header"
	KeyProofFailureSchema    KeyProofFailureReason = "schema"
	KeyProofFailureAudience  KeyProofFailureReason = "audience"
	KeyProofFailureFreshness KeyProofFailureReason = "freshness"
	KeyProofFailureSignature KeyProofFailureReason = "signature"
)

// KeyProofError carries the failing step alongside the family verdict. It
// unwraps to ErrKeyProofInvalid, so errors.Is(err, ErrKeyProofInvalid) holds for
// every rejection while a caller that cares can type-assert for the Reason.
type KeyProofError struct {
	Reason  KeyProofFailureReason
	Message string
}

func (e *KeyProofError) Error() string {
	return fmt.Sprintf("invalid key proof: %s", e.Message)
}

func (e *KeyProofError) Unwrap() error { return ErrKeyProofInvalid }

func keyProofInvalid(reason KeyProofFailureReason, format string, args ...any) error {
	return &KeyProofError{Reason: reason, Message: fmt.Sprintf(format, args...)}
}

// KeyProofPayload is the CLOSED payload. Exactly these four members, each a
// string, in exactly this order — the member set is EXHAUSTIVE and no amendment
// may introduce a member that carries intent or content.
type KeyProofPayload struct {
	// Nonce is the verifier-minted, single-use challenge, exactly as the carriage
	// delivered it.
	Nonce string
	// Audience is the completion endpoint's lowercase authority — host, or
	// host:port off 443.
	Audience string
	// PublicKeyMultibase is the candidate key's Multikey — and the key that signs
	// this envelope.
	PublicKeyMultibase string
	// Timestamp is the ISO 8601 creation time, floor-normalized to whole seconds.
	Timestamp string
}

// keyProofMembers is the canonical member order, and the closed member set.
var keyProofMembers = []string{"nonce", "audience", "publicKeyMultibase", "timestamp"}

// wholeSecondTimestampRe pins the .000Z spelling — literal zeros, not "any three
// digits". ParseProtocolTimestamp's layout accepts .123, so the suffix check is
// what makes the two languages agree that an unfloored millisecond component is
// not this grammar.
var wholeSecondTimestampRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z$`)

// validateKeyProofPayload applies KEY-PROOF.md step 3 and the producer-side
// member rules in ONE place: exactly the four members, each a non-empty string.
//
// The grammar checks past "is a string" are the ones a mismatch would otherwise
// surface later and less usefully: an audience that is not an authority could
// never byte-equal a verifier's configured authority, and a timestamp outside
// the canonical spelling could never be compared to a clock.
func validateKeyProofPayload(payload KeyProofPayload) error {
	for name, value := range map[string]string{
		"nonce": payload.Nonce, "audience": payload.Audience,
		"publicKeyMultibase": payload.PublicKeyMultibase, "timestamp": payload.Timestamp,
	} {
		if value == "" {
			return keyProofInvalid(KeyProofFailureSchema, "%s must be a non-empty string", name)
		}
		if !utf8.ValidString(value) {
			return keyProofInvalid(KeyProofFailureSchema, "%s must be well-formed Unicode", name)
		}
	}
	// The API-AUTH authority grammar, verbatim: lowercase, no scheme, no path.
	if payload.Audience != strings.ToLower(payload.Audience) ||
		strings.ContainsAny(payload.Audience, " \t\n\r\f\v/\\?#") {
		return keyProofInvalid(KeyProofFailureSchema,
			"audience must be a lowercase authority, without a scheme or path")
	}
	if !wholeSecondTimestampRe.MatchString(payload.Timestamp) {
		return keyProofInvalid(KeyProofFailureSchema, "timestamp must be ISO-8601 UTC whole-second .000Z")
	}
	if _, err := ParseProtocolTimestamp(payload.Timestamp); err != nil {
		return keyProofInvalid(KeyProofFailureSchema, "timestamp must be ISO-8601 UTC whole-second .000Z")
	}
	return nil
}

// KeyProofSigningInput returns THE BYTE CONTRACT: the canonical bytes that ARE
// the JWS payload segment — minimal UTF-8 JSON, no insignificant whitespace,
// members in exactly the order nonce, audience, publicKeyMultibase, timestamp.
// Byte-for-byte identical to the TS keyProofSigningInput.
func KeyProofSigningInput(payload KeyProofPayload) ([]byte, error) {
	if err := validateKeyProofPayload(payload); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(`{"nonce":`)
	b.WriteString(jsonStringifyString(payload.Nonce))
	b.WriteString(`,"audience":`)
	b.WriteString(jsonStringifyString(payload.Audience))
	b.WriteString(`,"publicKeyMultibase":`)
	b.WriteString(jsonStringifyString(payload.PublicKeyMultibase))
	b.WriteString(`,"timestamp":`)
	b.WriteString(jsonStringifyString(payload.Timestamp))
	b.WriteByte('}')
	return []byte(b.String()), nil
}

// -----------------------------------------------------------------------------
// produce
// -----------------------------------------------------------------------------

// KeyProofOptions carries optional build inputs.
type KeyProofOptions struct {
	// Timestamp overrides the creation time; it is floor-normalized to .000Z if
	// it carries a millisecond component. Empty means "use Now".
	Timestamp string
	// Now overrides the clock for the default timestamp; the zero time means
	// time.Now().
	Now time.Time
}

// SignKeyProof signs one key proof. The producer half of the byte contract.
//
// publicKeyMultibase is DERIVED from privateKey rather than accepted as an
// input: this envelope is self-proving, and a signer that could name a key it
// does not hold would be the one construction the artifact exists to foreclose.
//
// The protected header is EXACTLY {"alg":"EdDSA","typ":"<purpose>"} — two
// members, no kid (the key is in no chain and rides in the payload) and no cid
// (there is no operation to bind).
//
// HOLDER OBLIGATIONS THIS FUNCTION CANNOT DISCHARGE (KEY-PROOF.md, Holder
// Obligations). A holder MUST show its human the audience and the purpose before
// calling this, and SHOULD refuse to sign for a key any identity's chain has ever
// declared — the key= reverse index is has-ever-declared, and one key in two
// chains publishes an irreversible public link between them. Both are decisions
// about a human and a network, made before there is a signature to make; neither
// belongs to a pure signer.
func SignKeyProof(typ, nonce, audience string, privateKey ed25519.PrivateKey,
	opts KeyProofOptions) (string, KeyProofPayload, error) {
	if typ == "" {
		return "", KeyProofPayload{}, fmt.Errorf("invalid key proof: typ must be a registered purpose value")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", KeyProofPayload{}, fmt.Errorf("invalid key proof: privateKey must be a %d-byte Ed25519 private key",
			ed25519.PrivateKeySize)
	}

	timestamp := opts.Timestamp
	if timestamp == "" {
		now := opts.Now
		if now.IsZero() {
			now = time.Now()
		}
		timestamp = now.UTC().Truncate(time.Second).Format(protocolTimeFormat)
	} else {
		parsed, err := ParseProtocolTimestamp(timestamp)
		if err != nil {
			return "", KeyProofPayload{}, fmt.Errorf("invalid key proof: unparseable timestamp: %s", timestamp)
		}
		timestamp = parsed.UTC().Truncate(time.Second).Format(protocolTimeFormat)
	}

	payload := KeyProofPayload{
		Nonce:              nonce,
		Audience:           audience,
		PublicKeyMultibase: EncodeMultikey(privateKey.Public().(ed25519.PublicKey)),
		Timestamp:          timestamp,
	}
	payloadBytes, err := KeyProofSigningInput(payload)
	if err != nil {
		return "", KeyProofPayload{}, err
	}

	// Hand-rolled: JWSHeader would emit "kid":"" and "cid" handling this envelope
	// must not carry, and the two-member order is part of the pinned vector.
	header := `{"alg":"EdDSA","typ":` + jsonStringifyString(typ) + `}`
	signingInput := Base64urlEncodeString(header) + "." + Base64urlEncode(payloadBytes)
	proof := signingInput + "." + Base64urlEncode(ed25519.Sign(privateKey, []byte(signingInput)))
	if len(proof) > MaxKeyProofSize {
		return "", KeyProofPayload{}, fmt.Errorf("key proof exceeds max size: %d > %d", len(proof), MaxKeyProofSize)
	}
	return proof, payload, nil
}

// -----------------------------------------------------------------------------
// verify
// -----------------------------------------------------------------------------

// KeyProofExpectations is what the VERIFIER holds about the ceremony it is
// completing. Every value here comes from the deployment's own configuration —
// never from the request.
type KeyProofExpectations struct {
	// Typ is the registered typ THIS ceremony requires. The gate is absolute: it
	// is what keeps a proof signed for one ceremony from ever being presented for
	// another.
	Typ string
	// Audience is THE VERIFIER'S OWN CONFIGURED AUTHORITY — never a Host /
	// X-Forwarded-Host header or the request URL's authority, which are
	// attacker-supplied. A verifier that compared against one of them would have
	// no audience binding at all, and audience binding is the whole defense
	// against challenge relay.
	Audience string
	// MaxSkewSeconds is the acceptance window, seconds, EITHER SIDE. A nil pointer
	// means DefaultKeyProofSkewSeconds; a non-nil *0 is honored (the tightest
	// window). Pointer rather than a bare int64 so an explicit zero is
	// distinguishable from omission — matching the TS verifier's
	// `maxSkewSeconds?: number`.
	MaxSkewSeconds *int64
}

// VerifiedKeyProof is what a verified key proof hands back.
type VerifiedKeyProof struct {
	// Payload is the validated payload. THE CALLER MUST NOW RUN STEP 6 against
	// Payload.Nonce: check that it is a nonce this verifier minted, for this
	// ceremony, not yet consumed, and consume it ATOMICALLY (check-and-delete) so
	// two racing completions cannot both pass.
	Payload KeyProofPayload
	// Typ is the header typ — equal to the expectation, since anything else
	// rejected.
	Typ string
	// Now is the integer unix seconds the freshness check used.
	Now int64
}

// VerifyKeyProof verifies a key proof — KEY-PROOF.md's verification algorithm
// steps 1–5 and 7: size cap, header gates, closed payload schema, audience
// byte-equality, freshness, and the signature against the payload's OWN
// publicKeyMultibase.
//
// STEP 6 (NONCE) IS THE CALLER'S, and this function cannot stand in for it. The
// nonce MUST be one this verifier minted, for this ceremony, not yet consumed,
// checked and consumed ATOMICALLY — a check-and-delete against the verifier's own
// store, which is state this pure function does not hold. It is returned on
// Payload.Nonce precisely so the caller can run that step next. Without it a proof
// is replayable for the length of the freshness window.
//
// What the seven steps together establish is exactly one fact: THE NAMED KEY WAS
// HELD, AND CONSENTED TO THIS CEREMONY AT THIS VERIFIER, INSIDE THIS WINDOW.
// Everything after — appending the key to a chain, custody policy, notification —
// is the ceremony operator's.
func VerifyKeyProof(proof string, expect KeyProofExpectations, now time.Time) (*VerifiedKeyProof, error) {
	maxSkew := int64(DefaultKeyProofSkewSeconds)
	if expect.MaxSkewSeconds != nil {
		maxSkew = *expect.MaxSkewSeconds
	}
	if maxSkew < 0 {
		return nil, fmt.Errorf("invalid key proof verifier: MaxSkewSeconds must be non-negative")
	}

	// 1. Size cap — before any decode. A DoS guard at the header layer.
	if len(proof) > MaxKeyProofSize {
		return nil, keyProofInvalid(KeyProofFailureSize, "envelope exceeds max size: %d > %d",
			len(proof), MaxKeyProofSize)
	}

	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return nil, keyProofInvalid(KeyProofFailureHeader, "failed to decode JWS")
	}

	// 2. Header gates — the Signature Verification Profile, plus the two this
	// envelope adds. Applied to the RAW header object so a member present with any
	// value is observable, not to a typed struct that would silently drop it.
	headerBytes, err := Base64urlDecode(parts[0])
	if err != nil || !utf8.Valid(headerBytes) {
		return nil, keyProofInvalid(KeyProofFailureHeader, "failed to decode header")
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, keyProofInvalid(KeyProofFailureHeader, "protected header must be an object")
	}
	var alg string
	if raw, ok := header["alg"]; !ok || json.Unmarshal(raw, &alg) != nil || alg != "EdDSA" {
		return nil, keyProofInvalid(KeyProofFailureHeader, "unsupported algorithm: %s", string(header["alg"]))
	}
	if _, present := header["crit"]; present {
		return nil, keyProofInvalid(KeyProofFailureHeader, "crit header is not supported")
	}
	// Embedded key material, and the references that fetch it. jwk/x5c are the
	// profile's; jku/x5u are named by KEY-PROOF.md's "an embedded key member
	// (jwk, jku, x5c, …) rejects" — a URL that FETCHES a key is header key trust
	// with an extra hop, which is the thing being refused.
	for _, member := range []string{"jwk", "jku", "x5c", "x5u"} {
		if _, present := header[member]; present {
			return nil, keyProofInvalid(KeyProofFailureHeader,
				"%s header is not allowed (the key rides in the payload)", member)
		}
	}
	// A PRESENT kid REJECTS. The candidate key is in no chain, so there is no DID
	// URL to name; an envelope carrying one is claiming something this artifact
	// does not say, and admitting it would create a second place a verifier might
	// look for a key.
	if _, present := header["kid"]; present {
		return nil, keyProofInvalid(KeyProofFailureHeader, "kid must be absent — the candidate key is in no chain")
	}
	// THE TYP GATE, ABSOLUTE. A proof signed for one ceremony is dead bytes at
	// every other.
	var typ string
	if raw, ok := header["typ"]; !ok || json.Unmarshal(raw, &typ) != nil || typ != expect.Typ {
		return nil, keyProofInvalid(KeyProofFailureHeader, "invalid typ: expected %s, got %s",
			expect.Typ, string(header["typ"]))
	}

	// 3. Payload schema — CLOSED, exactly four string members. Parsed from the
	// ORIGINAL payload octets (the signature covers those bytes), not
	// re-canonicalized: the canonical rule binds PRODUCERS.
	payloadBytes, err := Base64urlDecode(parts[1])
	if err != nil {
		return nil, keyProofInvalid(KeyProofFailureSchema, "failed to decode payload")
	}
	// MALFORMED UTF-8 IS AN INVALID PROOF, NOT A LENIENT DECODE. encoding/json
	// silently substitutes U+FFFD for an invalid byte where the TS twin decodes
	// with TextDecoder('utf-8', {fatal:true}) and throws; without this gate the
	// same octets would authenticate here and reject there.
	if !utf8.Valid(payloadBytes) {
		return nil, keyProofInvalid(KeyProofFailureSchema, "payload is not valid UTF-8 JSON")
	}
	var rawPayload map[string]json.RawMessage
	if err := json.Unmarshal(payloadBytes, &rawPayload); err != nil {
		return nil, keyProofInvalid(KeyProofFailureSchema, "expected a JSON object")
	}
	for member := range rawPayload {
		known := false
		for _, canonical := range keyProofMembers {
			if member == canonical {
				known = true
				break
			}
		}
		if !known {
			return nil, keyProofInvalid(KeyProofFailureSchema,
				"unknown member %q — the payload is closed", member)
		}
	}
	members := map[string]string{}
	for _, name := range keyProofMembers {
		raw, present := rawPayload[name]
		if !present {
			return nil, keyProofInvalid(KeyProofFailureSchema, "%s must be a non-empty string", name)
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, keyProofInvalid(KeyProofFailureSchema, "%s must be a non-empty string", name)
		}
		members[name] = value
	}
	payload := KeyProofPayload{
		Nonce:              members["nonce"],
		Audience:           members["audience"],
		PublicKeyMultibase: members["publicKeyMultibase"],
		Timestamp:          members["timestamp"],
	}
	if err := validateKeyProofPayload(payload); err != nil {
		return nil, err
	}

	// 4. Audience — BYTE EQUALITY against the verifier's own configured authority.
	// This is what defeats challenge relay: a proof audienced to the host the
	// victim confirmed is unusable at every other host.
	if payload.Audience != expect.Audience {
		return nil, keyProofInvalid(KeyProofFailureAudience, "audience does not match this verifier authority")
	}

	// 5. Freshness — integer unix seconds on both sides, symmetric, because a
	// ceremony's window is its own lifetime in both directions.
	issuedAt, err := ParseProtocolTimestamp(payload.Timestamp)
	if err != nil {
		return nil, keyProofInvalid(KeyProofFailureSchema, "timestamp must be ISO-8601 UTC whole-second .000Z")
	}
	nowUnix := now.UTC().Unix()
	delta := nowUnix - issuedAt.UTC().Unix()
	if delta < 0 {
		delta = -delta
	}
	if delta > maxSkew {
		return nil, keyProofInvalid(KeyProofFailureFreshness, "timestamp is outside the acceptance window")
	}

	// 6. NONCE — THE CALLER'S. See the doc comment: check-and-delete, atomically.

	// 7. Signature, against the payload's OWN publicKeyMultibase. The circularity
	// is the point: a valid envelope is possession demonstrated over fresh
	// verifier-minted bytes.
	publicKey, err := DecodeMultikey(payload.PublicKeyMultibase)
	if err != nil {
		return nil, keyProofInvalid(KeyProofFailureSignature, "undecodable publicKeyMultibase: %s", err)
	}
	// ed25519.Verify PANICS on a wrong-size key, and a wrong-size key is an
	// invalid proof, never a crash.
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, keyProofInvalid(KeyProofFailureSignature,
			"publicKeyMultibase is not a %d-byte Ed25519 public key", ed25519.PublicKeySize)
	}
	signature, err := Base64urlDecode(parts[2])
	if err != nil {
		return nil, keyProofInvalid(KeyProofFailureSignature, "failed to decode signature")
	}
	if !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return nil, keyProofInvalid(KeyProofFailureSignature,
			"signature does not verify against publicKeyMultibase")
	}

	return &VerifiedKeyProof{Payload: payload, Typ: typ, Now: nowUnix}, nil
}
