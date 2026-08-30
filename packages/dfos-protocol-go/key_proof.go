package dfos

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// KEY PROOF — the Go byte-twin of dfos-protocol/src/key-proof/key-proof.ts.
//
// A KEY PROOF is a compact JWS over exactly seven members — {nonce, audience,
// did, roleSet, prevCID, publicKeyMultibase, timestamp} — signed by the candidate
// key ITSELF, scoped by a registered typ to exactly one ceremony purpose. It
// proves one fact: the named key was held, and consented to THIS POSITION — this
// chain, these roles, this head — at this verifier, inside this window. It never
// conveys intent, content, or authority. See specs/KEY-PROOF.md.
//
// WHAT THE THREE POSITIONAL MEMBERS BUY. nonce, audience and timestamp bind a
// proof to one ceremony at one verifier in one window; they say nothing about
// WHERE the key was going. did, roleSet and prevCID say exactly that, and each
// closes a distinct standing-consent hole:
//
//   - did — the chain the key is introduced to. Without it, a proof collected for
//     one identity is spendable against another.
//   - roleSet — the roles consented to, from the closed set {auth, assert,
//     controller} in one canonical spelling (see role_set.go). Without it,
//     consent to sign as an author is consent to become a controller.
//   - prevCID — the head the introduction builds on. This is the one that kills
//     STANDING CONSENT: an envelope is bound to a chain state that has already
//     moved on by the time a second introduction could reuse it, so re-adding a
//     removed key, or promoting a key to a new role, needs a FRESH envelope every
//     time. There is no such thing as an envelope held in reserve.
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
// TWO VERIFICATION MODES OVER ONE ENVELOPE. The same bytes are read twice in a
// key's life, by parties in different positions:
//
//   - PRESENTATION-TIME (VerifyKeyProof) — a ceremony operator completing a live
//     ceremony. It holds a clock, a configured audience, and a nonce store, so it
//     checks freshness and audience, and its caller runs step 6.
//   - CHAIN-WALK (VerifyChainKeyProof) — anyone replaying the chain later. The
//     ceremony is long over; the operator's authority, clock and nonce store are
//     not the walker's, and a proof embedded in a signed operation is FIXED
//     TRANSPORT, not a live presentation. So the walk checks NEITHER freshness
//     NOR audience.
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
// resolve: this verifier touches no network and no store. The caller mistakes
// that are not verdicts about the artifact — a negative skew, an empty or
// non-canonical expectation — are returned as plain errors rather than wrapped
// here.
var ErrKeyProofInvalid = errors.New("key proof invalid")

// KeyProofFailureReason names the verification step a failure arose in. Byte-twin
// of the TS KeyProofVerifyError.reason union.
type KeyProofFailureReason string

const (
	KeyProofFailureSize      KeyProofFailureReason = "size"
	KeyProofFailureHeader    KeyProofFailureReason = "header"
	KeyProofFailureSchema    KeyProofFailureReason = "schema"
	KeyProofFailureAudience  KeyProofFailureReason = "audience"
	KeyProofFailureDID       KeyProofFailureReason = "did"
	KeyProofFailureRoleSet   KeyProofFailureReason = "roleSet"
	KeyProofFailurePrevCID   KeyProofFailureReason = "prevCID"
	KeyProofFailureKey       KeyProofFailureReason = "key"
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

// KeyProofPayload is the CLOSED payload. Exactly these seven members, each a
// string, in exactly this order — the member set is EXHAUSTIVE and no amendment
// may introduce a member that carries intent or content.
type KeyProofPayload struct {
	// Nonce is the verifier-minted, single-use challenge, exactly as the carriage
	// delivered it.
	Nonce string
	// Audience is the completing authority's lowercase authority — host, or
	// host:port off 443. Held here as an opaque string: a leg whose completing
	// authority IS a chain rather than a host audiences to that chain's DID,
	// byte-equal to DID, and this file does not special-case the two spellings.
	Audience string
	// DID is the chain this key is introduced to.
	DID string
	// RoleSet is the canonical role set (see role_set.go) this envelope consents to.
	RoleSet string
	// PrevCID is the chain head the introduction builds on — equal to the
	// introducing operation's previousOperationCID. The member that forecloses
	// standing consent.
	PrevCID string
	// PublicKeyMultibase is the candidate key's Multikey — and the key that signs
	// this envelope.
	PublicKeyMultibase string
	// Timestamp is the ISO 8601 creation time, floor-normalized to whole seconds.
	Timestamp string
}

// keyProofMembers is the canonical member order, and the closed member set.
var keyProofMembers = []string{
	"nonce", "audience", "did", "roleSet", "prevCID", "publicKeyMultibase", "timestamp",
}

// keyProofMemberValues pairs each canonical member name with its value, in
// canonical order, so validation reports the FIRST offending member
// deterministically rather than whichever one a map iteration reached first.
func keyProofMemberValues(payload KeyProofPayload) [][2]string {
	return [][2]string{
		{"nonce", payload.Nonce},
		{"audience", payload.Audience},
		{"did", payload.DID},
		{"roleSet", payload.RoleSet},
		{"prevCID", payload.PrevCID},
		{"publicKeyMultibase", payload.PublicKeyMultibase},
		{"timestamp", payload.Timestamp},
	}
}

// wholeSecondTimestampRe pins the .000Z spelling — literal zeros, not "any three
// digits". ParseProtocolTimestamp's layout accepts .123, so the suffix check is
// what makes the two languages agree that an unfloored millisecond component is
// not this grammar.
var wholeSecondTimestampRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z$`)

// validateKeyProofPayload applies KEY-PROOF.md step 3 and the producer-side
// member rules in ONE place: exactly the seven members, each a non-empty string.
//
// The grammar checks past "is a string" are the ones a mismatch would otherwise
// surface later and less usefully: an audience that is not an authority could
// never byte-equal a verifier's configured authority, a timestamp outside the
// canonical spelling could never be compared to a clock, and a roleSet outside
// its one canonical spelling would give the same set of roles more than one
// payload — which is the malleability the canonical-bytes rule exists to refuse,
// one level down.
//
// did and prevCID carry NO grammar past non-empty. They are compared by byte
// equality against values the verifier already holds — the chain's DID, the
// carrying operation's previousOperationCID — so a malformed one cannot match
// anything, and a shape rule here would only be a second place for the two
// language twins to disagree.
func validateKeyProofPayload(payload KeyProofPayload) error {
	for _, member := range keyProofMemberValues(payload) {
		name, value := member[0], member[1]
		if value == "" {
			return keyProofInvalid(KeyProofFailureSchema, "%s must be a non-empty string", name)
		}
		if !utf8.ValidString(value) {
			return keyProofInvalid(KeyProofFailureSchema, "%s must be well-formed Unicode", name)
		}
	}
	// The API-AUTH authority grammar, verbatim: lowercase, no scheme, no path. A
	// did:dfos:… identifier satisfies it as written — lowercase, no separators —
	// which is why the DID-audienced leg needs no second grammar here.
	if payload.Audience != strings.ToLower(payload.Audience) ||
		strings.ContainsAny(payload.Audience, " \t\n\r\f\v/\\?#") {
		return keyProofInvalid(KeyProofFailureSchema,
			"audience must be a lowercase authority, without a scheme or path")
	}
	// The role set has ONE spelling. assert,auth, "auth, assert", auth,auth,
	// auth,owner and "" all name nothing this envelope can be signed for.
	if !IsCanonicalRoleSet(payload.RoleSet) {
		return keyProofInvalid(KeyProofFailureSchema,
			"roleSet must be a canonical, non-empty subset of auth,assert,controller in that order")
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
// members in exactly the order nonce, audience, did, roleSet, prevCID,
// publicKeyMultibase, timestamp. Byte-for-byte identical to the TS
// keyProofSigningInput.
func KeyProofSigningInput(payload KeyProofPayload) ([]byte, error) {
	if err := validateKeyProofPayload(payload); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(`{"nonce":`)
	b.WriteString(jsonStringifyString(payload.Nonce))
	b.WriteString(`,"audience":`)
	b.WriteString(jsonStringifyString(payload.Audience))
	b.WriteString(`,"did":`)
	b.WriteString(jsonStringifyString(payload.DID))
	b.WriteString(`,"roleSet":`)
	b.WriteString(jsonStringifyString(payload.RoleSet))
	b.WriteString(`,"prevCID":`)
	b.WriteString(jsonStringifyString(payload.PrevCID))
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

// SignKeyProofInput carries everything one key proof is signed from. A struct
// rather than a positional list because the seven-member payload needs six
// producer inputs plus two clock knobs, and a positional signature at that width
// is a silent-argument-swap waiting to happen.
type SignKeyProofInput struct {
	// Typ is the registered purpose this proof is scoped to — e.g. KeyAddJWSTyp.
	Typ string
	// Nonce is the verifier-minted nonce, exactly as the carriage delivered it.
	Nonce string
	// Audience is the completing authority — the one the human confirmed.
	Audience string
	// DID is the chain this key is being introduced to.
	DID string
	// RoleSet is the canonical role set — build it with SerializeRoleSet rather
	// than by hand; a non-canonical spelling is refused here, not silently
	// normalized.
	RoleSet string
	// PrevCID is the chain head the introduction builds on.
	PrevCID string
	// PrivateKey is the candidate key's Ed25519 private key. PublicKeyMultibase is
	// DERIVED from it rather than accepted as an input: this envelope is
	// self-proving, and a signer that could name a key it does not hold would be
	// the one construction the artifact exists to foreclose.
	PrivateKey ed25519.PrivateKey
	// Timestamp overrides the creation time; it is floor-normalized to .000Z if it
	// carries a millisecond component. Empty means "use Now".
	Timestamp string
	// Now overrides the clock for the default timestamp; the zero time means
	// time.Now().
	Now time.Time
}

// SignKeyProof signs one key proof. The producer half of the byte contract.
//
// The protected header is EXACTLY {"alg":"EdDSA","typ":"<purpose>"} — two
// members, no kid (the key is in no chain and rides in the payload) and no cid
// (there is no operation to bind).
//
// HOLDER OBLIGATIONS THIS FUNCTION CANNOT DISCHARGE (KEY-PROOF.md, Holder
// Obligations). A holder MUST show its human — before calling this — the
// audience, the purpose, the adopting identity, and the roles. A proof is
// consent, and consent that was never displayed was never given.
//
// It SHOULD also refuse to sign for a key some identity's chain has already
// PROVED, its own included: the key= reverse index is has-ever-proved across all
// three key sets, its rows survive rotation and deletion, and proving one key
// into two chains publishes an irreversible public link between them. An
// unproved DECLARATION of the key elsewhere is neither a link nor a burn — it is
// void, it never indexes, and it never obligates the true holder, which is
// precisely why the index counts proofs and not claims.
//
// Every one of those is a decision about a human and a network, made before
// there is a signature to make; none belongs to a pure signer.
func SignKeyProof(input SignKeyProofInput) (string, KeyProofPayload, error) {
	if input.Typ == "" {
		return "", KeyProofPayload{}, fmt.Errorf("invalid key proof: typ must be a registered purpose value")
	}
	if len(input.PrivateKey) != ed25519.PrivateKeySize {
		return "", KeyProofPayload{}, fmt.Errorf("invalid key proof: privateKey must be a %d-byte Ed25519 private key",
			ed25519.PrivateKeySize)
	}

	timestamp := input.Timestamp
	if timestamp == "" {
		now := input.Now
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
		Nonce:              input.Nonce,
		Audience:           input.Audience,
		DID:                input.DID,
		RoleSet:            input.RoleSet,
		PrevCID:            input.PrevCID,
		PublicKeyMultibase: EncodeMultikey(input.PrivateKey.Public().(ed25519.PublicKey)),
		Timestamp:          timestamp,
	}
	payloadBytes, err := KeyProofSigningInput(payload)
	if err != nil {
		return "", KeyProofPayload{}, err
	}

	// Hand-rolled: JWSHeader would emit "kid":"" and "cid" handling this envelope
	// must not carry, and the two-member order is part of the pinned vector.
	header := `{"alg":"EdDSA","typ":` + jsonStringifyString(input.Typ) + `}`
	signingInput := Base64urlEncodeString(header) + "." + Base64urlEncode(payloadBytes)
	proof := signingInput + "." + Base64urlEncode(ed25519.Sign(input.PrivateKey, []byte(signingInput)))
	if len(proof) > MaxKeyProofSize {
		return "", KeyProofPayload{}, fmt.Errorf("key proof exceeds max size: %d > %d", len(proof), MaxKeyProofSize)
	}
	return proof, payload, nil
}

// -----------------------------------------------------------------------------
// decode — the steps BOTH verification modes share
// -----------------------------------------------------------------------------

// decodedKeyProof is the envelope, split and validated as far as the two modes
// agree.
type decodedKeyProof struct {
	payload      KeyProofPayload
	headerB64    string
	payloadB64   string
	signatureB64 string
	typ          string
}

// decodeKeyProof runs KEY-PROOF.md verification steps 1–3: size cap, header
// gates, and the closed payload schema over CANONICAL bytes. Everything both
// modes do identically, because these three steps are about the ARTIFACT and not
// about the position the reader occupies.
func decodeKeyProof(proof string, expectedTyp string) (*decodedKeyProof, error) {
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
	// look for a key. It stays absent in the chain-walk mode too: by the time the
	// walk reads the envelope the key IS in a chain, but the envelope is the same
	// bytes it always was, and re-reading them under a looser rule would mean an
	// artifact that verifies at replay and not at presentation.
	if _, present := header["kid"]; present {
		return nil, keyProofInvalid(KeyProofFailureHeader, "kid must be absent — the candidate key is in no chain")
	}
	// THE TYP GATE, ABSOLUTE. A proof signed for one ceremony is dead bytes at
	// every other.
	var typ string
	if raw, ok := header["typ"]; !ok || json.Unmarshal(raw, &typ) != nil || typ != expectedTyp {
		return nil, keyProofInvalid(KeyProofFailureHeader, "invalid typ: expected %s, got %s",
			expectedTyp, string(header["typ"]))
	}

	// 3. Payload schema — CLOSED, exactly seven string members — AND the canonical
	// bytes. The parse runs against the ORIGINAL payload octets, because those are
	// the bytes the signature covers; the canonical serialization is then
	// RECOMPUTED from the parsed members and byte-compared against them.
	//
	// THE CANONICAL RULE BINDS THE VERIFIER, NOT ONLY THE PRODUCER. A signature
	// covers whatever octets arrived, so without that comparison a payload whose
	// seven members are REORDERED — or re-spelled with insignificant whitespace —
	// and signed over that serialization verifies exactly like the canonical one,
	// and the payload stops being a function of its members. The same argument one
	// level down is why roleSet has a single spelling: assert,auth names the set
	// auth,assert names, so admitting both would restore the malleability this
	// comparison removes.
	//
	// WHAT THIS PINS IS THE PAYLOAD'S OCTETS, AND NOTHING PAST THEM. The compact
	// envelope around them is not canonicalized: Base64urlDecode is
	// padding-tolerant (a family-wide choice), and no rule pins the protected
	// header's serialization — so one proof still has more than one envelope
	// spelling, and a caller must not treat the envelope string as an identity.
	// Nothing here needs it to be: what a completion spends is the NONCE, consumed
	// atomically and once by the caller's step 6. Conformant producers already emit
	// these bytes, so nothing that could be signed correctly is refused here.
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
		if !slices.Contains(keyProofMembers, member) {
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
		DID:                members["did"],
		RoleSet:            members["roleSet"],
		PrevCID:            members["prevCID"],
		PublicKeyMultibase: members["publicKeyMultibase"],
		Timestamp:          members["timestamp"],
	}
	if err := validateKeyProofPayload(payload); err != nil {
		return nil, err
	}
	canonical, err := KeyProofSigningInput(payload)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, payloadBytes) {
		return nil, keyProofInvalid(KeyProofFailureSchema,
			"payload is not the canonical signing input for its members")
	}

	return &decodedKeyProof{
		payload:      payload,
		headerB64:    parts[0],
		payloadB64:   parts[1],
		signatureB64: parts[2],
		typ:          typ,
	}, nil
}

// verifyKeyProofSignature runs KEY-PROOF.md verification step 7: the signature,
// against the payload's OWN publicKeyMultibase. The circularity is the point — a
// valid envelope is possession demonstrated over bytes the signer did not choose
// alone.
func verifyKeyProofSignature(decoded *decodedKeyProof) error {
	publicKey, err := DecodeMultikey(decoded.payload.PublicKeyMultibase)
	if err != nil {
		return keyProofInvalid(KeyProofFailureSignature, "undecodable publicKeyMultibase: %s", err)
	}
	// ed25519.Verify PANICS on a wrong-size key, and a wrong-size key is an
	// invalid proof, never a crash.
	if len(publicKey) != ed25519.PublicKeySize {
		return keyProofInvalid(KeyProofFailureSignature,
			"publicKeyMultibase is not a %d-byte Ed25519 public key", ed25519.PublicKeySize)
	}
	signature, err := Base64urlDecode(decoded.signatureB64)
	if err != nil {
		return keyProofInvalid(KeyProofFailureSignature, "failed to decode signature")
	}
	if !ed25519.Verify(publicKey, []byte(decoded.headerB64+"."+decoded.payloadB64), signature) {
		return keyProofInvalid(KeyProofFailureSignature,
			"signature does not verify against publicKeyMultibase")
	}
	return nil
}

// -----------------------------------------------------------------------------
// verify — presentation time
// -----------------------------------------------------------------------------

// KeyProofExpectations is what the VERIFIER holds about the ceremony it is
// completing. Every value here comes from the deployment's own configuration —
// never from the request, and never read back out of the envelope being checked.
//
// NONE OF THE FIVE IS OPTIONAL. An omitted or empty expectation is an arm that
// reads as satisfied while binding nothing, which is precisely the standing
// consent this envelope revision exists to foreclose. Each is guarded as a
// MISCONFIGURATION — a plain error, never wrapping ErrKeyProofInvalid.
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
	// DID is THE CHAIN THIS CEREMONY IS COMPLETING FOR. Like the audience, it is
	// the completing authority's own value — the identity whose ceremony this is.
	DID string
	// RoleSet is THE ROLES THIS CEREMONY GRANTS, in canonical spelling
	// (SerializeRoleSet). Byte-equality, not coverage: a ceremony that will write
	// auth,assert MUST NOT accept an envelope consenting to auth alone, and MUST
	// NOT accept one consenting to auth,assert,controller either — the second is
	// the holder conceding more than was asked, which a completing authority has
	// no business banking. A non-canonical expectation is a MISCONFIGURATION.
	RoleSet string
	// PrevCID is THE HEAD THE INTRODUCTION WILL BUILD ON — the
	// previousOperationCID the completing authority is about to write. A chain that
	// moved between minting the challenge and completing it invalidates the proof
	// here rather than writing an operation whose embedded envelope no walker will
	// accept.
	PrevCID string
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

// VerifyKeyProof verifies a key proof AT PRESENTATION TIME — KEY-PROOF.md's
// verification algorithm steps 1–5 and 7: size cap, header gates, the closed
// payload schema over CANONICAL bytes, the four expectation arms (audience, did,
// roleSet, prevCID), freshness, and the signature against the payload's OWN
// publicKeyMultibase.
//
// EVERY EXPECTATION IS THE DEPLOYMENT'S OWN VALUE. There is no arm here that
// compares the envelope to itself. DID, RoleSet and PrevCID are the position the
// completing authority is about to WRITE; if the envelope names a different one,
// the holder consented to something else.
//
// STEP 6 (NONCE) IS THE CALLER'S, and this function cannot stand in for it. The
// nonce MUST be one this verifier minted, for this ceremony, not yet consumed,
// checked and consumed ATOMICALLY — a check-and-delete against the verifier's own
// store, which is state this pure function does not hold. It is returned on
// Payload.Nonce precisely so the caller can run that step next. Without it a proof
// is replayable for the length of the freshness window.
//
// What the steps together establish is exactly one fact: THE NAMED KEY WAS HELD,
// AND CONSENTED TO THIS POSITION IN THIS CHAIN AT THIS VERIFIER, INSIDE THIS
// WINDOW. Everything after — appending the key to a chain, custody policy,
// notification — is the ceremony operator's.
func VerifyKeyProof(proof string, expect KeyProofExpectations, now time.Time) (*VerifiedKeyProof, error) {
	// THE TYP GATE IS ONLY A GATE WHEN THE EXPECTATION NAMES A PURPOSE. An empty
	// expect.Typ byte-equals an artifact carrying "typ":"", so a verifier
	// configured with one admits an envelope scoped to no ceremony at all — the
	// gate reads as satisfied while gating nothing. That is a MISCONFIGURATION,
	// not a verdict about a proof: it returns a plain error like the guards below
	// and never wraps ErrKeyProofInvalid, so a caller branching on Reason cannot
	// mistake a broken deployment for a bad envelope. Non-empty is the whole rule —
	// the purpose registry is KEY-PROOF.md's, and hardcoding its rows here would
	// make registering a new purpose a library release. SignKeyProof refuses an
	// empty typ on the producer side for the same reason, and the TS twin's
	// verifyKeyProof carries this guard byte-for-byte.
	//
	// The same argument covers the other four expectations, and it is why none of
	// them is optional: an omitted or empty positional expectation is an arm that
	// reads as satisfied while binding nothing.
	if expect.Typ == "" {
		return nil, fmt.Errorf("invalid key proof verifier: Typ must be a registered purpose value")
	}
	if expect.Audience == "" {
		return nil, fmt.Errorf("invalid key proof verifier: Audience must name this authority")
	}
	if expect.DID == "" {
		return nil, fmt.Errorf("invalid key proof verifier: DID must name the chain")
	}
	if expect.PrevCID == "" {
		return nil, fmt.Errorf("invalid key proof verifier: PrevCID must name the chain head")
	}
	if !IsCanonicalRoleSet(expect.RoleSet) {
		return nil, fmt.Errorf(
			"invalid key proof verifier: RoleSet must be a canonical role set — build it with SerializeRoleSet")
	}

	maxSkew := int64(DefaultKeyProofSkewSeconds)
	if expect.MaxSkewSeconds != nil {
		maxSkew = *expect.MaxSkewSeconds
	}
	if maxSkew < 0 {
		return nil, fmt.Errorf("invalid key proof verifier: MaxSkewSeconds must be non-negative")
	}

	// 1–3. Size, header gates, closed schema over canonical bytes.
	decoded, err := decodeKeyProof(proof, expect.Typ)
	if err != nil {
		return nil, err
	}
	payload := decoded.payload

	// 4. Audience — BYTE EQUALITY against the verifier's own configured authority.
	// This is what defeats challenge relay: a proof audienced to the host the
	// victim confirmed is unusable at every other host.
	if payload.Audience != expect.Audience {
		return nil, keyProofInvalid(KeyProofFailureAudience, "audience does not match this verifier authority")
	}

	// 4b. The three POSITIONAL arms, each byte equality against a value the
	// completing authority already holds. Audience binding says WHERE the proof may
	// be spent; these say WHAT it may be spent on.
	if payload.DID != expect.DID {
		return nil, keyProofInvalid(KeyProofFailureDID, "did does not match the chain this ceremony completes for")
	}
	if payload.RoleSet != expect.RoleSet {
		return nil, keyProofInvalid(KeyProofFailureRoleSet, "roleSet does not match the roles this ceremony grants")
	}
	if payload.PrevCID != expect.PrevCID {
		return nil, keyProofInvalid(KeyProofFailurePrevCID,
			"prevCID does not match the chain head this introduction builds on")
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

	// 7. Signature, against the payload's OWN publicKeyMultibase.
	if err := verifyKeyProofSignature(decoded); err != nil {
		return nil, err
	}

	return &VerifiedKeyProof{Payload: payload, Typ: decoded.typ, Now: nowUnix}, nil
}

// -----------------------------------------------------------------------------
// verify — chain walk
// -----------------------------------------------------------------------------

// UnsafeKeyProofSubject returns the publicKeyMultibase an envelope NAMES, read
// WITHOUT verifying anything — no signature, no schema, no gates. The second
// return is false when the bytes do not decode to an object carrying a string
// there.
//
// UNSAFE IS IN THE NAME BECAUSE THE ANSWER PROVES NOTHING. The only sound use is
// as an INDEX HINT. An operation carrying several envelopes and introducing
// several keys would otherwise be a quadratic scan — every envelope gated against
// every candidate — so the chain walk uses this to pick WHICH candidate an
// envelope is about, then runs the full VerifyChainKeyProof against that
// candidate's real, DECLARED Multikey. The gate's own publicKeyMultibase arm is
// what makes the pairing sound: a wrong or forged hint routes the envelope to a
// candidate it then fails against, which is exactly the verdict the exhaustive
// scan would have reached. Never read this value as an assertion about a key.
func UnsafeKeyProofSubject(proof string) (string, bool) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return "", false
	}
	payloadBytes, err := Base64urlDecode(parts[1])
	if err != nil || !utf8.Valid(payloadBytes) {
		return "", false
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payloadBytes, &raw); err != nil {
		return "", false
	}
	subject, present := raw["publicKeyMultibase"]
	if !present {
		return "", false
	}
	var value string
	if err := json.Unmarshal(subject, &value); err != nil {
		return "", false
	}
	return value, true
}

// ChainKeyProofExpectations is the POSITION a chain walker reads an envelope
// against. There is no clock and no audience here, and the absence is the
// contract — see VerifyChainKeyProof.
type ChainKeyProofExpectations struct {
	// Typ is the registered typ the introduction requires — KeyAddJWSTyp.
	Typ string
	// DID is the DID of the chain being walked.
	DID string
	// PrevCID is the carrying operation's previousOperationCID.
	PrevCID string
	// PublicKeyMultibase is the Multikey of the key this envelope is being read as
	// the proof FOR.
	PublicKeyMultibase string
	// Role is the role the introduction needs covered. Coverage, not equality.
	Role KeyRole
}

// VerifyChainKeyProof verifies a key proof AT CHAIN-WALK TIME — the mode a
// replayer uses on an envelope embedded in a signed identity operation.
//
// WHAT IT CHECKS: the signature, the typ, the closed schema over canonical bytes,
// and the four position arms — PublicKeyMultibase is the key being introduced,
// DID is this chain, PrevCID is the carrying operation's previousOperationCID,
// and roleSet COVERS the role in question.
//
// WHAT IT DELIBERATELY DOES NOT CHECK, AND WHY. Neither FRESHNESS nor AUDIENCE.
// Both are properties of a live ceremony, and the walk is not one: the envelope
// was fresh when it was presented, against a clock and an authority that belonged
// to the completing operator and not to whoever replays the chain a year later.
// Checking freshness at walk time would make every chain expire; checking audience
// would make a chain verifiable only by the relay that wrote it. The two members
// still travel, still sign, and are still returned — they are FIXED TRANSPORT the
// signature covers, evidence of which ceremony this was, not gates a walker is
// positioned to run.
//
// COVERAGE, NOT EQUALITY, ON THE ROLE. Presentation-time takes byte equality
// because the completing authority knows exactly which roles it is about to
// write. The walk asks a narrower question, once per (key, role) introduction:
// did the holder consent to THIS role? One envelope consenting to
// auth,assert,controller therefore proves three introductions in one operation,
// which is the ordinary rotation case.
//
// Returns the validated payload. A chain walker treats every rejection as "this
// introduction is not proved", never as "this chain is invalid": an unproved
// introduction voids a key-role membership and nothing more.
func VerifyChainKeyProof(proof string, expect ChainKeyProofExpectations) (*KeyProofPayload, error) {
	if expect.Typ == "" {
		return nil, fmt.Errorf("invalid key proof verifier: Typ must be a registered purpose value")
	}

	// 1–3. Size, header gates, closed schema over canonical bytes.
	decoded, err := decodeKeyProof(proof, expect.Typ)
	if err != nil {
		return nil, err
	}
	payload := decoded.payload

	// The key arm FIRST: an envelope for some other key is not evidence about this
	// one, whatever else it says.
	if payload.PublicKeyMultibase != expect.PublicKeyMultibase {
		return nil, keyProofInvalid(KeyProofFailureKey, "publicKeyMultibase is not the key being introduced")
	}
	if payload.DID != expect.DID {
		return nil, keyProofInvalid(KeyProofFailureDID, "did is not this chain")
	}
	if payload.PrevCID != expect.PrevCID {
		return nil, keyProofInvalid(KeyProofFailurePrevCID,
			"prevCID is not the carrying operation previousOperationCID")
	}
	if !RoleSetCovers(payload.RoleSet, expect.Role) {
		return nil, keyProofInvalid(KeyProofFailureRoleSet, "roleSet does not cover the %s role", expect.Role)
	}

	// Freshness and audience are NOT checked here. See the doc comment.

	if err := verifyKeyProofSignature(decoded); err != nil {
		return nil, err
	}

	return &payload, nil
}
