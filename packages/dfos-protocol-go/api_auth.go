package dfos

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// API AUTH — the Go byte-twin of dfos-client/src/api-auth.ts.
//
// ONE ENVELOPE FAMILY WITH AN OPTIONAL CREDENTIAL. A REQUEST PROOF is a
// short-lived JWS, signed by the key of the party a DFOS credential was issued
// to, binding ONE exact HTTP request (method, host, path, body) to that
// credential. An IDENTITY PROOF is the same envelope minus credentialCID: it
// binds the same exact request to a bare DID, proving only WHO IS ASKING. Same
// canonical-bytes machinery, same freshness bounds, same host binding, same
// current-state key resolution — that one member and the credential walk are the
// whole delta, and the typ gate keeps the two claims distinct on the wire. See
// specs/API-AUTH.md.
//
// This file MUST stay in sync with the TS twin. The canonical signing input is
// hand-rolled with jsonStringifyString rather than encoding/json for one
// load-bearing reason: `path` routinely carries `&` and admits `<` and `>`, and
// encoding/json escapes all three to \u0026 / \u003c / \u003e by default, which
// would silently fork the signed bytes away from what JavaScript's
// JSON.stringify emits. Building the object by hand forecloses that fork rather
// than relying on every call site remembering Encoder.SetEscapeHTML(false).
//
// NOTE ON SCOPE: this file implements the byte contract and the PROOF ENVELOPE
// verification only — size caps, header gates, payload schema, freshness,
// request binding, and signature (API-AUTH.md steps 1–7). Full credential-chain
// verification (steps 8–11: chain walk, revocation, the no-public-audience scan,
// subject selection, attenuation coverage) is TS-side for now. This mirrors the
// boundary siwd.go already draws: the Go twin carries the canonical bytes and
// the envelope, and the credential machinery lives in the TypeScript reference.
// For the IDENTITY proof that boundary is not a boundary at all: steps 1–7 are
// the entire algorithm, so VerifyIdentityProof here is complete.

const RequestProofJWSTyp = "did:dfos:request-proof"

// IdentityProofJWSTyp is the normative header typ for an identity proof — the
// request proof's credential-less sibling.
//
// THE TYP GATE IS ABSOLUTE, IN BOTH DIRECTIONS. "Possession of a grant's
// audience key" and "possession of a bare identity's key" are different claims,
// so a route requiring a credential rejects an identity proof at the header gate
// and a route requiring bare identity rejects a request proof at the same gate.
// No verifier ambiguity, no downgrade.
const IdentityProofJWSTyp = "did:dfos:identity-proof"

// EmptyBodySHA256 is the digest of zero octets. A request with no body hashes
// the empty string — there is deliberately no absent-member form for bodyless
// requests, so every proof is checked the same way.
const EmptyBodySHA256 = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"

const (
	// MaxRequestProofSize bounds the serialized proof token, checked BEFORE any decode.
	MaxRequestProofSize = 4096
	// DefaultProofWindowSeconds is the RECOMMENDED acceptance window W.
	DefaultProofWindowSeconds = 60
	// DefaultProofSkewSeconds is the RECOMMENDED clock-skew allowance S.
	DefaultProofSkewSeconds = 60
	// MaxProofFreshnessSpanSeconds caps W + S: the total span over which any one
	// proof is accepted, and therefore its worst-case replay window.
	MaxProofFreshnessSpanSeconds = 300
	// MaxBodyBytesDefault is the default cap on the decoded body a verifier will
	// hash (1 MiB). The v0 action registry is bodyless, so it never binds today.
	MaxBodyBytesDefault = 1 << 20
)

// Sentinel errors for the consumer-visible verdicts. Callers branch with
// errors.Is, never on diagnostic message text.
//
// Their TEXT is family-level ("api auth proof …") rather than request-specific,
// because one verdict set covers both artifacts and a log line reading "request
// proof invalid: identity proof is stale" would be a lie about which artifact
// failed. The variable names are the published surface and are unchanged.
//
// ErrRequestProofConfig is deliberately NOT a verdict about the artifact: it
// reports that the DEPLOYMENT is misconfigured (a W + S over the ceiling), which
// is a 500, not a 401.
var (
	ErrRequestProofInvalid      = errors.New("api auth proof invalid")
	ErrRequestProofUnverifiable = errors.New("api auth proof unverifiable")
	ErrRequestProofConfig       = errors.New("api auth verifier misconfigured")
)

// ErrProofPresenterInvalid lets a KeyResolver classify its OWN failure as a
// judgment about the presenter rather than an outage.
//
// The resolver seam cannot otherwise tell the two apart: "this DID's current
// state says deleted" and "the store is unreachable" both arrive as an error,
// and mapping every failure to unverifiable would report a DELETED presenter —
// the terminal off-switch — as a 503 the caller should retry. A resolver wraps
// this sentinel for the cases it has actually CHECKED (a non-canonical DID, a
// deleted identity, a key absent from current state) and returns a bare error
// for the ones it could not check. Byte-twin of the TS rule that a resolver may
// throw an already-classified ApiRequestVerifyError.
var ErrProofPresenterInvalid = errors.New("identity proof presenter is invalid")

// The identity proof reuses the family's verdict set — the SAME error values, so
// errors.Is branching is identical whichever artifact a route consumes. These
// names exist so an identity-proof consumer never has to name the request proof
// to classify its own failures.
var (
	ErrIdentityProofInvalid      = ErrRequestProofInvalid
	ErrIdentityProofUnverifiable = ErrRequestProofUnverifiable
	ErrIdentityProofConfig       = ErrRequestProofConfig
)

// RequestProofPayload is the closed API-AUTH 0.1 proof schema. All six members
// are required; there are no optionals, so the canonical form below carries no
// absent-member ambiguity.
type RequestProofPayload struct {
	Method        string
	Host          string
	Path          string
	BodyHash      string
	CredentialCID string
	Iat           int64
}

// IdentityProofPayload is the identity proof's schema: the request proof's five
// members MINUS CredentialCID. All five are required, under the SAME member
// rules — there is no relaxation here, only one fewer member.
type IdentityProofPayload struct {
	Method   string
	Host     string
	Path     string
	BodyHash string
	Iat      int64
}

// proofShape is how the INTERNALS see the two artifacts. One member-rules
// implementation, one canonical-bytes implementation, and one proof-phase
// implementation serve both — parameterized by the single member that differs
// (credentialCID) and by the typ that keeps the two claims distinct.
type proofShape struct {
	label        string
	typ          string
	credentialed bool
}

var (
	requestProofShape  = proofShape{label: "request proof", typ: RequestProofJWSTyp, credentialed: true}
	identityProofShape = proofShape{label: "identity proof", typ: IdentityProofJWSTyp, credentialed: false}
)

// proofPayload is the internal union of both payloads; CredentialCID is set iff
// the shape is credentialed.
type proofPayload struct {
	Method        string
	Host          string
	Path          string
	BodyHash      string
	CredentialCID string
	Iat           int64
}

func (p RequestProofPayload) internal() proofPayload {
	return proofPayload{Method: p.Method, Host: p.Host, Path: p.Path,
		BodyHash: p.BodyHash, CredentialCID: p.CredentialCID, Iat: p.Iat}
}

func (p IdentityProofPayload) internal() proofPayload {
	return proofPayload{Method: p.Method, Host: p.Host, Path: p.Path,
		BodyHash: p.BodyHash, Iat: p.Iat}
}

// ProofExtraMembers carries ADDITIVE members, appended AFTER the canonical
// order.
//
// API-AUTH.md's growth rule is additive members on this envelope, never a new
// envelope: "additional members register additively, appended to the canonical
// order". jti — the per-request uniqueness member a write-gating deployment
// requires — is the named one.
//
// TWO RULES MAKE THIS A BYTE-TWIN of the TS emitter. (1) Extra members are
// emitted AFTER every canonical member, so a verifier that ignores them still
// reconstructs the same prefix. (2) Among themselves they are emitted in
// LEXICOGRAPHIC ORDER OF MEMBER NAME — not insertion order, because Go map
// iteration is randomized and a TS signer and a Go signer must emit identical
// bytes from identical inputs.
//
// Values are strings. The registered member (jti) is a string, and restricting
// the type keeps the two encoders from disagreeing about number formatting.
type ProofExtraMembers map[string]string

// extraMemberNameRe restricts additive member names to a conservative ASCII set
// so lexicographic ordering is IDENTICAL in Go (bytes) and TS (UTF-16 units).
var extraMemberNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// canonicalMembers are the members an additive member may never shadow.
var canonicalMembers = map[string]struct{}{
	"method": {}, "host": {}, "path": {}, "bodyHash": {}, "credentialCID": {}, "iat": {},
}

type extraMember struct {
	name  string
	value string
}

// canonicalExtraMembers validates additive members and returns them in their
// canonical emission order: lexicographic by name, after every canonical member.
// A nil/empty map returns nil, so the bytes are unchanged from the five/six-member
// form when nothing additive is asked for.
func canonicalExtraMembers(extra ProofExtraMembers, label string) ([]extraMember, error) {
	if len(extra) == 0 {
		return nil, nil
	}
	out := make([]extraMember, 0, len(extra))
	for name, value := range extra {
		if !extraMemberNameRe.MatchString(name) {
			return nil, fmt.Errorf("invalid %s: additive member name %q is not [A-Za-z0-9_.-]+", label, name)
		}
		if _, clash := canonicalMembers[name]; clash {
			return nil, fmt.Errorf("invalid %s: %s is a canonical member and cannot be added", label, name)
		}
		if value == "" {
			return nil, fmt.Errorf("invalid %s: additive member %s must be a non-empty string", label, name)
		}
		if !utf8.ValidString(value) {
			return nil, fmt.Errorf("invalid %s: additive member %s must be well-formed Unicode", label, name)
		}
		out = append(out, extraMember{name: name, value: value})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// An HTTP method token per RFC 9110 tchar, with the lowercase letters removed:
// the member is normatively uppercase, and "get" MUST NOT verify against "GET".
var uppercaseMethodRe = regexp.MustCompile("^[A-Z0-9!#$%&'*+.^_`|~-]+$")

// 32 digest bytes are exactly 43 canonical unpadded base64url characters.
var base64url32Re = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// hasCtlOrSpace reports ASCII space, the C0 controls, or DEL — none of which can
// ride an origin-form request line, so a path carrying one was never a real
// request target.
func hasCtlOrSpace(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// validateProofPayload applies API-AUTH.md's step-3 schema — the SAME member
// rules for both artifacts, with credentialCID required iff the shape is
// credentialed.
func validateProofPayload(payload proofPayload, shape proofShape) error {
	fields := map[string]string{
		"method": payload.Method, "host": payload.Host, "path": payload.Path,
		"bodyHash": payload.BodyHash,
	}
	if shape.credentialed {
		fields["credentialCID"] = payload.CredentialCID
	}
	for field, value := range fields {
		if value == "" {
			return fmt.Errorf("invalid %s: %s must be a non-empty string", shape.label, field)
		}
		if !utf8.ValidString(value) {
			return fmt.Errorf("invalid %s: %s must be well-formed Unicode", shape.label, field)
		}
	}

	if !uppercaseMethodRe.MatchString(payload.Method) {
		return fmt.Errorf("invalid %s: method must be an uppercase HTTP method token", shape.label)
	}
	if payload.Host != strings.ToLower(payload.Host) || strings.ContainsAny(payload.Host, " \t\n\r\f\v/\\?#") {
		return fmt.Errorf("invalid %s: host must be a lowercase authority, without a scheme", shape.label)
	}

	// The wire string, not a normalization: no percent-decoding, no query
	// reordering, no trailing-slash equivalence.
	if !strings.HasPrefix(payload.Path, "/") {
		return fmt.Errorf("invalid %s: path must begin with /", shape.label)
	}
	if strings.Contains(payload.Path, "#") {
		return fmt.Errorf("invalid %s: path must not carry a fragment", shape.label)
	}
	if hasCtlOrSpace(payload.Path) {
		return fmt.Errorf("invalid %s: path must not contain whitespace or control characters", shape.label)
	}

	// bodyHash is compared as a STRING against the verifier's own re-encoding, so
	// a padded or otherwise non-canonical spelling of the right bytes is rejected
	// here, not normalized. Re-encoding the decoded bytes is the only check that
	// catches non-zero trailing bits.
	if !base64url32Re.MatchString(payload.BodyHash) {
		return fmt.Errorf("invalid %s: bodyHash must be the canonical unpadded base64url of 32 bytes", shape.label)
	}
	digest, err := base64.RawURLEncoding.DecodeString(payload.BodyHash)
	if err != nil || len(digest) != sha256.Size || base64.RawURLEncoding.EncodeToString(digest) != payload.BodyHash {
		return fmt.Errorf("invalid %s: bodyHash must be the canonical unpadded base64url of 32 bytes", shape.label)
	}

	if payload.Iat <= 0 {
		return fmt.Errorf("invalid %s: iat must be a positive integer", shape.label)
	}
	return nil
}

// proofSigningInput returns THE BYTE CONTRACT, in ONE place for both artifacts:
// the canonical bytes that ARE the JWS payload segment, in a fixed member order
// with no insignificant whitespace and iat as a bare JSON integer. The request
// proof's order is method, host, path, bodyHash, credentialCID, iat; the identity
// proof's is the same with credentialCID elided, so the two forms cannot drift
// apart on anything but that member.
func proofSigningInput(payload proofPayload, shape proofShape, extra []extraMember) ([]byte, error) {
	if err := validateProofPayload(payload, shape); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(`{"method":`)
	b.WriteString(jsonStringifyString(payload.Method))
	b.WriteString(`,"host":`)
	b.WriteString(jsonStringifyString(payload.Host))
	b.WriteString(`,"path":`)
	b.WriteString(jsonStringifyString(payload.Path))
	b.WriteString(`,"bodyHash":`)
	b.WriteString(jsonStringifyString(payload.BodyHash))
	if shape.credentialed {
		b.WriteString(`,"credentialCID":`)
		b.WriteString(jsonStringifyString(payload.CredentialCID))
	}
	b.WriteString(`,"iat":`)
	b.WriteString(strconv.FormatInt(payload.Iat, 10))
	// Additive members LAST, lexicographically — the canonical prefix above is
	// byte-identical whether or not any are present.
	for _, member := range extra {
		b.WriteByte(',')
		b.WriteString(jsonStringifyString(member.name))
		b.WriteByte(':')
		b.WriteString(jsonStringifyString(member.value))
	}
	b.WriteByte('}')
	return []byte(b.String()), nil
}

// ApiRequestSigningInput returns the request proof's canonical signing input —
// six members, method, host, path, bodyHash, credentialCID, iat. Byte-for-byte
// identical to the TS apiRequestSigningInput.
func ApiRequestSigningInput(payload RequestProofPayload, extra ProofExtraMembers) ([]byte, error) {
	members, err := canonicalExtraMembers(extra, requestProofShape.label)
	if err != nil {
		return nil, err
	}
	return proofSigningInput(payload.internal(), requestProofShape, members)
}

// ApiIdentitySigningInput returns the identity proof's canonical signing input —
// five members, method, host, path, bodyHash, iat: the request proof's bytes
// minus credentialCID, from the same encoder, under the same member rules.
// Byte-for-byte identical to the TS apiIdentitySigningInput.
func ApiIdentitySigningInput(payload IdentityProofPayload, extra ProofExtraMembers) ([]byte, error) {
	members, err := canonicalExtraMembers(extra, identityProofShape.label)
	if err != nil {
		return nil, err
	}
	return proofSigningInput(payload.internal(), identityProofShape, members)
}

// Sha256BodyHash returns the bodyHash member: canonical unpadded base64url of
// the SHA-256 of the APPLICATION body octets (post transfer- and
// content-decoding). Zero octets hash to EmptyBodySHA256.
func Sha256BodyHash(body []byte) string {
	digest := sha256.Sum256(body)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// RequestProofOptions carries optional build inputs.
type RequestProofOptions struct {
	// Body is the application body octets; nil or empty hashes to EmptyBodySHA256.
	Body []byte
	// Iat overrides the issued-at, unix seconds; zero means now.
	Iat int64
	// ExtraMembers are ADDITIVE members, appended after the canonical order in
	// lexicographic name order. {"jti": ...} is the registered one, and a
	// WRITE-SHAPED surface — relay ingestion, blob upload — REQUIRES it
	// (WEB-RELAY.md, Authentication).
	ExtraMembers ProofExtraMembers
}

// IdentityProofOptions is the same optional build inputs, under the name an
// identity-proof caller expects. One envelope family, one options shape.
type IdentityProofOptions = RequestProofOptions

// buildProof assembles and signs one proof of either shape.
//
// The JWS is assembled by hand rather than through CreateJWS because the payload
// segment MUST be exactly the shape's canonical signing input — encoding/json
// would sort nothing but would HTML-escape the path and marshal from a map in a
// shape this contract does not permit.
func buildProof(payload proofPayload, shape proofShape, kid string,
	privateKey ed25519.PrivateKey, extra ProofExtraMembers) (string, error) {
	if !strings.Contains(kid, "#") {
		return "", fmt.Errorf("invalid %s: kid must be a DID URL", shape.label)
	}
	members, err := canonicalExtraMembers(extra, shape.label)
	if err != nil {
		return "", err
	}
	signingInputBytes, err := proofSigningInput(payload, shape, members)
	if err != nil {
		return "", err
	}

	headerJSON, err := json.Marshal(JWSHeader{Alg: "EdDSA", Typ: shape.typ, Kid: kid})
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	signingInput := Base64urlEncode(headerJSON) + "." + Base64urlEncode(signingInputBytes)
	token := signingInput + "." + Base64urlEncode(ed25519.Sign(privateKey, []byte(signingInput)))
	if len(token) > MaxRequestProofSize {
		return "", fmt.Errorf("%s exceeds max size: %d > %d", shape.label, len(token), MaxRequestProofSize)
	}
	return token, nil
}

func proofIat(iat int64) int64 {
	if iat == 0 {
		return time.Now().UTC().Unix()
	}
	return iat
}

// BuildRequestProof signs one request. The producer half of the byte contract.
//
// kid MUST be a DID URL whose DID portion is the leaf credential's aud; that
// equality IS the possession being proven.
func BuildRequestProof(method, host, path, credentialCID, kid string,
	privateKey ed25519.PrivateKey, opts RequestProofOptions) (string, error) {
	return buildProof(proofPayload{
		Method: method, Host: host, Path: path,
		BodyHash: Sha256BodyHash(opts.Body), CredentialCID: credentialCID, Iat: proofIat(opts.Iat),
	}, requestProofShape, kid, privateKey, opts.ExtraMembers)
}

// BuildIdentityProof signs one request as a BARE IDENTITY — BuildRequestProof
// minus the credential material, and a payload minus credentialCID.
//
// kid MUST be a DID URL, and its DID portion IS THE PRINCIPAL: the identity
// proof names no other party, and nothing is looked up from it. What that DID
// may do is the resource's local policy, about which this envelope says nothing.
func BuildIdentityProof(method, host, path, kid string,
	privateKey ed25519.PrivateKey, opts IdentityProofOptions) (string, error) {
	return buildProof(proofPayload{
		Method: method, Host: host, Path: path,
		BodyHash: Sha256BodyHash(opts.Body), Iat: proofIat(opts.Iat),
	}, identityProofShape, kid, privateKey, opts.ExtraMembers)
}

// RequestProofExpectations is what the VERIFIER holds about the request it is
// serving. Every value here comes from the deployment's own configuration and
// the request it actually received — never from a Host / X-Forwarded-Host header
// or the request URL's authority, which are attacker-supplied. A verifier that
// compared the proof's host against a request header would have no host binding
// at all.
type RequestProofExpectations struct {
	// Method is the received request's method.
	Method string
	// Host is THE VERIFIER'S OWN CONFIGURED AUTHORITY for the route being served,
	// port included when it is not 443.
	Host string
	// Path is the received origin-form request target, byte for byte.
	Path string
	// Body is the received application body octets, post-content-decoding.
	Body []byte
	// WindowSeconds is the acceptance window W. A nil pointer means "unset" and
	// takes DefaultProofWindowSeconds; a non-nil *0 is honored (the tightest
	// window, age must be <= 0). Pointer rather than a bare int64 so an explicit
	// zero is distinguishable from omission — matching the TS verifier's
	// `windowSeconds?: number`, where undefined defaults and 0 is honored. A bare
	// int64 would silently rewrite a requested W=0 to 60.
	WindowSeconds *int64
	// SkewSeconds is the clock-skew allowance S; same nil-vs-*0 semantics as W.
	SkewSeconds *int64
	// MaxBodyBytes caps the decoded body this verifier will hash; nil means
	// MaxBodyBytesDefault, a non-nil *0 means "no body permitted". An over-cap
	// body is refused before the SHA-256.
	MaxBodyBytes *int64
}

// IdentityProofExpectations is the same verifier-held state, under the name an
// identity-proof route expects. The bindings are identical — the identity proof
// binds the same method, host, path, and body — so there is one shape, not two.
type IdentityProofExpectations = RequestProofExpectations

func (e RequestProofExpectations) maxBodyBytes() (int64, error) {
	if e.MaxBodyBytes == nil {
		return MaxBodyBytesDefault, nil
	}
	if *e.MaxBodyBytes < 0 {
		return 0, fmt.Errorf("%w: MaxBodyBytes must be non-negative", ErrRequestProofConfig)
	}
	return *e.MaxBodyBytes, nil
}

// Int64Ptr returns a pointer to v, for setting WindowSeconds / SkewSeconds to an
// explicit value (including an explicit 0).
func Int64Ptr(v int64) *int64 { return &v }

func (e RequestProofExpectations) bounds() (window, skew int64, err error) {
	window, skew = DefaultProofWindowSeconds, DefaultProofSkewSeconds
	if e.WindowSeconds != nil {
		window = *e.WindowSeconds
	}
	if e.SkewSeconds != nil {
		skew = *e.SkewSeconds
	}
	if window < 0 || skew < 0 {
		return 0, 0, fmt.Errorf("%w: WindowSeconds and SkewSeconds must be non-negative", ErrRequestProofConfig)
	}
	// Cap each bound before summing: neither alone may exceed the total ceiling,
	// and checking first means window+skew (each <= 300) cannot overflow int64 —
	// a bare `window+skew > cap` on two near-max int64 values wraps negative and
	// slips past the ceiling.
	if window > MaxProofFreshnessSpanSeconds || skew > MaxProofFreshnessSpanSeconds {
		return 0, 0, fmt.Errorf("%w: WindowSeconds and SkewSeconds must each be <= %d seconds",
			ErrRequestProofConfig, MaxProofFreshnessSpanSeconds)
	}
	if window+skew > MaxProofFreshnessSpanSeconds {
		return 0, 0, fmt.Errorf("%w: proof freshness span W + S exceeds %d seconds: %d + %d",
			ErrRequestProofConfig, MaxProofFreshnessSpanSeconds, window, skew)
	}
	return window, skew, nil
}

// verifyProofEnvelope is THE PROOF PHASE — API-AUTH.md steps 1–7, shared
// verbatim by both artifacts: size, header gates with THIS shape's typ, payload
// schema, freshness, request binding, current-state key resolution, signature.
//
// One implementation, so a check tightened for one artifact is tightened for
// both — and so the typ gate is provably the only place they diverge.
//
// resolveKey MUST perform CURRENT-STATE-ONLY resolution: rotated-out keys and
// deleted identities fail resolution. Rotation is how a presenter whose key is
// compromised stops that key minting proofs in its name, so a resolver answering
// from historical state would remove the only lever there is. A resolver failure
// maps to ErrRequestProofUnverifiable unless it wraps ErrProofPresenterInvalid,
// which is how a resolver says: I checked, and the answer is no.
// verifiedEnvelope is what a verified proof phase hands back: the validated
// canonical members, the DECODED payload (unknown members included), and the
// AUTHENTICATED PRINCIPAL.
//
// The principal is returned rather than discarded because it is the whole point
// of the identity proof — "the signer IS the principal" — and a consumer that
// had to re-decode the token to learn who signed would be re-deriving, outside
// the verifier, a fact the verifier already proved.
type verifiedEnvelope struct {
	payload      proofPayload
	rawPayload   map[string]any
	presenterDID string
	kid          string
}

func verifyProofEnvelope(proofToken string, expect RequestProofExpectations, shape proofShape,
	resolveKey KeyResolver, now time.Time) (result *verifiedEnvelope, err error) {
	// An unexpected panic is inability to complete verification, never evidence
	// that the proof itself is malformed.
	defer func() {
		if recovered := recover(); recovered != nil {
			result = nil
			err = fmt.Errorf("%w: verification could not complete: %v", ErrRequestProofUnverifiable, recovered)
		}
	}()

	// 4 (config half). Checked FIRST: a deployment whose window is out of bounds
	// must never verify anything, not merely fail some proofs.
	window, skew, err := expect.bounds()
	if err != nil {
		return nil, err
	}
	maxBody, err := expect.maxBodyBytes()
	if err != nil {
		return nil, err
	}

	// 1. Size — before any decode.
	if len(proofToken) > MaxRequestProofSize {
		return nil, fmt.Errorf("%w: %s exceeds max size: %d > %d",
			ErrRequestProofInvalid, shape.label, len(proofToken), MaxRequestProofSize)
	}

	// 2. Decode and profile gates, applied to the raw header bytes.
	parts := strings.Split(proofToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: failed to decode %s JWS", ErrRequestProofInvalid, shape.label)
	}
	headerBytes, decodeErr := Base64urlDecode(parts[0])
	if decodeErr != nil {
		return nil, fmt.Errorf("%w: failed to decode %s JWS", ErrRequestProofInvalid, shape.label)
	}
	if profileErr := assertJWSProfile(headerBytes); profileErr != nil {
		return nil, fmt.Errorf("%w: %s", ErrRequestProofInvalid, profileErr)
	}
	var header JWSHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: failed to decode %s JWS", ErrRequestProofInvalid, shape.label)
	}
	// THE TYP GATE, ABSOLUTE IN BOTH DIRECTIONS. A request proof presented where an
	// identity proof is required dies here, and so does the reverse: "possession of
	// a grant's audience key" and "possession of a bare identity's key" are
	// different claims, and one must never be spendable as the other.
	if header.Typ != shape.typ {
		return nil, fmt.Errorf("%w: invalid %s typ: %s", ErrRequestProofInvalid, shape.label, header.Typ)
	}
	if !strings.Contains(header.Kid, "#") {
		return nil, fmt.Errorf("%w: %s kid must be a DID URL", ErrRequestProofInvalid, shape.label)
	}

	// 3. Payload schema, from the ORIGINAL payload octets — but NOT
	// re-canonicalized: the presenter self-signs and the signature covers the
	// received bytes, so there is no third-party byte substitution to defend
	// against. The canonical rule binds PRODUCERS. Unknown members are ignored.
	payloadBytes, decodeErr := Base64urlDecode(parts[1])
	if decodeErr != nil {
		return nil, fmt.Errorf("%w: failed to decode %s payload", ErrRequestProofInvalid, shape.label)
	}
	// MALFORMED UTF-8 IS AN INVALID PROOF, NOT A LENIENT DECODE. encoding/json
	// silently substitutes U+FFFD for an invalid byte, where the TS twin decodes
	// with TextDecoder('utf-8', {fatal:true}) and throws. Without this gate a
	// hand-signed proof carrying a malformed byte in an unknown member (jti is the
	// live case) authenticates here and 401s there — the same octets, two verdicts.
	// Only the payload is gated: the TS twin's HEADER decode is non-fatal, and the
	// twins must agree on leniency as exactly as they agree on strictness.
	if !utf8.Valid(payloadBytes) {
		return nil, fmt.Errorf("%w: %s payload is not valid UTF-8", ErrRequestProofInvalid, shape.label)
	}
	// The DECODED payload, unknown members included. ADDITIVE MEMBERS ARE READ
	// FROM HERE, at the consuming layer, AFTER verification — the signature
	// already covers them and the canonical member set stays closed. jti is the
	// case this exists for.
	var rawPayload map[string]any
	if err := json.Unmarshal(payloadBytes, &rawPayload); err != nil {
		return nil, fmt.Errorf("%w: %s payload is not valid JSON", ErrRequestProofInvalid, shape.label)
	}
	var raw struct {
		Method        *string          `json:"method"`
		Host          *string          `json:"host"`
		Path          *string          `json:"path"`
		BodyHash      *string          `json:"bodyHash"`
		CredentialCID *string          `json:"credentialCID"`
		Iat           *json.RawMessage `json:"iat"`
	}
	if err := json.Unmarshal(payloadBytes, &raw); err != nil {
		return nil, fmt.Errorf("%w: %s payload is not valid JSON", ErrRequestProofInvalid, shape.label)
	}
	if raw.Method == nil || raw.Host == nil || raw.Path == nil ||
		raw.BodyHash == nil || raw.Iat == nil ||
		(shape.credentialed && raw.CredentialCID == nil) {
		return nil, fmt.Errorf("%w: %s payload is missing a required member", ErrRequestProofInvalid, shape.label)
	}
	// A bare JSON integer: no fraction, no exponent, no quotes.
	iat, iatErr := strconv.ParseInt(strings.TrimSpace(string(*raw.Iat)), 10, 64)
	if iatErr != nil {
		return nil, fmt.Errorf("%w: invalid %s: iat must be a positive integer", ErrRequestProofInvalid, shape.label)
	}
	payload := proofPayload{
		Method: *raw.Method, Host: *raw.Host, Path: *raw.Path,
		BodyHash: *raw.BodyHash, Iat: iat,
	}
	// A credentialCID on an IDENTITY proof is an unknown member, and the protocol's
	// MUST-ignore-unknown rule says ignore it: the typ gate above, not member
	// sniffing, is what tells the two artifacts apart.
	if shape.credentialed {
		payload.CredentialCID = *raw.CredentialCID
	}
	if schemaErr := validateProofPayload(payload, shape); schemaErr != nil {
		return nil, fmt.Errorf("%w: %s", ErrRequestProofInvalid, schemaErr)
	}

	// 4. Freshness — integer Unix seconds on both sides, so the boundary does not
	// turn on sub-second precision. AGE and FORWARD SKEW are separate bounds: a
	// symmetric |now - iat| <= W would make a fully forward-dated proof replayable
	// for 2W, which is exactly what the W + S ceiling above prices.
	nowUnix := now.UTC().Unix()
	if nowUnix-payload.Iat > window {
		return nil, fmt.Errorf("%w: %s is stale", ErrRequestProofInvalid, shape.label)
	}
	if payload.Iat-nowUnix > skew {
		return nil, fmt.Errorf("%w: %s iat is beyond the clock-skew allowance", ErrRequestProofInvalid, shape.label)
	}

	// 5. Request binding — the non-body half first, then the bounded hash.
	if payload.Method != expect.Method {
		return nil, fmt.Errorf("%w: %s method mismatch", ErrRequestProofInvalid, shape.label)
	}
	if payload.Host != expect.Host {
		return nil, fmt.Errorf("%w: %s host mismatch", ErrRequestProofInvalid, shape.label)
	}
	if payload.Path != expect.Path {
		return nil, fmt.Errorf("%w: %s path mismatch", ErrRequestProofInvalid, shape.label)
	}
	// Body hash last, and only up to the cap: an over-cap body is refused before
	// the SHA-256, so a bad-signature proof cannot force an unbounded hash. (As in
	// TS, this is the defensive cap on an already-buffered body; aborting decode at
	// the cap is the middleware's job upstream — a decompression bomb inflates
	// before the twin sees it.)
	if int64(len(expect.Body)) > maxBody {
		return nil, fmt.Errorf("%w: request body exceeds max size: %d > %d",
			ErrRequestProofInvalid, len(expect.Body), maxBody)
	}
	if payload.BodyHash != Sha256BodyHash(expect.Body) {
		return nil, fmt.Errorf("%w: %s bodyHash mismatch", ErrRequestProofInvalid, shape.label)
	}

	// 6–7. Current-state key resolution, then signature. For the request proof a
	// valid signature is the gate to the credential work the TS twin performs;
	// nothing unbounded or network-touching may run before it. For the identity
	// proof there is nothing after it — this IS the whole algorithm.
	publicKey, resolveErr := resolveKey(header.Kid)
	if resolveErr != nil {
		// A resolver that already CHECKED and rejected keeps its verdict; anything
		// else is a resolution failure, which is the server's condition.
		if errors.Is(resolveErr, ErrProofPresenterInvalid) {
			return nil, fmt.Errorf("%w: %s", ErrRequestProofInvalid, resolveErr)
		}
		return nil, fmt.Errorf("%w: failed to resolve current %s key: %s",
			ErrRequestProofUnverifiable, shape.label, resolveErr)
	}
	if _, _, verifyErr := VerifyJWS(proofToken, publicKey); verifyErr != nil {
		return nil, fmt.Errorf("%w: invalid %s signature", ErrRequestProofInvalid, shape.label)
	}

	return &verifiedEnvelope{
		payload:      payload,
		rawPayload:   rawPayload,
		presenterDID: header.Kid[:strings.Index(header.Kid, "#")],
		kid:          header.Kid,
	}, nil
}

// VerifiedRequestProof is a verified request proof: its canonical members, the
// decoded payload (unknown members included), and the AUTHENTICATED PRESENTER.
type VerifiedRequestProof struct {
	Payload RequestProofPayload
	// RawPayload is the decoded payload object, unknown members included — where
	// a consumer reads an ADDITIVE member (jti) the envelope verifier ignored.
	RawPayload map[string]any
	// PresenterDID is the kid's DID portion.
	PresenterDID string
	// Kid is the full DID URL that signed, key fragment included.
	Kid string
}

// VerifiedIdentityProof is a verified identity proof. PresenterDID is THE
// PRINCIPAL — the identity proof's entire point — so it is returned here rather
// than left for the consumer to re-decode out of the token.
type VerifiedIdentityProof struct {
	Payload IdentityProofPayload
	// RawPayload is the decoded payload object, unknown members included — where
	// a consumer reads an ADDITIVE member (jti) the envelope verifier ignored.
	RawPayload map[string]any
	// PresenterDID is the kid's DID portion: WHO the request is from. What that
	// DID may do is the resource's local policy.
	PresenterDID string
	// Kid is the full DID URL that signed, key fragment included.
	Kid string
}

// VerifyRequestProof verifies the request proof's ENVELOPE in API-AUTH.md's
// steps 1–7 order: size, header gates, payload schema, freshness, request
// binding, current-state key resolution, signature. It deliberately stops there
// — see the scope NOTE at the top of this file.
//
// A proof carrying any other typ — an identity proof included — is rejected at
// the header gate.
func VerifyRequestProof(proofToken string, expect RequestProofExpectations,
	resolveKey KeyResolver, now time.Time) (*VerifiedRequestProof, error) {
	env, err := verifyProofEnvelope(proofToken, expect, requestProofShape, resolveKey, now)
	if err != nil {
		return nil, err
	}
	return &VerifiedRequestProof{
		Payload: RequestProofPayload{
			Method: env.payload.Method, Host: env.payload.Host, Path: env.payload.Path,
			BodyHash: env.payload.BodyHash, CredentialCID: env.payload.CredentialCID, Iat: env.payload.Iat,
		},
		RawPayload:   env.rawPayload,
		PresenterDID: env.presenterDID,
		Kid:          env.kid,
	}, nil
}

// VerifyIdentityProof verifies an identity proof — API-AUTH.md's PROOF PHASE
// with the identity typ, and nothing more. Steps 8–11 do not exist for this
// artifact: there is no credential to walk, so there is no chain, no revocation
// lookup, and no attenuation coverage. Unlike the request proof, this is not a
// partial implementation of a longer algorithm — it is the whole one.
//
// THE SIGNER IS THE PRINCIPAL. The kid's DID is who the request is from; what
// that DID may do is the resource's local policy (quotas, reputation,
// self-access rules, admission tiers), about which this envelope says nothing.
// Authentication travels on the wire; authorization stays home.
//
// Verdicts are two, not three: invalid (401) and unverifiable (503), plus the
// config verdict (500) for a deployment whose W + S is out of bounds. There is
// no 403 tier — nothing credential-shaped can fail.
//
// A request proof presented here is rejected at the header gate, and an identity
// proof presented to VerifyRequestProof is rejected at the same gate.
//
// The header-layer rule this function cannot see: a request carrying
// X-Credential alongside an identity proof is MALFORMED (401) — the headers
// assert two different claims at once and a verifier MUST NOT pick one. That
// refusal belongs to the middleware, which is the only layer holding the header
// bag.
func VerifyIdentityProof(proofToken string, expect IdentityProofExpectations,
	resolveKey KeyResolver, now time.Time) (*VerifiedIdentityProof, error) {
	env, err := verifyProofEnvelope(proofToken, expect, identityProofShape, resolveKey, now)
	if err != nil {
		return nil, err
	}
	return &VerifiedIdentityProof{
		Payload: IdentityProofPayload{
			Method: env.payload.Method, Host: env.payload.Host, Path: env.payload.Path,
			BodyHash: env.payload.BodyHash, Iat: env.payload.Iat,
		},
		RawPayload:   env.rawPayload,
		PresenterDID: env.presenterDID,
		Kid:          env.kid,
	}, nil
}

// ParseDFOSAuthorization parses an "Authorization: DFOS <token>" header and
// returns the bare token.
//
// The scheme is matched CASE-INSENSITIVELY per RFC 9110 s11.1 (DFOS, dfos, Dfos
// are one scheme), separated from the token by one or more spaces, with
// surrounding optional whitespace ignored. The token itself is case-sensitive
// and is not further decoded here. Returns "" for an absent, differently
// schemed, or empty-token header — a Bearer header is NOT this family and never
// was.
func ParseDFOSAuthorization(header string) string {
	trimmed := strings.TrimSpace(header)
	space := strings.IndexAny(trimmed, " \t")
	if space < 0 {
		return ""
	}
	if !strings.EqualFold(trimmed[:space], "DFOS") {
		return ""
	}
	token := strings.TrimSpace(trimmed[space:])
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return ""
	}
	return token
}
