package dfos

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"
)

// CREDIT CLAIM — the Go twin of dfos-protocol/src/chain/credit-claim.ts.
//
// A claimant's standalone signed assertion that it holds a named role on a
// content chain. Attribution, not authorization: a credit claim grants nothing.
// It is a DOCUMENT-PLANE artifact — not gossiped, and relays are not
// credit-claim aware; a claim travels inside the document bytes that embed it.
// See specs/CREDITS.md for the two-way bind and the four verification states.
//
// This file MUST stay in sync with the TS twin. The payload fields, the
// validation ORDER, and the error strings are aligned deliberately: a claim that
// verifies on one implementation must verify on the other, byte for byte.
//
// Shape divergences from the TS twin, each following existing house convention
// rather than the TS signature:
//
//  1. Key resolution takes a KeyResolver (kid → public key), as every other Go
//     verify does (VerifyRevocation, VerifyArtifact, VerifyCountersignature).
//     The TS twin takes a resolveIdentity callback because its credential layer
//     already had one. Two consequences. First, the deleted-claimant doctrine (a
//     tombstoned claimant's claim STILL verifies) is structurally vacuous here —
//     this path has no isDeleted concept to consult. The doctrine is pinned by a
//     TS test; do NOT add an identity-deletion gate to this file to "match"
//     credentials. Second, a KeyResolver cannot distinguish "identity
//     unresolvable" (unverifiable) from "key absent from a resolved identity"
//     (invalid), so every resolver failure maps to ErrCreditClaimUnverifiable —
//     the honest verdict when the cause is unknown. A caller needing that
//     distinction resolves the identity itself first.
//  2. The optional expectedContentId binder is a separate Bound entry point
//     rather than an options struct, following the SignCountersign /
//     SignCountersignWithRelation precedent.
//
// KEY HISTORY IS THE RESOLVER'S CONTRACT. A claim is a permanent historical
// attribution, so the KeyResolver passed here MUST resolve every key the
// claimant's identity chain has ever held, not only its current head state — the
// same requirement the credential path already carries. A current-state-only
// resolver reports invalid for every claim signed before the claimant's most
// recent key rotation, silently un-crediting real work.

// maxCreditClaimSize bounds the byte length of a credit-claim JWS token — the
// claim's aggregate size bound, checked before any decode as a DoS guard and
// again on the sign path. Deliberately tight because claims travel INSIDE
// document bytes: a document embedding many credits carries one token per claimed
// entry. The payload's open-namespace role field therefore carries no separate
// length cap; this aggregate is the single byte arbiter. VALIDITY-determining:
// MUST match the TS reference (MAX_CREDIT_CLAIM_SIZE in chain/schemas.ts).
const maxCreditClaimSize = 4096

// Sentinel errors for the two consumer-visible verdicts the spec requires be kept
// apart. Every error from the verify path wraps exactly one of them, so consumers
// branch with errors.Is and NEVER by matching message text.
//
//   - ErrCreditClaimInvalid      — checked and failed (schema, signature, CID,
//     bind). A positive signal that something is wrong.
//   - ErrCreditClaimUnverifiable — could not check (the claimant key/identity did
//     not resolve). The claim may be perfectly valid.
//
// Collapsing these two, or rendering either as "unclaimed", is the one thing
// specs/CREDITS.md says a consumer MUST NOT do.
var (
	ErrCreditClaimInvalid      = errors.New("credit claim invalid")
	ErrCreditClaimUnverifiable = errors.New("credit claim unverifiable")
)

// CreditClaimOptions carries the optional inputs to credit-claim signing.
type CreditClaimOptions struct {
	// AsOfDocumentCID pins the document state the claimant credits itself on. A
	// nil pointer OMITS the field entirely (the default, and CID-neutral). A
	// non-nil pointer to an empty string is an ERROR, not an omission: an
	// empty-string flavor is a different signed encoding from an absent one, so
	// accepting it would mint two claim CIDs for the same statement.
	AsOfDocumentCID *string
	// CreatedAt overrides the signing timestamp so a previously issued claim's
	// exact bytes can be re-derived. The zero value means "now".
	//
	// TRUNCATED to whole seconds either way — a sub-second component passed here is
	// DISCARDED, not signed. createdAt lives inside the signed payload and is
	// therefore part of the claim's CID, so an override whose milliseconds survived
	// on one implementation but not the other would fork claim identity over a field
	// nothing reads for ordering. The TS twin normalizes overrides identically
	// (normalizeClaimCreatedAt); a shared parity vector pins the two together.
	CreatedAt time.Time
}

// SignCreditClaim signs a credit claim binding a claimant DID to a named role on
// a content chain.
//
// The claim binds to the chain's stable contentID, never to a document — so a
// signed claim stays valid verbatim across every subsequent edit. Callers SHOULD
// sign a given (contentID, did, role) triple once and reuse the token: re-signing
// mints a fresh createdAt, which changes the claim bytes, which changes the
// embedding document's CID.
//
// The kid is DERIVED from did + keyID rather than accepted from the caller, so a
// claim whose kid DID disagrees with its payload DID — the shape every verifier
// MUST reject — is unrepresentable at sign time. Matches the TS twin.
func SignCreditClaim(did, contentID, role, keyID string, privateKey ed25519.PrivateKey) (jwsToken string, claimCID string, err error) {
	return SignCreditClaimWithOptions(did, contentID, role, keyID, privateKey, CreditClaimOptions{})
}

// SignCreditClaimWithAsOf is SignCreditClaim plus the optional content-strength
// flavor. An empty asOfDocumentCID is an ERROR here, not an omission — callers
// meaning "no flavor" call SignCreditClaim.
func SignCreditClaimWithAsOf(did, contentID, role, asOfDocumentCID, keyID string, privateKey ed25519.PrivateKey) (jwsToken string, claimCID string, err error) {
	return SignCreditClaimWithOptions(did, contentID, role, keyID, privateKey, CreditClaimOptions{AsOfDocumentCID: &asOfDocumentCID})
}

// SignCreditClaimWithOptions is SignCreditClaim with the full optional input set.
func SignCreditClaimWithOptions(did, contentID, role, keyID string, privateKey ed25519.PrivateKey, opts CreditClaimOptions) (jwsToken string, claimCID string, err error) {
	// validate before signing — a malformed payload must never reach the wire
	if !strings.HasPrefix(did, "did:") {
		return "", "", fmt.Errorf("invalid credit claim payload: did must be a DID (did: prefix)")
	}
	if !contentIDAnchorRe.MatchString(contentID) {
		return "", "", fmt.Errorf("invalid credit claim payload: contentId must be a 31-char content chain id")
	}
	if role == "" {
		return "", "", fmt.Errorf("invalid credit claim payload: missing role")
	}
	if opts.AsOfDocumentCID != nil && *opts.AsOfDocumentCID == "" {
		return "", "", fmt.Errorf("invalid credit claim payload: asOfDocumentCID must be non-empty when present (omit the field instead)")
	}

	// millisecond component zeroed, per the signRevocation convention the TS twin
	// follows. protocolTimestamp's sub-second monotonicity is not needed here: a
	// claim orders nothing and gates nothing.
	now := opts.CreatedAt
	if now.IsZero() {
		now = protocolTimestamp()
	}
	createdAt := now.UTC().Truncate(time.Second).Format(protocolTimeFormat)

	payload := map[string]any{
		"version":   1,
		"type":      "credit-claim",
		"contentId": contentID,
		"did":       did,
		"role":      role,
		"createdAt": createdAt,
	}
	if opts.AsOfDocumentCID != nil {
		payload["asOfDocumentCID"] = *opts.AsOfDocumentCID
	}

	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		return "", "", err
	}

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:credit-claim",
		Kid: did + "#" + keyID,
		CID: cidStr,
	}

	jwsToken, err = CreateJWS(header, payload, privateKey)
	if err != nil {
		return "", "", err
	}

	// enforce the aggregate cap on the SIGN path too. A signer that mints a token
	// over the cap has produced a claim every verifier — including this one — MUST
	// reject, so failing here beats embedding dead bytes in a document.
	if len(jwsToken) > maxCreditClaimSize {
		return "", "", fmt.Errorf("credit claim exceeds max size: %d > %d", len(jwsToken), maxCreditClaimSize)
	}

	return jwsToken, cidStr, nil
}

// VerifiedCreditClaimResult is the result of credit-claim verification.
type VerifiedCreditClaimResult struct {
	// The claimant DID that signed this claim
	DID string
	// The content chain this claim binds to — the 31-char contentId
	ContentID string
	// The claimed role, compared by exact byte equality
	Role string
	// Timestamp of the claim
	CreatedAt string
	// Optional pinned document state the claimant credited itself on ("" if absent)
	AsOfDocumentCID string
	// kid from the JWS header
	SignerKeyId string
	// CID of the claim artifact itself
	ClaimCID string
}

// VerifyCreditClaim verifies a credit claim JWS — size, typ, payload schema,
// signer match, signature, CID integrity.
//
// It does NOT enforce the contentId binder. Prefer VerifyCreditEntry, which
// resolves a whole credits entry and performs the full three-component bind;
// failing that, VerifyCreditClaimBound. Without the binder a valid claim lifted
// from one chain's document verifies when replayed into another's.
//
// Errors wrap ErrCreditClaimInvalid or ErrCreditClaimUnverifiable — branch with
// errors.Is, never on message text.
func VerifyCreditClaim(jwsToken string, resolveKey KeyResolver) (*VerifiedCreditClaimResult, error) {
	return verifyCreditClaimCore(jwsToken, resolveKey, "")
}

// VerifyCreditClaimBound is VerifyCreditClaim plus the anti-replay half of the
// bind: the claim's contentId MUST equal expectedContentID.
//
// An EMPTY expectedContentID is an error, never a skip. The empty string is a
// zero value — an unhydrated struct field, a failed parse — and treating it as
// "no binder wanted" is exactly how a caller that asked for bound semantics
// silently gets unbound ones, reopening the cross-chain replay the binder exists
// to close. Callers wanting the unbound form call VerifyCreditClaim by name.
//
// The remaining two components of the bind — did and role — are compared by the
// caller against the credits entry plaintext, or by VerifyCreditEntry.
func VerifyCreditClaimBound(jwsToken string, resolveKey KeyResolver, expectedContentID string) (*VerifiedCreditClaimResult, error) {
	if expectedContentID == "" {
		// Wrapped as Invalid so a consumer mapping errors onto a verdict fails
		// CLOSED. It is really a caller bug, and deliberately NOT Unverifiable: a
		// programming error must never be laundered into "we just couldn't check".
		return nil, fmt.Errorf("%w: VerifyCreditClaimBound requires a non-empty expectedContentID (call VerifyCreditClaim for the unbound form)", ErrCreditClaimInvalid)
	}
	return verifyCreditClaimCore(jwsToken, resolveKey, expectedContentID)
}

func verifyCreditClaimCore(jwsToken string, resolveKey KeyResolver, expectedContentID string) (*VerifiedCreditClaimResult, error) {
	// bound claim size before any decode
	if len(jwsToken) > maxCreditClaimSize {
		return nil, fmt.Errorf("%w: credit claim exceeds max size: %d > %d", ErrCreditClaimInvalid, len(jwsToken), maxCreditClaimSize)
	}

	// DecodeJWSUnsafe unmarshals the protected header into a typed struct, so a
	// non-string typ/kid fails HERE (invalid) and a missing kid arrives as "" and is
	// caught by the DID-URL check below (also invalid). Keep it that way: decoding
	// the header into a map[string]any instead would let a malformed header reach
	// the field reads and surface as an untyped fault, which the entry-level
	// classifier would then report as unverifiable rather than invalid. The TS twin
	// has to validate the header shape explicitly for exactly this reason.
	header, payload, err := DecodeJWSUnsafe(jwsToken)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode credit claim JWS", ErrCreditClaimInvalid)
	}

	// verify typ
	if header.Typ != "did:dfos:credit-claim" {
		return nil, fmt.Errorf("%w: invalid credit claim typ: %s", ErrCreditClaimInvalid, header.Typ)
	}

	// validate payload
	version, _ := payload["version"].(int64)
	if version != 1 {
		return nil, fmt.Errorf("%w: invalid credit claim payload: invalid or missing version", ErrCreditClaimInvalid)
	}
	if payloadString(payload, "type") != "credit-claim" {
		return nil, fmt.Errorf("%w: invalid credit claim payload: wrong type", ErrCreditClaimInvalid)
	}
	contentID := payloadString(payload, "contentId")
	if !contentIDAnchorRe.MatchString(contentID) {
		return nil, fmt.Errorf("%w: invalid credit claim payload: contentId must be a 31-char content chain id", ErrCreditClaimInvalid)
	}
	did := payloadString(payload, "did")
	if !strings.HasPrefix(did, "did:") {
		return nil, fmt.Errorf("%w: invalid credit claim payload: did must be a DID (did: prefix)", ErrCreditClaimInvalid)
	}
	role := payloadString(payload, "role")
	if role == "" {
		return nil, fmt.Errorf("%w: invalid credit claim payload: missing role", ErrCreditClaimInvalid)
	}
	createdAt := payloadString(payload, "createdAt")
	if err := validateCreatedAt(createdAt); err != nil {
		return nil, fmt.Errorf("%w: invalid credit claim payload: %s", ErrCreditClaimInvalid, err)
	}
	// asOfDocumentCID is optional, but when the KEY IS PRESENT it must be a
	// non-empty string. Reading it through payloadString alone would coerce null,
	// a number, or "" to "" and accept the claim — bytes the TS twin rejects
	// outright, which is a cross-implementation verdict fork on exactly the claim
	// a nullable-optional producer emits (JS `?? null`, a nil *string, Python None).
	asOfDocumentCID := ""
	if raw, present := payload["asOfDocumentCID"]; present {
		s, ok := raw.(string)
		if !ok || s == "" {
			return nil, fmt.Errorf("%w: invalid credit claim payload: asOfDocumentCID must be a non-empty string when present", ErrCreditClaimInvalid)
		}
		asOfDocumentCID = s
	}

	// verify kid DID matches payload did (only the claimant can claim its credit)
	kid := header.Kid
	hashIdx := strings.Index(kid, "#")
	if hashIdx < 0 {
		return nil, fmt.Errorf("%w: credit claim kid must be a DID URL", ErrCreditClaimInvalid)
	}
	kidDid := kid[:hashIdx]
	if kidDid != did {
		return nil, fmt.Errorf("%w: credit claim kid DID does not match payload did", ErrCreditClaimInvalid)
	}

	// verify signature. A resolver failure is "could not check" — see the
	// KeyResolver note at the top of this file for why it cannot be narrowed.
	publicKey, err := resolveKey(kid)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to resolve credit claim key: %s", ErrCreditClaimUnverifiable, err)
	}
	if _, _, err := VerifyJWS(jwsToken, publicKey); err != nil {
		return nil, fmt.Errorf("%w: invalid credit claim signature", ErrCreditClaimInvalid)
	}

	// verify CID
	_, _, claimCID, err := DagCborCID(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to derive credit claim CID: %s", ErrCreditClaimInvalid, err)
	}
	if header.CID == "" {
		return nil, fmt.Errorf("%w: missing cid in credit claim header", ErrCreditClaimInvalid)
	}
	if header.CID != claimCID {
		return nil, fmt.Errorf("%w: credit claim cid mismatch", ErrCreditClaimInvalid)
	}

	// enforce the binder — a claim is only about the chain it names
	if expectedContentID != "" && contentID != expectedContentID {
		return nil, fmt.Errorf("%w: credit claim contentId %s does not match expected %s", ErrCreditClaimInvalid, contentID, expectedContentID)
	}

	return &VerifiedCreditClaimResult{
		DID:             did,
		ContentID:       contentID,
		Role:            role,
		CreatedAt:       createdAt,
		AsOfDocumentCID: asOfDocumentCID,
		SignerKeyId:     kid,
		ClaimCID:        claimCID,
	}, nil
}

// -----------------------------------------------------------------------------
// entry verification (the full bind)
// -----------------------------------------------------------------------------

// CreditEntryState is one of the four states a credits[] entry resolves to.
//
// CreditEntryInvalid and CreditEntryUnverifiable are deliberately distinct and
// MUST NOT be collapsed: invalid means "checked and failed", unverifiable means
// "could not check". Rendering either as unclaimed launders a failure into the
// ordinary case.
type CreditEntryState string

const (
	CreditEntryClaimed      CreditEntryState = "claimed"
	CreditEntryUnclaimed    CreditEntryState = "unclaimed"
	CreditEntryInvalid      CreditEntryState = "invalid"
	CreditEntryUnverifiable CreditEntryState = "unverifiable"
)

// VerifiedCreditEntry is the resolved state of one credits[] entry.
type VerifiedCreditEntry struct {
	State CreditEntryState
	// Note is human-readable diagnosis — display prose, never a branch target.
	Note string
	// Claim is set only when State is CreditEntryClaimed.
	Claim *VerifiedCreditClaimResult
}

// VerifyCreditEntry resolves one credits[] entry to its spec state, performing
// the FULL three-component bind. This is the call most consumers want.
//
// VerifyCreditClaim alone checks only the contentId component; the did and role
// comparisons are what make a claim an assertion about THIS entry, and skipping
// them verifies the wrong proposition — that some valid claim exists, not that it
// is about this credit.
//
// entry is the raw decoded credits entry (a JSON object out of document bytes),
// so every field is untrusted and type-checked here. contentID is the chain whose
// document contains the entry, and is REQUIRED.
//
// It returns an error only when contentID is empty, which is a caller bug rather
// than a verdict about the entry; every claim-level outcome is a State.
func VerifyCreditEntry(entry map[string]any, resolveKey KeyResolver, contentID string) (*VerifiedCreditEntry, error) {
	if contentID == "" {
		return nil, fmt.Errorf("VerifyCreditEntry requires the hosting chain contentID")
	}

	rawClaim, claimPresent := entry["claim"]
	if !claimPresent {
		return &VerifiedCreditEntry{
			State: CreditEntryUnclaimed,
			Note:  "the document signer asserts this credit; the claimant has not signed it",
		}, nil
	}

	claim, ok := rawClaim.(string)
	if !ok || claim == "" {
		return &VerifiedCreditEntry{
			State: CreditEntryInvalid,
			Note:  "claim is present but is not a JWS string",
		}, nil
	}
	entryDID, ok := entry["did"].(string)
	if !ok || entryDID == "" {
		return &VerifiedCreditEntry{
			State: CreditEntryInvalid,
			Note:  "claim-bearing entry has no credited DID to bind to",
		}, nil
	}
	// The claim-requires-role rule. An absent entry role is a BIND MISMATCH, not a
	// wildcard: the payload role is always present and non-empty, so there is
	// nothing for it to equal. Never unclaimed — a claim is present and failing.
	entryRole, ok := entry["role"].(string)
	if !ok || entryRole == "" {
		return &VerifiedCreditEntry{
			State: CreditEntryInvalid,
			Note:  "claim-bearing entry has no role to bind to",
		}, nil
	}

	verified, err := VerifyCreditClaimBound(claim, resolveKey, contentID)
	if err != nil {
		state := CreditEntryInvalid
		if errors.Is(err, ErrCreditClaimUnverifiable) {
			state = CreditEntryUnverifiable
		}
		return &VerifiedCreditEntry{State: state, Note: err.Error()}, nil
	}

	// the remaining two components of the bind, byte-exact, no normalization
	if verified.DID != entryDID {
		return &VerifiedCreditEntry{
			State: CreditEntryInvalid,
			Note:  "signed claimant DID does not match the credited DID",
		}, nil
	}
	if verified.Role != entryRole {
		return &VerifiedCreditEntry{
			State: CreditEntryInvalid,
			Note:  "signed role does not match the credited role",
		}, nil
	}

	return &VerifiedCreditEntry{
		State: CreditEntryClaimed,
		Note:  "signature and the exact (contentId, did, role) bind verified",
		Claim: verified,
	}, nil
}
