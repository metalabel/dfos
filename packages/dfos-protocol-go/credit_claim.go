package dfos

import (
	"crypto/ed25519"
	"fmt"
	"strings"
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
// Two shape divergences from the TS twin, both following existing house
// convention rather than the TS signature:
//
//  1. Key resolution takes a KeyResolver (kid → public key), as every other Go
//     verify does (VerifyRevocation, VerifyArtifact, VerifyCountersignature).
//     The TS twin takes a resolveIdentity callback because its credential layer
//     already had one. Consequence: the deleted-claimant doctrine (a tombstoned
//     claimant's claim STILL verifies) is structurally vacuous here — this path
//     has no isDeleted concept to consult. The doctrine is pinned by a TS test;
//     do not add an identity-deletion gate to this file to "match" credentials.
//  2. The optional expectedContentId binder is a separate Bound entry point
//     rather than an options struct, following the SignCountersign /
//     SignCountersignWithRelation precedent.

// maxCreditClaimSize bounds the byte length of a credit-claim JWS token — the
// claim's aggregate size bound, checked before any decode as a DoS guard.
// Deliberately tight because claims travel INSIDE document bytes: a document
// embedding many credits carries one token per claimed entry. The payload's
// open-namespace role field therefore carries no separate length cap; this
// aggregate is the single byte arbiter. VALIDITY-determining: MUST match the TS
// reference (MAX_CREDIT_CLAIM_SIZE in chain/schemas.ts).
const maxCreditClaimSize = 4096

// SignCreditClaim signs a credit claim binding a claimant DID to a named role on
// a content chain.
//
// The claim binds to the chain's stable contentID, never to a document — so a
// signed claim stays valid verbatim across every subsequent edit. Callers SHOULD
// sign a given (contentID, did, role) triple once and reuse the token: re-signing
// mints a fresh createdAt, which changes the claim bytes, which changes the
// embedding document's CID.
func SignCreditClaim(did, contentID, role, kid string, privateKey ed25519.PrivateKey) (jwsToken string, claimCID string, err error) {
	return SignCreditClaimWithAsOf(did, contentID, role, "", kid, privateKey)
}

// SignCreditClaimWithAsOf is SignCreditClaim plus the optional content-strength
// flavor: the document state the claimant pins its credit to. An empty
// asOfDocumentCID is omitted from the payload entirely, so it encodes identically
// to a claim that never carried the field (CID-neutral).
func SignCreditClaimWithAsOf(did, contentID, role, asOfDocumentCID, kid string, privateKey ed25519.PrivateKey) (jwsToken string, claimCID string, err error) {
	// validate before signing — a malformed binder must never reach the wire
	if !contentIDAnchorRe.MatchString(contentID) {
		return "", "", fmt.Errorf("invalid credit claim payload: contentId must be a 31-char content chain id")
	}
	if role == "" {
		return "", "", fmt.Errorf("invalid credit claim payload: missing role")
	}

	now := protocolTimestamp()

	payload := map[string]any{
		"version":   1,
		"type":      "credit-claim",
		"contentId": contentID,
		"did":       did,
		"role":      role,
		"createdAt": now.Format(protocolTimeFormat),
	}
	if asOfDocumentCID != "" {
		payload["asOfDocumentCID"] = asOfDocumentCID
	}

	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		return "", "", err
	}

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:credit-claim",
		Kid: kid,
		CID: cidStr,
	}

	jwsToken, err = CreateJWS(header, payload, privateKey)
	if err != nil {
		return "", "", err
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
// It does NOT enforce the contentId binder. Prefer VerifyCreditClaimBound: a
// consumer reading a credits entry always knows which chain it is reading, and
// without the binder a valid claim lifted from one chain's document verifies when
// replayed into another's.
func VerifyCreditClaim(jwsToken string, resolveKey KeyResolver) (*VerifiedCreditClaimResult, error) {
	return verifyCreditClaimCore(jwsToken, resolveKey, "")
}

// VerifyCreditClaimBound is VerifyCreditClaim plus the anti-replay half of the
// bind: the claim's contentId MUST equal expectedContentID. The remaining two
// components of the bind — did and role — are compared by the caller against the
// credits entry plaintext (exact byte equality, no normalization).
func VerifyCreditClaimBound(jwsToken string, resolveKey KeyResolver, expectedContentID string) (*VerifiedCreditClaimResult, error) {
	return verifyCreditClaimCore(jwsToken, resolveKey, expectedContentID)
}

func verifyCreditClaimCore(jwsToken string, resolveKey KeyResolver, expectedContentID string) (*VerifiedCreditClaimResult, error) {
	// bound claim size before any decode
	if len(jwsToken) > maxCreditClaimSize {
		return nil, fmt.Errorf("credit claim exceeds max size: %d > %d", len(jwsToken), maxCreditClaimSize)
	}

	header, payload, err := DecodeJWSUnsafe(jwsToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode credit claim JWS")
	}

	// verify typ
	if header.Typ != "did:dfos:credit-claim" {
		return nil, fmt.Errorf("invalid credit claim typ: %s", header.Typ)
	}

	// validate payload
	version, _ := payload["version"].(int64)
	if version != 1 {
		return nil, fmt.Errorf("invalid credit claim payload: invalid or missing version")
	}
	if payloadString(payload, "type") != "credit-claim" {
		return nil, fmt.Errorf("invalid credit claim payload: wrong type")
	}
	contentID := payloadString(payload, "contentId")
	if !contentIDAnchorRe.MatchString(contentID) {
		return nil, fmt.Errorf("invalid credit claim payload: contentId must be a 31-char content chain id")
	}
	did := payloadString(payload, "did")
	if did == "" {
		return nil, fmt.Errorf("invalid credit claim payload: missing did")
	}
	role := payloadString(payload, "role")
	if role == "" {
		return nil, fmt.Errorf("invalid credit claim payload: missing role")
	}
	createdAt := payloadString(payload, "createdAt")
	if err := validateCreatedAt(createdAt); err != nil {
		return nil, fmt.Errorf("invalid credit claim payload: %w", err)
	}

	// verify kid DID matches payload did (only the claimant can claim its credit)
	kid := header.Kid
	hashIdx := strings.Index(kid, "#")
	if hashIdx < 0 {
		return nil, fmt.Errorf("credit claim kid must be a DID URL")
	}
	kidDid := kid[:hashIdx]
	if kidDid != did {
		return nil, fmt.Errorf("credit claim kid DID does not match payload did")
	}

	// verify signature
	publicKey, err := resolveKey(kid)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve credit claim key: %w", err)
	}
	if _, _, err := VerifyJWS(jwsToken, publicKey); err != nil {
		return nil, fmt.Errorf("invalid credit claim signature")
	}

	// verify CID
	_, _, claimCID, err := DagCborCID(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to derive credit claim CID: %w", err)
	}
	if header.CID == "" {
		return nil, fmt.Errorf("missing cid in credit claim header")
	}
	if header.CID != claimCID {
		return nil, fmt.Errorf("credit claim cid mismatch")
	}

	// enforce the binder — a claim is only about the chain it names
	if expectedContentID != "" && contentID != expectedContentID {
		return nil, fmt.Errorf("credit claim contentId %s does not match expected %s", contentID, expectedContentID)
	}

	return &VerifiedCreditClaimResult{
		DID:             did,
		ContentID:       contentID,
		Role:            role,
		CreatedAt:       createdAt,
		AsOfDocumentCID: payloadString(payload, "asOfDocumentCID"),
		SignerKeyId:     kid,
		ClaimCID:        claimCID,
	}, nil
}
