package dfos

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ===========================================================================
// PARENT CREDENTIAL EXPIRY BASIS (Go twin)
//
// CREDENTIALS.md "Expiry Basis": at ingest, a credential's exp is compared
// against the operation's own createdAt, and a relay MUST NOT add an
// ingest-time wall-clock exp check. The rule covers the whole presented
// credential — leaf AND every parent in its delegation chain. A chain judged on
// two different clocks is not judged at one point in time.
//
// Go used to verify the leaf at the operation basis (verify.go) but every
// parent against time.Now() (delegation.go calling VerifyCredential). A
// delegated op signed under a 30-day root credential verified today and stopped
// verifying the day that root's TTL lapsed — non-convergent across relays and
// divergent from the TS twin, which threads `now` to every hop
// (dfos-credential.ts verifyDelegationChain).
//
// Keep these in lockstep with the TS twin.
// ===========================================================================

// mintCredentialWindow mints a credential with an explicit [iat, exp) window and
// an optional prf parent. mintAsOfCredential pins its window to "now ± 4h", which
// cannot express a credential that expired years ago.
func mintCredentialWindow(t *testing.T, issuerDID, issuerKid string, issuerPriv ed25519.PrivateKey, aud, resource, action string, prf []string, iat, exp int64) (token, cid string) {
	t.Helper()
	prfAny := make([]any, len(prf))
	for i, p := range prf {
		prfAny[i] = p
	}
	payload := map[string]any{
		"version": 1,
		"type":    "DFOSCredential",
		"iss":     issuerDID,
		"aud":     aud,
		"att":     []any{map[string]any{"resource": resource, "action": action}},
		"prf":     prfAny,
		"exp":     exp,
		"iat":     iat,
	}
	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID(credential): %v", err)
	}
	header := JWSHeader{Alg: "EdDSA", Typ: "did:dfos:credential", Kid: issuerKid, CID: cidStr}
	token, err = CreateJWS(header, payload, issuerPriv)
	if err != nil {
		t.Fatalf("CreateJWS(credential): %v", err)
	}
	return token, cidStr
}

func mustUnix(t *testing.T, value string) int64 {
	t.Helper()
	parsed, err := time.Parse(protocolTimeFormat, value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return parsed.Unix()
}

// verifyChainAt is verifyChain with an explicit temporal basis: the leaf is
// verified at asOfUnix and the same basis is threaded into the walk. asOfUnix 0
// leaves the leaf on the wall clock too, matching the read path.
func verifyChainAt(t *testing.T, childToken string, resolve KeyResolver, rootDID string, asOfUnix int64) error {
	t.Helper()
	header, payload, err := DecodeJWSUnsafe(childToken)
	if err != nil {
		t.Fatalf("decode child: %v", err)
	}
	pubKey, err := resolve(header.Kid)
	if err != nil {
		return err
	}
	var vc *VerifiedCredential
	if asOfUnix > 0 {
		vc, err = VerifyCredentialAt(childToken, pubKey, "", "", asOfUnix)
	} else {
		vc, err = VerifyCredential(childToken, pubKey, "", "")
	}
	if err != nil {
		return err
	}
	childAtt := ParseAtt(payload)
	childPrf, err := ParsePrf(payload)
	if err != nil {
		return err
	}
	return verifyDelegationChain(childToken, vc, childAtt, childPrf, resolve, rootDID, nil, nil, asOfUnix, 0)
}

// ---------------------------------------------------------------------------
// fold: a historical delegated op under a long-expired parent
// ---------------------------------------------------------------------------

// TestParentExpiryUsesOperationBasis is the C1 case: a delegated update signed in
// 2020 under a two-hop chain whose PARENT credential expired in 2021. The op was
// temporally authorized when it was signed and is permanently part of the log, so
// the fold must still verify today — the parent's exp is judged against the
// operation's createdAt, never the verifier's wall clock.
func TestParentExpiryUsesOperationBasis(t *testing.T) {
	genesisTime := "2020-01-01T00:00:00.000Z"
	updateTime := "2020-06-01T00:00:00.000Z"

	creatorPriv, creatorPub, _, creatorKeyID := testKeys(t)
	_, creatorDID, _ := testSignIdentityGenesis(t, NewMultikeyPublicKey(creatorKeyID, creatorPub), creatorKeyID, creatorPriv, genesisTime)
	middlePriv, middlePub, _, middleKeyID := testKeys(t)
	_, middleDID, _ := testSignIdentityGenesis(t, NewMultikeyPublicKey(middleKeyID, middlePub), middleKeyID, middlePriv, genesisTime)
	delegatePriv, delegatePub, _, delegateKeyID := testKeys(t)
	_, delegateDID, _ := testSignIdentityGenesis(t, NewMultikeyPublicKey(delegateKeyID, delegatePub), delegateKeyID, delegatePriv, genesisTime)

	creatorKid := creatorDID + "#" + creatorKeyID
	middleKid := middleDID + "#" + middleKeyID
	delegateKid := delegateDID + "#" + delegateKeyID
	resolver := func(k string) (ed25519.PublicKey, error) {
		switch k {
		case creatorKid:
			return creatorPub, nil
		case middleKid:
			return middlePub, nil
		case delegateKid:
			return delegatePub, nil
		default:
			return nil, fmt.Errorf("unknown kid: %s", k)
		}
	}

	docCID, _, _ := DocumentCID(map[string]any{"hello": "world"})
	contentJWS, _, contentCID := testSignContentGenesis(t, creatorDID, docCID, creatorKid, creatorPriv, genesisTime)

	// parent: creator → middle, valid 2019-01-01 through 2021-01-01 (long expired
	// on any present-day wall clock, live at the operation's createdAt)
	parentToken, _ := mintCredentialWindow(t, creatorDID, creatorKid, creatorPriv, middleDID, "chain:*", "write", nil,
		mustUnix(t, "2019-01-01T00:00:00.000Z"), mustUnix(t, "2021-01-01T00:00:00.000Z"))
	// leaf: middle → delegate, narrower window (exp <= parent exp)
	leafToken, _ := mintCredentialWindow(t, middleDID, middleKid, middlePriv, delegateDID, "chain:*", "write", []string{parentToken},
		mustUnix(t, "2019-06-01T00:00:00.000Z"), mustUnix(t, "2020-12-01T00:00:00.000Z"))

	updateJWS := buildDelegatedUpdate(t, delegateDID, delegateKid, delegatePriv, contentCID, updateTime, leafToken)

	result, err := VerifyContentChain([]string{contentJWS, updateJWS}, resolver, true)
	if err != nil {
		t.Fatalf("expected fold to VERIFY (parent credential was live at the op's createdAt): %v", err)
	}
	if result.State.Length != 2 {
		t.Fatalf("Length: got %d, want 2", result.State.Length)
	}
}

// TestParentExpiredBeforeOperationStillRejects is the other side: a parent whose
// window had already closed when the op was signed does not become valid just
// because the basis moved off the wall clock. The parent's temporal check runs
// before the expiry-narrowing check, so the rejection names the parent.
func TestParentExpiredBeforeOperationStillRejects(t *testing.T) {
	basis := mustUnix(t, "2020-06-01T00:00:00.000Z")
	root := newCredParty(t, "rootexp")
	member := newCredParty(t, "memberexp")

	// root → member, already expired at the basis
	rootCred := mintCred(t, credSpec{
		issuer: root, aud: member.did,
		att: att("chain:abc", "read"),
		iat: mustUnix(t, "2019-01-01T00:00:00.000Z"),
		exp: mustUnix(t, "2020-03-01T00:00:00.000Z"),
	})
	// leaf still live at the basis, so the walk is reached
	childCred := mintCred(t, credSpec{
		issuer: member, aud: "*",
		att: att("chain:abc", "read"),
		prf: []string{rootCred},
		iat: mustUnix(t, "2019-01-01T00:00:00.000Z"),
		exp: mustUnix(t, "2020-12-01T00:00:00.000Z"),
	})

	err := verifyChainAt(t, childCred, mapResolver(root, member), root.did, basis)
	if err == nil {
		t.Fatal("expected a parent expired BEFORE the operation basis to be REJECTED, got nil")
	}
	if !strings.Contains(err.Error(), "parent credential verification failed") {
		t.Errorf("expected a parent verification failure, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// read path: asOfUnix == 0 keeps the wall clock
// ---------------------------------------------------------------------------

// TestParentExpiryAtReadBasisUsesWallClock pins the half that must NOT change.
// The live read path passes asOfUnix 0 (relay auth.go, signing.go) — reads are
// local, ephemeral decisions that never enter the replicated log, so an expired
// parent must reject there, exactly as the TS twin does when `now` is omitted.
func TestParentExpiryAtReadBasisUsesWallClock(t *testing.T) {
	now := time.Now().Unix()
	root := newCredParty(t, "rootread")
	member := newCredParty(t, "memberread")

	// root → member, expired in 2021
	rootCred := mintCred(t, credSpec{
		issuer: root, aud: member.did,
		att: att("chain:abc", "read"),
		iat: mustUnix(t, "2019-01-01T00:00:00.000Z"),
		exp: mustUnix(t, "2021-01-01T00:00:00.000Z"),
	})
	// leaf live on the wall clock, so the read path reaches the walk
	childCred := mintCred(t, credSpec{
		issuer: member, aud: "*",
		att: att("chain:abc", "read"),
		prf: []string{rootCred},
		iat: now - 3600,
		exp: now + 3600,
	})

	err := verifyChainAt(t, childCred, mapResolver(root, member), root.did, 0)
	if err == nil {
		t.Fatal("expected an expired parent to be REJECTED on the read path (asOfUnix 0), got nil")
	}
	// the parent's temporal check fires before expiry narrowing, so this message
	// (not the narrowing one) is what proves the wall clock was the basis
	if !strings.Contains(err.Error(), "parent credential verification failed") {
		t.Errorf("expected a parent verification failure, got: %v", err)
	}
}
