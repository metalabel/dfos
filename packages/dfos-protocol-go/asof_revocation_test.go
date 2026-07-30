package dfos

import (
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"
)

// ===================================================================
// AS-OF REVOCATION — acceptance vs validity (Go twin)
//
// Acceptance is a freshness decision; verification of committed history is a
// validity decision. A timeless revocation check conflates the two: it makes
// revoking a credential today retroactively invalidate every operation it ever
// authorized, contradicting CREDENTIALS.md "Revocation Scope" ("does not
// retroactively invalidate operations already committed to the content chain").
//
// These tests pin the fold side: the verifier calls the RevocationChecker with
// asOfUnix = the operation's OWN createdAt, at the leaf AND at every parent hop,
// in both VerifyContentChain and VerifyContentExtension. Twin of
// dfos-protocol/tests/asof-revocation.spec.ts — keep the two in lockstep.
// ===================================================================

// asOfRevocationChecker is the as-of rule as a store would implement it: a
// revocation counts only when its own signed createdAt is at or before the
// queried instant. asOfUnix == 0 means timeless (current knowledge).
func asOfRevocationChecker(revoked map[string]int64) RevocationChecker {
	return func(issuerDID, credentialCID string, asOfUnix int64) (bool, error) {
		revokedAt, ok := revoked[issuerDID+"::"+credentialCID]
		if !ok {
			return false, nil
		}
		if asOfUnix == 0 {
			return true, nil
		}
		return revokedAt <= asOfUnix, nil
	}
}

// timelessRevocationChecker is the pre-change behavior: a timeless boolean.
func timelessRevocationChecker(revoked map[string]int64) RevocationChecker {
	return func(issuerDID, credentialCID string, _ int64) (bool, error) {
		_, ok := revoked[issuerDID+"::"+credentialCID]
		return ok, nil
	}
}

// asOfFixture is a two-op content chain: a creator's genesis plus a delegated
// update signed by a delegate under an inline write credential.
type asOfFixture struct {
	log             []string
	genesisState    ContentState
	genesisLastAt   string
	updateJWS       string
	resolver        KeyResolver
	opCreatedAtUnix int64
	// leafKey / parentKey are the (issuerDID::credentialCID) revocation-set keys
	leafKey   string
	parentKey string
}

// buildAsOfFixture assembles the fixture. With depth 2 it inserts an
// intermediate delegate so the PARENT hop of the delegation walk is exercised.
func buildAsOfFixture(t *testing.T, depth int) asOfFixture {
	t.Helper()
	now := time.Now().UTC()
	genesisTime := now.Format(protocolTimeFormat)
	// the delegated op is timestamped +1 minute, so a revocation at now+10min is
	// strictly after it and a revocation at now-10min strictly before it
	updateTime := now.Add(1 * time.Minute).Format(protocolTimeFormat)

	creatorPriv, creatorPub, _, creatorKeyID := testKeys(t)
	_, creatorDID, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{NewMultikeyPublicKey(creatorKeyID, creatorPub)}, nil, nil,
		creatorKeyID, creatorPriv, genesisTime,
	)
	middlePriv, middlePub, _, middleKeyID := testKeys(t)
	_, middleDID, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{NewMultikeyPublicKey(middleKeyID, middlePub)}, nil, nil,
		middleKeyID, middlePriv, genesisTime,
	)
	delegatePriv, delegatePub, _, delegateKeyID := testKeys(t)
	_, delegateDID, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{NewMultikeyPublicKey(delegateKeyID, delegatePub)}, nil, nil,
		delegateKeyID, delegatePriv, genesisTime,
	)

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
	genesis, err := VerifyContentChain([]string{contentJWS}, resolver, true)
	if err != nil {
		t.Fatalf("verify genesis: %v", err)
	}

	// leaf credential: creator → delegate at depth 1, creator → middle → delegate
	// at depth 2 (so the delegation walk has a parent hop to check)
	var leafToken, leafKey, parentKey string
	if depth == 2 {
		parentToken, parentCID := mintAsOfCredential(t, creatorDID, creatorKid, creatorPriv, middleDID, "chain:*", "write", nil)
		token, leafCID := mintAsOfCredential(t, middleDID, middleKid, middlePriv, delegateDID, "chain:*", "write", []string{parentToken})
		leafToken = token
		leafKey = middleDID + "::" + leafCID
		parentKey = creatorDID + "::" + parentCID
	} else {
		token, leafCID := mintAsOfCredential(t, creatorDID, creatorKid, creatorPriv, delegateDID, "chain:*", "write", nil)
		leafToken = token
		leafKey = creatorDID + "::" + leafCID
	}

	updateJWS := buildDelegatedUpdate(t, delegateDID, delegateKid, delegatePriv, contentCID, updateTime, leafToken)
	return asOfFixture{
		log:             []string{contentJWS, updateJWS},
		genesisState:    genesis.State,
		genesisLastAt:   genesis.LastCreatedAt,
		updateJWS:       updateJWS,
		resolver:        resolver,
		opCreatedAtUnix: mustParseProtocolTime(t, updateTime).Unix(),
		leafKey:         leafKey,
		parentKey:       parentKey,
	}
}

// mintAsOfCredential mints a credential with an optional prf parent, backdating
// iat so it is valid relative to the delegated op's createdAt.
func mintAsOfCredential(t *testing.T, issuerDID, issuerKid string, issuerPriv ed25519.PrivateKey, aud, resource, action string, prf []string) (token, cid string) {
	t.Helper()
	now := time.Now().Unix()
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
		"exp":     now + int64(time.Hour.Seconds()),
		"iat":     now - 600,
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

// buildDelegatedUpdate hand-builds a delegated update op carrying an inline
// authorization credential.
func buildDelegatedUpdate(t *testing.T, delegateDID, delegateKid string, delegatePriv ed25519.PrivateKey, previousCID, createdAt, authorization string) string {
	t.Helper()
	docCID, _, _ := DocumentCID(map[string]any{"v": int64(2)})
	payload := map[string]any{
		"version":              int64(1),
		"type":                 "update",
		"did":                  delegateDID,
		"previousOperationCID": previousCID,
		"documentCID":          docCID,
		"baseDocumentCID":      nil,
		"createdAt":            createdAt,
		"authorization":        authorization,
	}
	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID(update): %v", err)
	}
	header := JWSHeader{Alg: "EdDSA", Typ: "did:dfos:content-op", Kid: delegateKid, CID: cidStr}
	token, err := CreateJWS(header, payload, delegatePriv)
	if err != nil {
		t.Fatalf("CreateJWS(update): %v", err)
	}
	return token
}

func mustParseProtocolTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(protocolTimeFormat, value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return parsed
}

// ---------------------------------------------------------------------------
// full fold
// ---------------------------------------------------------------------------

// TestAsOfFoldAcceptsLaterRevocation is the healed case: a committed delegated op
// whose authorizing credential was revoked AFTER the op was signed still verifies.
func TestAsOfFoldAcceptsLaterRevocation(t *testing.T) {
	f := buildAsOfFixture(t, 1)
	revoked := map[string]int64{f.leafKey: time.Now().Add(10 * time.Minute).Unix()}

	result, err := VerifyContentChain(f.log, f.resolver, true, WithRevocationChecker(asOfRevocationChecker(revoked)))
	if err != nil {
		t.Fatalf("expected fold to VERIFY (credential revoked after the op): %v", err)
	}
	if result.State.Length != 2 {
		t.Fatalf("Length: got %d, want 2", result.State.Length)
	}
}

// TestAsOfFoldRejectsEarlierRevocation is the other side: a revocation that
// predates the op does invalidate it.
func TestAsOfFoldRejectsEarlierRevocation(t *testing.T) {
	f := buildAsOfFixture(t, 1)
	revoked := map[string]int64{f.leafKey: time.Now().Add(-10 * time.Minute).Unix()}

	if _, err := VerifyContentChain(f.log, f.resolver, true, WithRevocationChecker(asOfRevocationChecker(revoked))); err == nil {
		t.Fatal("expected fold to REJECT an op authorized by an already-revoked credential")
	}
}

// TestAsOfFoldRejectsRevocationAtOpBoundary pins the inclusive boundary: a
// revocation timestamped exactly at the op's createdAt bites.
func TestAsOfFoldRejectsRevocationAtOpBoundary(t *testing.T) {
	f := buildAsOfFixture(t, 1)
	revoked := map[string]int64{f.leafKey: f.opCreatedAtUnix}

	if _, err := VerifyContentChain(f.log, f.resolver, true, WithRevocationChecker(asOfRevocationChecker(revoked))); err == nil {
		t.Fatal("expected fold to REJECT when the revocation lands exactly at the op createdAt")
	}
}

// TestAsOfFoldTimelessCheckerPreservesOldBehavior confirms a checker that ignores
// asOfUnix still rejects — the pre-change behavior is available to any caller that
// wants it, and the semantics change lives entirely in the checker.
func TestAsOfFoldTimelessCheckerPreservesOldBehavior(t *testing.T) {
	f := buildAsOfFixture(t, 1)
	revoked := map[string]int64{f.leafKey: time.Now().Add(10 * time.Minute).Unix()}

	if _, err := VerifyContentChain(f.log, f.resolver, true, WithRevocationChecker(timelessRevocationChecker(revoked))); err == nil {
		t.Fatal("expected a timeless checker to REJECT (pre-as-of behavior)")
	}
}

// TestAsOfBasisIsOpCreatedAt pins WHICH clock is threaded: every call must carry
// the operation's own createdAt, never the verifier's wall clock.
func TestAsOfBasisIsOpCreatedAt(t *testing.T) {
	f := buildAsOfFixture(t, 1)
	var seen []int64
	checker := func(_, _ string, asOfUnix int64) (bool, error) {
		seen = append(seen, asOfUnix)
		return false, nil
	}

	if _, err := VerifyContentChain(f.log, f.resolver, true, WithRevocationChecker(checker)); err != nil {
		t.Fatalf("VerifyContentChain: %v", err)
	}
	if len(seen) == 0 {
		t.Fatal("revocation checker was never called")
	}
	for i, asOf := range seen {
		if asOf != f.opCreatedAtUnix {
			t.Fatalf("call %d: as-of basis %d, want the op createdAt %d", i, asOf, f.opCreatedAtUnix)
		}
	}
}

// ---------------------------------------------------------------------------
// parent hops
// ---------------------------------------------------------------------------

// TestAsOfParentAcceptsLaterRevocation — the as-of basis reaches PARENT hops of
// the delegation walk, not just the leaf.
func TestAsOfParentAcceptsLaterRevocation(t *testing.T) {
	f := buildAsOfFixture(t, 2)
	revoked := map[string]int64{f.parentKey: time.Now().Add(10 * time.Minute).Unix()}

	result, err := VerifyContentChain(f.log, f.resolver, true, WithRevocationChecker(asOfRevocationChecker(revoked)))
	if err != nil {
		t.Fatalf("expected fold to VERIFY (parent revoked after the op): %v", err)
	}
	if result.State.Length != 2 {
		t.Fatalf("Length: got %d, want 2", result.State.Length)
	}
}

// TestAsOfParentRejectsEarlierRevocation — a parent already revoked at op time
// still cascades the rejection.
func TestAsOfParentRejectsEarlierRevocation(t *testing.T) {
	f := buildAsOfFixture(t, 2)
	revoked := map[string]int64{f.parentKey: time.Now().Add(-10 * time.Minute).Unix()}

	if _, err := VerifyContentChain(f.log, f.resolver, true, WithRevocationChecker(asOfRevocationChecker(revoked))); err == nil {
		t.Fatal("expected fold to REJECT an op whose PARENT credential was already revoked")
	}
}

// ---------------------------------------------------------------------------
// extension from trusted state
// ---------------------------------------------------------------------------

// TestAsOfExtensionAcceptsLaterRevocation — the O(1) extension path carries the
// same as-of basis as the full fold.
func TestAsOfExtensionAcceptsLaterRevocation(t *testing.T) {
	f := buildAsOfFixture(t, 1)
	revoked := map[string]int64{f.leafKey: time.Now().Add(10 * time.Minute).Unix()}

	result, err := VerifyContentExtension(f.genesisState, f.genesisLastAt, f.updateJWS, f.resolver, true,
		WithRevocationChecker(asOfRevocationChecker(revoked)))
	if err != nil {
		t.Fatalf("expected extension to VERIFY (credential revoked after the op): %v", err)
	}
	if result.State.Length != 2 {
		t.Fatalf("Length: got %d, want 2", result.State.Length)
	}
}

// TestAsOfExtensionRejectsEarlierRevocation — and rejects the pre-dated case.
func TestAsOfExtensionRejectsEarlierRevocation(t *testing.T) {
	f := buildAsOfFixture(t, 1)
	revoked := map[string]int64{f.leafKey: time.Now().Add(-10 * time.Minute).Unix()}

	if _, err := VerifyContentExtension(f.genesisState, f.genesisLastAt, f.updateJWS, f.resolver, true,
		WithRevocationChecker(asOfRevocationChecker(revoked))); err == nil {
		t.Fatal("expected extension to REJECT an op authorized by an already-revoked credential")
	}
}
