package dfos

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

// ===================================================================
// THE SINGLE TIME BASIS (PROTOCOL.md "Time basis").
//
// Every verification has one basis time. For a committed artifact — an operation
// in a chain and anything carried inline in it — the basis is the operation's own
// createdAt. For an ephemeral presentation the basis is now. At the basis the
// signing key must be effective in the identity's state as of the basis, exp must
// exceed the basis, and no revocation effective as of the basis may cover it.
//
// The fixture is one rotation: an identity holds K1 from T0, rotates to K2 at
// T_r, so K1 is effective on [T0, T_r) and K2 on [T_r, ∞).
//
// Twin: dfos-protocol/tests/time-basis.spec.ts — keep the two in lockstep.
// ===================================================================

const (
	basisT0        = "2026-03-07T00:00:00.000Z"
	basisT1        = "2026-03-07T00:05:00.000Z"
	basisBeforeT0  = "2026-03-06T23:50:00.000Z"
	basisRotation  = "2026-03-07T00:10:00.000Z"
	basisT3        = "2026-03-07T00:20:00.000Z"
	basisGenesisT0 = "2026-03-07T00:01:00.000Z"
)

func basisUnix(t *testing.T, value string) int64 {
	t.Helper()
	parsed, err := time.Parse(protocolTimeFormat, value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return parsed.Unix()
}

// rotatingIdentity is an identity with K1 at T0 that rotates to K2 at T_r.
type rotatingIdentity struct {
	did        string
	k1Priv     ed25519.PrivateKey
	k1KeyID    string
	k2Priv     ed25519.PrivateKey
	k2KeyID    string
	log        []string
	rotationCI string
}

func newRotatingIdentity(t *testing.T) rotatingIdentity {
	t.Helper()
	k1Priv, k1Pub, k1MK, k1KeyID := testKeys(t)
	genesis, did, genesisCID := testSignIdentityGenesis(t, k1MK, k1KeyID, k1Priv, basisT0)
	_ = k1Pub

	k2Priv, k2Pub, k2MK, k2KeyID := testKeys(t)
	_ = k2Pub
	one := []MultikeyPublicKey{k2MK}
	rotation, rotationCID := testSignIdentityUpdateWithProofs(t, did, one, one, one,
		[]string{testKeyProof(t, k2Priv, did, genesisCID)},
		k1KeyID, k1Priv, genesisCID, basisRotation)

	return rotatingIdentity{
		did: did, k1Priv: k1Priv, k1KeyID: k1KeyID, k2Priv: k2Priv, k2KeyID: k2KeyID,
		log: []string{genesis, rotation}, rotationCI: rotationCID,
	}
}

// asOfKeyResolver answers with the identity's effective key state as of the
// basis it is handed, which is the contract every committed verification relies
// on.
func asOfKeyResolver(t *testing.T, chains ...rotatingIdentity) KeyResolver {
	t.Helper()
	return func(kid string, basis string) (ed25519.PublicKey, error) {
		hash := strings.Index(kid, "#")
		if hash < 0 {
			return nil, errUnknownTestKid
		}
		did, keyID := kid[:hash], kid[hash+1:]
		for _, chain := range chains {
			if chain.did != did {
				continue
			}
			var result *VerifiedIdentityResult
			var err error
			if basis == "" {
				result, err = VerifyIdentityChain(chain.log)
			} else {
				result, err = VerifyIdentityChainAsOf(chain.log, basis)
			}
			if err != nil {
				return nil, err
			}
			if key, ok := findTestKey(result.State, keyID); ok {
				return DecodeMultikey(key.PublicKeyMultibase)
			}
			return nil, errUnknownTestKid
		}
		return nil, errUnknownTestKid
	}
}

func findTestKey(state IdentityState, keyID string) (MultikeyPublicKey, bool) {
	for _, list := range [][]MultikeyPublicKey{state.AuthKeys, state.AssertKeys, state.ControllerKeys} {
		for _, key := range list {
			if key.ID == keyID {
				return key, true
			}
		}
	}
	return MultikeyPublicKey{}, false
}

var errUnknownTestKid = &testKidError{}

type testKidError struct{}

func (e *testKidError) Error() string { return "unknown key" }

// ---------------------------------------------------------------------------
// state as of a basis
// ---------------------------------------------------------------------------

func TestIdentityStateAsOfBasis(t *testing.T) {
	id := newRotatingIdentity(t)

	before, err := VerifyIdentityChainAsOf(id.log, basisT1)
	if err != nil {
		t.Fatalf("as of T1: %v", err)
	}
	if _, ok := findTestKey(before.State, id.k1KeyID); !ok {
		t.Fatal("K1 must be effective before the rotation")
	}
	if _, ok := findTestKey(before.State, id.k2KeyID); ok {
		t.Fatal("K2 must not be effective before the rotation")
	}

	after, err := VerifyIdentityChainAsOf(id.log, basisT3)
	if err != nil {
		t.Fatalf("as of T3: %v", err)
	}
	if _, ok := findTestKey(after.State, id.k2KeyID); !ok {
		t.Fatal("K2 must be effective after the rotation")
	}
	if _, ok := findTestKey(after.State, id.k1KeyID); ok {
		t.Fatal("K1 must not be effective after the rotation")
	}

	// The comparison is createdAt <= basis, so the rotation's own instant already
	// sees the successor.
	atRotation, err := VerifyIdentityChainAsOf(id.log, basisRotation)
	if err != nil {
		t.Fatalf("as of the rotation: %v", err)
	}
	if _, ok := findTestKey(atRotation.State, id.k2KeyID); !ok {
		t.Fatal("K2 must be effective at the rotation's own instant")
	}

	// Omitting the basis is the head, which is the state as of now.
	head, err := VerifyIdentityChain(id.log)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if _, ok := findTestKey(head.State, id.k2KeyID); !ok {
		t.Fatal("K2 must be effective at the head")
	}
}

func TestIdentityStateBeforeGenesisIsAnError(t *testing.T) {
	id := newRotatingIdentity(t)
	if _, err := VerifyIdentityChainAsOf(id.log, basisBeforeT0); err == nil {
		t.Fatal("a basis earlier than the genesis names no state")
	} else if !strings.Contains(err.Error(), "identity has no state as of") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIdentityChainAsOfVerifiesTheWholeLog(t *testing.T) {
	id := newRotatingIdentity(t)
	tampered := []string{id.log[0], id.log[1][:len(id.log[1])-4] + "AAAA"}
	if _, err := VerifyIdentityChainAsOf(tampered, basisT1); err == nil {
		t.Fatal("a broken tail must fail whatever the basis selects")
	}
}

// ---------------------------------------------------------------------------
// forward issuance
// ---------------------------------------------------------------------------

// delegatedBasisFixture is a creator chain, a delegate chain, a content genesis
// signed at T0+1m, and a write credential the creator's K1 signed while it was
// still effective.
type delegatedBasisFixture struct {
	creator    rotatingIdentity
	delegate   rotatingIdentity
	contentID  string
	genesisJWS string
	genesisCID string
	credential string
	resolveKey KeyResolver
}

func newDelegatedBasisFixture(t *testing.T) delegatedBasisFixture {
	t.Helper()
	creator := newRotatingIdentity(t)
	delegate := newRotatingIdentity(t)

	docCID, _, _ := DocumentCID(map[string]any{"hello": "world"})
	creatorKid := creator.did + "#" + creator.k1KeyID
	genesisJWS, contentID, genesisCID := testSignContentGenesis(t, creator.did, docCID, creatorKid, creator.k1Priv, basisGenesisT0)

	credential, _ := mintCredentialWindow(t, creator.did, creatorKid, creator.k1Priv,
		delegate.did, "chain:"+contentID, "write", nil,
		basisUnix(t, basisT0), basisUnix(t, basisT3)+3600)

	return delegatedBasisFixture{
		creator: creator, delegate: delegate, contentID: contentID,
		genesisJWS: genesisJWS, genesisCID: genesisCID, credential: credential,
		resolveKey: asOfKeyResolver(t, creator, delegate),
	}
}

// delegatedWrite signs a delegated update at createdAt, with whichever of the
// delegate's keys is effective then.
func (f delegatedBasisFixture) delegatedWrite(t *testing.T, previousCID, title, createdAt string) (string, string) {
	t.Helper()
	priv, keyID := f.delegate.k1Priv, f.delegate.k1KeyID
	if createdAt >= basisRotation {
		priv, keyID = f.delegate.k2Priv, f.delegate.k2KeyID
	}
	docCID, _, _ := DocumentCID(map[string]any{"title": title})
	payload := map[string]any{
		"version":              int64(1),
		"type":                 "update",
		"did":                  f.delegate.did,
		"previousOperationCID": previousCID,
		"documentCID":          docCID,
		"baseDocumentCID":      nil,
		"createdAt":            createdAt,
		"authorization":        f.credential,
	}
	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID(update): %v", err)
	}
	header := JWSHeader{Alg: "EdDSA", Typ: "did:dfos:content-op",
		Kid: f.delegate.did + "#" + keyID, CID: cidStr}
	token, err := CreateJWS(header, payload, priv)
	if err != nil {
		t.Fatalf("CreateJWS(update): %v", err)
	}
	return token, cidStr
}

func TestInlineCredentialVerifiesAtTheOperationBasis(t *testing.T) {
	f := newDelegatedBasisFixture(t)
	early, earlyCID := f.delegatedWrite(t, f.genesisCID, "early", basisT1)

	// Full-log walk.
	if _, err := VerifyContentChain([]string{f.genesisJWS, early}, f.resolveKey, true); err != nil {
		t.Fatalf("write dated while the issuing key is effective: %v", err)
	}

	// Extension from trusted state.
	genesisState, err := VerifyContentChain([]string{f.genesisJWS}, f.resolveKey, true)
	if err != nil {
		t.Fatalf("genesis: %v", err)
	}
	if _, err := VerifyContentExtension(genesisState.State, basisGenesisT0, early, f.resolveKey, true); err != nil {
		t.Fatalf("extension dated while the issuing key is effective: %v", err)
	}
	if earlyCID == "" {
		t.Fatal("missing early op CID")
	}
}

func TestInlineCredentialIsRefusedAfterTheIssuingKeyRotatesOut(t *testing.T) {
	f := newDelegatedBasisFixture(t)
	early, earlyCID := f.delegatedWrite(t, f.genesisCID, "early", basisT1)
	late, _ := f.delegatedWrite(t, earlyCID, "late", basisT3)

	if _, err := VerifyContentChain([]string{f.genesisJWS, early, late}, f.resolveKey, true); err == nil {
		t.Fatal("a write dated after the issuing key rotated out must be refused")
	}

	throughEarly, err := VerifyContentChain([]string{f.genesisJWS, early}, f.resolveKey, true)
	if err != nil {
		t.Fatalf("through early: %v", err)
	}
	if _, err := VerifyContentExtension(throughEarly.State, basisT1, late, f.resolveKey, true); err == nil {
		t.Fatal("the extension path must refuse it too")
	}
}

// ---------------------------------------------------------------------------
// the rules that do not run against the basis
// ---------------------------------------------------------------------------

// Deletion is the one credential rule that does not run against the basis: it
// reads HEAD state, so a deleted issuer authorizes nothing at any point in
// history (CREDENTIALS.md "Deleted issuers").
func TestDeletedIssuerIsRefusedAtEveryBasis(t *testing.T) {
	f := newDelegatedBasisFixture(t)
	early, _ := f.delegatedWrite(t, f.genesisCID, "early", basisT1)

	// Without the gate the write verifies at its own basis.
	if _, err := VerifyContentChain([]string{f.genesisJWS, early}, f.resolveKey, true); err != nil {
		t.Fatalf("write before the deletion must verify without the gate: %v", err)
	}

	// The creator deletes at T3, after the write. The gate reads head state, so
	// the write dated at T1 stops verifying.
	deleted := WithIdentityDeletedChecker(func(did string) (bool, error) {
		return did == f.creator.did, nil
	})
	if _, err := VerifyContentChain([]string{f.genesisJWS, early}, f.resolveKey, true, deleted); err == nil {
		t.Fatal("a deleted issuer must invalidate the credential retroactively")
	} else if !strings.Contains(err.Error(), "issuer identity is deleted") {
		t.Fatalf("unexpected error: %v", err)
	}
}
