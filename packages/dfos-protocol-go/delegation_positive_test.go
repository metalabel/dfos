package dfos

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

// ===========================================================================
// Go delegation POSITIVE coverage
//
// The Go single-parent delegation walk (verifyDelegationChain) previously had
// only TestVerifyDelegationChainRejectsMultiParent — a negative test, no
// positive full-chain walk. These tests mirror the TS credentials.spec.ts
// 2-hop / 3-hop accept and the audience-gap / expiry-extension / scope-widening
// rejects.
//
// CreateCredential (jwt.go) hardcodes a single att + prf:[] and cannot mint a
// DELEGATED child, so we build the payload map + CreateJWS + DagCborCID by hand
// (mintCred) and resolve keys from a map (the protocol layer is store-agnostic;
// the resolver is the seam where the relay would inject store-backed lookup).
// ===========================================================================

// credParty is a delegation participant: a DID + its signing keypair.
type credParty struct {
	did  string
	kid  string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newCredParty(t *testing.T, didSuffix string) credParty {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := "did:dfos:" + didSuffix
	return credParty{did: did, kid: did + "#key-1", priv: priv, pub: pub}
}

// credSpec describes a credential to mint.
type credSpec struct {
	issuer credParty
	aud    string
	att    []map[string]string
	prf    []string // parent JWS tokens
	exp    int64
	iat    int64
}

// mintCred builds a DFOS credential payload, derives its CID, signs the JWS, and
// returns the token. Mirrors CreateCredential but allows arbitrary att + prf so
// a delegated child can be minted.
func mintCred(t *testing.T, spec credSpec) string {
	t.Helper()
	att := make([]any, len(spec.att))
	for i, a := range spec.att {
		att[i] = map[string]any{"resource": a["resource"], "action": a["action"]}
	}
	prf := make([]any, len(spec.prf))
	for i, p := range spec.prf {
		prf[i] = p
	}
	payload := map[string]any{
		"version": 1,
		"type":    "DFOSCredential",
		"iss":     spec.issuer.did,
		"aud":     spec.aud,
		"att":     att,
		"prf":     prf,
		"exp":     spec.exp,
		"iat":     spec.iat,
	}
	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}
	header := JWSHeader{Alg: "EdDSA", Typ: "did:dfos:credential", Kid: spec.issuer.kid, CID: cidStr}
	token, err := CreateJWS(header, payload, spec.issuer.priv)
	if err != nil {
		t.Fatalf("CreateJWS: %v", err)
	}
	return token
}

// mapResolver builds a KeyResolver from a set of parties.
func mapResolver(parties ...credParty) KeyResolver {
	keys := map[string]ed25519.PublicKey{}
	for _, p := range parties {
		keys[p.kid] = p.pub
	}
	return func(kid string) (ed25519.PublicKey, error) {
		k, ok := keys[kid]
		if !ok {
			return nil, errKeyNotFound{kid}
		}
		return k, nil
	}
}

type errKeyNotFound struct{ kid string }

func (e errKeyNotFound) Error() string { return "unknown key " + e.kid }

// verifyChain decodes a child credential token and drives verifyDelegationChain.
func verifyChain(t *testing.T, childToken string, resolve KeyResolver, rootDID string) error {
	t.Helper()
	header, payload, err := DecodeJWSUnsafe(childToken)
	if err != nil {
		t.Fatalf("decode child: %v", err)
	}
	pubKey, err := resolve(header.Kid)
	if err != nil {
		return err
	}
	vc, err := VerifyCredential(childToken, pubKey, "", "")
	if err != nil {
		return err
	}
	childAtt := ParseAtt(payload)
	childPrf, err := ParsePrf(payload)
	if err != nil {
		return err
	}
	return verifyDelegationChain(childToken, vc, childAtt, childPrf, resolve, rootDID, nil, nil, 0)
}

func att(resource, action string) []map[string]string {
	return []map[string]string{{"resource": resource, "action": action}}
}

// ---------------------------------------------------------------------------
// 2-hop accept
// ---------------------------------------------------------------------------

func TestDelegationTwoHopAccept(t *testing.T) {
	now := time.Now().Unix()
	root := newCredParty(t, "root")
	member := newCredParty(t, "member")

	rootCred := mintCred(t, credSpec{
		issuer: root, aud: member.did,
		att: att("chain:abc", "read"),
		exp: now + 3600, iat: now,
	})
	childCred := mintCred(t, credSpec{
		issuer: member, aud: "*",
		att: att("chain:abc", "read"),
		prf: []string{rootCred},
		exp: now + 1800, iat: now,
	})

	if err := verifyChain(t, childCred, mapResolver(root, member), root.did); err != nil {
		t.Fatalf("expected 2-hop chain to verify, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 3-hop accept (root → member → sub-delegate)
// ---------------------------------------------------------------------------

func TestDelegationThreeHopAccept(t *testing.T) {
	now := time.Now().Unix()
	root := newCredParty(t, "root")
	member := newCredParty(t, "member")
	sub := newCredParty(t, "sub")

	rootCred := mintCred(t, credSpec{
		issuer: root, aud: member.did,
		att: att("chain:abc", "read"),
		exp: now + 3600, iat: now,
	})
	memberCred := mintCred(t, credSpec{
		issuer: member, aud: sub.did,
		att: att("chain:abc", "read"),
		prf: []string{rootCred},
		exp: now + 1800, iat: now,
	})
	subCred := mintCred(t, credSpec{
		issuer: sub, aud: "*",
		att: att("chain:abc", "read"),
		prf: []string{memberCred},
		exp: now + 900, iat: now,
	})

	if err := verifyChain(t, subCred, mapResolver(root, member, sub), root.did); err != nil {
		t.Fatalf("expected 3-hop chain to verify, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// scope-narrowing accept (multi-resource parent, single-resource child)
// ---------------------------------------------------------------------------

func TestDelegationScopeNarrowingAccept(t *testing.T) {
	now := time.Now().Unix()
	root := newCredParty(t, "root")
	member := newCredParty(t, "member")

	rootCred := mintCred(t, credSpec{
		issuer: root, aud: member.did,
		att: []map[string]string{
			{"resource": "chain:abc", "action": "read"},
			{"resource": "chain:def", "action": "read"},
		},
		exp: now + 3600, iat: now,
	})
	// child narrows to just chain:abc — allowed
	childCred := mintCred(t, credSpec{
		issuer: member, aud: "*",
		att: att("chain:abc", "read"),
		prf: []string{rootCred},
		exp: now + 1800, iat: now,
	})

	if err := verifyChain(t, childCred, mapResolver(root, member), root.did); err != nil {
		t.Fatalf("expected scope-narrowing child to verify, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// audience-gap reject (child issuer != parent audience)
// ---------------------------------------------------------------------------

func TestDelegationAudienceGapReject(t *testing.T) {
	now := time.Now().Unix()
	root := newCredParty(t, "root")
	member := newCredParty(t, "member")
	stranger := newCredParty(t, "stranger")

	// root delegates to member, but the child is issued by STRANGER
	rootCred := mintCred(t, credSpec{
		issuer: root, aud: member.did,
		att: att("chain:abc", "read"),
		exp: now + 3600, iat: now,
	})
	childCred := mintCred(t, credSpec{
		issuer: stranger, aud: "*",
		att: att("chain:abc", "read"),
		prf: []string{rootCred},
		exp: now + 1800, iat: now,
	})

	err := verifyChain(t, childCred, mapResolver(root, member, stranger), root.did)
	if err == nil {
		t.Fatal("expected audience-gap chain to be REJECTED, got nil")
	}
	if !strings.Contains(err.Error(), "delegation gap") {
		t.Errorf("expected delegation-gap rejection, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// expiry-extension reject (child exp exceeds parent exp)
// ---------------------------------------------------------------------------

func TestDelegationExpiryExtensionReject(t *testing.T) {
	now := time.Now().Unix()
	root := newCredParty(t, "root")
	member := newCredParty(t, "member")

	rootCred := mintCred(t, credSpec{
		issuer: root, aud: member.did,
		att: att("chain:abc", "read"),
		exp: now + 1800, iat: now,
	})
	// child tries to extend expiry BEYOND the parent
	childCred := mintCred(t, credSpec{
		issuer: member, aud: "*",
		att: att("chain:abc", "read"),
		prf: []string{rootCred},
		exp: now + 3600, iat: now,
	})

	err := verifyChain(t, childCred, mapResolver(root, member), root.did)
	if err == nil {
		t.Fatal("expected expiry-extension chain to be REJECTED, got nil")
	}
	if !strings.Contains(err.Error(), "expiry exceeds parent") {
		t.Errorf("expected expiry-extension rejection, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// scope-widening reject (child resource not covered by parent)
// ---------------------------------------------------------------------------

func TestDelegationScopeWideningReject(t *testing.T) {
	now := time.Now().Unix()
	root := newCredParty(t, "root")
	member := newCredParty(t, "member")

	rootCred := mintCred(t, credSpec{
		issuer: root, aud: member.did,
		att: att("chain:abc", "read"),
		exp: now + 3600, iat: now,
	})
	// child tries to widen to chain:def, which the parent never granted
	childCred := mintCred(t, credSpec{
		issuer: member, aud: "*",
		att: att("chain:def", "read"),
		prf: []string{rootCred},
		exp: now + 1800, iat: now,
	})

	err := verifyChain(t, childCred, mapResolver(root, member), root.did)
	if err == nil {
		t.Fatal("expected scope-widening chain to be REJECTED, got nil")
	}
	if !strings.Contains(err.Error(), "scope exceeds parent") {
		t.Errorf("expected scope-widening rejection, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// root-issuer-mismatch reject (a prf-less credential whose issuer is not root)
// ---------------------------------------------------------------------------

func TestDelegationRootIssuerMismatchReject(t *testing.T) {
	now := time.Now().Unix()
	root := newCredParty(t, "root")
	impostor := newCredParty(t, "impostor")

	// a root credential issued by the impostor, claiming to root at `root.did`
	cred := mintCred(t, credSpec{
		issuer: impostor, aud: "*",
		att: att("chain:abc", "read"),
		exp: now + 3600, iat: now,
	})

	err := verifyChain(t, cred, mapResolver(impostor), root.did)
	if err == nil {
		t.Fatal("expected root-issuer-mismatch to be REJECTED, got nil")
	}
	if !strings.Contains(err.Error(), "root issuer") {
		t.Errorf("expected root-issuer-mismatch rejection, got: %v", err)
	}
}
