package conformance

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// Credential semantic-rejection conformance. These four rules are enforced
// identically in the TS and Go credential verifiers (unlike the field-size /
// strict-schema family, which is TS-only, and the max-depth boundary, which is
// off-by-one between the two impls — both excluded here):
//   - version MUST be literal 1
//   - delegation is LINEAR — prf MUST have at most one entry
//   - a child's action set MUST be a subset of the parent's (no action widening)
//   - a child MUST NOT widen a chain:<id> grant to chain:* (resource widening)
//
// Each test pairs the rejection with a POSITIVE CONTROL — the same delegation
// without the violation grants access — so a rejection is provably the rule
// under test and not an unrelated malformation.

// signCredentialV builds + signs a DFOS credential with an explicit version,
// mirroring the library's credential construction (DagCborCID + CreateJWS).
func signCredentialV(t *testing.T, version int64, iss, aud, kid string, att []map[string]string, prf []string, exp int64, priv ed25519.PrivateKey) string {
	t.Helper()
	payload := map[string]any{
		"version": version,
		"type":    "DFOSCredential",
		"iss":     iss,
		"aud":     aud,
		"att":     att,
		"prf":     prf,
		"exp":     exp,
		"iat":     time.Now().Unix(),
	}
	_, _, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID for credential: %v", err)
	}
	header := dfos.JWSHeader{Alg: "EdDSA", Typ: "did:dfos:credential", Kid: kid, CID: cidStr}
	token, err := dfos.CreateJWS(header, payload, priv)
	if err != nil {
		t.Fatalf("CreateJWS for credential: %v", err)
	}
	return token
}

// credContentFixture creates a content chain with an uploaded blob and returns
// the creator + content for credential read-path tests.
func credContentFixture(t *testing.T, base string) (creator identity, cc contentChain, blob []byte) {
	t.Helper()
	creator = createIdentity(t, base)
	cc = createContent(t, base, creator)
	tok := authToken(t, base, creator)
	blob, _ = json.Marshal(cc.document)
	putBlob(t, base, cc.contentID, cc.genCID, tok, blob).Body.Close()
	return creator, cc, blob
}

func TestCredentialRejectsWrongVersion(t *testing.T) {
	base := relayURL(t)
	creator, cc, _ := credContentFixture(t, base)

	reader := createIdentity(t, base)
	readerTok := authToken(t, base, reader)
	creatorKid := creator.did + "#" + creator.auth.keyID
	att := []map[string]string{{"resource": "chain:" + cc.contentID, "action": "read"}}
	exp := time.Now().Unix() + 300

	// positive control: a version-1 root credential grants access.
	ok := signCredentialV(t, 1, creator.did, reader.did, creatorKid, att, []string{}, exp, creator.auth.priv)
	if r := getBlobWithCred(t, base, cc.contentID, readerTok, ok); r.StatusCode != 200 {
		b := readBody(t, r)
		t.Fatalf("positive control: version-1 credential should grant access, got %d: %s", r.StatusCode, b)
	} else {
		r.Body.Close()
	}

	// version != 1 → rejected.
	bad := signCredentialV(t, 2, creator.did, reader.did, creatorKid, att, []string{}, exp, creator.auth.priv)
	if r := getBlobWithCred(t, base, cc.contentID, readerTok, bad); r.StatusCode == 200 {
		t.Fatal("credential with version != 1 should be rejected")
	} else {
		r.Body.Close()
	}
}

func TestCredentialRejectsMultiParentPrf(t *testing.T) {
	base := relayURL(t)
	creator, cc, _ := credContentFixture(t, base)

	delegate := createIdentity(t, base)
	reader := createIdentity(t, base)
	readerTok := authToken(t, base, reader)
	creatorKid := creator.did + "#" + creator.auth.keyID
	delegateKid := delegate.did + "#" + delegate.auth.keyID
	att := []map[string]string{{"resource": "chain:" + cc.contentID, "action": "read"}}
	rootExp := time.Now().Unix() + 300
	leafExp := time.Now().Unix() + 200

	rootCred := signCredentialV(t, 1, creator.did, delegate.did, creatorKid, att, []string{}, rootExp, creator.auth.priv)

	// positive control: a single-parent leaf grants access.
	okLeaf := signCredentialV(t, 1, delegate.did, reader.did, delegateKid, att, []string{rootCred}, leafExp, delegate.auth.priv)
	if r := getBlobWithCred(t, base, cc.contentID, readerTok, okLeaf); r.StatusCode != 200 {
		b := readBody(t, r)
		t.Fatalf("positive control: single-parent delegation should grant access, got %d: %s", r.StatusCode, b)
	} else {
		r.Body.Close()
	}

	// two parents (prf length > 1) → rejected: delegation is linear.
	badLeaf := signCredentialV(t, 1, delegate.did, reader.did, delegateKid, att, []string{rootCred, rootCred}, leafExp, delegate.auth.priv)
	if r := getBlobWithCred(t, base, cc.contentID, readerTok, badLeaf); r.StatusCode == 200 {
		t.Fatal("multi-parent credential (prf > 1) should be rejected")
	} else {
		r.Body.Close()
	}
}

func TestDelegationRejectsActionWidening(t *testing.T) {
	base := relayURL(t)
	creator, cc, _ := credContentFixture(t, base)

	delegate := createIdentity(t, base)
	reader := createIdentity(t, base)
	readerTok := authToken(t, base, reader)
	creatorKid := creator.did + "#" + creator.auth.keyID
	delegateKid := delegate.did + "#" + delegate.auth.keyID
	rootExp := time.Now().Unix() + 300
	leafExp := time.Now().Unix() + 200

	// root grants read only.
	rootAtt := []map[string]string{{"resource": "chain:" + cc.contentID, "action": "read"}}
	rootCred := signCredentialV(t, 1, creator.did, delegate.did, creatorKid, rootAtt, []string{}, rootExp, creator.auth.priv)

	// positive control: child with the same (read) action grants access.
	okLeaf := signCredentialV(t, 1, delegate.did, reader.did, delegateKid, rootAtt, []string{rootCred}, leafExp, delegate.auth.priv)
	if r := getBlobWithCred(t, base, cc.contentID, readerTok, okLeaf); r.StatusCode != 200 {
		b := readBody(t, r)
		t.Fatalf("positive control: non-widened action should grant access, got %d: %s", r.StatusCode, b)
	} else {
		r.Body.Close()
	}

	// child widens the action set (read,write ⊋ read) → rejected.
	wideAtt := []map[string]string{{"resource": "chain:" + cc.contentID, "action": "read,write"}}
	badLeaf := signCredentialV(t, 1, delegate.did, reader.did, delegateKid, wideAtt, []string{rootCred}, leafExp, delegate.auth.priv)
	if r := getBlobWithCred(t, base, cc.contentID, readerTok, badLeaf); r.StatusCode == 200 {
		t.Fatal("delegated credential widening the action set should be rejected")
	} else {
		r.Body.Close()
	}
}

func TestDelegationRejectsChainWildcardWidening(t *testing.T) {
	base := relayURL(t)
	creator, cc, _ := credContentFixture(t, base)

	delegate := createIdentity(t, base)
	reader := createIdentity(t, base)
	readerTok := authToken(t, base, reader)
	creatorKid := creator.did + "#" + creator.auth.keyID
	delegateKid := delegate.did + "#" + delegate.auth.keyID
	rootExp := time.Now().Unix() + 300
	leafExp := time.Now().Unix() + 200

	// root grants a specific chain.
	rootAtt := []map[string]string{{"resource": "chain:" + cc.contentID, "action": "read"}}
	rootCred := signCredentialV(t, 1, creator.did, delegate.did, creatorKid, rootAtt, []string{}, rootExp, creator.auth.priv)

	// positive control: child scoped to the same specific chain grants access.
	okLeaf := signCredentialV(t, 1, delegate.did, reader.did, delegateKid, rootAtt, []string{rootCred}, leafExp, delegate.auth.priv)
	if r := getBlobWithCred(t, base, cc.contentID, readerTok, okLeaf); r.StatusCode != 200 {
		b := readBody(t, r)
		t.Fatalf("positive control: non-widened resource should grant access, got %d: %s", r.StatusCode, b)
	} else {
		r.Body.Close()
	}

	// child widens chain:<id> → chain:* → rejected.
	wideAtt := []map[string]string{{"resource": "chain:*", "action": "read"}}
	badLeaf := signCredentialV(t, 1, delegate.did, reader.did, delegateKid, wideAtt, []string{rootCred}, leafExp, delegate.auth.priv)
	if r := getBlobWithCred(t, base, cc.contentID, readerTok, badLeaf); r.StatusCode == 200 {
		t.Fatal("delegated credential widening chain:<id> to chain:* should be rejected")
	} else {
		r.Body.Close()
	}
}
