package conformance

import (
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// Bounds conformance — the cardinality caps and the ignore-unknown contract that
// replaced the per-field string-length zoo. Each rule holds identically on both
// relays (validity-determining), and each rejection is paired with a POSITIVE
// CONTROL just under the bound so the rejection is provably the rule under test.

// keys-per-role: an identity operation MUST carry at most 16 keys in any single
// role array (authKeys/assertKeys/controllerKeys). A cardinality cap, enforced
// in the TS schema (.max(MAX_KEYS_PER_ROLE)) and the Go library
// (payloadMultikeyArray); previously TS-only.
func TestKeysPerRoleCap(t *testing.T) {
	base := relayURL(t)

	// 17 auth keys → over the cap → rejected.
	ctrlOver := newKeypair()
	over := make([]dfos.MultikeyPublicKey, 17)
	for i := range over {
		over[i] = newKeypair().mk
	}
	overTok, _, _, err := dfos.SignIdentityCreate(
		[]dfos.MultikeyPublicKey{ctrlOver.mk}, over, []dfos.MultikeyPublicKey{},
		ctrlOver.keyID, ctrlOver.priv,
	)
	if err != nil {
		t.Fatalf("SignIdentityCreate (over): %v", err)
	}
	if st, _ := postStatus(t, base, overTok); st != "rejected" {
		t.Fatalf("17 authKeys should be rejected, got status %q", st)
	}

	// 16 auth keys → at the cap → accepted (positive control).
	ctrlUnder := newKeypair()
	under := make([]dfos.MultikeyPublicKey, 16)
	for i := range under {
		under[i] = newKeypair().mk
	}
	underTok, _, _, err := dfos.SignIdentityCreate(
		[]dfos.MultikeyPublicKey{ctrlUnder.mk}, under, []dfos.MultikeyPublicKey{},
		ctrlUnder.keyID, ctrlUnder.priv,
	)
	if err != nil {
		t.Fatalf("SignIdentityCreate (under): %v", err)
	}
	if st, _ := postStatus(t, base, underTok); st != "new" {
		t.Fatalf("16 authKeys should be accepted, got status %q", st)
	}
}

// att cardinality: a credential MUST carry at most 32 attenuation entries. A
// cardinality cap, enforced in the TS schema (.max(MAX_ATT)) and the Go library
// (verifyCredentialCore); previously TS-only. Tested over the credential read
// path with a positive control at exactly 32.
func TestCredentialAttCardinalityCap(t *testing.T) {
	base := relayURL(t)
	creator, cc, _ := credContentFixture(t, base)

	reader := createIdentity(t, base)
	readerTok := authToken(t, base, reader)
	creatorKid := creator.did + "#" + creator.auth.keyID
	exp := time.Now().Unix() + 300
	grant := map[string]string{"resource": "chain:" + cc.contentID, "action": "read"}

	// positive control: 32 entries (all granting the read) → access granted.
	att32 := make([]map[string]string, 32)
	for i := range att32 {
		att32[i] = grant
	}
	ok := signCredentialV(t, 1, creator.did, reader.did, creatorKid, att32, []string{}, exp, creator.auth.priv)
	if r := getBlobWithCred(t, base, cc.contentID, readerTok, ok); r.StatusCode != 200 {
		b := readBody(t, r)
		t.Fatalf("positive control: 32-att credential should grant access, got %d: %s", r.StatusCode, b)
	} else {
		r.Body.Close()
	}

	// 33 entries → over the cap → rejected.
	att33 := make([]map[string]string, 33)
	for i := range att33 {
		att33[i] = grant
	}
	bad := signCredentialV(t, 1, creator.did, reader.did, creatorKid, att33, []string{}, exp, creator.auth.priv)
	if r := getBlobWithCred(t, base, cc.contentID, readerTok, bad); r.StatusCode == 200 {
		t.Fatal("33-att credential (over cap) should be rejected")
	} else {
		r.Body.Close()
	}
}

// ignore-unknown: a proof-plane operation carrying an unknown top-level field is
// ACCEPTED — unknown keys are preserved-and-ignored, honoring the protocol's
// MUST-ignore-unknown forward-compat rule. Both relays agree (TS uses
// looseObject; Go decodes into map[string]any). The CID commits to the exact
// bytes including the unknown key, so integrity is unaffected. This is the
// cross-impl proof of the strictObject → looseObject relaxation.
func TestUnknownEnvelopeKeyTolerated(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	doc := map[string]any{"$schema": "https://schemas.dfos.com/post/v1", "format": "short-post", "body": "hi"}
	docCID, _, err := dfos.DocumentCID(doc)
	if err != nil {
		t.Fatalf("DocumentCID: %v", err)
	}
	kid := id.did + "#" + id.auth.keyID

	// hand-built content-create with an unknown top-level field, CID committing
	// to the full payload (including the unknown key).
	payload := map[string]any{
		"version":         1,
		"type":            "create",
		"did":             id.did,
		"documentCID":     docCID,
		"baseDocumentCID": nil,
		"createdAt":       time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"note":            nil,
		"futureExtension": "ignored-by-spec",
	}
	_, _, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}
	header := dfos.JWSHeader{Alg: "EdDSA", Typ: "did:dfos:content-op", Kid: kid, CID: cidStr}
	tok, err := dfos.CreateJWS(header, payload, id.auth.priv)
	if err != nil {
		t.Fatalf("CreateJWS: %v", err)
	}

	if st, msg := postStatus(t, base, tok); st != "new" {
		t.Fatalf("operation with an unknown top-level field should be accepted, got status %q (%s)", st, msg)
	}
}
