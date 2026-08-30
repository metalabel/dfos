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

// keys-per-role: an identity operation MUST carry at most 256 keys in any single
// role array (authKeys/assertKeys/controllerKeys). A generous cardinality cap,
// enforced in the TS schema (.max(MAX_KEYS_PER_ROLE)) and the Go library
// (payloadMultikeyArray). The op-size cap is the real byte arbiter; this cap
// rarely binds in practice.
//
// THE CAP IS EXERCISED ON AN UPDATE, not a genesis, because a genesis declares
// exactly one key in each role and any other shape is refused for THAT reason —
// a 257-key create would come back rejected without the cap ever running.
//
// The 256-key positive control carries NO possession envelopes, and is accepted
// anyway. That is not an oversight: cardinality is structural and possession is
// not, so the 255 introduced keys are void — declared, never effective — while
// the operation itself sequences exactly as any other. An accept here is the
// cap's answer, and nothing else's.
func TestKeysPerRoleCap(t *testing.T) {
	base := relayURL(t)

	// 257 auth keys on an update → over the cap → rejected.
	overID := createIdentity(t, base)
	over := make([]dfos.MultikeyPublicKey, 257)
	for i := range over {
		over[i] = newKeypair().mk
	}
	overTok, _ := signIdentityUpdateWithProofs(t, overID.genCID,
		[]dfos.MultikeyPublicKey{overID.controller.mk}, over, []dfos.MultikeyPublicKey{},
		nil, overID.did+"#"+overID.controller.keyID, overID.controller.priv,
	)
	if st, _ := postStatus(t, base, overTok); st != "rejected" {
		t.Fatalf("257 authKeys should be rejected, got status %q", st)
	}

	// 256 auth keys → at the cap → accepted (positive control).
	underID := createIdentity(t, base)
	under := make([]dfos.MultikeyPublicKey, 256)
	for i := range under {
		under[i] = newKeypair().mk
	}
	underTok, _ := signIdentityUpdateWithProofs(t, underID.genCID,
		[]dfos.MultikeyPublicKey{underID.controller.mk}, under, []dfos.MultikeyPublicKey{},
		nil, underID.did+"#"+underID.controller.keyID, underID.controller.priv,
	)
	if st, e := postStatus(t, base, underTok); st != "new" {
		t.Fatalf("256 authKeys should be accepted, got status %q (%s)", st, e)
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
	readerSigner := signerFor(reader)
	creatorKid := creator.did + "#" + creator.auth.keyID
	exp := time.Now().Unix() + 300
	grant := map[string]string{"resource": "chain:" + cc.contentID, "action": "read"}

	// positive control: 32 entries (all granting the read) → access granted.
	att32 := make([]map[string]string, 32)
	for i := range att32 {
		att32[i] = grant
	}
	ok := signCredentialV(t, 1, creator.did, reader.did, creatorKid, att32, []string{}, exp, creator.auth.priv)
	if r := getBlobWithCred(t, base, cc.contentID, readerSigner, ok); r.StatusCode != 200 {
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
	if r := getBlobWithCred(t, base, cc.contentID, readerSigner, bad); r.StatusCode == 200 {
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
		"futureExtension": "ignored-by-spec",
	}
	_, _, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}
	header := dfos.JWSHeader{Alg: "EdDSA", Typ: "did:dfos:content-op", Kid: kid, CID: cidStr}
	signer, err := dfos.CreateJWS(header, payload, id.auth.priv)
	if err != nil {
		t.Fatalf("CreateJWS: %v", err)
	}

	if st, msg := postStatus(t, base, signer); st != "new" {
		t.Fatalf("operation with an unknown top-level field should be accepted, got status %q (%s)", st, msg)
	}
}
