package relay

import (
	"strings"
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// Relay-tier boundary coverage for the 16384-byte artifact payload cap.
//
// The cap itself lives in the protocol library (VerifyArtifact in
// packages/dfos-protocol-go/verify.go, const maxArtifactPayloadSize = 16384),
// enforced on the dag-cbor-encoded artifact payload AFTER signature + CID
// verification. The protocol suite already covers the constant; this test
// codifies that the relay's Ingest path honors it — an artifact whose payload
// is exactly 16384 bytes is accepted ("new"), and one a single byte over
// (16385) is rejected with the size-cap error.
//
// dfos.SignArtifact refuses to emit an over-cap token (it guards at sign time),
// so the over-cap fixture is signed directly via CreateJWS, exactly mirroring
// SignArtifact's payload shape minus that guard. Pad lengths are solved at
// runtime against the live dag-cbor encoder so the fixtures stay exact even if
// the did width or encoding overhead ever shifts.

func artifactPayloadCBORLen(t *testing.T, did string, content map[string]any) int {
	t.Helper()
	payload := map[string]any{
		"version":   1,
		"type":      "artifact",
		"did":       did,
		"content":   content,
		"createdAt": "2026-01-01T00:00:00.000Z",
	}
	cbor, _, _, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}
	return len(cbor)
}

func artifactPadContent(n int) map[string]any {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return map[string]any{
		"$schema": "https://schemas.dfos.com/profile/v1",
		"bio":     string(b),
	}
}

// padForCBOR returns the bio length whose full artifact payload dag-cbor-encodes
// to exactly targetCBOR bytes.
func padForCBOR(t *testing.T, did string, targetCBOR int) int {
	t.Helper()
	for n := 0; n <= targetCBOR; n++ {
		if artifactPayloadCBORLen(t, did, artifactPadContent(n)) == targetCBOR {
			return n
		}
	}
	t.Fatalf("no bio length yields cbor payload of %d bytes for did %s", targetCBOR, did)
	return 0
}

// signArtifactRaw mirrors dfos.SignArtifact but skips the sign-time size guard,
// so an over-cap artifact can be presented to the relay's ingest path.
func signArtifactRaw(t *testing.T, did, kid string, priv []byte, content map[string]any) string {
	t.Helper()
	payload := map[string]any{
		"version":   1,
		"type":      "artifact",
		"did":       did,
		"content":   content,
		"createdAt": "2026-01-01T00:00:00.000Z",
	}
	_, _, cid, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}
	tok, err := dfos.CreateJWS(
		dfos.JWSHeader{Alg: "EdDSA", Typ: "did:dfos:artifact", Kid: kid, CID: cid},
		payload,
		priv,
	)
	if err != nil {
		t.Fatalf("CreateJWS: %v", err)
	}
	return tok
}

func TestRelayArtifactPayloadSizeBoundary(t *testing.T) {
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}

	// seed the signing identity so the artifact's kid resolves during verify
	id := createTestIdentity(t)
	if res := relay.Ingest([]string{id.token}); res[0].Status != "new" {
		t.Fatalf("seed identity: status=%s err=%s", res[0].Status, res[0].Error)
	}
	kid := id.did + "#" + id.auth.keyID

	// at the cap (16384 bytes) — accepted
	atContent := artifactPadContent(padForCBOR(t, id.did, 16384))
	if got := artifactPayloadCBORLen(t, id.did, atContent); got != 16384 {
		t.Fatalf("at-cap fixture cbor=%d, want 16384", got)
	}
	atRes := relay.Ingest([]string{signArtifactRaw(t, id.did, kid, id.auth.priv, atContent)})
	if atRes[0].Status != "new" {
		t.Fatalf("at-cap (16384) artifact must be accepted: status=%s err=%q", atRes[0].Status, atRes[0].Error)
	}

	// one byte over the cap (16385 bytes) — rejected, citing the size cap
	overContent := artifactPadContent(padForCBOR(t, id.did, 16385))
	if got := artifactPayloadCBORLen(t, id.did, overContent); got != 16385 {
		t.Fatalf("over-cap fixture cbor=%d, want 16385", got)
	}
	overRes := relay.Ingest([]string{signArtifactRaw(t, id.did, kid, id.auth.priv, overContent)})
	if overRes[0].Status != "rejected" {
		t.Fatalf("over-cap (16385) artifact must be rejected: status=%s", overRes[0].Status)
	}
	if !strings.Contains(overRes[0].Error, "exceeds max size") {
		t.Fatalf("over-cap rejection should cite the size cap, got: %q", overRes[0].Error)
	}
}
