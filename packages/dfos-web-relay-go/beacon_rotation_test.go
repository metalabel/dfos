package relay

import (
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// ===================================================================
// Beacon rotation (WP-9) — FIRST beacon-resolver coverage for the Go twin
//
// Beacons resolve against CURRENT identity state (ingestBeacon uses
// CreateCurrentKeyResolver), so a beacon signed by a ROTATED-OUT key must be
// rejected and a beacon signed by the CURRENT key accepted + become the head.
// The test must go through relay Ingest() with the ROTATION ingested first —
// the only beacon tests in dfos-protocol-go call VerifyBeacon with a fixed
// single-key resolver (no rotation, no relay), so this is the first end-to-end
// rotation coverage on the Go side. Mirrors the TS relay.spec.ts beacon-rotation
// test added in this PR.
// ===================================================================

func TestBeaconRejectsRotatedOutKeyAcceptsCurrent(t *testing.T) {
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}

	// create an identity (controller key = the beacon signer)
	id := createTestIdentity(t)
	if r := relay.Ingest([]string{id.token}); r[0].Status != "new" {
		t.Fatalf("expected identity create to be new, got %s (%s)", r[0].Status, r[0].Error)
	}

	// rotate the controller key — the old controller key is removed from current
	// state. The current controller signs its own rotation.
	newController := newTestKeypair()
	updateToken, _, err := dfos.SignIdentityUpdate(
		id.opCID,
		[]dfos.MultikeyPublicKey{newController.mk}, // new controller (old removed)
		[]dfos.MultikeyPublicKey{id.auth.mk},
		[]dfos.MultikeyPublicKey{},
		id.did+"#"+id.controller.keyID, // signed by the CURRENT (old) controller
		id.controller.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	if r := relay.Ingest([]string{updateToken}); r[0].Status != "new" {
		t.Fatalf("expected rotation to be new, got %s (%s)", r[0].Status, r[0].Error)
	}

	// beacon signed by the OLD (rotated-out) controller key → REJECTED
	staleBeacon, _, err := dfos.SignBeacon(
		id.did, staleManifestID,
		id.did+"#"+id.controller.keyID, // OLD controller key
		id.controller.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	if r := relay.Ingest([]string{staleBeacon}); r[0].Status != "rejected" {
		t.Fatalf("expected beacon from rotated-out key to be REJECTED, got %s", r[0].Status)
	}

	// no beacon should be recorded
	if b, _ := store.GetBeacon(id.did); b != nil {
		t.Fatal("expected no beacon recorded after rotated-out-key rejection")
	}

	// beacon signed by the CURRENT (new) controller key → ACCEPTED + head
	freshBeacon, freshCID, err := dfos.SignBeacon(
		id.did, freshManifestID,
		id.did+"#"+newController.keyID, // CURRENT controller key
		newController.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	if r := relay.Ingest([]string{freshBeacon}); r[0].Status != "new" {
		t.Fatalf("expected beacon from current key to be ACCEPTED, got %s (%s)", r[0].Status, r[0].Error)
	}

	b, _ := store.GetBeacon(id.did)
	if b == nil {
		t.Fatal("expected the current-key beacon to be recorded as head")
	}
	if b.BeaconCID != freshCID {
		t.Fatalf("expected head beacon CID %s, got %s", freshCID, b.BeaconCID)
	}
	if b.Payload.ManifestContentId != freshManifestID {
		t.Fatalf("expected %s, got %s", freshManifestID, b.Payload.ManifestContentId)
	}
}

// 31-character content IDs (the Go VerifyBeacon validates manifestContentId
// length == 31). Content of the string is unchecked; only the length matters.
const (
	staleManifestID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	freshManifestID = "ccccccccccccccccccccccccccccccc"
)
