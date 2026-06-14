package relay

import (
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// signBeaconAtFixed hand-builds a beacon JWS with an explicit createdAt (the
// library SignBeacon stamps time.Now()), so two beacons can share an identical
// createdAt and differ only in manifest — exercising the equal-timestamp tiebreak.
func signBeaconAtFixed(t *testing.T, did, manifest, kid string, priv []byte, createdAt string) (token, cid string) {
	t.Helper()
	payload := map[string]any{
		"version":           int64(1),
		"type":              "beacon",
		"did":               did,
		"manifestContentId": manifest,
		"createdAt":         createdAt,
	}
	_, _, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID: %v", err)
	}
	header := dfos.JWSHeader{Alg: "EdDSA", Typ: "did:dfos:beacon", Kid: kid, CID: cidStr}
	token, err = dfos.CreateJWS(header, payload, priv)
	if err != nil {
		t.Fatalf("CreateJWS: %v", err)
	}
	return token, cidStr
}

// TestBeaconEqualTimestampCIDTiebreakConverges pins the equal-createdAt beacon
// tiebreak: two beacons for the same DID with identical createdAt but distinct
// CIDs must converge to the lexicographically-higher CID regardless of arrival
// order. Without the tiebreak, a relay seeing them low-then-high would replace
// while a relay seeing high-then-low would not — a divergence.
func TestBeaconEqualTimestampCIDTiebreakConverges(t *testing.T) {
	id := createTestIdentity(t)
	kid := id.did + "#" + id.controller.keyID
	createdAt := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	bA, cidA := signBeaconAtFixed(t, id.did, staleManifestID, kid, id.controller.priv, createdAt)
	bB, cidB := signBeaconAtFixed(t, id.did, freshManifestID, kid, id.controller.priv, createdAt)
	if cidA == cidB {
		t.Fatal("expected distinct beacon CIDs for distinct manifests")
	}

	higher, lower, higherCID := bA, bB, cidA
	if cidB > cidA {
		higher, lower, higherCID = bB, bA, cidB
	}

	// order 1: lower first, then higher → higher must REPLACE.
	{
		store := NewMemoryStore()
		r, _ := NewRelay(RelayOptions{Store: store})
		r.Ingest([]string{id.token})
		if res := r.Ingest([]string{lower}); res[0].Status != "new" {
			t.Fatalf("order1: first beacon should be new, got %s (%s)", res[0].Status, res[0].Error)
		}
		if res := r.Ingest([]string{higher}); res[0].Status != "new" {
			t.Fatalf("order1: higher-CID beacon should REPLACE (new), got %s", res[0].Status)
		}
		if b, _ := store.GetBeacon(id.did); b == nil || b.BeaconCID != higherCID {
			t.Fatalf("order1: expected head %s, got %v", higherCID, b)
		}
	}

	// order 2: higher first, then lower → lower must be DUPLICATE (higher stays).
	{
		store := NewMemoryStore()
		r, _ := NewRelay(RelayOptions{Store: store})
		r.Ingest([]string{id.token})
		if res := r.Ingest([]string{higher}); res[0].Status != "new" {
			t.Fatalf("order2: first beacon should be new, got %s (%s)", res[0].Status, res[0].Error)
		}
		if res := r.Ingest([]string{lower}); res[0].Status != "duplicate" {
			t.Fatalf("order2: lower-CID beacon should be DUPLICATE, got %s", res[0].Status)
		}
		if b, _ := store.GetBeacon(id.did); b == nil || b.BeaconCID != higherCID {
			t.Fatalf("order2: expected head %s, got %v", higherCID, b)
		}
	}
}
