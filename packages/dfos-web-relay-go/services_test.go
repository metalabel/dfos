package relay

import (
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// 0.11.0 relay-level coverage: the relay must project a full-state identity
// `services` set into stored identity state, and round-trip a countersignature
// `relation` tag. These exercise the ingest → store → read path directly,
// complementing the cross-implementation suite in packages/relay-conformance.

const svcAnchor = "cv7n8vkvr64cctf3294h9k4eanhff8z" // 31-char content id

func svcEntry(fields map[string]any) dfos.ServiceEntry { return fields }

// ingestIdentityWithServices signs + ingests a genesis carrying services and
// returns the controller/auth keys + did for follow-up updates.
func ingestIdentityWithServices(t *testing.T, relay *Relay, services []dfos.ServiceEntry) (did, headCID string, ctrl, auth testKeypair) {
	t.Helper()
	ctrl = newTestKeypair()
	auth = newTestKeypair()
	token, did, opCID, err := dfos.SignIdentityCreateWithServices(
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{auth.mk},
		nil,
		services,
		ctrl.keyID,
		ctrl.priv,
	)
	if err != nil {
		t.Fatalf("SignIdentityCreateWithServices: %v", err)
	}
	if res := relay.Ingest([]string{token}); res[0].Status != "new" {
		t.Fatalf("ingest identity w/ services: status %s err %s", res[0].Status, res[0].Error)
	}
	return did, opCID, ctrl, auth
}

func servicesByID(svcs []dfos.ServiceEntry, id string) map[string]any {
	for _, e := range svcs {
		m := map[string]any(e)
		if s, _ := m["id"].(string); s == id {
			return m
		}
	}
	return nil
}

func TestRelayProjectsServices(t *testing.T) {
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}

	did, headCID, ctrl, auth := ingestIdentityWithServices(t, relay, []dfos.ServiceEntry{
		svcEntry(map[string]any{"id": "relay", "type": "DfosRelay", "endpoint": "https://relay.dfos.com"}),
		svcEntry(map[string]any{"id": "avatar", "type": "ContentAnchor", "label": "avatar", "anchor": svcAnchor}),
	})

	chain, err := store.GetIdentityChain(did)
	if err != nil || chain == nil {
		t.Fatalf("GetIdentityChain: %v", err)
	}
	if len(chain.State.Services) != 2 {
		t.Fatalf("expected 2 projected services, got %d: %+v", len(chain.State.Services), chain.State.Services)
	}
	if r := servicesByID(chain.State.Services, "relay"); r == nil || r["endpoint"] != "https://relay.dfos.com" {
		t.Fatalf("DfosRelay not projected: %+v", r)
	}
	if a := servicesByID(chain.State.Services, "avatar"); a == nil || a["anchor"] != svcAnchor {
		t.Fatalf("ContentAnchor not projected: %+v", a)
	}

	// full-state replace: an update with a new set drops the old entries.
	updToken, updCID, err := dfos.SignIdentityUpdateWithServices(
		headCID,
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{auth.mk},
		nil,
		[]dfos.ServiceEntry{svcEntry(map[string]any{"id": "relay2", "type": "DfosRelay", "endpoint": "https://r2.example.com"})},
		did+"#"+ctrl.keyID,
		ctrl.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	if res := relay.Ingest([]string{updToken}); res[0].Status != "new" {
		t.Fatalf("ingest replace update: status %s err %s", res[0].Status, res[0].Error)
	}
	chain, _ = store.GetIdentityChain(did)
	if len(chain.State.Services) != 1 || servicesByID(chain.State.Services, "relay") != nil || servicesByID(chain.State.Services, "relay2") == nil {
		t.Fatalf("full-state replace failed: %+v", chain.State.Services)
	}

	// service-less update clears the set entirely.
	clrToken, _, err := dfos.SignIdentityUpdateWithServices(
		updCID,
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{auth.mk},
		nil,
		nil,
		did+"#"+ctrl.keyID,
		ctrl.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	if res := relay.Ingest([]string{clrToken}); res[0].Status != "new" {
		t.Fatalf("ingest clear update: status %s err %s", res[0].Status, res[0].Error)
	}
	chain, _ = store.GetIdentityChain(did)
	if len(chain.State.Services) != 0 {
		t.Fatalf("expected services cleared, got %+v", chain.State.Services)
	}
}

func TestRelayRejectsInvalidServiceEntry(t *testing.T) {
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	ctrl := newTestKeypair()
	auth := newTestKeypair()
	// ContentAnchor missing the required non-empty label.
	token, _, _, err := dfos.SignIdentityCreateWithServices(
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{auth.mk},
		nil,
		[]dfos.ServiceEntry{svcEntry(map[string]any{"id": "x", "type": "ContentAnchor", "anchor": svcAnchor})},
		ctrl.keyID,
		ctrl.priv,
	)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if res := relay.Ingest([]string{token}); res[0].Status != "rejected" {
		t.Fatalf("expected invalid ContentAnchor rejected, got status %q", res[0].Status)
	}
}

func TestRelayRoundTripsCountersignRelation(t *testing.T) {
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	author := createTestIdentity(t)
	witness := createTestIdentity(t)
	if res := relay.Ingest([]string{author.token, witness.token}); res[0].Status == "rejected" || res[1].Status == "rejected" {
		t.Fatalf("ingest identities: %+v", res)
	}

	const relation = "endorses"
	witnessKid := witness.did + "#" + witness.auth.keyID
	csToken, _, err := dfos.SignCountersignWithRelation(witness.did, author.opCID, relation, witnessKid, witness.auth.priv)
	if err != nil {
		t.Fatalf("SignCountersignWithRelation: %v", err)
	}
	if res := relay.Ingest([]string{csToken}); res[0].Status != "new" {
		t.Fatalf("ingest countersign: status %s err %s", res[0].Status, res[0].Error)
	}

	cs, err := store.GetCountersignatures(author.opCID)
	if err != nil {
		t.Fatalf("GetCountersignatures: %v", err)
	}
	if len(cs) != 1 {
		t.Fatalf("expected 1 countersignature, got %d", len(cs))
	}
	payload, err := dfos.PayloadFromJWS(cs[0])
	if err != nil {
		t.Fatalf("PayloadFromJWS: %v", err)
	}
	if got, _ := payload["relation"].(string); got != relation {
		t.Fatalf("round-tripped relation = %q, want %q", got, relation)
	}
}
