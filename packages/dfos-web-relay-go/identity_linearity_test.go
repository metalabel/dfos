package relay

import (
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

func TestIdentityConflictingExtensionPermanentDirectAndPeer(t *testing.T) {
	store := NewMemoryStore()
	id := createTestIdentity(t)
	if got := IngestOperations([]string{id.token}, store)[0]; got.Status != "new" {
		t.Fatalf("genesis: %+v", got)
	}

	time.Sleep(2 * time.Millisecond)
	kid := id.did + "#" + id.controller.keyID
	first, _, err := dfos.SignIdentityUpdate(
		genesisState(id.did, id.controller),
		id.opCID,
		[]dfos.MultikeyPublicKey{id.controller.mk},
		[]dfos.MultikeyPublicKey{id.auth.mk},
		[]dfos.MultikeyPublicKey{},
		nil, // carries the genesis key forward; introduces nothing
		kid,
		id.controller.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := IngestOperations([]string{first}, store)[0]; got.Status != "new" {
		t.Fatalf("first child: %+v", got)
	}

	time.Sleep(2 * time.Millisecond)
	otherAuth := newTestKeypair()
	conflict, conflictCID, err := dfos.SignIdentityUpdate(
		genesisState(id.did, id.controller),
		id.opCID,
		[]dfos.MultikeyPublicKey{id.controller.mk},
		[]dfos.MultikeyPublicKey{otherAuth.mk},
		[]dfos.MultikeyPublicKey{},
		[]string{testKeyProof(t, otherAuth.priv, id.did, id.opCID, "auth")},
		kid,
		id.controller.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertConflict := func(got IngestionResult) {
		t.Helper()
		if got.Status != "rejected" || got.Error != identityConflictingExtensionError || got.DependencyMissing {
			t.Fatalf("conflict: %+v", got)
		}
	}
	assertConflict(IngestOperations([]string{conflict}, store)[0])

	relay, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutRawOp(conflictCID, conflict, OpOriginPeer); err != nil {
		t.Fatal(err)
	}
	_, firstRun := relay.RunSequencer()
	if firstRun.Rejected != 1 || firstRun.Pending != 0 {
		t.Fatalf("peer conflict sequencer result: %+v", firstRun)
	}
	pending, err := store.CountUnsequenced()
	if err != nil || pending != 0 {
		t.Fatalf("peer conflict remained pending: count=%d err=%v", pending, err)
	}
	_, secondRun := relay.RunSequencer()
	if secondRun.Rejected != 0 || secondRun.Pending != 0 {
		t.Fatalf("peer conflict retried: %+v", secondRun)
	}
}
