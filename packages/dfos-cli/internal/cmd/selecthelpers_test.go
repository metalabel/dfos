package cmd

// Unit tests for the held-key selection + guarded-append helpers. These do not
// touch a relay and only use the in-memory keystore, so they are cheap. They
// still mutate the package-global `keys`, so they MUST NOT run in parallel.

import (
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/keystore"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

func mkSet(ids ...string) []protocol.MultikeyPublicKey {
	out := make([]protocol.MultikeyPublicKey, 0, len(ids))
	for _, id := range ids {
		out = append(out, protocol.MultikeyPublicKey{ID: id, Type: "Multikey", PublicKeyMultibase: "z" + id})
	}
	return out
}

func TestSelectHeldKey_FirstHeldInPublishedOrder(t *testing.T) {
	did := "did:dfos:test"
	store := keystore.NewMemoryStore()
	// device holds only key1, not key0 — selection must skip key0 and return key1
	if _, _, err := store.GenerateKey(did + "#key1"); err != nil {
		t.Fatal(err)
	}
	prev := keys
	keys = store
	defer func() { keys = prev }()

	kid, err := selectHeldKey(did, mkSet("key0", "key1", "key2"), "auth")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kid != did+"#key1" {
		t.Fatalf("got %s, want %s", kid, did+"#key1")
	}
}

func TestSelectHeldKey_FirstWhenMultipleHeld(t *testing.T) {
	did := "did:dfos:test"
	store := keystore.NewMemoryStore()
	store.GenerateKey(did + "#key0")
	store.GenerateKey(did + "#key2")
	prev := keys
	keys = store
	defer func() { keys = prev }()

	// holds key0 and key2 — published order picks key0 first (deterministic)
	kid, err := selectHeldKey(did, mkSet("key0", "key1", "key2"), "auth")
	if err != nil {
		t.Fatal(err)
	}
	if kid != did+"#key0" {
		t.Fatalf("got %s, want first-held %s", kid, did+"#key0")
	}
}

func TestSelectHeldKey_EmptySet(t *testing.T) {
	prev := keys
	keys = keystore.NewMemoryStore()
	defer func() { keys = prev }()

	_, err := selectHeldKey("did:dfos:test", nil, "auth")
	if err == nil {
		t.Fatal("expected error for empty set")
	}
	if !strings.Contains(err.Error(), "no held auth key") {
		t.Fatalf("unexpected message: %v", err)
	}
}

func TestSelectHeldKey_NoneHeld(t *testing.T) {
	prev := keys
	keys = keystore.NewMemoryStore() // holds nothing
	defer func() { keys = prev }()

	_, err := selectHeldKey("did:dfos:test", mkSet("key0", "key1"), "controller")
	if err == nil {
		t.Fatal("expected error when device holds none of the keys")
	}
	if !strings.Contains(err.Error(), "no held controller key") {
		t.Fatalf("unexpected message: %v", err)
	}
}

func TestAppendKeyGuarded_AppendsCopy(t *testing.T) {
	set := mkSet("key0")
	newKey := protocol.MultikeyPublicKey{ID: "key1", Type: "Multikey", PublicKeyMultibase: "zkey1"}

	out, err := appendKeyGuarded(set, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[1].ID != "key1" {
		t.Fatalf("expected [key0 key1], got %+v", out)
	}
	// original set must be untouched (copy-then-append, no aliasing)
	if len(set) != 1 {
		t.Fatalf("input set was mutated: %+v", set)
	}
}

func TestAppendKeyGuarded_DuplicateRejected(t *testing.T) {
	set := mkSet("key0", "key1")
	dup := protocol.MultikeyPublicKey{ID: "key1", Type: "Multikey", PublicKeyMultibase: "zkey1"}
	if _, err := appendKeyGuarded(set, dup); err == nil {
		t.Fatal("expected duplicate id to be rejected")
	}
}

func TestAppendKeyGuarded_CapRejectsSeventeenth(t *testing.T) {
	ids := make([]string, roleKeyCap)
	for i := range ids {
		ids[i] = "key" + string(rune('a'+i))
	}
	set := mkSet(ids...) // exactly roleKeyCap (16) keys
	newKey := protocol.MultikeyPublicKey{ID: "overflow", Type: "Multikey", PublicKeyMultibase: "zoverflow"}
	_, err := appendKeyGuarded(set, newKey)
	if err == nil {
		t.Fatalf("expected cap error when appending key %d", roleKeyCap+1)
	}
	if !strings.Contains(err.Error(), "max") {
		t.Fatalf("unexpected cap error: %v", err)
	}
}

func TestDeviceMultikeyRoundTrip(t *testing.T) {
	// the transport string from device-pubkey must decode back to the raw pubkey
	_, pub, err := keystore.NewMemoryStore().GenerateKey("did:dfos:test#k")
	if err != nil {
		t.Fatal(err)
	}
	mk := protocol.NewMultikeyPublicKey("k", pub)
	raw, err := protocol.DecodeMultikey(mk.PublicKeyMultibase)
	if err != nil {
		t.Fatalf("decode multikey: %v", err)
	}
	if string(raw) != string(pub) {
		t.Fatal("round-trip mismatch: decoded pubkey != original")
	}
}
