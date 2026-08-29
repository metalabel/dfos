package cmd

// Unit tests for the held-key selection + guarded-append helpers. These do not
// touch a relay and only use the in-memory keystore, so they are cheap. They
// still mutate the package-global `keys`, so they MUST NOT run in parallel.

import (
	"fmt"
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

// The accounts here are the LEGACY `<did>#<keyId>` shape on purpose: this is the
// read-compat case, a key written before keys were addressed by their content.
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

	got, err := selectHeldKey(did, mkSet("key0", "key1", "key2"), "auth")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.KID != did+"#key1" {
		t.Fatalf("got kid %s, want %s", got.KID, did+"#key1")
	}
	if got.Account != did+"#key1" {
		t.Fatalf("got account %s, want the legacy account %s", got.Account, did+"#key1")
	}
}

// A key written under its content address resolves through the same call, and
// the kid it reports is still the DID URL a signature has to carry.
func TestSelectHeldKey_ContentAddressedAccount(t *testing.T) {
	did := "did:dfos:test"
	store := keystore.NewMemoryStore()
	set := mkSet("key0", "key1")
	if _, _, err := store.GenerateKey(keyAccount(set[1].PublicKeyMultibase)); err != nil {
		t.Fatal(err)
	}
	prev := keys
	keys = store
	defer func() { keys = prev }()

	got, err := selectHeldKey(did, set, "auth")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.KID != did+"#key1" {
		t.Fatalf("got kid %s, want %s", got.KID, did+"#key1")
	}
	if got.Account != keyAccount(set[1].PublicKeyMultibase) {
		t.Fatalf("got account %s, want the content address", got.Account)
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
	got, err := selectHeldKey(did, mkSet("key0", "key1", "key2"), "auth")
	if err != nil {
		t.Fatal(err)
	}
	if got.KID != did+"#key0" {
		t.Fatalf("got %s, want first-held %s", got.KID, did+"#key0")
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

// keySet builds n distinct keys, for exercising the cap boundary.
func keySet(n int) []protocol.MultikeyPublicKey {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("key%d", i)
	}
	return mkSet(ids...)
}

// TestAppendKeyGuarded_CapIsTheProtocolCap pins the boundary to the number
// PROTOCOL.md and the TS schemas both state — 256 per role. The guard read 16,
// which rejected a seventeenth key every conformant implementation accepts.
func TestAppendKeyGuarded_CapIsTheProtocolCap(t *testing.T) {
	if roleKeyCap != 256 {
		t.Fatalf("roleKeyCap = %d, want 256 (PROTOCOL.md 'Cardinality caps', MAX_KEYS_PER_ROLE)", roleKeyCap)
	}

	newKey := protocol.MultikeyPublicKey{ID: "overflow", Type: "Multikey", PublicKeyMultibase: "zoverflow"}

	// One under the cap: a spec-valid set the CLI must not refuse.
	if _, err := appendKeyGuarded(keySet(roleKeyCap-1), newKey); err != nil {
		t.Fatalf("appending key %d must be allowed: %v", roleKeyCap, err)
	}

	// At the cap: the next one overflows.
	_, err := appendKeyGuarded(keySet(roleKeyCap), newKey)
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
