package cmd

// Multi-device 1-of-N integration tests.
//
// The cmd package leans on package-globals (keys, cfg, localRelayInstance) that
// the root command's PersistentPreRunE normally populates. These tests bypass
// cobra wiring and set those globals directly, then drive each command's RunE.
//
// To model TWO devices that share one identity but hold DIFFERENT private keys,
// we swap the global `keys` between two MemoryStore instances around each
// operation: device A's keystore holds A's seeds, device B's holds only B's.
// The single shared local relay is the gossiped chain both devices read. This
// isolates "which private keys this device holds" (the thing under test) from
// "what the chain published" (shared). Because the globals are shared mutable
// state, these tests MUST NOT run with t.Parallel().

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/keystore"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/localrelay"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/spf13/cobra"
)

// setupDevices wires the package globals for a multi-device test and returns
// the two device keystores plus the shared local relay. cfg/keys/
// localRelayInstance and the identityFlag override are reset on cleanup so
// tests don't leak into each other.
func setupDevices(t *testing.T) (storeA, storeB *keystore.MemoryStore, lr *localrelay.LocalRelay) {
	t.Helper()

	// isolate config.Save — DFOS_CONFIG is the config.toml file path, and
	// ConfigDir() is its parent, so point it at a file inside a temp dir.
	t.Setenv("DFOS_CONFIG", t.TempDir()+"/config.toml")

	storeA = keystore.NewMemoryStore()
	storeB = keystore.NewMemoryStore()

	cfg = &config.Config{
		Relays:     map[string]config.RelayConfig{},
		Identities: map[string]config.IdentityConfig{},
		Contexts:   map[string]config.ContextConfig{},
	}

	var err error
	lr, err = localrelay.Open(cfg, &localrelay.Options{DBPath: t.TempDir() + "/relay.db"})
	if err != nil {
		t.Fatalf("open local relay: %v", err)
	}
	localRelayInstance = lr

	prevID := identityFlag
	prevJSON := jsonFlag
	t.Cleanup(func() {
		lr.Close()
		localRelayInstance = nil
		cfg = nil
		keys = nil
		identityFlag = prevID
		jsonFlag = prevJSON
	})

	return storeA, storeB, lr
}

// runJSON drives a command's RunE with jsonFlag set, capturing stdout, and
// unmarshals the JSON result into out.
func runJSON(t *testing.T, cmd *cobra.Command, args []string, out any) {
	t.Helper()
	prev := jsonFlag
	jsonFlag = true
	defer func() { jsonFlag = prev }()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	runErr := cmd.RunE(cmd, args)
	w.Close()
	os.Stdout = oldStdout
	data, _ := io.ReadAll(r)

	if runErr != nil {
		t.Fatalf("command %q failed: %v", cmd.Use, runErr)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("unmarshal output of %q: %v\nraw: %s", cmd.Use, err, data)
		}
	}
}

// createIdentity runs `dfos identity create` with the given keystore active and
// returns the DID. It registers the identity name and points identityFlag at it.
func createIdentity(t *testing.T, name string, store *keystore.MemoryStore) string {
	t.Helper()
	keys = store
	cmd := newIdentityCreateCmd()
	mustSetFlag(t, cmd, "name", name)
	var res struct {
		DID string `json:"did"`
	}
	runJSON(t, cmd, nil, &res)
	identityFlag = name
	return res.DID
}

func writeTempDoc(t *testing.T, body string) string {
	t.Helper()
	f := t.TempDir() + "/doc.json"
	if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
		t.Fatalf("write doc: %v", err)
	}
	return f
}

func mustSetFlag(t *testing.T, cmd *cobra.Command, name, val string) {
	t.Helper()
	if err := cmd.Flags().Set(name, val); err != nil {
		t.Fatalf("set --%s=%s: %v", name, val, err)
	}
}

// TestMultiDevice_HappyPath exercises the full handoff: A creates an identity,
// B generates a device key, A adds B's public key, then B publishes content
// signed with its OWN key. Under the old slot-0 signer code B's publish would
// fail with "auth key not in keychain" because AuthKeys[0] is A's key; with
// selectHeldKey B signs with its own key.
func TestMultiDevice_HappyPath(t *testing.T) {
	storeA, storeB, lr := setupDevices(t)

	did := createIdentity(t, "alice", storeA)

	// --- device B: generate a device pubkey (private seed stays on B) ---
	keys = storeB
	var dev struct {
		ID                 string `json:"id"`
		PublicKeyMultibase string `json:"publicKeyMultibase"`
		Role               string `json:"role"`
	}
	runJSON(t, newIdentityDevicePubkeyCmd(), nil, &dev)
	if dev.Role != "auth" {
		t.Fatalf("device-pubkey default role = %q, want auth", dev.Role)
	}
	bKid := did + "#" + dev.ID
	if !storeB.HasKey(bKid) {
		t.Fatalf("expected B to hold private key %s", bKid)
	}
	if storeA.HasKey(bKid) {
		t.Fatalf("device B's private key must NOT be on device A")
	}

	// --- device A: add B's public key to the auth set ---
	keys = storeA
	ak := newIdentityAddKeyCmd()
	mustSetFlag(t, ak, "auth-key", "true")
	mustSetFlag(t, ak, "id", dev.ID)
	mustSetFlag(t, ak, "pubkey", dev.PublicKeyMultibase)
	if err := ak.RunE(ak, nil); err != nil {
		t.Fatalf("add-key: %v", err)
	}

	// chain now has 2 auth keys, including B's
	chain, err := lr.Relay.GetIdentity(did)
	if err != nil || chain == nil {
		t.Fatalf("get identity: %v", err)
	}
	if got := len(chain.State.AuthKeys); got != 2 {
		t.Fatalf("expected 2 auth keys after add-key, got %d", got)
	}
	if !hasKeyID(chain.State.AuthKeys, dev.ID) {
		t.Fatalf("B's key %s not found in auth set", dev.ID)
	}

	// selectHeldKey resolves to B's key when B's keystore is active
	keys = storeB
	gotKid, err := selectHeldKey(did, chain.State.AuthKeys, "auth")
	if err != nil {
		t.Fatalf("selectHeldKey for B: %v", err)
	}
	if gotKid != bKid {
		t.Fatalf("selectHeldKey returned %s, want %s", gotKid, bKid)
	}

	// --- device B publishes content signed with its own key ---
	keys = storeB
	cc := newContentCreateCmd()
	mustSetFlag(t, cc, "no-schema-warn", "true")
	docPath := writeTempDoc(t, `{"hello":"from device B"}`)
	var content struct {
		ContentID string `json:"contentId"`
	}
	runJSON(t, cc, []string{docPath}, &content)
	if content.ContentID == "" {
		t.Fatalf("expected a content id from device B's publish")
	}

	// the content op is in the relay
	chains, err := lr.Store.ListContentChains()
	if err != nil {
		t.Fatalf("list content chains: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("expected 1 content chain, got %d", len(chains))
	}
	if chains[0].State.CreatorDID != did {
		t.Fatalf("content creator %s, want %s", chains[0].State.CreatorDID, did)
	}
}

// TestMultiDevice_NonMemberRejected proves that a device holding NONE of the
// published keys cannot publish, and cannot add-key (no held controller key).
func TestMultiDevice_NonMemberRejected(t *testing.T) {
	storeA, _, lr := setupDevices(t)

	did := createIdentity(t, "alice", storeA)

	// storeC holds no keys in alice's chain
	storeC := keystore.NewMemoryStore()

	// content create from C must fail with selectHeldKey's message
	keys = storeC
	cc := newContentCreateCmd()
	mustSetFlag(t, cc, "no-schema-warn", "true")
	docPath := writeTempDoc(t, `{"hello":"from non-member"}`)
	err := cc.RunE(cc, []string{docPath})
	if err == nil {
		t.Fatalf("content create from a non-member device should fail")
	}
	if !strings.Contains(err.Error(), "no held auth key") {
		t.Fatalf("expected 'no held auth key' error, got: %v", err)
	}

	// add-key from C must fail: C holds no controller key to sign the update
	chain, _ := lr.Relay.GetIdentity(did)
	someMulti := chain.State.AuthKeys[0].PublicKeyMultibase // any valid multikey string
	keys = storeC
	ak := newIdentityAddKeyCmd()
	mustSetFlag(t, ak, "auth-key", "true")
	mustSetFlag(t, ak, "id", protocol.GenerateKeyID())
	mustSetFlag(t, ak, "pubkey", someMulti)
	err = ak.RunE(ak, nil)
	if err == nil {
		t.Fatalf("add-key from a device with no controller key should fail")
	}
	if !strings.Contains(err.Error(), "no held controller key") {
		t.Fatalf("expected 'no held controller key' error, got: %v", err)
	}
}

// TestMultiDevice_RejectsMalformedPubkey proves add-key validates the length of
// a human-supplied --pubkey: DecodeMultikey only checks the multicodec prefix,
// so a prefix-valid but wrong-length key must still be rejected before it can be
// appended to the published set.
func TestMultiDevice_RejectsMalformedPubkey(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	createIdentity(t, "alice", storeA) // storeA holds alice's controller key

	// prefix-valid (0xed01) but only 16 bytes of key material
	malformed := protocol.EncodeMultikey(make([]byte, 16))

	keys = storeA
	ak := newIdentityAddKeyCmd()
	mustSetFlag(t, ak, "auth-key", "true")
	mustSetFlag(t, ak, "id", protocol.GenerateKeyID())
	mustSetFlag(t, ak, "pubkey", malformed)
	err := ak.RunE(ak, nil)
	if err == nil {
		t.Fatalf("add-key with a 16-byte --pubkey should fail")
	}
	if !strings.Contains(err.Error(), "ed25519 key") {
		t.Fatalf("expected an ed25519 key-length error, got: %v", err)
	}
}

func hasKeyID(set []protocol.MultikeyPublicKey, id string) bool {
	for _, k := range set {
		if k.ID == id {
			return true
		}
	}
	return false
}
