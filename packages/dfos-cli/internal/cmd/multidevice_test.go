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
// localRelayInstance and the selector flags are reset on cleanup so tests don't
// leak into each other.
func setupDevices(t *testing.T) (storeA, storeB *keystore.MemoryStore, lr *localrelay.LocalRelay) {
	t.Helper()

	// isolate config.Save — DFOS_CONFIG is the config.toml file path, and
	// ConfigDir() is its parent, so point it at a file inside a temp dir.
	// Vaults live under the same directory, so this isolates them too; the
	// keychain is skipped outright so no test can reach the developer's own.
	t.Setenv("DFOS_CONFIG", t.TempDir()+"/config.toml")
	t.Setenv("DFOS_NO_KEYCHAIN", "1")
	vaultStore = nil
	// Pin verification is memoized for the life of the process; a test process
	// runs many "processes" worth of invocations.
	peerPinChecks = map[string]error{}

	storeA = keystore.NewMemoryStore()
	storeB = keystore.NewMemoryStore()

	cfg = &config.Config{
		Relays:     map[string]config.RelayConfig{},
		Identities: map[string]config.IdentityConfig{},
	}

	var err error
	lr, err = localrelay.Open(cfg, &localrelay.Options{DBPath: t.TempDir() + "/relay.db"})
	if err != nil {
		t.Fatalf("open local relay: %v", err)
	}
	localRelayInstance = lr

	// The resolution stack reads the environment before the config, so blank
	// every mechanism a developer's own shell may carry.
	for _, k := range []string{config.SourceEnvAs, config.SourceEnvRelay} {
		t.Setenv(k, "")
	}

	prevAs, prevRelay := asFlag, relayFlag
	prevJSON, prevQuiet, prevAnnounced := jsonFlag, quietFlag, signerAnnounced
	asFlag, relayFlag = "", ""
	quietFlag, signerAnnounced = false, false
	t.Cleanup(func() {
		lr.Close()
		localRelayInstance = nil
		cfg = nil
		keys = nil
		vaultStore = nil
		asFlag, relayFlag = prevAs, prevRelay
		jsonFlag, quietFlag, signerAnnounced = prevJSON, prevQuiet, prevAnnounced
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

// captureStdout runs fn with stdout redirected and returns what it wrote. The
// human half of a command is prose on stdout, so this is where an assertion
// about what an operator is TOLD has to look.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out)
}

// createIdentity runs `dfos identity create` with the given keystore active and
// returns the DID. It registers the identity name and points asFlag at it.
func createIdentity(t *testing.T, name string, store *keystore.MemoryStore) string {
	t.Helper()
	keys = store
	cmd := newIdentityCreateCmd()
	mustSetFlag(t, cmd, "name", name)
	var res struct {
		DID string `json:"did"`
	}
	runJSON(t, cmd, nil, &res)
	asFlag = name
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

// TestMultiDevice_AddKeyRefusesAKeyItCannotProve is what became of the old
// add-key handoff.
//
// A device generating a key and handing its PUBLIC half to a controller was how a
// second device used to join an identity. It no longer is, and the reason is the
// whole point of key possession: a key enters a chain carrying its OWN signature
// over the introduction, and a controller holds no such signature for a key that
// lives on another device. Authoring it anyway would publish a membership no
// proof admits — void, resolving nowhere, indexed nowhere — so `add-key` refuses
// and names the two ways forward.
//
// Everything before the refusal still holds and is still asserted: B generates
// its own key, B alone holds the private half, and both machines derive the same
// id from the public key without exchanging one.
func TestMultiDevice_AddKeyRefusesAKeyItCannotProve(t *testing.T) {
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
	// The key is filed by its own content address, which B can compute before
	// any chain names it — and the id it will be published under is derived from
	// the same public key, so A and B name it identically without exchanging one.
	bAccount := keyAccount(dev.PublicKeyMultibase)
	if !storeB.HasKey(bAccount) {
		t.Fatalf("expected B to hold private key %s", bAccount)
	}
	if storeA.HasKey(bAccount) {
		t.Fatalf("device B's private key must NOT be on device A")
	}
	if want := protocol.DeriveKeyID(dev.PublicKeyMultibase); dev.ID != want {
		t.Fatalf("device-pubkey id = %q, want the derived %q", dev.ID, want)
	}
	// --- device A: try to add B's public key to the auth set ---
	keys = storeA
	ak := newIdentityAddKeyCmd()
	mustSetFlag(t, ak, "auth-key", "true")
	mustSetFlag(t, ak, "id", dev.ID)
	mustSetFlag(t, ak, "pubkey", dev.PublicKeyMultibase)
	err := ak.RunE(ak, nil)
	if err == nil {
		t.Fatal("add-key published a key it cannot prove")
	}
	// The refusal names the key, the roles, and both ways forward — a person
	// holding two devices has to be able to act on it without reading the spec.
	for _, want := range []string{
		"cannot prove", dev.ID, dev.PublicKeyMultibase, "(auth)",
		"VOID", "REMOVE", "RE-PROVE", "dfos keys add", "nothing was signed",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal is missing %q:\n%v", want, err)
		}
	}

	// NOTHING was written. A refusal that still appended the operation would be
	// the void membership arriving by another door.
	chain, getErr := lr.Relay.GetIdentity(did)
	if getErr != nil || chain == nil {
		t.Fatalf("get identity: %v", getErr)
	}
	if got := len(chain.State.AuthKeys); got != 1 {
		t.Fatalf("auth keys after a refused add-key = %d, want the genesis key alone", got)
	}
	if hasKeyID(chain.State.AuthKeys, dev.ID) {
		t.Fatalf("B's key %s reached the chain through a refusal", dev.ID)
	}
	if len(chain.State.VoidKeys) != 0 {
		t.Fatalf("a refused add-key left void memberships behind: %+v", chain.State.VoidKeys)
	}
	if len(chain.Log) != 1 {
		t.Fatalf("chain has %d operations after a refused add-key, want 1", len(chain.Log))
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
