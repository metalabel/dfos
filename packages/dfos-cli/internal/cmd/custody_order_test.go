package cmd

// Ordering and trust-carrying, as behavior.
//
// Every test here covers a failure that CONVERGED WRONG rather than one that
// stopped: recovery installing keys over a counter that never moved, a re-add
// dropping a DID pin on its way past an unreachable relay, a rotation reading an
// unreadable vault directory as "no vault", a create losing its provenance trail
// to a network it could not reach. None of them printed an error the operator
// could act on; all of them left custody quietly weaker than it was.
//
// Like the rest of the cmd tests these drive RunE against the package globals
// setupDevices wires, so they MUST NOT run with t.Parallel().

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/keystore"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/vault"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// deadURL is an address nothing is listening on: a port bound long enough to be
// unique, then released. It refuses connections immediately rather than hanging,
// which is what makes "unreachable" a fast, deterministic branch to test.
func deadURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind a port to release: %v", err)
	}
	url := "http://" + l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("release the port: %v", err)
	}
	return url
}

// breakConfigSaves makes every subsequent config.Save fail, by turning the
// config FILE into a directory. Everything else on disk is unaffected: the
// vaults live in a sibling directory that already exists, and the keystore under
// test is in memory.
func breakConfigSaves(t *testing.T) {
	t.Helper()
	path := config.ConfigPath()
	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("remove config file: %v", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("put a directory where the config file goes: %v", err)
	}
}

// oneKeyToRecover builds the disaster: an identity minted at index 0 on device
// A, then a fresh machine holding nothing but the phrase and an oracle that can
// answer for it. It returns the mnemonic, the DID, and device B's keystore, with
// the vault imported as "restored" and device B active.
func oneKeyToRecover(t *testing.T) (mnemonic, did string, storeB *keystore.MemoryStore) {
	t.Helper()
	storeA, _, lr := setupDevices(t)
	keys = storeA
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")

	mnemonic = createVault(t, "personal")
	did = createIdentity(t, "alice", storeA)
	chain, err := lr.Relay.GetIdentity(did)
	if err != nil || chain == nil {
		t.Fatalf("chain for %s: %v", did, err)
	}
	oracle.logsByDID[did] = chain.Log
	for _, k := range chain.State.ControllerKeys {
		oracle.declare(k.PublicKeyMultibase, did, false, "")
	}

	storeB, _, _ = setupDevices(t)
	keys = storeB
	importVault(t, "restored", mnemonic)
	oracle.registerAsPeer(t, "oracle")
	return mnemonic, did, storeB
}

// --- 1: the counter rises before anything that can fail ---

// TestRecoverRaisesTheCounterBeforeTheStepsThatCanFail is the catastrophic one.
// The old order installed keys, then registered names with config.Save — which
// RETURNS ON ERROR — and only then raised the counter. A config.Save that failed
// left recovered keys standing over a vault still at index 0, and the next mint
// handed index 0 to a second identity: one Ed25519 private key, two DIDs.
//
// A burned index is the acceptable failure and a reusable one is not, so the
// counter goes first and the assertion is that it survives the later error.
func TestRecoverRaisesTheCounterBeforeTheStepsThatCanFail(t *testing.T) {
	mnemonic, _, storeB := oneKeyToRecover(t)

	if before, _ := getVaults().Load("restored"); before.NextIndex != 0 {
		t.Fatalf("an imported vault starts at %d, want 0", before.NextIndex)
	}

	breakConfigSaves(t)

	_, _, err := runCapturing(t, newRecover(t, map[string]string{"vault": "restored", "peer": "oracle"}), nil)
	if err == nil {
		t.Fatal("config.Save was supposed to fail; the rest of this test proves nothing without it")
	}
	if !strings.Contains(err.Error(), "register recovered identities in config") {
		t.Fatalf("the run failed somewhere other than the config write: %v", err)
	}

	// The counter cleared index 0 anyway. This is the whole fix.
	meta, loadErr := getVaults().Load("restored")
	if loadErr != nil {
		t.Fatalf("load vault after the failed run: %v", loadErr)
	}
	if meta.NextIndex != 1 {
		t.Fatalf("counter = %d after a run that installed index 0 and then failed, want 1 — "+
			"the next mint would hand index 0 to a second identity", meta.NextIndex)
	}
	// And the provenance trail, which is also ahead of the config write now.
	if len(meta.Minted) != 1 {
		t.Errorf("minted records = %d, want the one key this run recovered", len(meta.Minted))
	}
	if !storeB.HasKey(keyAccount(derivedPublicKey(t, mnemonic, 0))) {
		t.Error("the key was not installed, so the counter has nothing to be ahead of")
	}
}

// --- 5: an already-present claim is about bytes, not about a name ---

// TestRecoverChecksWhatTheLegacyAccountActuallyHolds: `<did>#<key_id>` is a name
// a machine chose, not a claim about the key behind it. Declaring already-present
// on existence alone told an operator a key was recovered when this machine holds
// a DIFFERENT one under that name.
func TestRecoverChecksWhatTheLegacyAccountActuallyHolds(t *testing.T) {
	for _, tc := range []struct {
		name        string
		sameKey     bool
		wantOutcome string
	}{
		{"the same key under the old name converges", true, "already-present"},
		{"a different key under the old name is a conflict", false, "not-installed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mnemonic, did, storeB := oneKeyToRecover(t)

			// The key id is the key's own content address since genesis mints one
			// key, so the legacy account is derivable without reading the chain.
			publicKey := derivedPublicKey(t, mnemonic, 0)
			legacy := legacyKeyAccount(did, protocol.DeriveKeyID(publicKey))

			if tc.sameKey {
				seed, err := vault.MnemonicSeed(mnemonic)
				if err != nil {
					t.Fatalf("seed: %v", err)
				}
				priv, _, err := vault.DeriveKey(seed, 0)
				if err != nil {
					t.Fatalf("derive: %v", err)
				}
				if _, err := storeB.PutKey(legacy, priv); err != nil {
					t.Fatalf("seed the legacy account: %v", err)
				}
			} else {
				// Some other key entirely, filed under the name this recovery is
				// about. A half-migrated store or a hand-edited keychain looks
				// exactly like this.
				if _, _, err := storeB.GenerateKey(legacy); err != nil {
					t.Fatalf("seed the legacy account: %v", err)
				}
			}

			var res recoverResult
			runJSON(t, newRecover(t, map[string]string{"vault": "restored", "peer": "oracle"}), nil, &res)

			if len(res.Keys) != 1 {
				t.Fatalf("recovered %d keys, want 1: %+v", len(res.Keys), res.Keys)
			}
			got := res.Keys[0]
			if got.Outcome != tc.wantOutcome {
				t.Fatalf("outcome = %q (%s), want %q", got.Outcome, got.Reason, tc.wantOutcome)
			}

			meta, _ := getVaults().Load("restored")
			if tc.sameKey {
				if got.Account != legacy {
					t.Errorf("account = %q, want the legacy account it converged on", got.Account)
				}
				if len(meta.Minted) != 1 {
					t.Errorf("a converged key wrote %d provenance records, want 1", len(meta.Minted))
				}
				return
			}

			// The conflict names both accounts and both keys, records nothing,
			// and still leaves the counter ahead — the index IS spent whatever
			// this machine's keystore is confused about.
			for _, want := range []string{legacy, "NOT recovered", "dfos keys list"} {
				if !strings.Contains(got.Reason, want) {
					t.Errorf("the reason must name %q: %s", want, got.Reason)
				}
			}
			if len(meta.Minted) != 0 {
				t.Errorf("a conflicted key wrote provenance anyway: %+v", meta.Minted)
			}
			if meta.NextIndex != 1 {
				t.Errorf("counter = %d, want 1: the index is spent whatever the keystore holds", meta.NextIndex)
			}
		})
	}
}

// --- 2: a pin is posture, and posture carries forward ---

// TestPeerReAddKeepsThePinAcrossAnUnreachableRelay: the reachable path's own
// comment swears re-registration "does not MOVE the pin". The unreachable path
// rebuilt every posture field except the DID and saved that, so a re-add against
// a relay that happened to be down un-pinned it — and the next successful contact
// TOFU-pinned whoever answered at that URL.
func TestPeerReAddKeepsThePinAcrossAnUnreachableRelay(t *testing.T) {
	setupSync(t)
	dead := deadURL(t)

	// A peer registered and pinned by an earlier, successful contact.
	cfg.Relays["prod"] = config.RelayConfig{URL: dead, DID: pinnedDID, ProfileName: "prod"}

	var same struct {
		DID       string `json:"did"`
		Reachable bool   `json:"reachable"`
	}
	stdout, _, err := runCapturingJSON(t, newPeerAddCmd(), []string{"prod", dead}, &same)
	if err != nil {
		t.Fatalf("re-registering an unreachable peer must still succeed: %v", err)
	}
	if same.Reachable {
		t.Fatal("the peer answered; this test needs the unreachable branch")
	}
	if same.DID != pinnedDID {
		t.Errorf("a same-URL re-add reported DID %q, want the pin it already had", same.DID)
	}
	if got := cfg.Relays["prod"].DID; got != pinnedDID {
		t.Fatalf("a same-URL re-add erased the pin: %q, want %s", got, pinnedDID)
	}
	_ = stdout

	// A CHANGED URL is a new registration. It inherits nothing — a different
	// address is a different relay until something says otherwise.
	moved := deadURL(t)
	var changed struct {
		DID string `json:"did"`
	}
	if _, _, err := runCapturingJSON(t, newPeerAddCmd(), []string{"prod", moved}, &changed); err != nil {
		t.Fatalf("re-registering at a new URL: %v", err)
	}
	if changed.DID != "" {
		t.Errorf("a changed-URL re-add reported DID %q, want none", changed.DID)
	}
	if got := cfg.Relays["prod"].DID; got != "" {
		t.Fatalf("a changed-URL re-add inherited the old pin: %q", got)
	}
}

// TestPeerReAddSaysWhichWayThePinWent: the retained pin is on screen, because a
// posture that is only visible when it is unusual is a posture nobody checks.
func TestPeerReAddSaysWhichWayThePinWent(t *testing.T) {
	setupSync(t)
	dead := deadURL(t)
	cfg.Relays["prod"] = config.RelayConfig{URL: dead, DID: pinnedDID}

	stdout, _, err := runCapturing(t, newPeerAddCmd(), []string{"prod", dead})
	if err != nil {
		t.Fatalf("peer add: %v", err)
	}
	if !strings.Contains(stdout, "Pin retained: "+pinnedDID) {
		t.Errorf("a retained pin was not announced:\n%s", stdout)
	}
	if strings.Contains(stdout, "no DID pinned") {
		t.Errorf("the output claims no DID is pinned while retaining one:\n%s", stdout)
	}

	// A first registration against an unreachable relay really has no pin, and
	// still says so.
	fresh := deadURL(t)
	stdout, _, err = runCapturing(t, newPeerAddCmd(), []string{"other", fresh})
	if err != nil {
		t.Fatalf("peer add: %v", err)
	}
	if !strings.Contains(stdout, "no DID pinned") {
		t.Errorf("an unpinned registration did not say so:\n%s", stdout)
	}
}

// --- 3: an unreadable provenance directory is not "no vault" ---

// TestBareRotationRefusesOverUnreadableProvenance: Store.List() fails wholesale
// if ANY .toml fails to parse, FindMinted swallowed that into "not found", and a
// bare `identity update --rotate-auth` then minted a STANDALONE replacement. A
// mnemonic-backed identity rotated onto a key no phrase can ever recover, because
// an unrelated sibling file was corrupt.
func TestBareRotationRefusesOverUnreadableProvenance(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA

	createVault(t, "personal")
	createIdentity(t, "alice", storeA)

	// A sibling vault file with nothing to do with alice, unparseable.
	corrupt := filepath.Join(getVaults().Dir(), "burner.toml")
	if err := os.WriteFile(corrupt, []byte("this is not toml = = ["), 0o600); err != nil {
		t.Fatalf("write corrupt vault: %v", err)
	}

	rotate := newIdentityUpdateCmd()
	mustSetFlag(t, rotate, "rotate-auth", "true")
	_, _, err := runCapturingJSON(t, rotate, nil, nil)
	if err == nil {
		t.Fatal("a bare rotation minted a replacement key over provenance it could not read")
	}
	for _, want := range []string{corrupt, "--vault", "--no-vault", "standalone"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name %q:\n%v", want, err)
		}
	}
	// Nothing was minted: the refusal is before the reservation.
	if meta, _ := getVaults().Load("personal"); meta.NextIndex != 1 {
		t.Errorf("counter = %d after a refused rotation, want 1 (genesis only)", meta.NextIndex)
	}

	// --vault names the seed explicitly and does not need the directory read.
	named := newIdentityUpdateCmd()
	mustSetFlag(t, named, "rotate-auth", "true")
	mustSetFlag(t, named, "vault", "personal")
	var rotated struct {
		Vault struct {
			Name string `json:"name"`
		} `json:"vault"`
	}
	runJSON(t, named, nil, &rotated)
	if rotated.Vault.Name != "personal" {
		t.Fatalf("--vault resolved to %q, want personal", rotated.Vault.Name)
	}
}

// --- 4: the provenance trail follows the LOCAL ingest, not the peer ---

// TestIdentityCreateRecordsProvenanceBeforeThePeerSubmit: the trail was written
// after a successful peer publish, so `identity create --peer <unreachable>`
// left the key in the keystore and the chain in the local relay with no vault
// record at all — and a later bare rotation fell to standalone. The local relay
// accepting the genesis is what makes the trail true; a peer is not.
func TestIdentityCreateRecordsProvenanceBeforeThePeerSubmit(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	cfg.Relays["prod"] = config.RelayConfig{URL: deadURL(t)}

	create := newIdentityCreateCmd()
	mustSetFlag(t, create, "name", "alice")
	mustSetFlag(t, create, "peer", "prod")
	_, _, err := runCapturingJSON(t, create, nil, nil)
	if err == nil {
		t.Fatal("a create against an unreachable peer must still report the submit failure")
	}
	if !strings.Contains(err.Error(), "submit to peer") {
		t.Fatalf("the create failed somewhere other than the peer submit: %v", err)
	}

	meta, loadErr := getVaults().Load("personal")
	if loadErr != nil {
		t.Fatalf("load vault: %v", loadErr)
	}
	if len(meta.Minted) != 1 {
		t.Fatalf("vault holds %d provenance records after a failed publish, want 1 — "+
			"the key exists and the chain is local, so the trail is true", len(meta.Minted))
	}

	// The point of the trail: a later bare rotation stays on the seed rather
	// than minting a standalone replacement for a phrase-backed identity.
	asFlag = meta.Minted[0].DID
	rotate := newIdentityUpdateCmd()
	mustSetFlag(t, rotate, "rotate-auth", "true")
	var rotated struct {
		Vault struct {
			Name string `json:"name"`
		} `json:"vault"`
	}
	runJSON(t, rotate, nil, &rotated)
	if rotated.Vault.Name != "personal" {
		t.Fatalf("a bare rotation drew from %q, want personal — the trail did not survive", rotated.Vault.Name)
	}
}

// --- 6: the closest name wins ---

// TestCommandLocalPeerOutranksTheGlobalRelay: requirePeer folded a command-local
// --peer into the flag tier, where ResolveContext ranks --relay above it — so
// `dfos --relay stale recover --peer authoritative` asked `stale`. A flag typed
// on the command is the more specific statement of the two.
func TestCommandLocalPeerOutranksTheGlobalRelay(t *testing.T) {
	setupSync(t)
	stale := newFakePeer(t)
	authoritative := newFakePeer(t)
	cfg.Relays["stale"] = config.RelayConfig{URL: stale.server.URL, DID: pinnedDID}
	cfg.Relays["authoritative"] = config.RelayConfig{URL: authoritative.server.URL, DID: pinnedDID}

	relayFlag = "stale"

	ctx, _, err := requirePeer("authoritative", true)
	if err != nil {
		t.Fatalf("requirePeer: %v", err)
	}
	if ctx.RelayName != "authoritative" {
		t.Fatalf("resolved peer = %q (via %s), want authoritative — the command-local flag lost to --relay",
			ctx.RelayName, ctx.RelaySource)
	}
	if ctx.RelayURL != authoritative.server.URL {
		t.Errorf("resolved URL = %q, want %q", ctx.RelayURL, authoritative.server.URL)
	}

	// With no command-local flag the global --relay answers exactly as before.
	ctx, _, err = requirePeer("", true)
	if err != nil {
		t.Fatalf("requirePeer: %v", err)
	}
	if ctx.RelayName != "stale" {
		t.Fatalf("resolved peer = %q with no command-local flag, want stale", ctx.RelayName)
	}

}
