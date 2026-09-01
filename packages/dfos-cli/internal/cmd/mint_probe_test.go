package cmd

// Mint-collision probe tests. Like the vault and recover tests these drive RunE
// directly against the package globals setupDevices wires, so they MUST NOT run
// with t.Parallel(). They reuse recover's fakeOracle, because the question the
// probe asks is byte-identical to the one recover's scan asks, and the failure
// modes worth testing are the HTTP-shaped ones a hand-written client cannot get
// wrong in the way a real relay does.
//
// The oracle is reached through default-peer rather than a command --peer: the
// probe is a read the ordinary resolution stack decides, and `identity create
// --peer` would also PUSH the genesis, which is a different thing under test.

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/spf13/cobra"
)

// createNamed builds an `identity create` with a name already set, so each test
// says only what it is actually varying.
func createNamed(t *testing.T, name string) *cobra.Command {
	t.Helper()
	cmd := newIdentityCreateCmd()
	mustSetFlag(t, cmd, "name", name)
	return cmd
}

func TestMintProbeRefusesAnIndexTheRelayReportsAsSpent(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	keys = storeA
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	cfg.DefaultPeer = "oracle"

	mnemonic := createVault(t, "personal")
	// Another machine holding this same phrase already minted at index 0 and
	// published it. Nothing local can see that; the index can.
	pub := derivedPublicKey(t, mnemonic, 0)
	oracle.declare(pub, "did:dfos:othermachine", false, "")

	// The relay opens holding its own node identity, so the assertion below is
	// that the refused mint added nothing — not that the store is empty.
	before, err := lr.Store.RelayStats()
	if err != nil {
		t.Fatalf("relay stats: %v", err)
	}

	_, stderr, err := runCapturing(t, createNamed(t, "alice"), nil)
	if err == nil {
		t.Fatal("a mint at an index the relay reports as spent was allowed")
	}
	var coded *CodedError
	if !errors.As(err, &coded) {
		t.Fatalf("the refusal is not a CodedError: %v", err)
	}
	if coded.Reason != mintProbeReason {
		t.Errorf("reason = %q, want %q", coded.Reason, mintProbeReason)
	}
	for field, want := range map[string]string{
		"vault": "personal", "index": "0", "publicKey": pub,
		"relay": "oracle", "dids": "did:dfos:othermachine",
	} {
		if got := coded.Fields[field]; got != want {
			t.Errorf("field %q = %q, want %q", field, got, want)
		}
	}
	msg := err.Error()
	for _, want := range []string{
		"refusing to mint from vault 'personal'", "index 0 is already spent",
		"oracle (" + oracle.server.URL + ")", "did:dfos:othermachine",
		"one private key under two identities",
		"dfos recover --vault personal", "stays burned", "--no-mint-probe",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, msg)
		}
	}
	if strings.Contains(stderr, "did not run") {
		t.Errorf("a probe that answered still printed a skip notice:\n%s", stderr)
	}

	// NOTHING was stored: no key, no config name, no chain. The refusal lands
	// before the first write, which is the whole reason it is at mint time.
	if storeA.HasKey(keyAccount(pub)) {
		t.Error("the refused mint wrote the key into the keystore")
	}
	if _, ok := cfg.Identities["alice"]; ok {
		t.Error("the refused mint registered a name in config")
	}
	after, err := lr.Store.RelayStats()
	if err != nil {
		t.Fatalf("relay stats: %v", err)
	}
	if after.OpCount != before.OpCount {
		t.Errorf("the refused mint left %d operation(s) in the local relay", after.OpCount-before.OpCount)
	}

	// The counter DID move. Burn-on-failure is the design: a hole is what the
	// recovery scan's gap limit walks through, and a returned index is one two
	// identities can still both reach.
	meta, err := getVaults().Load("personal")
	if err != nil {
		t.Fatalf("load vault: %v", err)
	}
	if meta.NextIndex != 1 {
		t.Errorf("NextIndex = %d, want 1 — the reserved index must stay burned", meta.NextIndex)
	}
}

func TestMintProbeSaysNothingWhenTheIndexIsUnclaimed(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	cfg.DefaultPeer = "oracle"

	createVault(t, "personal")

	_, stderr, err := runCapturing(t, createNamed(t, "alice"), nil)
	if err != nil {
		t.Fatalf("a mint at an unclaimed index was refused: %v", err)
	}
	// An unspent index is the ordinary case and is not news. Announcing it every
	// time would teach an operator to read past the line that matters.
	if strings.Contains(stderr, "mint-collision probe") {
		t.Errorf("a clean probe printed something:\n%s", stderr)
	}
	// The sentinel capability question, then the one reserved key.
	if oracle.indexQueries != 2 {
		t.Errorf("index queries = %d, want 2 (the sentinel probe and one reserved key)", oracle.indexQueries)
	}
}

func TestMintProbeMintsWithALoudNoticeWhenTheRelayCannotAnswer(t *testing.T) {
	// Each cause is a different next move for the operator — turn the index on,
	// upgrade the relay, fix the network — so each is named rather than folded
	// into one "the probe failed".
	cases := []struct {
		name  string
		setup func(t *testing.T, oracle *fakeOracle)
		// deadPeer replaces the oracle with a URL nothing is listening on.
		deadPeer bool
		want     []string
	}{
		{
			name:  "the relay serves no index",
			setup: func(t *testing.T, o *fakeOracle) { o.indexStatus = http.StatusNotImplemented },
			want:  []string{"cannot answer", "501 Not Implemented", "capabilities.index is off"},
		},
		{
			name: "the relay ignores the key filter",
			setup: func(t *testing.T, o *fakeOracle) {
				o.declare("zSomeKeyThisVaultNeverDerived", "did:dfos:unrelated", false, "")
				o.ignoresKeyParam = true
			},
			want: []string{"cannot answer", "ignored the 'key=' parameter", "web-relay >= 0.39.0"},
		},
		{
			name:     "the relay is unreachable",
			deadPeer: true,
			want:     []string{"cannot answer", "127.0.0.1:1"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			storeA, _, _ := setupDevices(t)
			keys = storeA
			oracle := newFakeOracle(t)
			oracle.registerAsPeer(t, "oracle")
			cfg.DefaultPeer = "oracle"
			if tc.deadPeer {
				cfg.Relays["oracle"] = config.RelayConfig{URL: "http://127.0.0.1:1"}
			}
			if tc.setup != nil {
				tc.setup(t, oracle)
			}
			createVault(t, "personal")

			_, stderr, err := runCapturing(t, createNamed(t, "alice"), nil)
			if err != nil {
				t.Fatalf("a relay that cannot answer stopped the mint: %v", err)
			}
			want := append([]string{
				"the mint-collision probe did not run", "index 0 may already be spent",
				"dfos recover --vault personal",
			}, tc.want...)
			for _, w := range want {
				if !strings.Contains(stderr, w) {
					t.Errorf("the skip notice does not say %q:\n%s", w, stderr)
				}
			}
		})
	}
}

func TestMintProbeSaysSoWhenAnImportedVaultHasNoRelayToAsk(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	// An IMPORTED phrase already exists somewhere else — that is what an import
	// is — so the other holder the notice hypothesizes is not a hypothesis.
	importVault(t, "restored", testMnemonic)

	_, stderr, err := runCapturing(t, createNamed(t, "alice"), nil)
	if err != nil {
		t.Fatalf("a local-first mint was stopped by having no relay: %v", err)
	}
	for _, want := range []string{
		"the mint-collision probe did not run — no relay to ask",
		"index 0 may already be spent there",
		"'dfos recover --vault restored' converges the counter",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the no-relay notice does not say %q:\n%s", want, stderr)
		}
	}
}

func TestALocalFirstMintFromAVaultCreatedHereSaysNothing(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")

	_, stderr, err := runCapturing(t, createNamed(t, "alice"), nil)
	if err != nil {
		t.Fatalf("a local-first mint failed: %v", err)
	}
	// A phrase generated on this machine has no other holder at mint time, so
	// there is no unasked question to report. Opening a first `identity create`
	// with a warning about a machine that does not exist is what teaches an
	// operator to read past the notice on the day it is true.
	if strings.Contains(stderr, "mint-collision probe") {
		t.Errorf("a vault created on this machine carried a no-relay notice:\n%s", stderr)
	}
}

func TestNoMintProbeAsksNothingAndSaysNothing(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	cfg.DefaultPeer = "oracle"

	mnemonic := createVault(t, "personal")
	oracle.declare(derivedPublicKey(t, mnemonic, 0), "did:dfos:othermachine", false, "")

	cmd := createNamed(t, "alice")
	mustSetFlag(t, cmd, "no-mint-probe", "true")
	_, stderr, err := runCapturing(t, cmd, nil)
	if err != nil {
		t.Fatalf("--no-mint-probe still refused the mint: %v", err)
	}
	// An operator who opted out is not lectured about what the opt-out cost.
	if strings.Contains(stderr, "mint-collision probe") {
		t.Errorf("--no-mint-probe printed a notice anyway:\n%s", stderr)
	}
	if oracle.indexQueries != 0 {
		t.Errorf("--no-mint-probe made %d index queries", oracle.indexQueries)
	}
}

func TestAVaultlessMintAsksTheRelayNothing(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	cfg.DefaultPeer = "oracle"

	createVault(t, "personal")

	cmd := createNamed(t, "detached")
	mustSetFlag(t, cmd, "no-vault", "true")
	_, stderr, err := runCapturing(t, cmd, nil)
	if err != nil {
		t.Fatalf("--no-vault create failed: %v", err)
	}
	// A key drawn from entropy has no index and cannot collide with one, so
	// there is no question to ask and nothing to report.
	if oracle.indexQueries != 0 {
		t.Errorf("a vault-less mint made %d index queries", oracle.indexQueries)
	}
	if strings.Contains(stderr, "mint-collision probe") {
		t.Errorf("a vault-less mint printed a probe notice:\n%s", stderr)
	}
}

func TestMintProbeRefusesARotationOntoASpentIndex(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	keys = storeA
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")

	mnemonic := createVault(t, "personal")
	// Genesis takes index 0 with no relay in the picture; the rotation below is
	// what meets the oracle.
	did := createIdentity(t, "alice", storeA)
	cfg.DefaultPeer = "oracle"

	replacement := derivedPublicKey(t, mnemonic, 1)
	oracle.declare(replacement, "did:dfos:othermachine", false, "")

	rotate := newIdentityUpdateCmd()
	mustSetFlag(t, rotate, "rotate-auth", "true")
	_, _, err := runCapturing(t, rotate, nil)
	if err == nil {
		t.Fatal("a rotation onto an index the relay reports as spent was allowed")
	}
	var coded *CodedError
	if !errors.As(err, &coded) || coded.Reason != mintProbeReason {
		t.Fatalf("the rotation refusal is not the probe's: %v", err)
	}
	if !strings.Contains(err.Error(), "index 1 is already spent") {
		t.Errorf("the refusal does not name the reserved index:\n%s", err)
	}

	// The chain is untouched and the replacement key was never stored.
	chain, err := lr.Relay.GetIdentity(did)
	if err != nil || chain == nil {
		t.Fatalf("chain for %s: %v", did, err)
	}
	if len(chain.Log) != 1 {
		t.Errorf("the refused rotation appended %d operation(s)", len(chain.Log)-1)
	}
	if storeA.HasKey(keyAccount(replacement)) {
		t.Error("the refused rotation wrote the replacement key into the keystore")
	}
	if meta, _ := getVaults().Load("personal"); meta.NextIndex != 2 {
		t.Errorf("NextIndex = %d, want 2 — the rotation's index stays burned", meta.NextIndex)
	}
}
