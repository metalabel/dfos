package cmd

// `dfos identity status` tests. Like the other cmd tests these drive RunE
// against the package globals setupDevices wires, so they MUST NOT run with
// t.Parallel().
//
// Both sides of the comparison are real. The local side is a chain built by the
// ordinary commands and held in a local relay; the remote side is the same kind
// of log served over HTTP by the fake oracle, so protocol.VerifyIdentityChain
// has something to verify rather than something to wave through. The two are
// forced apart by ingesting different prefixes — and, for the divergence, by
// signing two different second operations over one genesis, which is the only
// way to produce a fork that is not just a shorter chain.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/localrelay"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
	"github.com/spf13/cobra"
)

// --- helpers ---

// newMachineRelay swaps the package-global local relay for a fresh, empty one:
// one test process standing in for a second machine, or for the same machine at
// an earlier point in a chain's history. The previous relay is restored on
// cleanup, so setupDevices' own teardown still finds what it opened.
func newMachineRelay(t *testing.T) *localrelay.LocalRelay {
	t.Helper()
	lr, err := localrelay.Open(cfg, &localrelay.Options{DBPath: t.TempDir() + "/relay.db"})
	if err != nil {
		t.Fatalf("open a second local relay: %v", err)
	}
	prev := localRelayInstance
	localRelayInstance = lr
	t.Cleanup(func() {
		lr.Close()
		localRelayInstance = prev
	})
	return lr
}

// heldLog reads the operation log the ACTIVE local relay holds for a DID —
// whichever relay newMachineRelay last installed.
func heldLog(t *testing.T, did string) []string {
	t.Helper()
	return chainLog(t, localRelayInstance, did)
}

// rotateEverything retires the identity's current key across all three roles,
// which appends exactly one operation.
func rotateEverything(t *testing.T, name string) {
	t.Helper()
	identityFlag = name
	update := newIdentityUpdateCmd()
	mustSetFlag(t, update, "rotate-controller", "true")
	mustSetFlag(t, update, "rotate-auth", "true")
	mustSetFlag(t, update, "rotate-assert", "true")
	if _, _, err := runCapturing(t, update, nil); err != nil {
		t.Fatalf("identity update --rotate-*: %v", err)
	}
}

func statusCmdFor(t *testing.T, peer string) *cobra.Command {
	t.Helper()
	cmd := newIdentityStatusCmd()
	if peer != "" {
		mustSetFlag(t, cmd, "peer", peer)
	}
	return cmd
}

// statusJSON runs the command with --json and parses the document. An `unknown`
// verdict comes back with a non-nil error AND a document, which is the whole
// point of the exit code, so the error never stops the parse.
func statusJSON(t *testing.T, target, peer string) (identityStatusResult, error) {
	t.Helper()
	prev := jsonFlag
	jsonFlag = true
	defer func() { jsonFlag = prev }()

	stdout, _, err := runCapturing(t, statusCmdFor(t, peer), []string{target})
	var res identityStatusResult
	if jsonErr := json.Unmarshal(bytes.TrimSpace([]byte(stdout)), &res); jsonErr != nil {
		t.Fatalf("unmarshal identity status: %v\nraw: %s", jsonErr, stdout)
	}
	return res, err
}

func statusHuman(t *testing.T, target, peer string) (string, error) {
	t.Helper()
	stdout, _, err := runCapturing(t, statusCmdFor(t, peer), []string{target})
	return stdout, err
}

func assertContains(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Fatalf("output is missing %q:\n%s", want, out)
		}
	}
}

// --- the verdicts ---

// The relay serves what this machine holds. `in-sync` is that answer and no
// more: the relay is named on the row above it and in the sentence itself.
func TestIdentityStatusInSyncNamesTheRelayThatAnswered(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	keys = storeA

	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	oracle.logsByDID[did] = heldLog(t, did)

	res, err := statusJSON(t, "alice", "oracle")
	if err != nil {
		t.Fatalf("identity status: %v", err)
	}
	if res.Verdict != identityStatusInSync {
		t.Fatalf("verdict = %q, want %q (%+v)", res.Verdict, identityStatusInSync, res)
	}
	if res.Relay == nil || res.Relay.Name != "oracle" || res.Relay.Source != "--peer" || res.Relay.URL == "" {
		t.Fatalf("the relay consulted is not named: %+v", res.Relay)
	}
	if res.Local == nil || res.Remote == nil || res.Local.HeadCID != res.Remote.HeadCID {
		t.Fatalf("in-sync over two different heads: %+v / %+v", res.Local, res.Remote)
	}
	if res.Local.Operations != 1 || res.Remote.Operations != 1 {
		t.Fatalf("operation counts = %d local / %d remote, want 1 each", res.Local.Operations, res.Remote.Operations)
	}

	out, err := statusHuman(t, "alice", "oracle")
	if err != nil {
		t.Fatalf("identity status: %v", err)
	}
	// The epistemic scope is in the sentence, not only in the help text.
	assertContains(t, out, "VERDICT: in-sync", "oracle (", "via --peer",
		"Another relay can hold another chain")
}

// The relay holds an operation this machine has never seen. The count is the
// answer, and the command that closes the gap is named with the peer it names.
func TestIdentityStatusBehindCountsTheOperationsItLacks(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	keys = storeA
	genesisOnly := heldLog(t, did)
	rotateEverything(t, "alice")
	rotated := heldLog(t, did)
	if len(rotated) != 2 {
		t.Fatalf("the rotated chain has %d operations, want 2", len(rotated))
	}

	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	oracle.logsByDID[did] = rotated

	// This machine is the same machine one operation ago.
	machine := newMachineRelay(t)
	mustIngest(t, machine, genesisOnly)

	res, err := statusJSON(t, did, "oracle")
	if err != nil {
		t.Fatalf("identity status: %v", err)
	}
	if res.Verdict != identityStatusBehind || res.BehindBy != 1 {
		t.Fatalf("verdict = %q behindBy = %d, want behind/1 (%+v)", res.Verdict, res.BehindBy, res)
	}

	// One chain of each length, so both halves of the agreement are asserted:
	// this machine holds one operation, the relay holds two.
	out, _ := statusHuman(t, did, "oracle")
	assertContains(t, out, "VERDICT: behind", "1 operation this machine has not seen",
		"— 1 operation, ", "— 2 operations, ",
		"dfos identity fetch "+did+" --peer oracle")
}

// The other direction: operations signed here and never published. The verdict
// names the command that publishes them, which is what makes it actionable.
func TestIdentityStatusAheadUnpublishedNamesThePublishPath(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	keys = storeA
	genesisOnly := heldLog(t, did)
	rotateEverything(t, "alice")

	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	oracle.logsByDID[did] = genesisOnly

	res, err := statusJSON(t, "alice", "oracle")
	if err != nil {
		t.Fatalf("identity status: %v", err)
	}
	if res.Verdict != identityStatusAhead || res.AheadBy != 1 {
		t.Fatalf("verdict = %q aheadBy = %d, want ahead-unpublished/1 (%+v)", res.Verdict, res.AheadBy, res)
	}

	out, _ := statusHuman(t, "alice", "oracle")
	assertContains(t, out, "VERDICT: ahead-unpublished", "1 operation that oracle (",
		"dfos identity publish alice --peer oracle")
}

// Two second operations over one genesis: a fork, not a shorter chain. The
// report locates it and refuses to resolve it.
func TestIdentityStatusDivergedReportsTheForkAndChoosesNothing(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	keys = storeA
	genesisOnly := heldLog(t, did)
	rotateEverything(t, "alice")
	remote := heldLog(t, did)

	// A second machine holding the same genesis rotates independently. Its second
	// operation names the same previous CID and is a different operation.
	machine := newMachineRelay(t)
	mustIngest(t, machine, genesisOnly)
	rotateEverything(t, "alice")
	local := heldLog(t, did)
	if len(local) != 2 || len(remote) != 2 || local[1] == remote[1] {
		t.Fatalf("the two chains did not fork: local %d ops, remote %d ops", len(local), len(remote))
	}

	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	oracle.logsByDID[did] = remote

	res, err := statusJSON(t, "alice", "oracle")
	if err != nil {
		t.Fatalf("identity status: %v", err)
	}
	if res.Verdict != identityStatusDiverged {
		t.Fatalf("verdict = %q, want %q (%+v)", res.Verdict, identityStatusDiverged, res)
	}
	if res.ForkIndex == nil || *res.ForkIndex != 1 {
		t.Fatalf("fork index = %v, want 1", res.ForkIndex)
	}
	if res.LocalForkCreatedAt == "" || res.RemoteForkCreatedAt == "" {
		t.Fatalf("the fork point carries no dates: %+v", res)
	}
	// Equal operation counts is exactly the case a head comparison alone gets
	// wrong, so the two sides must not be reported as agreeing on anything.
	if res.BehindBy != 0 || res.AheadBy != 0 {
		t.Fatalf("a divergence was counted as a distance: behindBy=%d aheadBy=%d", res.BehindBy, res.AheadBy)
	}

	out, _ := statusHuman(t, "alice", "oracle")
	assertContains(t, out, "VERDICT: diverged", "shared history of 1 operation and then parted",
		"Fork at operation 1", "Neither side is the answer", "deliberately")
}

// No chain here is a reportable state. The relay's side still answers, and the
// report says how to bring the chain over rather than erroring out.
func TestIdentityStatusNoLocalChainStillReportsTheRelay(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	keys = storeA
	published := heldLog(t, did)

	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	oracle.logsByDID[did] = published

	newMachineRelay(t) // empty: this machine has never held the chain

	res, err := statusJSON(t, did, "oracle")
	if err != nil {
		t.Fatalf("identity status: %v", err)
	}
	if res.Verdict != identityStatusNoLocalChain {
		t.Fatalf("verdict = %q, want %q (%+v)", res.Verdict, identityStatusNoLocalChain, res)
	}
	if res.Local != nil {
		t.Fatalf("a machine holding no chain reported one: %+v", res.Local)
	}
	if res.Remote == nil || res.Remote.Operations != 1 {
		t.Fatalf("the relay's side was not reported: %+v", res.Remote)
	}

	out, _ := statusHuman(t, did, "oracle")
	assertContains(t, out, "VERDICT: no-local-chain", "dfos identity fetch "+did+" --peer oracle")
}

// --- the ways it cannot answer ---

// A relay that does not answer is never agreement. The verdict is unknown, the
// relay is named with the transport's own words, and the exit status is 1 so a
// script cannot read the silence as a match.
func TestIdentityStatusUnreachableRelayIsUnknownAndLoud(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	keys = storeA

	dead := newFakeOracle(t)
	dead.registerAsPeer(t, "gone")
	dead.server.Close()

	res, err := statusJSON(t, did, "gone")
	if res.Verdict != identityStatusUnknown {
		t.Fatalf("verdict = %q, want %q (%+v)", res.Verdict, identityStatusUnknown, res)
	}
	if res.Reason == "" || !strings.Contains(res.Reason, "gone") {
		t.Fatalf("the reason does not name the relay: %q", res.Reason)
	}
	assertExitCode(t, err, 1)

	out, _ := statusHuman(t, did, "gone")
	assertContains(t, out, "VERDICT: unknown", "gone (", "This is NOT in-sync")
}

// A log that does not verify is not a chain, and comparing against one would
// produce a verdict about bytes. Same posture: unknown, named, exit 1.
func TestIdentityStatusUnverifiableRemoteChainIsUnknownAndLoud(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	keys = storeA
	rotateEverything(t, "alice")

	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	// The genesis dropped: real operations, in order, over no beginning.
	oracle.logsByDID[did] = heldLog(t, did)[1:]

	res, err := statusJSON(t, did, "oracle")
	if res.Verdict != identityStatusUnknown {
		t.Fatalf("verdict = %q, want %q (%+v)", res.Verdict, identityStatusUnknown, res)
	}
	if !strings.Contains(res.Reason, "does not verify") || !strings.Contains(res.Reason, "oracle") {
		t.Fatalf("the reason does not name the relay and the failure: %q", res.Reason)
	}
	assertExitCode(t, err, 1)
}

// Nothing to ask is its own answer, and it is not silence: the identity
// advertises no relay and none was named, so no comparison was attempted.
func TestIdentityStatusWithNoRelayToConsultIsLoud(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	keys = storeA

	res, err := statusJSON(t, did, "")
	if res.Verdict != identityStatusUnknown {
		t.Fatalf("verdict = %q, want %q (%+v)", res.Verdict, identityStatusUnknown, res)
	}
	assertContains(t, res.Reason, "no relay to compare against",
		"advertises no DfosRelay service", "no --peer was given")
	if res.Relay != nil {
		t.Fatalf("a relay was reported when none was asked: %+v", res.Relay)
	}
	// The local side is still reported: what this machine holds is a fact even
	// when nothing can be compared against it.
	if res.Local == nil {
		t.Fatalf("the local chain went unreported: %+v", res)
	}
	assertExitCode(t, err, 1)
}

// With no --peer the relay comes from the identity's own chain, and the source
// says which of the two it was.
func TestIdentityStatusUsesTheAdvertisedRelayWhenNoPeerIsNamed(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA

	oracle := newFakeOracle(t)
	create := newIdentityCreateCmd()
	mustSetFlag(t, create, "name", "alice")
	mustSetFlag(t, create, "no-vault", "true")
	mustSetFlag(t, create, "service", "id=relay,type=DfosRelay,endpoint="+oracle.server.URL)
	var created struct {
		DID string `json:"did"`
	}
	runJSON(t, create, nil, &created)
	identityFlag = "alice"
	oracle.logsByDID[created.DID] = heldLog(t, created.DID)

	res, err := statusJSON(t, "alice", "")
	if err != nil {
		t.Fatalf("identity status: %v", err)
	}
	if res.Verdict != identityStatusInSync {
		t.Fatalf("verdict = %q, want %q (%+v)", res.Verdict, identityStatusInSync, res)
	}
	if res.Relay == nil || res.Relay.Source != "advertised DfosRelay" || res.Relay.URL != oracle.server.URL {
		t.Fatalf("the advertised relay was not the one consulted: %+v", res.Relay)
	}

	out, _ := statusHuman(t, "alice", "")
	assertContains(t, out, "via advertised DfosRelay", oracle.server.URL)
}

// --- the possession roster ---
//
// The roster answers a question the verdict does not: which keys the chain
// declares, and which of them this machine can actually sign with. Both halves
// are asserted against the same chain, because a roster read off the wrong head
// is a confident answer about keys an identity no longer has.

// keyRow finds one roster row by key id.
func keyRow(t *testing.T, res identityStatusResult, id string) identityStatusKeyRow {
	t.Helper()
	for _, k := range res.Keys {
		if k.ID == id {
			return k
		}
	}
	t.Fatalf("no roster row for %q; roster holds %+v", id, res.Keys)
	return identityStatusKeyRow{}
}

// chainState reads the state the ACTIVE local relay projects for a DID.
func chainState(t *testing.T, did string) *relay.StoredIdentityChain {
	t.Helper()
	chain, err := localRelayInstance.Relay.GetIdentity(did)
	if err != nil || chain == nil {
		t.Fatalf("get the chain for %s: chain=%v err=%v", did, chain, err)
	}
	return chain
}

// Possession is read off the KEYSTORE and the roster off the chain, so the same
// chain reports the same key differently on two machines. Both renderings are
// asserted over one identity, with only the active keystore changing.
func TestIdentityStatusRosterReportsPossessionAgainstTheVerifiedHead(t *testing.T) {
	storeA, storeB, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	keys = storeA

	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	oracle.logsByDID[did] = heldLog(t, did)
	genesisKey := chainState(t, did).State.AuthKeys[0]

	res, err := statusJSON(t, "alice", "oracle")
	if err != nil {
		t.Fatalf("identity status: %v", err)
	}
	// The sync half is untouched by the roster attaching to the same document.
	if res.Verdict != identityStatusInSync || res.Local == nil || res.Remote == nil {
		t.Fatalf("the verdict moved when the roster attached: %+v", res)
	}
	if res.KeysBasis == nil || res.KeysBasis.Source != identityStatusKeysRemote {
		t.Fatalf("the roster names no remote basis: %+v", res.KeysBasis)
	}
	if res.KeysBasis.HeadCID != res.Remote.HeadCID {
		t.Fatalf("basis head %q is not the verified remote head %q", res.KeysBasis.HeadCID, res.Remote.HeadCID)
	}
	row := keyRow(t, res, genesisKey.ID)
	if !row.Held || row.Vault != "" || row.PublicKey != genesisKey.PublicKeyMultibase {
		t.Fatalf("the genesis key of a --no-vault identity came out %+v", row)
	}
	if len(row.Roles) != 3 {
		t.Fatalf("roles %v, want all three the genesis key is declared in", row.Roles)
	}

	out, err := statusHuman(t, "alice", "oracle")
	if err != nil {
		t.Fatalf("identity status: %v", err)
	}
	assertContains(t, out, "Keys:        roster as of remote head", "the verified chain oracle (",
		"KEY ID", genesisKey.ID, "held (standalone)")

	// The same chain, on a machine that holds none of its keys. Nothing about the
	// declaration changed; what changed is what this machine can sign with.
	keys = storeB
	res, err = statusJSON(t, "alice", "oracle")
	if err != nil {
		t.Fatalf("identity status: %v", err)
	}
	if row := keyRow(t, res, genesisKey.ID); row.Held {
		t.Fatalf("a key on the other machine's keystore reported as held: %+v", row)
	}
	out, _ = statusHuman(t, "alice", "oracle")
	assertContains(t, out, "not held on this machine")
}

// A vault-minted key is one a written-down phrase can mint again; a standalone
// key is one this keystore is the only copy of. The roster says which, because
// the two are different answers to "what happens if this machine is lost".
func TestIdentityStatusRosterNamesTheVaultThatMintedAHeldKey(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	createVault(t, "personal")
	did := createIdentity(t, "alice", storeA)
	keys = storeA

	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	oracle.logsByDID[did] = heldLog(t, did)

	res, err := statusJSON(t, "alice", "oracle")
	if err != nil {
		t.Fatalf("identity status: %v", err)
	}
	row := keyRow(t, res, chainState(t, did).State.AuthKeys[0].ID)
	if !row.Held || row.Vault != "personal" {
		t.Fatalf("a vault-minted key lost its provenance: %+v", row)
	}

	out, _ := statusHuman(t, "alice", "oracle")
	assertContains(t, out, "held (vault 'personal' — derivable from phrase)")
}

// Unreadable vault records and absent vault records are opposite answers.
// "standalone" means this keystore is the only copy, and a roster that says it
// because the records could not be read tells an operator to treat a
// phrase-covered key as unrecoverable. The roster says `held`, says why the
// custody half is missing, and keeps the possession half — which the keystore
// answered by itself.
func TestIdentityStatusRosterSaysWhenVaultRecordsAreUnreadable(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	createVault(t, "personal")
	did := createIdentity(t, "alice", storeA)
	keys = storeA

	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	oracle.logsByDID[did] = heldLog(t, did)
	genesisKey := chainState(t, did).State.AuthKeys[0]

	// A regular file where the vaults directory belongs: List fails for a reason
	// that is not "no vaults exist", which is the case the index must not absorb.
	dir := getVaults().Dir()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove vaults dir: %v", err)
	}
	if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("plant file at vaults dir: %v", err)
	}

	res, err := statusJSON(t, "alice", "oracle")
	if err != nil {
		t.Fatalf("identity status: %v", err)
	}
	if res.VaultsUnavailable == "" {
		t.Fatalf("unreadable vault records went unreported: %+v", res.KeysBasis)
	}
	row := keyRow(t, res, genesisKey.ID)
	if !row.Held || row.Vault != "" {
		t.Fatalf("a held key under unreadable records came out %+v", row)
	}

	out, _ := statusHuman(t, "alice", "oracle")
	assertContains(t, out, "vault records could not be read")
	if strings.Contains(out, "held (standalone)") || strings.Contains(out, "derivable from phrase") {
		t.Fatalf("the roster made a custody claim off unreadable records:\n%s", out)
	}
}

// The recovery case the section exists for: no chain here at all. The roster is
// the relay's, and it is what says whether the keys of an identity this machine
// has lost are still on this machine.
func TestIdentityStatusRosterAttachesFromTheRelayWithNoLocalChain(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	keys = storeA
	published := heldLog(t, did)
	genesisKey := chainState(t, did).State.AuthKeys[0]

	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	oracle.logsByDID[did] = published

	newMachineRelay(t) // the chain is gone from here; the keys are not

	res, err := statusJSON(t, did, "oracle")
	if err != nil {
		t.Fatalf("identity status: %v", err)
	}
	if res.Verdict != identityStatusNoLocalChain {
		t.Fatalf("verdict = %q, want %q", res.Verdict, identityStatusNoLocalChain)
	}
	if res.KeysBasis == nil || res.KeysBasis.Source != identityStatusKeysRemote {
		t.Fatalf("with no local chain the roster must come from the relay: %+v", res.KeysBasis)
	}
	if row := keyRow(t, res, genesisKey.ID); !row.Held {
		t.Fatalf("a key this machine still holds reported as absent: %+v", row)
	}
}

// A relay that cannot be reached makes the COMPARISON unanswerable, not the
// possession question. The roster stays, its basis says which head it came from
// and that no comparison stands behind it, and the exit code is still 1.
func TestIdentityStatusRosterSurvivesAnUnknownVerdict(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	keys = storeA
	local := chainState(t, did)

	dead := newFakeOracle(t)
	dead.registerAsPeer(t, "gone")
	dead.server.Close()

	res, err := statusJSON(t, did, "gone")
	if res.Verdict != identityStatusUnknown {
		t.Fatalf("verdict = %q, want %q", res.Verdict, identityStatusUnknown)
	}
	assertExitCode(t, err, 1)
	if res.KeysBasis == nil || res.KeysBasis.Source != identityStatusKeysLocal {
		t.Fatalf("the roster names no local basis: %+v", res.KeysBasis)
	}
	if res.KeysBasis.HeadCID != local.HeadCID {
		t.Fatalf("basis head %q is not the local head %q", res.KeysBasis.HeadCID, local.HeadCID)
	}
	if row := keyRow(t, res, local.State.AuthKeys[0].ID); !row.Held {
		t.Fatalf("possession went unreported on an unknown verdict: %+v", row)
	}

	out, _ := statusHuman(t, did, "gone")
	assertContains(t, out, "Keys:        roster as of local head", "the relay comparison could not be made")
}

// Ahead of the relay, the local head is the fresher one: it declares a key the
// relay has never been told about. The roster reads THAT head, and says so.
func TestIdentityStatusAheadRostersTheLocalHead(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	keys = storeA
	genesisOnly := heldLog(t, did)
	genesisKey := chainState(t, did).State.AuthKeys[0]
	rotateEverything(t, "alice")
	rotated := chainState(t, did)
	if rotated.State.AuthKeys[0].ID == genesisKey.ID {
		t.Fatal("the rotation did not replace the auth key")
	}

	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	oracle.logsByDID[did] = genesisOnly

	res, err := statusJSON(t, "alice", "oracle")
	if err != nil {
		t.Fatalf("identity status: %v", err)
	}
	if res.Verdict != identityStatusAhead {
		t.Fatalf("verdict = %q, want %q", res.Verdict, identityStatusAhead)
	}
	if res.KeysBasis == nil || res.KeysBasis.Source != identityStatusKeysLocal {
		t.Fatalf("an ahead roster read the relay's head: %+v", res.KeysBasis)
	}
	if res.KeysBasis.HeadCID != rotated.HeadCID {
		t.Fatalf("basis head %q is not the local head %q", res.KeysBasis.HeadCID, rotated.HeadCID)
	}
	// The unpublished key is the whole reason this verdict reads the local head.
	if row := keyRow(t, res, rotated.State.AuthKeys[0].ID); !row.Held {
		t.Fatalf("the unpublished key is missing from the roster: %+v", res.Keys)
	}

	out, _ := statusHuman(t, "alice", "oracle")
	assertContains(t, out, "Keys:        roster as of local head",
		"ahead of the relay; includes operations not yet published", rotated.State.AuthKeys[0].ID)
}

// A void membership is a key the chain names and nothing proved. It is a row,
// marked, with the footnote that says what the marker means — the same posture
// `identity keys` takes, for the same reason: it looks like a key.
func TestIdentityStatusRosterMarksAVoidMembership(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", storeA)
	keys = storeA

	chain := chainState(t, did)
	signer, err := selectHeldKey(did, chain.State.ControllerKeys, "controller")
	if err != nil {
		t.Fatalf("held controller key: %v", err)
	}
	controllerPriv, err := keys.GetPrivateKey(signer.Account)
	if err != nil {
		t.Fatalf("read controller key: %v", err)
	}
	// Introduced with no proof and no seed on this machine: declared, void, and
	// unheld all at once, which is the row every part of the rendering is for.
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	unproved := protocol.NewMultikeyPublicKey(protocol.DeriveKeyID(protocol.EncodeMultikey(pub)), pub)
	head, _, err := protocol.DecodeJWSUnsafe(chain.Log[len(chain.Log)-1])
	if err != nil {
		t.Fatalf("decode head: %v", err)
	}
	jws := signUnprovedIdentityUpdate(t, unprovedUpdate{
		previousCID:    head.CID,
		after:          chain.LastCreatedAt,
		controllerKeys: chain.State.ControllerKeys,
		authKeys:       append(append([]protocol.MultikeyPublicKey{}, chain.State.AuthKeys...), unproved),
		assertKeys:     chain.State.AssertKeys,
		kid:            signer.KID,
		privateKey:     controllerPriv,
	})
	if res := lr.Relay.Ingest([]string{jws}); len(res) > 0 && res[0].Status == "rejected" {
		t.Fatalf("the relay rejected an unproved introduction instead of voiding it: %s", res[0].Error)
	}

	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	oracle.logsByDID[did] = heldLog(t, did)

	res, err := statusJSON(t, "alice", "oracle")
	if err != nil {
		t.Fatalf("identity status: %v", err)
	}
	row := keyRow(t, res, unproved.ID)
	if !row.Void || row.Held {
		t.Fatalf("a void, unheld membership came out %+v", row)
	}
	if len(row.Roles) != 1 || row.Roles[0] != "auth (void)" {
		t.Fatalf("roles %v, want the void marker", row.Roles)
	}

	out, _ := statusHuman(t, "alice", "oracle")
	assertContains(t, out, "auth (void)", "not held on this machine",
		"declared by this chain and never proved", "resolve nowhere")
}

func assertExitCode(t *testing.T, err error, want int) {
	t.Helper()
	coded, ok := err.(*ExitCodeError)
	if !ok {
		t.Fatalf("error is %v (%T), want an ExitCodeError", err, err)
	}
	if coded.Code != want {
		t.Fatalf("exit code = %d, want %d", coded.Code, want)
	}
}
