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
	"encoding/json"
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/localrelay"
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

	out, _ := statusHuman(t, did, "oracle")
	assertContains(t, out, "VERDICT: behind", "1 operation(s) this machine has not seen",
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
	assertContains(t, out, "VERDICT: ahead-unpublished", "1 operation(s) that oracle (",
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
	assertContains(t, out, "VERDICT: diverged", "shared history of 1 operation(s)",
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
