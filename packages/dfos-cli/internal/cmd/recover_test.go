package cmd

// `dfos recover` tests. Like the vault and multi-device tests these drive RunE
// directly against the package globals setupDevices wires, so they MUST NOT run
// with t.Parallel().
//
// The oracle is a loopback server rather than a mock client: the failure modes
// that matter here are HTTP-shaped (a 501, an unreachable relay, a relay that
// ignores an unknown query parameter and answers 200 with a full page), and a
// hand-written fake client cannot get any of them wrong in the way a real relay
// does.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/vault"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/spf13/cobra"
)

// --- the fake oracle ---

type fakeOracle struct {
	server *httptest.Server
	// rowsByKey is the has-ever-proved index: public multikey → identity rows. Only
	// memberships a possession proof admitted appear here, which is why a chain
	// that merely declares a key can neither claim it nor burn it.
	rowsByKey map[string][]client.IndexIdentityRow
	// logsByDID is the proof plane: DID → ordered JWS tokens.
	logsByDID map[string][]string

	// indexStatus, when non-zero, is returned for every index request — 501 is
	// the relay that does not serve the family at all.
	indexStatus int
	// ignoresKeyParam models a relay predating the `key=` filter: it answers 200
	// with an UNFILTERED page, which is the failure with no status code.
	ignoresKeyParam bool
	// failIndexAfter, when positive, makes every index query past that count fail
	// — a partition arriving mid-scan.
	failIndexAfter int

	indexQueries int
}

func newFakeOracle(t *testing.T) *fakeOracle {
	t.Helper()
	f := &fakeOracle{
		rowsByKey: map[string][]client.IndexIdentityRow{},
		logsByDID: map[string][]string{},
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeOracle) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/index/v0/identities":
		f.indexQueries++
		if f.indexStatus != 0 {
			w.WriteHeader(f.indexStatus)
			_, _ = w.Write([]byte(`{"error":"index not served"}`))
			return
		}
		if f.failIndexAfter > 0 && f.indexQueries > f.failIndexAfter {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"upstream gone"}`))
			return
		}
		rows := []client.IndexIdentityRow{}
		if f.ignoresKeyParam {
			// Every row it holds, regardless of the key asked about.
			for _, set := range f.rowsByKey {
				rows = append(rows, set...)
			}
		} else {
			rows = append(rows, f.rowsByKey[r.URL.Query().Get("key")]...)
		}
		writeJSON(w, map[string]any{"identities": rows, "next": nil})

	case strings.HasPrefix(r.URL.Path, "/proof/v1/identities/") && strings.HasSuffix(r.URL.Path, "/log"):
		raw := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/proof/v1/identities/"), "/log")
		did, err := url.PathUnescape(raw)
		if err != nil {
			did = raw
		}
		log, ok := f.logsByDID[did]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"identity not found"}`))
			return
		}
		entries := make([]map[string]string, 0, len(log))
		for i, token := range log {
			entries = append(entries, map[string]string{"cid": fmt.Sprintf("bafyfake%d", i), "jwsToken": token})
		}
		writeJSON(w, map[string]any{"entries": entries, "next": nil})

	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"no route"}`))
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	body, _ := json.Marshal(v)
	_, _ = w.Write(body)
}

// declare records that DID declared publicKey — the row the index would return.
func (f *fakeOracle) declare(publicKey, did string, deleted bool, profileName string) {
	row := client.IndexIdentityRow{DID: did, HeadCID: "bafyhead", OpCount: 1, IsDeleted: deleted}
	if profileName != "" {
		row.Profile = &client.IndexIdentityProfile{Anchor: "anchor", PublicRead: true, Name: profileName}
	}
	f.rowsByKey[publicKey] = append(f.rowsByKey[publicKey], row)
}

// registerAsPeer points the resolution stack at this oracle under a name.
func (f *fakeOracle) registerAsPeer(t *testing.T, name string) {
	t.Helper()
	cfg.Relays[name] = config.RelayConfig{URL: f.server.URL}
}

// --- helpers ---

// importVault adopts a mnemonic under a name, the way an operator holding a
// phrase and nothing else does.
func importVault(t *testing.T, name, mnemonic string) {
	t.Helper()
	cmd := newVaultImportCmd()
	cmd.SetIn(strings.NewReader(mnemonic + "\n"))
	if _, _, err := runCapturing(t, cmd, []string{name}); err != nil {
		t.Fatalf("vault import %s: %v", name, err)
	}
}

// derivedPublicKey is the multibase public key a vault's seed produces at index.
func derivedPublicKey(t *testing.T, mnemonic string, index uint32) string {
	t.Helper()
	seed, err := vault.MnemonicSeed(mnemonic)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, pub, err := vault.DeriveKey(seed, index)
	if err != nil {
		t.Fatalf("derive %d: %v", index, err)
	}
	return protocol.EncodeMultikey(pub)
}

// newRecover builds the command with the standard test flags already set.
func newRecover(t *testing.T, flags map[string]string) *cobra.Command {
	t.Helper()
	cmd := newRecoverCmd()
	for k, v := range flags {
		mustSetFlag(t, cmd, k, v)
	}
	return cmd
}

// --- the scan ---

func TestRecoverGapLimitStopsOnlyAfterNConsecutiveUnused(t *testing.T) {
	store, _, _ := setupDevices(t)
	keys = store
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")

	mnemonic := createVault(t, "personal")

	// Used at 0, 1, and 5. The hole at 2–4 is three long; with a depth of five
	// it must NOT stop the walk, because a burned index leaves exactly that
	// shape and the identity at 5 is the one worth finding.
	for _, i := range []uint32{0, 1, 5} {
		oracle.declare(derivedPublicKey(t, mnemonic, i), "did:dfos:absent"+fmt.Sprint(i), false, "")
	}

	var res recoverResult
	runJSON(t, newRecover(t, map[string]string{"vault": "personal", "peer": "oracle", "scan-depth": "5"}), nil, &res)

	if got := usedIndices(res); !equalIndices(got, []uint32{0, 1, 5}) {
		t.Fatalf("used indices = %v, want [0 1 5] — the hole at 2–4 stopped the scan", got)
	}
	// 0…10: the walk ends once 6,7,8,9,10 are five consecutive unused.
	if res.IndicesScanned != 11 {
		t.Errorf("scanned %d indices, want 11 (0–10)", res.IndicesScanned)
	}
	if res.HighestUsedIndex != 5 {
		t.Errorf("highest used index = %d, want 5", res.HighestUsedIndex)
	}
	if !res.Scanned {
		t.Error("the result does not record that a scan ran")
	}
	if res.Oracle != "oracle" || res.OracleURL == "" {
		t.Errorf("the oracle is not named in the result: %+v", res)
	}
}

func TestRecoverScanDepthOverridesTheGapLimit(t *testing.T) {
	store, _, _ := setupDevices(t)
	keys = store
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")

	mnemonic := createVault(t, "personal")
	for _, i := range []uint32{0, 1, 5} {
		oracle.declare(derivedPublicKey(t, mnemonic, i), "did:dfos:absent"+fmt.Sprint(i), false, "")
	}

	// A depth of two stops in the middle of the same hole, and the index at 5 is
	// never reached. Same corpus, different N, different answer — which is the
	// whole reason the flag exists and the reason the report names its depth.
	var shallow recoverResult
	runJSON(t, newRecover(t, map[string]string{"vault": "personal", "peer": "oracle", "scan-depth": "2"}), nil, &shallow)
	if got := usedIndices(shallow); !equalIndices(got, []uint32{0, 1}) {
		t.Fatalf("used indices at depth 2 = %v, want [0 1]", got)
	}
	if shallow.IndicesScanned != 4 {
		t.Errorf("scanned %d indices at depth 2, want 4 (0–3)", shallow.IndicesScanned)
	}
	if shallow.ScanDepth != 2 {
		t.Errorf("the report claims depth %d, want 2", shallow.ScanDepth)
	}

	// A depth below one is refused rather than looped on.
	if _, _, err := runCapturing(t, newRecover(t, map[string]string{"vault": "personal", "peer": "oracle", "scan-depth": "0"}), nil); err == nil {
		t.Error("--scan-depth 0 was accepted")
	}
}

func TestRecoverCountsAManifestRecordAsUsedWithoutTheOracle(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	keys = storeA
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")

	mnemonic := createVault(t, "personal")
	did := createIdentity(t, "alice", storeA)

	// The oracle knows NOTHING — no rows for any key. The manifest is the primary
	// record, so the index this machine minted is still used, and the hole it
	// would otherwise open does not shorten the scan.
	chain, err := lr.Relay.GetIdentity(did)
	if err != nil || chain == nil {
		t.Fatalf("chain for %s: %v", did, err)
	}
	oracle.logsByDID[did] = chain.Log

	var res recoverResult
	runJSON(t, newRecover(t, map[string]string{"vault": "personal", "peer": "oracle", "scan-depth": "3"}), nil, &res)

	if got := usedIndices(res); !equalIndices(got, []uint32{0}) {
		t.Fatalf("used indices = %v, want [0] from the vault's own record", got)
	}
	for _, k := range res.Keys {
		if k.Outcome != "already-present" {
			t.Errorf("index %d outcome = %q, want already-present (this machine minted it)", k.Index, k.Outcome)
		}
	}
	_ = mnemonic
}

func usedIndices(r recoverResult) []uint32 {
	seen := map[uint32]bool{}
	var out []uint32
	for _, k := range r.Keys {
		if !seen[k.Index] {
			seen[k.Index] = true
			out = append(out, k.Index)
		}
	}
	return out
}

func equalIndices(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- fail loud ---

func TestRecoverFailsLoudWhenTheOracleDoesNotServeTheIndex(t *testing.T) {
	store, _, _ := setupDevices(t)
	keys = store
	oracle := newFakeOracle(t)
	oracle.indexStatus = http.StatusNotImplemented
	oracle.registerAsPeer(t, "oracle")
	createVault(t, "personal")

	stdout, _, err := runCapturing(t, newRecover(t, map[string]string{"vault": "personal", "peer": "oracle"}), nil)
	if err == nil {
		t.Fatal("a 501 on the index routes was not a failure")
	}
	msg := err.Error()
	for _, want := range []string{"oracle", "501", "/index/v0/identities?key=", "NOT 'no keys found'", "--manifest-only"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error does not mention %q:\n%s", want, msg)
		}
	}
	if stdout != "" {
		t.Errorf("a refused scan printed a report anyway:\n%s", stdout)
	}
	if oracle.indexQueries != 1 {
		t.Errorf("the scan ran %d index queries past a 501, want only the probe", oracle.indexQueries)
	}
}

func TestRecoverFailsLoudWhenTheRelayIgnoresTheKeyParameter(t *testing.T) {
	store, _, _ := setupDevices(t)
	keys = store
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	mnemonic := createVault(t, "personal")

	// A relay that holds identities and predates `key=`: it answers 200 with an
	// unfiltered page. Without the sentinel probe every derived index would look
	// used and the scan would never stop.
	oracle.declare(derivedPublicKey(t, mnemonic, 0), "did:dfos:somebodyelse", false, "")
	oracle.ignoresKeyParam = true

	_, _, err := runCapturing(t, newRecover(t, map[string]string{"vault": "personal", "peer": "oracle"}), nil)
	if err == nil {
		t.Fatal("a relay that ignores 'key=' was treated as an oracle")
	}
	msg := err.Error()
	for _, want := range []string{"ignored the 'key=' parameter", "web-relay >= 0.39.0", "NOT 'no keys found'"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error does not mention %q:\n%s", want, msg)
		}
	}
	if oracle.indexQueries != 1 {
		t.Errorf("the scan ran on past the probe: %d index queries", oracle.indexQueries)
	}
}

func TestRecoverFailsLoudOnAPartitionMidScan(t *testing.T) {
	store, _, _ := setupDevices(t)
	keys = store
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")
	createVault(t, "personal")

	// The probe and two scan queries answer; the third does not. The indices past
	// that point are UNKNOWN, and a truncated prefix that reads like a whole
	// answer is the exact failure this command exists to prevent.
	oracle.failIndexAfter = 3

	_, _, err := runCapturing(t, newRecover(t, map[string]string{"vault": "personal", "peer": "oracle"}), nil)
	if err == nil {
		t.Fatal("a partition mid-scan produced a clean 'no keys found'")
	}
	msg := err.Error()
	for _, want := range []string{"stopped answering at index", "UNKNOWN, not unused", "incomplete"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error does not mention %q:\n%s", want, msg)
		}
	}
}

func TestRecoverFailsLoudWhenTheOracleIsUnreachable(t *testing.T) {
	store, _, _ := setupDevices(t)
	keys = store
	createVault(t, "personal")
	// A port nothing is listening on. Unreachable is not empty.
	cfg.Relays["dead"] = config.RelayConfig{URL: "http://127.0.0.1:1"}

	_, _, err := runCapturing(t, newRecover(t, map[string]string{"vault": "personal", "peer": "dead"}), nil)
	if err == nil {
		t.Fatal("an unreachable oracle produced a clean result")
	}
	if !strings.Contains(err.Error(), "NOT 'no keys found'") {
		t.Errorf("the error does not say what it is not:\n%s", err)
	}
}

func TestRecoverRequiresAVaultAndAPeer(t *testing.T) {
	store, _, _ := setupDevices(t)
	keys = store

	// No vault at all: the error points at the import path, because an operator
	// reaching this command is usually holding a phrase and nothing else.
	_, _, err := runCapturing(t, newRecoverCmd(), nil)
	if err == nil || !strings.Contains(err.Error(), "dfos vault import") {
		t.Fatalf("recover with no vault did not point at the import path: %v", err)
	}

	// A vault but no peer: the scan needs an oracle and says so through the same
	// three-mechanism error every peer-requiring command uses.
	createVault(t, "personal")
	_, _, err = runCapturing(t, newRecover(t, map[string]string{"vault": "personal"}), nil)
	if err == nil || !strings.Contains(err.Error(), "no peer to talk to") {
		t.Fatalf("recover with no peer did not ask for one: %v", err)
	}
}

// --- manifest-only degradation ---

func TestRecoverManifestOnlyRunsNoScanAndSaysSo(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	oracle := newFakeOracle(t)
	oracle.indexStatus = http.StatusNotImplemented
	oracle.registerAsPeer(t, "oracle")

	createVault(t, "personal")
	createIdentity(t, "alice", storeA)

	// The degradation is available even against a relay that cannot answer, and
	// it never touches the index — but it must announce that the scan did not run.
	stdout, _, err := runCapturing(t, newRecover(t, map[string]string{
		"vault": "personal", "peer": "oracle", "manifest-only": "true",
	}), nil)
	if err != nil {
		t.Fatalf("manifest-only recover: %v", err)
	}
	for _, want := range []string{"MANIFEST ONLY", "did NOT run", "NOTHING about keys this seed minted elsewhere"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the manifest-only banner does not say %q:\n%s", want, stdout)
		}
	}
	if oracle.indexQueries != 0 {
		t.Errorf("manifest-only made %d index queries, want none", oracle.indexQueries)
	}

	var res recoverResult
	runJSON(t, newRecover(t, map[string]string{"vault": "personal", "peer": "oracle", "manifest-only": "true"}), nil, &res)
	if res.Scanned {
		t.Error("a manifest-only run claims a scan ran")
	}
	if !res.ManifestOnly {
		t.Error("a manifest-only run does not record itself as one")
	}
	if got := usedIndices(res); !equalIndices(got, []uint32{0}) {
		t.Errorf("manifest-only found %v, want the vault's own record", got)
	}
}

// --- restore ---

func TestRecoverInstallsKeysReconcilesTheVaultAndRaisesTheCounter(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	keys = storeA
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")

	mnemonic := createVault(t, "personal")
	did := createIdentity(t, "alice", storeA)
	chain, _ := lr.Relay.GetIdentity(did)
	oracle.logsByDID[did] = chain.Log
	for _, k := range chain.State.ControllerKeys {
		oracle.declare(k.PublicKeyMultibase, did, false, "alice")
	}
	for _, k := range chain.State.AuthKeys {
		oracle.declare(k.PublicKeyMultibase, did, false, "alice")
	}

	// The disaster: a fresh machine holding only the phrase. Everything the old
	// one knew — config, keystore, relay, vault metadata — is gone.
	storeB, _, _ := setupDevices(t)
	keys = storeB
	importVault(t, "restored", mnemonic)
	oracle.registerAsPeer(t, "oracle")

	if before, _ := getVaults().Load("restored"); before.NextIndex != 0 {
		t.Fatalf("an imported vault starts at %d, want 0", before.NextIndex)
	}

	var res recoverResult
	runJSON(t, newRecover(t, map[string]string{"vault": "restored", "peer": "oracle"}), nil, &res)

	// ONE key, in all three roles, at one index.
	if len(res.Keys) != 1 {
		t.Fatalf("recovered %d keys, want 1 (the genesis key, in all three roles): %+v", len(res.Keys), res.Keys)
	}
	for _, k := range res.Keys {
		if k.Outcome != "recovered" {
			t.Errorf("index %d outcome = %q (%s), want recovered", k.Index, k.Outcome, k.Reason)
		}
		if !keys.HasKey(k.Account) {
			t.Errorf("key %s is not in the keystore after recovery", k.Account)
		}
		if k.Account != keyAccount(k.PublicKey) {
			t.Errorf("a recovered key was filed under %q, want its content address", k.Account)
		}
		if strings.Join(k.Roles, ",") != "controller,auth,assert" {
			t.Errorf("index %d roles = %v, want all three", k.Index, k.Roles)
		}
	}

	if len(res.Identities) != 1 || res.Identities[0].DID != did {
		t.Fatalf("identities = %+v, want the one chain", res.Identities)
	}
	if res.Identities[0].Status != "recovered" {
		t.Errorf("identity status = %q, want recovered", res.Identities[0].Status)
	}
	// The projected profile name is amber, so with none projected the name falls
	// back to a DID-derived label rather than inventing one.
	name := res.Identities[0].Name
	if name == "" {
		t.Fatal("the recovered identity was not registered under any name")
	}
	if cfg.Identities[name].DID != did {
		t.Errorf("config does not map %q to %s: %+v", name, did, cfg.Identities)
	}

	// The counter is the correctness half: an imported vault that stayed at 0
	// would hand index 0 to a second identity on the next mint.
	meta, _ := getVaults().Load("restored")
	if meta.NextIndex != 1 {
		t.Errorf("counter = %d after recovering index 0, want 1", meta.NextIndex)
	}
	if len(meta.Minted) != 1 {
		t.Errorf("minted records = %d, want 1 rebuilt", len(meta.Minted))
	}
	if res.MintedAdded != 1 {
		t.Errorf("report claims %d records added, want 1", res.MintedAdded)
	}

	// Idempotent: running it again converges rather than duplicating.
	var again recoverResult
	runJSON(t, newRecover(t, map[string]string{"vault": "restored", "peer": "oracle"}), nil, &again)
	if again.MintedAdded != 0 {
		t.Errorf("a second run added %d records, want 0", again.MintedAdded)
	}
	for _, k := range again.Keys {
		if k.Outcome != "already-present" {
			t.Errorf("a second run reports index %d as %q, want already-present", k.Index, k.Outcome)
		}
	}
	if meta2, _ := getVaults().Load("restored"); len(meta2.Minted) != 1 || meta2.NextIndex != 1 {
		t.Errorf("a second run moved the vault: %d records, counter %d", len(meta2.Minted), meta2.NextIndex)
	}
}

func TestRecoverFindsADeletedIdentityAndSaysItIsDeleted(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	keys = storeA
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")

	mnemonic := createVault(t, "personal")
	did := createIdentity(t, "alice", storeA)

	if _, _, err := runCapturing(t, newIdentityDeleteCmd(), []string{"alice"}); err != nil {
		t.Fatalf("identity delete: %v", err)
	}
	chain, _ := lr.Relay.GetIdentity(did)
	if !chain.State.IsDeleted {
		t.Fatal("the identity was not deleted")
	}
	oracle.logsByDID[did] = chain.Log
	// The one minted key, found through has-ever-proved.
	oracle.declare(derivedPublicKey(t, mnemonic, 0), did, true, "")

	storeB, _, _ := setupDevices(t)
	keys = storeB
	importVault(t, "restored", mnemonic)
	oracle.registerAsPeer(t, "oracle")

	var res recoverResult
	runJSON(t, newRecover(t, map[string]string{"vault": "restored", "peer": "oracle"}), nil, &res)

	if len(res.Identities) != 1 {
		t.Fatalf("identities = %+v, want one", res.Identities)
	}
	// Deletion is not revocation and `identity restore` is real, so the chain is
	// still fetched, the keys are still installed, and the report says deleted.
	if !res.Identities[0].Deleted {
		t.Error("the recovered identity is not reported as deleted")
	}
	if res.Identities[0].Status != "recovered" {
		t.Errorf("a deleted identity's status = %q, want recovered", res.Identities[0].Status)
	}
	if len(res.Keys) != 1 {
		t.Fatalf("recovered %d keys for a deleted identity, want 1", len(res.Keys))
	}
	for _, k := range res.Keys {
		if k.Outcome != "recovered" || !keys.HasKey(k.Account) {
			t.Errorf("key %s was not installed: %+v", k.Account, k)
		}
	}
}

func TestRecoverFindsAKeyARotationLeftBehind(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	keys = storeA
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")

	mnemonic := createVault(t, "personal")
	did := createIdentity(t, "alice", storeA)

	// Every role, so the genesis key is left declared in nothing — the only way a
	// single-key identity produces a fully rotated-out key.
	rotate := newIdentityUpdateCmd()
	mustSetFlag(t, rotate, "rotate-controller", "true")
	mustSetFlag(t, rotate, "rotate-auth", "true")
	mustSetFlag(t, rotate, "rotate-assert", "true")
	runJSON(t, rotate, nil, &struct{}{})

	chain, _ := lr.Relay.GetIdentity(did)
	oracle.logsByDID[did] = chain.Log
	// 0 the rotated-OUT genesis key, 1 the current one. The index answers
	// has-ever-proved precisely so index 0 is findable: rotating a key out
	// removes it from current state without retracting the proof that admitted
	// it.
	for _, i := range []uint32{0, 1} {
		oracle.declare(derivedPublicKey(t, mnemonic, i), did, false, "")
	}

	storeB, _, _ := setupDevices(t)
	keys = storeB
	importVault(t, "restored", mnemonic)
	oracle.registerAsPeer(t, "oracle")

	var res recoverResult
	runJSON(t, newRecover(t, map[string]string{"vault": "restored", "peer": "oracle"}), nil, &res)

	byIndex := map[uint32]recoveredKey{}
	for _, k := range res.Keys {
		byIndex[k.Index] = k
	}
	if len(byIndex) != 2 {
		t.Fatalf("recovered %d indices, want 0 and 1: %+v", len(byIndex), res.Keys)
	}
	old := byIndex[0]
	if old.Outcome != "recovered" || !old.Superseded || len(old.Roles) != 0 {
		t.Errorf("the rotated-out key at index 0 = %+v, want recovered and superseded with no current role", old)
	}
	if !keys.HasKey(old.Account) {
		t.Errorf("the rotated-out key was not written to the keystore under %s", old.Account)
	}
	current := byIndex[1]
	if strings.Join(current.Roles, ",") != "controller,auth,assert" || current.Superseded {
		t.Errorf("the current key at index 1 = %+v, want all three roles and not superseded", current)
	}
	// The counter must clear the rotation too, not just the genesis index.
	if meta, _ := getVaults().Load("restored"); meta.NextIndex != 2 {
		t.Errorf("counter = %d, want 2", meta.NextIndex)
	}
}

// TestRecoverDryRunPredictsTheRealRunAndWritesNothing pins both halves of the
// dry-run contract at once, because either alone is satisfiable by a lie: a run
// that writes nothing is trivially achieved by looking at nothing, and a run
// that predicts correctly is trivially achieved by doing the work for real.
//
// So it runs dry, asserts the keystore, the config, and the vault are untouched,
// then runs wet against the same corpus and asserts the two reports agree on
// every number an operator would act on.
func TestRecoverDryRunPredictsTheRealRunAndWritesNothing(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	keys = storeA
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")

	mnemonic := createVault(t, "personal")
	did := createIdentity(t, "alice", storeA)
	chain, _ := lr.Relay.GetIdentity(did)
	oracle.logsByDID[did] = chain.Log
	for _, k := range chain.State.ControllerKeys {
		oracle.declare(k.PublicKeyMultibase, did, false, "")
	}

	storeB, _, _ := setupDevices(t)
	keys = storeB
	importVault(t, "restored", mnemonic)
	oracle.registerAsPeer(t, "oracle")

	// The prose half. A dry run that found a live recoverable key must READ as
	// having found one — the would-mood throughout, and a verdict at the end.
	stdout, _, err := runCapturing(t, newRecover(t, map[string]string{
		"vault": "restored", "peer": "oracle", "dry-run": "true",
	}), nil)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	for _, want := range []string{
		"dry run — fetches and verifies, writes nothing",
		"would-install",
		"would-recover",
		"would be added by a real run",
		// The counter line is the one place a dry run can promise a protection
		// it did not install. It rose nothing, so it claims nothing: an operator
		// who dry-runs and then mints is still exposed to the collision.
		"Counter:       0 — would rise to 1, putting the next mint past every index this run learned",
		"DRY RUN: 1 recoverable key across 1 identity — nothing was written. Re-run without --dry-run to restore.",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the dry run does not say %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "cannot reuse") {
		t.Errorf("the dry run asserts a reuse guarantee it did not install:\n%s", stdout)
	}
	// The verdict is the LAST thing on screen, because it is the sentence an
	// operator scrolls to.
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, "DRY RUN:") {
		t.Errorf("the dry run ends on %q rather than its verdict:\n%s", last, stdout)
	}

	held, err := storeB.Entries()
	if err != nil {
		t.Fatalf("enumerate the keystore: %v", err)
	}
	if len(held) != 0 {
		t.Errorf("the dry run wrote %d key(s) into the keystore", len(held))
	}
	if len(cfg.Identities) != 0 {
		t.Errorf("the dry run registered identities in config: %+v", cfg.Identities)
	}
	meta, _ := getVaults().Load("restored")
	if meta.NextIndex != 0 || len(meta.Minted) != 0 {
		t.Errorf("the dry run moved the vault: counter %d, %d records", meta.NextIndex, len(meta.Minted))
	}

	var dry recoverResult
	runJSON(t, newRecover(t, map[string]string{"vault": "restored", "peer": "oracle", "dry-run": "true"}), nil, &dry)
	if len(dry.Identities) != 1 || dry.Identities[0].Status != "would-recover" {
		t.Fatalf("dry-run identity status = %+v, want would-recover", dry.Identities)
	}
	for _, k := range dry.Keys {
		if k.Outcome != "would-install" {
			t.Errorf("dry-run key at index %d = %q (%s), want would-install", k.Index, k.Outcome, k.Reason)
		}
		// The outcome carries the mood, so there is nothing left for a reason to
		// say — and a reason beside a success is what made the old output read
		// as a failure.
		if k.Reason != "" {
			t.Errorf("a would-install key carries a reason it does not need: %q", k.Reason)
		}
	}
	// Every chain was fetched and verified, so the completeness verdict is
	// earned rather than withheld on account of the mode.
	if !dry.ScanComplete {
		t.Errorf("a dry run that verified every chain reports an incomplete scan: %+v", dry)
	}

	// The fidelity half: the same corpus, for real.
	var wet recoverResult
	runJSON(t, newRecover(t, map[string]string{"vault": "restored", "peer": "oracle"}), nil, &wet)

	if wet.MintedAdded != dry.MintedAdded {
		t.Errorf("the dry run predicted %d vault records, the real run added %d", dry.MintedAdded, wet.MintedAdded)
	}
	if wet.CounterAfter != dry.CounterAfter {
		t.Errorf("the dry run predicted counter %d, the real run landed on %d", dry.CounterAfter, wet.CounterAfter)
	}
	if wet.ScanComplete != dry.ScanComplete || wet.HighestUsedIndex != dry.HighestUsedIndex {
		t.Errorf("dry run and real run disagree on the scan: %+v vs %+v", dry, wet)
	}
	if len(wet.Keys) != len(dry.Keys) {
		t.Fatalf("the dry run predicted %d keys, the real run reported %d", len(dry.Keys), len(wet.Keys))
	}
	for i := range wet.Keys {
		d, w := dry.Keys[i], wet.Keys[i]
		if d.Index != w.Index || d.PublicKey != w.PublicKey || d.DID != w.DID || d.KeyID != w.KeyID || d.Account != w.Account {
			t.Errorf("key %d differs between prediction and run:\n dry %+v\n wet %+v", i, d, w)
		}
		if d.Outcome != "would-install" || w.Outcome != "recovered" {
			t.Errorf("key %d outcomes = %q then %q, want would-install then recovered", i, d.Outcome, w.Outcome)
		}
		if !keys.HasKey(w.Account) {
			t.Errorf("the real run did not install the key the dry run promised: %s", w.Account)
		}
	}
}

// TestRecoverDryRunReportsAChainTheOracleCannotServe is the loud half held
// steady. Fetching in memory is what makes the dry run a prediction, and a fetch
// that fails is still a named failure — never an absence, and never softened by
// the verdict line at the end.
func TestRecoverDryRunReportsAChainTheOracleCannotServe(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	keys = storeA
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")

	mnemonic := createVault(t, "personal")
	did := createIdentity(t, "alice", storeA)
	chain, _ := lr.Relay.GetIdentity(did)
	// The INDEX names the identity; the proof plane does not serve its log. A
	// relay whose index outruns its own proof plane looks exactly like this.
	for _, k := range chain.State.ControllerKeys {
		oracle.declare(k.PublicKeyMultibase, did, false, "")
	}

	storeB, _, _ := setupDevices(t)
	keys = storeB
	importVault(t, "restored", mnemonic)
	oracle.registerAsPeer(t, "oracle")

	stdout, _, err := runCapturing(t, newRecover(t, map[string]string{
		"vault": "restored", "peer": "oracle", "dry-run": "true",
	}), nil)
	// An unreadable chain is a finding, not a crash: the report still prints, so
	// the operator sees which identity is affected and why.
	if err != nil {
		t.Fatalf("a dry run whose chain fetch failed errored out: %v", err)
	}
	for _, want := range []string{"found-but-not-fetched", "DRY RUN: nothing here is recoverable"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the report does not say %q:\n%s", want, stdout)
		}
	}

	var res recoverResult
	runJSON(t, newRecover(t, map[string]string{"vault": "restored", "peer": "oracle", "dry-run": "true"}), nil, &res)
	if len(res.Identities) != 1 || res.Identities[0].Status != "found-but-not-fetched" {
		t.Fatalf("identity status = %+v, want found-but-not-fetched", res.Identities)
	}
	if res.Identities[0].Reason == "" {
		t.Error("a found-but-not-fetched identity carries no reason")
	}
	for _, k := range res.Keys {
		if k.Outcome != "not-installed" || k.Reason == "" {
			t.Errorf("key at index %d = %+v, want not-installed with a reason", k.Index, k)
		}
	}
	// A chain it could not read is a chain whose declared keys it never checked
	// against a derivation, so completeness is withheld — in dry run exactly as
	// in a real one.
	if res.ScanComplete {
		t.Error("a chain the dry run could not read did not withhold scan completeness")
	}
}

// TestRecoverEndToEndRestoresSigning is the whole disaster path: an identity is
// created on one machine, the machine is destroyed, the phrase is carried to a
// new one, and the recovered identity signs again.
func TestRecoverEndToEndRestoresSigning(t *testing.T) {
	storeA, _, lrA := setupDevices(t)
	keys = storeA
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")

	mnemonic := createVault(t, "personal")
	did := createIdentity(t, "alice", storeA)
	chain, _ := lrA.Relay.GetIdentity(did)
	oracle.logsByDID[did] = chain.Log
	for _, k := range append(append([]protocol.MultikeyPublicKey{}, chain.State.ControllerKeys...), chain.State.AuthKeys...) {
		oracle.declare(k.PublicKeyMultibase, did, false, "Alice Example")
	}

	// Everything is gone but the words.
	storeB, _, _ := setupDevices(t)
	keys = storeB
	importVault(t, "restored", mnemonic)
	oracle.registerAsPeer(t, "oracle")

	var res recoverResult
	runJSON(t, newRecover(t, map[string]string{"vault": "restored", "peer": "oracle"}), nil, &res)
	if len(res.Identities) != 1 || res.Identities[0].Status != "recovered" {
		t.Fatalf("recovery did not restore the identity: %+v", res.Identities)
	}
	// The relay projected a profile name, so the local name comes from it rather
	// than from a DID-derived label.
	name := res.Identities[0].Name
	if name != "alice-example" {
		t.Errorf("local name = %q, want the sanitized projected name alice-example", name)
	}

	// The proof: sign something as the recovered identity. Signing resolves the
	// identity and intersects its published auth keys with what this device
	// holds — it never consults a vault — so a recovered key is indistinguishable
	// from one that was never lost.
	identityFlag = name
	content := newContentCreateCmd()
	var created struct {
		ContentID string `json:"contentId"`
	}
	runJSON(t, content, []string{writeTempDoc(t, `{"$schema":"https://schemas.dfos.com/post/v1","body":"back"}`)}, &created)
	if created.ContentID == "" {
		t.Fatal("the recovered identity could not sign content")
	}
}

// --- the client's own contract ---

func TestIdentitiesByKeyDistinguishesAbsenceFromUnavailability(t *testing.T) {
	store, _, _ := setupDevices(t)
	keys = store
	oracle := newFakeOracle(t)
	c := client.New(oracle.server.URL)

	rows, err := c.IdentitiesByKey("z6MkNothingEverDeclaredThis", 1)
	if err != nil {
		t.Fatalf("an empty answer is not an error: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("rows = %d, want 0", len(rows))
	}

	oracle.indexStatus = http.StatusNotImplemented
	if _, err := c.IdentitiesByKey("z6MkNothingEverDeclaredThis", 1); err == nil {
		t.Fatal("a 501 read as an empty result")
	} else if err != client.ErrIndexUnavailable {
		t.Errorf("a 501 produced %v, want ErrIndexUnavailable", err)
	}
}

func TestSanitizeIdentityNameAndCollisionSuffix(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Alice Example", "alice-example"},
		{"  ..Bob..  ", "bob"},
		{"did:dfos:abc", ""},
		{"", ""},
		{"!!!", ""},
	} {
		if got := sanitizeIdentityName(tc.in); got != tc.want {
			t.Errorf("sanitizeIdentityName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	c := &config.Config{Identities: map[string]config.IdentityConfig{
		"alice":   {DID: "did:dfos:one"},
		"alice-2": {DID: "did:dfos:two"},
	}}
	if got := pickIdentityName(c, "Alice", "did:dfos:three"); got != "alice-3" {
		t.Errorf("collision name = %q, want alice-3", got)
	}
	// No projection: a DID-derived label, never a guess.
	got := pickIdentityName(c, "", "did:dfos:hd34z9a4tf6h62864nh4f7at6hr36r4")
	if got != "recovered-hd34z9a4" {
		t.Errorf("fallback name = %q, want recovered-hd34z9a4", got)
	}
}
