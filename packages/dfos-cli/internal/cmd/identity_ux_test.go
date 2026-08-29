package cmd

// Tests for the identity roster and the update verb's subject.
//
// Like the multi-device and vault tests these drive RunE against the package
// globals setupDevices wires, so they MUST NOT run with t.Parallel().
// setupDevices points DFOS_CONFIG at a temp directory and sets
// DFOS_NO_KEYCHAIN, so nothing here can reach the developer's own keystore.

import (
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/keystore"
)

// createNamedIdentity is createIdentity without the identityFlag side effect,
// so a test can exercise the resolution stack itself rather than the flag tier
// that would otherwise sit in front of it.
func createNamedIdentity(t *testing.T, name string, store *keystore.MemoryStore) string {
	t.Helper()
	did := createIdentity(t, name, store)
	identityFlag = ""
	return did
}

// A typed positional target is the subject of the operation, ahead of every
// tier of the resolution stack. Before this, cobra swallowed the argument and
// the rotation landed on whatever the stack resolved — the wrong identity, with
// a success line that named the right one.
func TestIdentityUpdateTargetsThePositionalIdentity(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	keys = storeA

	alice := createNamedIdentity(t, "alice", storeA)
	bob := createNamedIdentity(t, "bob", storeA)

	// Every ambient mechanism points at bob.
	cfg.DefaultIdentity = "bob"
	t.Setenv(config.SourceEnvAs, "bob")

	rotate := newIdentityUpdateCmd()
	mustSetFlag(t, rotate, "rotate-auth", "true")
	var out struct {
		DID string `json:"did"`
	}
	_, stderr, err := runCapturingJSON(t, rotate, []string{"alice"}, &out)
	if err != nil {
		t.Fatalf("identity update alice --rotate-auth: %v", err)
	}
	if out.DID != alice {
		t.Fatalf("rotation applied to %s, want the positional target %s", out.DID, alice)
	}
	if !strings.Contains(stderr, config.SourcePositionalTarget) {
		t.Fatalf("announce line did not name the mechanism:\n%s", stderr)
	}
	if !strings.Contains(stderr, "alice") {
		t.Fatalf("announce line did not name the principal:\n%s", stderr)
	}

	// bob signed nothing: still just its genesis.
	bobChain, err := lr.Relay.GetIdentity(bob)
	if err != nil || bobChain == nil {
		t.Fatalf("get bob: %v", err)
	}
	if len(bobChain.Log) != 1 {
		t.Fatalf("bob's chain grew to %d operations; the positional target was ignored", len(bobChain.Log))
	}
}

// A bare DID is as good a positional as a name — the same rule `show`, `log`,
// and `delete` follow.
func TestIdentityUpdateAcceptsADIDPositional(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA

	alice := createNamedIdentity(t, "alice", storeA)
	createNamedIdentity(t, "bob", storeA)
	cfg.DefaultIdentity = "bob"

	rotate := newIdentityUpdateCmd()
	mustSetFlag(t, rotate, "rotate-auth", "true")
	var out struct {
		DID string `json:"did"`
	}
	runJSON(t, rotate, []string{alice}, &out)
	if out.DID != alice {
		t.Fatalf("rotation applied to %s, want %s", out.DID, alice)
	}
}

// With no positional, resolution is exactly what it always was.
func TestIdentityUpdateWithoutPositionalResolvesThroughTheStack(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA

	createNamedIdentity(t, "alice", storeA)
	bob := createNamedIdentity(t, "bob", storeA)
	cfg.DefaultIdentity = "bob"

	rotate := newIdentityUpdateCmd()
	mustSetFlag(t, rotate, "rotate-auth", "true")
	var out struct {
		DID string `json:"did"`
	}
	_, stderr, err := runCapturingJSON(t, rotate, nil, &out)
	if err != nil {
		t.Fatalf("identity update --rotate-auth: %v", err)
	}
	if out.DID != bob {
		t.Fatalf("rotation applied to %s, want the default-identity %s", out.DID, bob)
	}
	if !strings.Contains(stderr, config.SourceDefaultIdentity) {
		t.Fatalf("announce line did not name default-identity:\n%s", stderr)
	}
}

// One subject, or none. Two positionals is a typo, not an ambiguity to resolve.
func TestIdentityUpdateRejectsASecondPositional(t *testing.T) {
	cmd := newIdentityUpdateCmd()
	if err := cmd.Args(cmd, []string{"alice"}); err != nil {
		t.Fatalf("one positional rejected: %v", err)
	}
	if err := cmd.Args(cmd, nil); err != nil {
		t.Fatalf("no positional rejected: %v", err)
	}
	if err := cmd.Args(cmd, []string{"alice", "bob"}); err == nil {
		t.Fatal("two positionals were accepted")
	}
}

// An update that rotates nothing mints nothing, so it must not reserve a
// derivation index — asking a vault for zero keys is not a request it can
// serve, and it used to fail every services-only update on a vault-derived
// identity with an error about mint counts.
func TestIdentityUpdateServicesOnlyOnAVaultDerivedIdentity(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA

	createVault(t, "personal") // the first vault becomes the default
	createIdentity(t, "alice", storeA)

	before, err := getVaults().Load("personal")
	if err != nil {
		t.Fatalf("load vault: %v", err)
	}

	setServices := newIdentityUpdateCmd()
	mustSetFlag(t, setServices, "service", "id=relay,type=DfosRelay,endpoint=https://relay.dfos.com")
	var out struct {
		Services int            `json:"services"`
		Vault    map[string]any `json:"vault"`
	}
	if _, _, err := runCapturingJSON(t, setServices, nil, &out); err != nil {
		t.Fatalf("services-only update on a vault-derived identity: %v", err)
	}
	if out.Services != 1 {
		t.Fatalf("services = %d, want 1", out.Services)
	}
	if out.Vault != nil {
		t.Fatalf("a services-only update reported vault provenance: %v", out.Vault)
	}

	after, err := getVaults().Load("personal")
	if err != nil {
		t.Fatalf("reload vault: %v", err)
	}
	if after.NextIndex != before.NextIndex {
		t.Fatalf("the vault counter moved from %d to %d on an update that minted nothing",
			before.NextIndex, after.NextIndex)
	}

	// And clearing them is the same shape.
	clear := newIdentityUpdateCmd()
	mustSetFlag(t, clear, "clear-services", "true")
	if _, _, err := runCapturingJSON(t, clear, nil, &out); err != nil {
		t.Fatalf("--clear-services on a vault-derived identity: %v", err)
	}

	// Rotation still draws from the minting vault, one index per key.
	rotate := newIdentityUpdateCmd()
	mustSetFlag(t, rotate, "rotate-auth", "true")
	var rotated struct {
		Vault struct {
			Name    string   `json:"name"`
			Indices []uint32 `json:"indices"`
		} `json:"vault"`
	}
	runJSON(t, rotate, nil, &rotated)
	if rotated.Vault.Name != "personal" || len(rotated.Vault.Indices) != 1 {
		t.Fatalf("rotation after a services-only update = %+v, want one index from personal", rotated.Vault)
	}
}

// `identity remove` clears the same dangling pointers `forget` does, and says
// so in the same field names.
func TestIdentityRemoveReportsClearedState(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA

	did := createNamedIdentity(t, "alice", storeA)
	cfg.DefaultIdentity = "alice"
	cfg.ActiveContext = "alice@prod"

	var out identityRemoveResult
	runJSON(t, newIdentityRemoveCmd(), []string{"alice"}, &out)
	if out.Removed != "alice" || out.DID != did {
		t.Fatalf("remove reported %+v, want alice/%s", out, did)
	}
	if !out.DefaultIdentityCleared {
		t.Error("a default-identity pointing at the removed name was not reported as cleared")
	}
	if !out.ActiveContextCleared {
		t.Error("an active context referencing the removed name was not reported as cleared")
	}
	if cfg.DefaultIdentity != "" || cfg.ActiveContext != "" {
		t.Fatalf("config still holds a dangling pointer: default=%q active=%q", cfg.DefaultIdentity, cfg.ActiveContext)
	}

	// Nothing dangling, nothing reported.
	createNamedIdentity(t, "bob", storeA)
	createNamedIdentity(t, "carol", storeA)
	cfg.DefaultIdentity = "carol"
	var quiet identityRemoveResult
	runJSON(t, newIdentityRemoveCmd(), []string{"bob"}, &quiet)
	if quiet.DefaultIdentityCleared || quiet.ActiveContextCleared {
		t.Fatalf("removing an unreferenced name reported cleared state: %+v", quiet)
	}
	if cfg.DefaultIdentity != "carol" {
		t.Fatalf("default-identity = %q, want carol untouched", cfg.DefaultIdentity)
	}
}

// The roster's JSON is a roster: every identity's whole operation log inlined
// is the corpus, not a list.
func TestIdentityListJSONOmitsTheLogUntilAsked(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA

	did := createNamedIdentity(t, "alice", storeA)

	var lean []map[string]any
	runJSON(t, newIdentityListCmd(), nil, &lean)
	if len(lean) != 1 {
		t.Fatalf("list returned %d identities, want 1", len(lean))
	}
	if _, present := lean[0]["log"]; present {
		t.Fatalf("the default --json carried the operation log: %v", lean[0])
	}
	if lean[0]["did"] != did {
		t.Fatalf("did = %v, want %s", lean[0]["did"], did)
	}
	if lean[0]["name"] != "alice" {
		t.Fatalf("name = %v, want alice", lean[0]["name"])
	}
	if ops, _ := lean[0]["operations"].(float64); ops != 1 {
		t.Fatalf("operations = %v, want 1", lean[0]["operations"])
	}
	if _, present := lean[0]["state"]; !present {
		t.Fatalf("the lean shape dropped resolved state: %v", lean[0])
	}

	withLog := newIdentityListCmd()
	mustSetFlag(t, withLog, "include-log", "true")
	var full []map[string]any
	runJSON(t, withLog, nil, &full)
	log, ok := full[0]["log"].([]any)
	if !ok || len(log) != 1 {
		t.Fatalf("--include-log did not restore the full shape: %v", full[0])
	}
}

// The roster's KEYS column answers "how many of this chain's keys does this
// machine hold". For an identity no local name points at, no probe runs — and
// "?" says that, where "-" would have said "none held".
func TestIdentityListMarksUnprobedAndDeletedRows(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA

	createNamedIdentity(t, "alice", storeA)
	stranger := createNamedIdentity(t, "stranger", storeA)
	delete(cfg.Identities, "stranger") // now a chain with no local name

	stdout, _, err := runCapturing(t, newIdentityListCmd(), nil)
	if err != nil {
		t.Fatalf("identity list: %v", err)
	}
	strangerRow := rowFor(t, stdout, stranger)
	if !strings.Contains(strangerRow, "?") {
		t.Fatalf("an unregistered identity's KEYS column did not read '?':\n%s", strangerRow)
	}
	if !strings.Contains(stdout, "not probed") {
		t.Fatalf("the '?' mark carries no legend:\n%s", stdout)
	}
	if strings.Contains(stdout, "(deleted)") {
		t.Fatalf("a live roster reported a deletion:\n%s", stdout)
	}

	del := newIdentityDeleteCmd()
	if err := del.RunE(del, []string{"alice"}); err != nil {
		t.Fatalf("identity delete alice: %v", err)
	}

	stdout, _, err = runCapturing(t, newIdentityListCmd(), nil)
	if err != nil {
		t.Fatalf("identity list after delete: %v", err)
	}
	if !strings.Contains(rowFor(t, stdout, cfg.Identities["alice"].DID), "(deleted)") {
		t.Fatalf("a deleted identity's row carries no deletion mark:\n%s", stdout)
	}
}

func rowFor(t *testing.T, table, did string) string {
	t.Helper()
	for _, line := range strings.Split(table, "\n") {
		if strings.Contains(line, did) {
			return line
		}
	}
	t.Fatalf("no row for %s in:\n%s", did, table)
	return ""
}
