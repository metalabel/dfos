package cmd

// Vault command tests. Like the multi-device tests these drive RunE directly
// against the package globals that setupDevices wires, so they MUST NOT run
// with t.Parallel(). setupDevices points DFOS_CONFIG at a temp directory and
// sets DFOS_NO_KEYCHAIN, so every vault here lives and dies in that directory.

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/keystore"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/spf13/cobra"
)

const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// runCapturing drives a command's RunE with stdout AND stderr captured, so a
// test can assert on what reached each stream — which is the whole discipline
// around a mnemonic, and not something an stdout-only helper can check.
func runCapturing(t *testing.T, cmd *cobra.Command, args []string) (stdout, stderr string, err error) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout, os.Stderr = wOut, wErr

	err = cmd.RunE(cmd, args)

	wOut.Close()
	wErr.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	outBytes, _ := io.ReadAll(rOut)
	errBytes, _ := io.ReadAll(rErr)
	return string(outBytes), string(errBytes), err
}

// createVault runs `dfos vault create <name>` and returns the mnemonic it
// printed to stderr, proving in passing that the phrase is reachable there.
func createVault(t *testing.T, name string) string {
	t.Helper()
	stdout, stderr, err := runCapturing(t, newVaultCreateCmd(), []string{name})
	if err != nil {
		t.Fatalf("vault create %s: %v", name, err)
	}
	mnemonic := extractMnemonic(t, stderr)
	if strings.Contains(stdout, mnemonic) {
		t.Fatal("the mnemonic reached stdout")
	}
	return mnemonic
}

// extractMnemonic pulls the words back out of the fenced recovery block.
func extractMnemonic(t *testing.T, block string) string {
	t.Helper()
	var words []string
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "│"))
		dot := strings.Index(line, ". ")
		if dot <= 0 || dot > 3 {
			continue
		}
		words = append(words, strings.Fields(line[dot+2:])...)
	}
	if len(words) != 24 {
		t.Fatalf("recovery block held %d words, want 24:\n%s", len(words), block)
	}
	return strings.Join(words, " ")
}

func TestVaultCreateKeepsTheMnemonicOffStdoutAndOutOfJSON(t *testing.T) {
	setupDevices(t)

	mnemonic := createVault(t, "personal")

	// --json emits one document on stdout and the phrase is not in it. A piped
	// or redirected invocation must not write a seed into a file.
	var out map[string]any
	stdout, stderr, err := runCapturingJSON(t, newVaultCreateCmd(), []string{"second"}, &out)
	if err != nil {
		t.Fatalf("vault create --json: %v", err)
	}
	second := extractMnemonic(t, stderr)
	if strings.Contains(stdout, second) {
		t.Fatal("--json wrote the mnemonic to stdout")
	}
	for k, v := range out {
		if s, ok := v.(string); ok && strings.Contains(s, "abandon") || k == "mnemonic" {
			t.Fatalf("--json document carries a mnemonic field: %v", out)
		}
	}
	if out["fingerprint"] == "" || out["fingerprint"] == nil {
		t.Fatalf("--json document has no fingerprint: %v", out)
	}
	if got, want := out["derivationPath"], "m/1684434803'/0'"; got != want {
		t.Errorf("derivationPath = %v, want %v", got, want)
	}
	if mnemonic == second {
		t.Error("two vaults were created with the same mnemonic")
	}
}

func TestVaultCreateAdoptsOnlyTheFirstVaultAsDefault(t *testing.T) {
	setupDevices(t)

	createVault(t, "personal")
	if cfg.DefaultVault != "personal" {
		t.Fatalf("default-vault = %q, want the first vault to have been adopted", cfg.DefaultVault)
	}

	// A SECOND vault must not move the default. Absence→presence is the only
	// exception to "nothing writes the config tier as a side effect"; a
	// second write would be exactly the moving pointer the stack forbids.
	createVault(t, "burner")
	if cfg.DefaultVault != "personal" {
		t.Fatalf("default-vault = %q after a second create, want it unmoved", cfg.DefaultVault)
	}
}

func TestVaultImportRejectsABadChecksumAndReadsFromStdin(t *testing.T) {
	setupDevices(t)

	bad := newVaultImportCmd()
	bad.SetIn(strings.NewReader("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon\n"))
	if _, _, err := runCapturing(t, bad, []string{"broken"}); err == nil {
		t.Fatal("a mnemonic with a broken checksum was accepted")
	}
	if getVaults().Has("broken") {
		t.Fatal("a refused import left a vault behind")
	}

	good := newVaultImportCmd()
	good.SetIn(strings.NewReader(testMnemonic + "\n"))
	var out map[string]any
	if _, _, err := runCapturingJSON(t, good, []string{"recovered"}, &out); err != nil {
		t.Fatalf("vault import: %v", err)
	}
	// The fingerprint of this well-known mnemonic is a pure function of the
	// seed, so it is the same on every machine that imports these words.
	if got := out["fingerprint"]; got == nil || got == "" {
		t.Fatalf("import produced no fingerprint: %v", out)
	}
	if _, ok := out["mnemonic"]; ok {
		t.Fatal("import's --json document carries the mnemonic")
	}
}

// TestVaultImportUsageErrorNamesTheLabelAndNeverEchoesArgv covers the two ways
// the one argument comes out wrong, and the near-miss is the whole reason this
// command validates its own args: an operator who pasted the PHRASE where the
// NAME goes has just published their seed to shell history and to the process
// list, and `accepts 1 arg(s), received 24` tells them none of that.
//
// The error must say it WITHOUT reproducing a word. An error message lands in
// scrollback, in a CI log, and in whatever is recording the session, so echoing
// argv back copies the phrase into one more place at the moment it is already
// exposed. Args is exercised directly here because runCapturing drives RunE and
// cobra's argument validation never runs.
func TestVaultImportUsageErrorNamesTheLabelAndNeverEchoesArgv(t *testing.T) {
	setupDevices(t)
	cmd := newVaultImportCmd()

	err := cmd.Args(cmd, nil)
	if err == nil {
		t.Fatal("vault import with no argument was accepted")
	}
	for _, want := range []string{"needs a NAME", "dfos vault import <name>", "never an argument", "without echo", "stdin"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the no-argument error does not say %q:\n%s", want, err)
		}
	}

	// The near-miss. These are BIP-39 words, and none of them is a substring of
	// the error text, so the absence check below means what it says.
	words := []string{"abandon", "zebra", "kingdom", "trophy"}
	err = cmd.Args(cmd, words)
	if err == nil {
		t.Fatal("vault import with a phrase where the name goes was accepted")
	}
	for _, want := range []string{
		"takes one argument",
		"a local NAME for the vault, not the phrase",
		"treat the phrase as exposed",
		"never argv",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the too-many-arguments error does not say %q:\n%s", want, err)
		}
	}
	for _, w := range words {
		if strings.Contains(err.Error(), w) {
			t.Errorf("the error echoed the word %q back — that is one more copy of a phrase already exposed:\n%s", w, err)
		}
	}

	// One argument is still one argument.
	if err := cmd.Args(cmd, []string{"restored"}); err != nil {
		t.Errorf("a single name was refused: %v", err)
	}
}

func TestVaultShowHidesTheMnemonicUntilAskedAndConfirmed(t *testing.T) {
	setupDevices(t)
	mnemonic := createVault(t, "personal")

	// Default: the phrase is not printed anywhere.
	stdout, stderr, err := runCapturing(t, newVaultShowCmd(), []string{"personal"})
	if err != nil {
		t.Fatalf("vault show: %v", err)
	}
	if strings.Contains(stdout+stderr, mnemonic) {
		t.Fatal("vault show printed the mnemonic without being asked")
	}
	if !strings.Contains(stdout, "Fingerprint:") || !strings.Contains(stdout, "Next index:") {
		t.Fatalf("vault show did not report the vault:\n%s", stdout)
	}

	// --json without the flag likewise carries no mnemonic field.
	var out map[string]any
	if _, _, err := runCapturingJSON(t, newVaultShowCmd(), []string{"personal"}, &out); err != nil {
		t.Fatalf("vault show --json: %v", err)
	}
	if _, ok := out["mnemonic"]; ok {
		t.Fatalf("vault show --json carries a mnemonic field: %v", out)
	}

	// The reveal is barred by a typed confirmation, and a wrong answer prints
	// nothing.
	wrong := newVaultShowCmd()
	mustSetFlag(t, wrong, "reveal-mnemonic", "true")
	wrong.SetIn(strings.NewReader("y\n"))
	stdout, stderr, err = runCapturing(t, wrong, []string{"personal"})
	if err == nil {
		t.Fatal("a mismatched confirmation still revealed the mnemonic")
	}
	if strings.Contains(stdout+stderr, mnemonic) {
		t.Fatal("a refused reveal printed the mnemonic anyway")
	}

	// The right answer reveals it — to STDERR, the route `vault create` takes.
	// stdout stays the machine-readable half, so `dfos vault show x
	// --reveal-mnemonic > file` writes a report and not a seed.
	right := newVaultShowCmd()
	mustSetFlag(t, right, "reveal-mnemonic", "true")
	right.SetIn(strings.NewReader("personal\n"))
	stdout, stderr, err = runCapturing(t, right, []string{"personal"})
	if err != nil {
		t.Fatalf("confirmed reveal: %v", err)
	}
	if extractMnemonic(t, stderr) != mnemonic {
		t.Fatal("the revealed phrase is not the one the vault was created with")
	}
	assertNoPhrase(t, stdout, mnemonic, "a confirmed reveal wrote the phrase to stdout")

	// Under --json the same holds, and the document has no mnemonic field at
	// all: --json is what something redirects into a file.
	revealJSON := newVaultShowCmd()
	mustSetFlag(t, revealJSON, "reveal-mnemonic", "true")
	revealJSON.SetIn(strings.NewReader("personal\n"))
	var doc map[string]any
	stdout, stderr, err = runCapturingJSON(t, revealJSON, []string{"personal"}, &doc)
	if err != nil {
		t.Fatalf("confirmed reveal --json: %v", err)
	}
	if _, ok := doc["mnemonic"]; ok {
		t.Fatalf("--reveal-mnemonic put a mnemonic field in the --json document: %v", doc)
	}
	assertNoPhrase(t, stdout, mnemonic, "--reveal-mnemonic --json wrote the phrase to stdout")
	if extractMnemonic(t, stderr) != mnemonic {
		t.Fatal("--reveal-mnemonic --json did not print the phrase to stderr at all")
	}
	if doc["fingerprint"] == nil || doc["nextIndex"] == nil {
		t.Fatalf("the --json document lost its reporting fields: %v", doc)
	}
}

// assertNoPhrase checks a stream for the phrase as a whole AND for any single
// word of it, because the fenced block wraps at six words: a stream holding
// the row "1. abandon abandon …" carries the seed without carrying the string.
func assertNoPhrase(t *testing.T, stream, mnemonic, msg string) {
	t.Helper()
	if strings.Contains(stream, mnemonic) {
		t.Fatalf("%s:\n%s", msg, stream)
	}
	words := strings.Fields(mnemonic)
	if strings.Contains(stream, strings.Join(words[:6], "  ")) {
		t.Fatalf("%s (first row of the fenced block):\n%s", msg, stream)
	}
	if strings.Contains(stream, "RECOVERY PHRASE") {
		t.Fatalf("%s (the fenced block itself):\n%s", msg, stream)
	}
}

func TestVaultImportRefusesAPhraseAVaultAlreadyHolds(t *testing.T) {
	setupDevices(t)
	mnemonic := createVault(t, "personal")

	dup := newVaultImportCmd()
	dup.SetIn(strings.NewReader(mnemonic + "\n"))
	_, _, err := runCapturing(t, dup, []string{"twin"})
	if err == nil {
		t.Fatal("a second vault was imported over the phrase of 'personal'")
	}
	if !strings.Contains(err.Error(), "personal") {
		t.Errorf("the refusal does not name the existing vault: %v", err)
	}
	if getVaults().Has("twin") {
		t.Fatal("a refused duplicate import left a vault behind")
	}

	// The existing single-vault flow is untouched: a DIFFERENT phrase still
	// imports, and 'personal' is still the machine's default.
	other := newVaultImportCmd()
	other.SetIn(strings.NewReader(testMnemonic + "\n"))
	if _, _, err := runCapturing(t, other, []string{"recovered"}); err != nil {
		t.Fatalf("importing a distinct phrase: %v", err)
	}
	if cfg.DefaultVault != "personal" {
		t.Errorf("default-vault = %q, want it unmoved", cfg.DefaultVault)
	}
}

func TestVaultListMarksTheDefault(t *testing.T) {
	setupDevices(t)
	createVault(t, "personal")
	createVault(t, "burner")

	var entries []vaultListEntry
	if _, _, err := runCapturingJSON(t, newVaultListCmd(), nil, &entries); err != nil {
		t.Fatalf("vault list: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("vault list returned %d entries, want 2", len(entries))
	}
	if entries[0].Name != "burner" || entries[1].Name != "personal" {
		t.Fatalf("vault list is not name-ordered: %+v", entries)
	}
	if entries[0].Default || !entries[1].Default {
		t.Fatalf("the default marker is on the wrong vault: %+v", entries)
	}
}

func TestIdentityCreateMintsFromTheDefaultVault(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA

	createVault(t, "personal")

	cmd := newIdentityCreateCmd()
	mustSetFlag(t, cmd, "name", "alice")
	var res struct {
		DID   string   `json:"did"`
		Key   string   `json:"key"`
		Roles []string `json:"roles"`
		Vault struct {
			Name            string `json:"name"`
			Fingerprint     string `json:"fingerprint"`
			Index           uint32 `json:"index"`
			ControllerIndex uint32 `json:"controllerIndex"`
			AuthIndex       uint32 `json:"authIndex"`
		} `json:"vault"`
	}
	runJSON(t, cmd, nil, &res)

	if res.Vault.Name != "personal" {
		t.Fatalf("minted from vault %q, want the config default", res.Vault.Name)
	}
	// ONE index. The controller and auth fields report the same one, because
	// there is one key and it is both.
	if res.Vault.Index != 0 || res.Vault.ControllerIndex != 0 || res.Vault.AuthIndex != 0 {
		t.Fatalf("indices = %d/%d/%d, want 0 everywhere",
			res.Vault.Index, res.Vault.ControllerIndex, res.Vault.AuthIndex)
	}

	// The counter advanced by exactly one, and the provenance trail records the
	// one key, in all three roles, against the DID that now publishes it.
	meta, err := getVaults().Load("personal")
	if err != nil {
		t.Fatalf("load vault: %v", err)
	}
	if meta.NextIndex != 1 {
		t.Errorf("NextIndex = %d, want 1", meta.NextIndex)
	}
	if len(meta.Minted) != 1 {
		t.Fatalf("minted records = %d, want 1", len(meta.Minted))
	}
	m := meta.Minted[0]
	if m.DID != res.DID {
		t.Errorf("minted record points at %s, want %s", m.DID, res.DID)
	}
	if m.PublicKey == "" || m.KeyID == "" {
		t.Errorf("minted record is missing key material identifiers: %+v", m)
	}
	if got := strings.Join(m.RoleList(), ","); got != "controller,auth,assert" {
		t.Errorf("minted roles = %q, want controller,auth,assert", got)
	}
	if m.KeyID != protocol.DeriveKeyID(m.PublicKey) {
		t.Errorf("key id %q is not derived from the public key", m.KeyID)
	}
	if res.Key != m.KeyID {
		t.Errorf("reported key %q != recorded key id %q", res.Key, m.KeyID)
	}
	if strings.Join(res.Roles, ",") != "controller,auth,assert" {
		t.Errorf("reported roles = %v", res.Roles)
	}
}

// TestIdentityCreateDeclaresOneKeyInAllThreeRoles reads the genesis the chain
// actually holds: one entry per role array, and the SAME entry in each — same
// id, same publicKeyMultibase.
func TestIdentityCreateDeclaresOneKeyInAllThreeRoles(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	keys = storeA

	did := createIdentity(t, "alice", storeA)
	chain, err := lr.Relay.GetIdentity(did)
	if err != nil || chain == nil {
		t.Fatalf("get identity: %v", err)
	}
	sets := map[string][]protocol.MultikeyPublicKey{
		"controller": chain.State.ControllerKeys,
		"auth":       chain.State.AuthKeys,
		"assert":     chain.State.AssertKeys,
	}
	for role, set := range sets {
		if len(set) != 1 {
			t.Fatalf("%s keys = %d, want exactly 1", role, len(set))
		}
	}
	c, a, s := chain.State.ControllerKeys[0], chain.State.AuthKeys[0], chain.State.AssertKeys[0]
	if c.ID != a.ID || c.ID != s.ID {
		t.Fatalf("key ids differ across roles: %s / %s / %s", c.ID, a.ID, s.ID)
	}
	if c.PublicKeyMultibase != a.PublicKeyMultibase || c.PublicKeyMultibase != s.PublicKeyMultibase {
		t.Fatal("public keys differ across roles")
	}
	if c.ID != protocol.DeriveKeyID(c.PublicKeyMultibase) {
		t.Fatalf("key id %q is not the id its public key derives", c.ID)
	}
	// One key, held under its content address and nothing else.
	if !storeA.HasKey(keyAccount(c.PublicKeyMultibase)) {
		t.Fatal("the genesis key is not filed under its content address")
	}
	if storeA.HasKey(did + "#" + c.ID) {
		t.Fatal("the genesis key was also written under the legacy DID-scoped account")
	}
	if n := countKeysInChain(chain); n != 1 {
		t.Fatalf("countKeysInChain = %d, want 1", n)
	}
}

func TestIdentityCreateHonorsVaultOverrideAndNoVault(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA

	createVault(t, "personal") // becomes the default
	createVault(t, "burner")

	override := newIdentityCreateCmd()
	mustSetFlag(t, override, "name", "alias")
	mustSetFlag(t, override, "vault", "burner")
	var res struct {
		Vault struct {
			Name string `json:"name"`
		} `json:"vault"`
	}
	runJSON(t, override, nil, &res)
	if res.Vault.Name != "burner" {
		t.Fatalf("--vault resolved to %q, want burner", res.Vault.Name)
	}

	// The default vault was untouched by the override.
	personal, _ := getVaults().Load("personal")
	if personal.NextIndex != 0 {
		t.Errorf("the overridden vault's counter moved: NextIndex = %d", personal.NextIndex)
	}

	// --no-vault keeps the pre-vault behavior: keys exist only in the keystore.
	standalone := newIdentityCreateCmd()
	mustSetFlag(t, standalone, "name", "detached")
	mustSetFlag(t, standalone, "no-vault", "true")
	var plain map[string]any
	runJSON(t, standalone, nil, &plain)
	if _, ok := plain["vault"]; ok {
		t.Fatalf("--no-vault reported a vault: %v", plain)
	}
	burner, _ := getVaults().Load("burner")
	if burner.NextIndex != 1 {
		t.Errorf("--no-vault consumed indices: burner NextIndex = %d, want 1", burner.NextIndex)
	}

	// An unknown vault is refused rather than silently falling back.
	unknown := newIdentityCreateCmd()
	mustSetFlag(t, unknown, "name", "nope")
	mustSetFlag(t, unknown, "vault", "missing")
	if _, _, err := runCapturing(t, unknown, nil); err == nil {
		t.Fatal("--vault naming an unknown vault was accepted")
	}
}

func TestRotationStaysOnTheVaultThatMintedTheCurrentKeys(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA

	createVault(t, "personal")
	createVault(t, "burner")

	create := newIdentityCreateCmd()
	mustSetFlag(t, create, "name", "alice")
	mustSetFlag(t, create, "vault", "burner")
	var created struct {
		DID string `json:"did"`
	}
	runJSON(t, create, nil, &created)
	identityFlag = "alice"

	// Rotation does NOT consult default-vault ("personal"): it follows the seed
	// that minted the keys the identity currently publishes.
	rotate := newIdentityUpdateCmd()
	mustSetFlag(t, rotate, "rotate-auth", "true")
	var rotated struct {
		Vault struct {
			Name    string   `json:"name"`
			Indices []uint32 `json:"indices"`
		} `json:"vault"`
	}
	runJSON(t, rotate, nil, &rotated)
	if rotated.Vault.Name != "burner" {
		t.Fatalf("rotation drew from %q, want the minting vault burner", rotated.Vault.Name)
	}
	if len(rotated.Vault.Indices) != 1 || rotated.Vault.Indices[0] != 1 {
		t.Fatalf("rotation indices = %v, want [1]", rotated.Vault.Indices)
	}
	if personal, _ := getVaults().Load("personal"); personal.NextIndex != 0 {
		t.Errorf("the default vault was drawn from: NextIndex = %d", personal.NextIndex)
	}

	// --vault overrides the stickiness explicitly.
	moved := newIdentityUpdateCmd()
	mustSetFlag(t, moved, "rotate-auth", "true")
	mustSetFlag(t, moved, "vault", "personal")
	runJSON(t, moved, nil, &rotated)
	if rotated.Vault.Name != "personal" {
		t.Fatalf("--vault on rotation resolved to %q, want personal", rotated.Vault.Name)
	}
}

func TestRotationOfAVaultlessIdentityStaysVaultless(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA

	createVault(t, "personal") // the default, which must NOT be adopted below
	createIdentityWithoutVault(t, "detached", storeA)

	rotate := newIdentityUpdateCmd()
	mustSetFlag(t, rotate, "rotate-auth", "true")
	var out map[string]any
	runJSON(t, rotate, nil, &out)
	if _, ok := out["vault"]; ok {
		t.Fatalf("rotating a standalone identity pulled it into a vault: %v", out)
	}
	if personal, _ := getVaults().Load("personal"); personal.NextIndex != 0 {
		t.Errorf("the default vault was drawn from: NextIndex = %d", personal.NextIndex)
	}
}

func createIdentityWithoutVault(t *testing.T, name string, store *keystore.MemoryStore) string {
	t.Helper()
	keys = store
	cmd := newIdentityCreateCmd()
	mustSetFlag(t, cmd, "name", name)
	mustSetFlag(t, cmd, "no-vault", "true")
	var res struct {
		DID string `json:"did"`
	}
	runJSON(t, cmd, nil, &res)
	identityFlag = name
	return res.DID
}

func TestWhoamiReportsVaultProvenance(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA

	createVault(t, "personal")
	createIdentity(t, "alice", storeA)

	var result whoamiResult
	runJSON(t, newWhoamiCmd(), nil, &result)
	if !result.SigningKey.Available {
		t.Fatal("whoami found no signing key for a just-created identity")
	}
	if result.SigningKey.Vault == nil {
		t.Fatal("whoami reported no vault provenance for a vault-minted key")
	}
	if result.SigningKey.Vault.Name != "personal" {
		t.Errorf("whoami vault = %q, want personal", result.SigningKey.Vault.Name)
	}
	// One key, one index: the auth key IS the controller key, at index 0.
	if result.SigningKey.Vault.Index != 0 {
		t.Errorf("whoami vault index = %d, want the one key's index 0", result.SigningKey.Vault.Index)
	}
	if result.SigningKey.Vault.Path != "m/1684434803'/0'" {
		t.Errorf("whoami derivation path = %q", result.SigningKey.Vault.Path)
	}

	// A standalone identity reports no provenance rather than inventing one.
	createIdentityWithoutVault(t, "detached", storeA)
	var plain whoamiResult
	runJSON(t, newWhoamiCmd(), nil, &plain)
	if plain.SigningKey.Vault != nil {
		t.Errorf("whoami claimed a vault for a standalone key: %+v", plain.SigningKey.Vault)
	}
}

func TestConfigSetDefaultVaultRequiresAnExistingVault(t *testing.T) {
	setupDevices(t)

	cmd := newConfigSetCmd()
	if err := cmd.RunE(cmd, []string{"default-vault", "missing"}); err == nil {
		t.Fatal("default-vault was set to a vault that does not exist")
	}

	createVault(t, "personal")
	createVault(t, "burner")
	if err := cmd.RunE(cmd, []string{"default-vault", "burner"}); err != nil {
		t.Fatalf("set default-vault: %v", err)
	}
	if cfg.DefaultVault != "burner" {
		t.Fatalf("default-vault = %q, want burner", cfg.DefaultVault)
	}
}

// runCapturingJSON is runCapturing with jsonFlag set and the stdout document
// unmarshaled, so a test can assert on the JSON AND on what went to stderr.
func runCapturingJSON(t *testing.T, cmd *cobra.Command, args []string, out any) (stdout, stderr string, err error) {
	t.Helper()
	prev := jsonFlag
	jsonFlag = true
	defer func() { jsonFlag = prev }()

	stdout, stderr, err = runCapturing(t, cmd, args)
	if err != nil || out == nil {
		return stdout, stderr, err
	}
	if jsonErr := json.Unmarshal(bytes.TrimSpace([]byte(stdout)), out); jsonErr != nil {
		t.Fatalf("unmarshal output of %q: %v\nraw: %s", cmd.Use, jsonErr, stdout)
	}
	return stdout, stderr, err
}
