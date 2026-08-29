package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestStore returns a store whose metadata and mnemonics both live in a temp
// directory, so nothing here reaches the operator's real vaults or keychain.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	return Open(dir, &FileSecrets{dir: dir})
}

func TestCreateStoresAndFingerprints(t *testing.T) {
	s := newTestStore(t)

	meta, mnemonic, err := s.Create("personal")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if n := len(strings.Fields(mnemonic)); n != 24 {
		t.Errorf("created mnemonic has %d words, want 24", n)
	}
	if len(meta.Fingerprint) != 8 {
		t.Errorf("fingerprint = %q, want 8 hex characters", meta.Fingerprint)
	}
	if meta.NextIndex != 0 {
		t.Errorf("NextIndex = %d, want 0 on a fresh vault", meta.NextIndex)
	}
	if meta.Imported {
		t.Error("a generated vault is marked imported")
	}

	// The mnemonic is retrievable, and the fingerprint is a function of it — the
	// same seed always fingerprints the same way, on any machine.
	back, err := s.Mnemonic("personal")
	if err != nil {
		t.Fatalf("Mnemonic: %v", err)
	}
	if back != mnemonic {
		t.Error("stored mnemonic does not round-trip")
	}
	seed, _ := MnemonicSeed(back)
	if Fingerprint(seed) != meta.Fingerprint {
		t.Error("fingerprint does not match the stored mnemonic's seed")
	}

	if !s.Has("personal") {
		t.Error("Has() says a just-created vault does not exist")
	}
	if _, _, err := s.Create("personal"); err == nil {
		t.Error("creating a vault over an existing name was allowed")
	}
}

func TestSecretsAndMetadataAreOwnerOnly(t *testing.T) {
	// A directory the store has to CREATE, so the mode under test is the one the
	// store chooses rather than whatever the temp dir happened to be.
	dir := filepath.Join(t.TempDir(), "vaults")
	s := Open(dir, &FileSecrets{dir: dir})
	if _, _, err := s.Create("personal"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, name := range []string{"personal.toml", "personal.seed"} {
		info, err := os.Stat(filepath.Join(s.Dir(), name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 600", name, perm)
		}
	}
	dirInfo, err := os.Stat(s.Dir())
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("vault dir mode = %o, want 700", perm)
	}
}

func TestImportValidatesChecksum(t *testing.T) {
	s := newTestStore(t)
	const good = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	const badChecksum = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
	const notAWord = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon vault"

	if _, err := s.Import("bad", badChecksum); err == nil {
		t.Error("a mnemonic with a broken checksum was imported")
	}
	if s.Has("bad") {
		t.Error("a refused import left a vault behind")
	}
	if _, err := s.Import("nonword", notAWord); err == nil {
		t.Error("a mnemonic with a non-wordlist word was imported")
	}

	meta, err := s.Import("recovered", good)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !meta.Imported {
		t.Error("an imported vault is not marked imported")
	}

	// Importing the same words under a second name yields the same fingerprint:
	// the fingerprint identifies the SEED, not the vault.
	twin, err := s.Import("twin", strings.ToUpper(good))
	if err != nil {
		t.Fatalf("Import twin: %v", err)
	}
	if twin.Fingerprint != meta.Fingerprint {
		t.Error("the same mnemonic fingerprinted differently under two names")
	}
}

func TestMintAdvancesTheCounterAndPersistsIt(t *testing.T) {
	dir := t.TempDir()
	s := Open(dir, &FileSecrets{dir: dir})
	if _, _, err := s.Create("personal"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	first, err := s.Mint("personal", 2)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if len(first) != 2 || first[0].Index != 0 || first[1].Index != 1 {
		t.Fatalf("first mint = %+v, want indices 0 and 1", first)
	}

	// A SECOND store over the same directory stands in for a second `dfos`
	// invocation: the counter has to come back off disk, not out of memory.
	reopened := Open(dir, &FileSecrets{dir: dir})
	second, err := reopened.Mint("personal", 1)
	if err != nil {
		t.Fatalf("Mint after reopen: %v", err)
	}
	if second[0].Index != 2 {
		t.Fatalf("index after reopen = %d, want 2", second[0].Index)
	}

	meta, err := reopened.Load("personal")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if meta.NextIndex != 3 {
		t.Errorf("NextIndex = %d, want 3", meta.NextIndex)
	}

	// Indices are never handed out twice, and each derives its own key.
	if first[0].Public.Equal(first[1].Public) || first[0].Public.Equal(second[0].Public) {
		t.Error("two derivation indices produced the same public key")
	}

	// The derivation is a pure function of (seed, index): the same vault
	// rederives index 0 to the same key it minted.
	mnemonic, _ := s.Mnemonic("personal")
	seed, _ := MnemonicSeed(mnemonic)
	_, pub, err := DeriveKey(seed, 0)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if !pub.Equal(first[0].Public) {
		t.Error("rederiving index 0 from the mnemonic did not reproduce the minted key")
	}
}

func TestRecordAndFindMinted(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.Create("personal"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, _, err := s.Create("burner"); err != nil {
		t.Fatalf("Create burner: %v", err)
	}

	const did = "did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar"
	if err := s.Record("personal",
		MintedKey{Index: 0, DID: did, KeyID: "key_ctrl", Role: "controller", PublicKey: "z6Mkctrl"},
		MintedKey{Index: 1, DID: did, KeyID: "key_auth", Role: "auth", PublicKey: "z6Mkauth"},
	); err != nil {
		t.Fatalf("Record: %v", err)
	}

	meta, rec, ok := s.FindMinted(did, "key_auth")
	if !ok {
		t.Fatal("FindMinted did not find a recorded key")
	}
	if meta.Name != "personal" || rec.Index != 1 || rec.Role != "auth" {
		t.Errorf("FindMinted = %s %+v, want personal index 1 auth", meta.Name, rec)
	}
	if rec.MintedAt == "" {
		t.Error("Record did not stamp a mint time")
	}

	if _, _, ok := s.FindMinted(did, "key_unknown"); ok {
		t.Error("FindMinted matched a key nothing minted")
	}
	if _, _, ok := s.FindMinted("did:dfos:other", "key_auth"); ok {
		t.Error("FindMinted matched on key id alone, ignoring the DID")
	}

	// Rotation stickiness: the vault that minted the current keys is found from
	// the identity's key ids, in the order the caller considers authoritative.
	found, ok := s.FindMintingVault(did, []string{"key_nope", "key_ctrl"})
	if !ok || found.Name != "personal" {
		t.Errorf("FindMintingVault = %v %v, want personal", found, ok)
	}
	if _, ok := s.FindMintingVault("did:dfos:unminted", []string{"key_ctrl"}); ok {
		t.Error("FindMintingVault claimed a vault for an identity it never minted")
	}
}

func TestListIsNameOrdered(t *testing.T) {
	s := newTestStore(t)
	if got, err := s.List(); err != nil || len(got) != 0 {
		t.Fatalf("List on an empty store = %v, %v; want empty", got, err)
	}
	for _, name := range []string{"work", "burner", "personal"} {
		if _, _, err := s.Create(name); err != nil {
			t.Fatalf("Create %s: %v", name, err)
		}
	}
	all, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"burner", "personal", "work"}
	if len(all) != len(want) {
		t.Fatalf("List returned %d vaults, want %d", len(all), len(want))
	}
	for i, meta := range all {
		if meta.Name != want[i] {
			t.Errorf("List[%d] = %s, want %s", i, meta.Name, want[i])
		}
	}
}

func TestNameValidation(t *testing.T) {
	bad := []string{"", "../escape", "with/slash", "with space", ".", "..", "-leading", strings.Repeat("a", 65)}
	for _, name := range bad {
		if err := ValidateName(name); err == nil {
			t.Errorf("ValidateName(%q) accepted an unusable name", name)
		}
	}
	for _, name := range []string{"a", "personal", "work-2", "cold.storage", "v_1", strings.Repeat("a", 64)} {
		if err := ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) = %v, want accepted", name, err)
		}
	}

	s := newTestStore(t)
	if _, _, err := s.Create("../escape"); err == nil {
		t.Error("Create accepted a path-traversing name")
	}
	if _, err := s.Load("missing"); err == nil {
		t.Error("Load of an absent vault returned no error")
	}
}

func TestReconcileIsIdempotentAndOnlyRaisesTheCounter(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Import("restored", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"); err != nil {
		t.Fatalf("Import: %v", err)
	}

	records := []MintedKey{
		{Index: 0, DID: "did:dfos:a", KeyID: "key_1", Role: "controller", PublicKey: "z1"},
		{Index: 1, DID: "did:dfos:a", KeyID: "key_2", Role: "auth", PublicKey: "z2"},
	}
	added, next, err := s.Reconcile("restored", 2, records...)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if added != 2 {
		t.Errorf("added = %d, want 2", added)
	}
	// An imported vault starts at 0 knowing nothing about what the seed minted
	// elsewhere. Leaving it there would hand index 0 out a second time.
	if next != 2 {
		t.Errorf("counter = %d, want 2", next)
	}

	// Re-running converges: a recovery is re-runnable by nature.
	added, next, err = s.Reconcile("restored", 2, records...)
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if added != 0 || next != 2 {
		t.Errorf("second run added %d records and moved the counter to %d, want 0 and 2", added, next)
	}
	meta, _ := s.Load("restored")
	if len(meta.Minted) != 2 {
		t.Errorf("minted records = %d after two runs, want 2", len(meta.Minted))
	}

	// A record's own index raises the counter even when the caller asks for less,
	// and a lower floor never lowers it.
	if _, next, err = s.Reconcile("restored", 0,
		MintedKey{Index: 7, DID: "did:dfos:b", KeyID: "key_3", Role: "auth", PublicKey: "z3"}); err != nil {
		t.Fatalf("third Reconcile: %v", err)
	}
	if next != 8 {
		t.Errorf("counter = %d after a record at index 7, want 8", next)
	}
	if _, next, _ = s.Reconcile("restored", 1); next != 8 {
		t.Errorf("a floor of 1 lowered the counter to %d", next)
	}

	// Every record it wrote carries a mint timestamp, so provenance a scan
	// rebuilt is not distinguishable-by-absence from provenance a mint wrote.
	meta, _ = s.Load("restored")
	for _, r := range meta.Minted {
		if r.MintedAt == "" {
			t.Errorf("reconciled record %+v has no timestamp", r)
		}
	}
}
