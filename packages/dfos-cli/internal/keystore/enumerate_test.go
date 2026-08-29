package keystore

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The naming scheme has one job beyond being path-safe: it must be readable
// BACKWARDS, or the store cannot say what it holds. These hold that shut for
// every account shape the CLI actually writes.
func TestFileNameRoundTripsEveryAccountShape(t *testing.T) {
	accounts := []string{
		"did:dfos:z6MkfR9Qa1b2c3d4e5f6g7h8#key_2FvA9",
		"pending:key_2FvA9",
		"login-client__key_2FvA9",
		"vault:personal",
		"plain",
		"weird account/with:every#thing %25 in it",
	}
	for _, account := range accounts {
		name := fileName(account)
		if strings.ContainsAny(name, `/\:#`) {
			t.Fatalf("fileName(%q) = %q, which is not a safe file name", account, name)
		}
		got, ok := accountFromFileName(name)
		if !ok {
			t.Fatalf("accountFromFileName(%q) refused a name this package wrote", name)
		}
		if got != account {
			t.Fatalf("round trip of %q gave %q", account, got)
		}
	}
}

// The scheme this replaces was many-to-one. The new one must not be, or a
// second account can silently overwrite the first.
func TestFileNamesDoNotCollideWhereTheOldOnesDid(t *testing.T) {
	a, b := "pending:key_a", "pending_key:a"
	if legacyFileName(a) != legacyFileName(b) {
		t.Fatalf("test premise wrong: the legacy names differ (%q, %q)", legacyFileName(a), legacyFileName(b))
	}
	if fileName(a) == fileName(b) {
		t.Fatalf("fileName collides on %q and %q: both %q", a, b, fileName(a))
	}
}

func TestFileStoreReadsKeysWrittenByTheLegacyNaming(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	account := "did:dfos:abc#key_x"

	// Exactly what the pre-reversible store wrote.
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 7
	priv := ed25519.NewKeyFromSeed(seed)
	legacy := filepath.Join(dir, legacyFileName(account))
	if err := os.WriteFile(legacy, []byte("07"+strings.Repeat("00", 31)), 0o600); err != nil {
		t.Fatalf("write legacy key file: %v", err)
	}

	if !store.HasKey(account) {
		t.Fatal("HasKey missed a key stored under the legacy name")
	}
	got, err := store.GetPrivateKey(account)
	if err != nil {
		t.Fatalf("GetPrivateKey on a legacy file: %v", err)
	}
	if !got.Equal(priv) {
		t.Fatal("GetPrivateKey returned different key material for a legacy file")
	}
	if err := store.DeleteKey(account); err != nil {
		t.Fatalf("DeleteKey on a legacy file: %v", err)
	}
	if store.HasKey(account) {
		t.Fatal("the legacy file survived DeleteKey")
	}
}

// Writing an account that already has a legacy file must leave ONE file, not
// two: two files for one account is a store that enumerates a key twice.
func TestWritingAnAccountReplacesItsLegacyFile(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	account := "did:dfos:abc#key_x"
	if err := os.WriteFile(filepath.Join(dir, legacyFileName(account)), []byte(strings.Repeat("00", 32)), 0o600); err != nil {
		t.Fatalf("write legacy key file: %v", err)
	}

	if _, _, err := store.GenerateKey(account); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	entries, err := store.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 file after rewriting a legacy account, got %d: %+v", len(entries), entries)
	}
	if entries[0].Account != account {
		t.Fatalf("Entries named the key %q, want %q", entries[0].Account, account)
	}
}

func TestFileStoreEntriesNamesWhatItCanAndAdmitsWhatItCannot(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	for _, account := range []string{"did:dfos:abc#key_x", "pending:key_y"} {
		if _, _, err := store.GenerateKey(account); err != nil {
			t.Fatalf("GenerateKey(%s): %v", account, err)
		}
	}
	// A file only the old scheme could have written, whose account is genuinely
	// ambiguous. It must be reported, and reported as unnamed.
	if err := os.WriteFile(filepath.Join(dir, "did_dfos_zzz__key_q"), []byte(strings.Repeat("00", 32)), 0o600); err != nil {
		t.Fatalf("write legacy key file: %v", err)
	}

	entries, err := store.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d: %+v", len(entries), entries)
	}
	named := map[string]bool{}
	unnamed := 0
	for _, e := range entries {
		if e.Account == "" {
			unnamed++
			if e.Ref == "" {
				t.Fatal("an unnamed entry carried no reference either")
			}
			continue
		}
		named[e.Account] = true
	}
	if unnamed != 1 {
		t.Fatalf("expected exactly 1 unnamed entry, got %d", unnamed)
	}
	for _, want := range []string{"did:dfos:abc#key_x", "pending:key_y"} {
		if !named[want] {
			t.Fatalf("Entries did not name %q: %+v", want, entries)
		}
	}
}

// A vault mnemonic shares the keychain service with key seeds. Enumeration must
// drop it where the list is made, not leave it to every caller.
func TestEnumerationDropsReservedAccounts(t *testing.T) {
	mem := NewMemoryStore()
	if _, _, err := mem.GenerateKey("did:dfos:abc#key_x"); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	mem.keys["vault:personal"] = "not a seed at all"
	mem.keys["dfos-keychain-probe"] = "probe"

	entries, err := mem.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 || entries[0].Account != "did:dfos:abc#key_x" {
		t.Fatalf("reserved accounts leaked into the listing: %+v", entries)
	}
	for _, reserved := range []string{"vault:personal", "vault:", "dfos-keychain-probe", "dfos-vault-keychain-probe"} {
		if !IsReservedAccount(reserved) {
			t.Fatalf("IsReservedAccount(%q) = false", reserved)
		}
	}
	if IsReservedAccount("did:dfos:abc#key_x") {
		t.Fatal("IsReservedAccount flagged a real key account")
	}
}

func TestFileStoreEntriesOnAMissingDirectoryIsEmptyNotAnError(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "never-created"))
	entries, err := store.Entries()
	if err != nil {
		t.Fatalf("Entries on a missing dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no entries, got %+v", entries)
	}
}

// The macOS listing is a parse of `security dump-keychain`. The parse is what
// is worth testing anywhere; the exec around it is three lines.
func TestParseKeychainDumpTakesOnlyThisServicesAccounts(t *testing.T) {
	dump := `keychain: "/Users/x/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="dfos"
    "acct"<blob>="did:dfos:abc#key_x"
    "svce"<blob>="dfos"
    "type"<uint32>=<NULL>
class: "genp"
attributes:
    "acct"<blob>="someone@example.com"
    "svce"<blob>="some-other-app"
class: "genp"
attributes:
    "acct"<blob>="pending:key_y"
    "svce"<blob>="dfos"
class: "genp"
attributes:
    "acct"<blob>="vault:personal"
    "svce"<blob>="dfos"
class: "genp"
attributes:
    "acct"<blob>=<NULL>
    "svce"<blob>="dfos"
`
	got := parseKeychainDump(strings.NewReader(dump), "dfos")
	want := []string{"did:dfos:abc#key_x", "pending:key_y"}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parsed %v, want %v", got, want)
		}
	}
}

// An item's account must never be paired with a different item's service.
func TestParseKeychainDumpDoesNotCarryAttributesAcrossItems(t *testing.T) {
	dump := `class: "genp"
attributes:
    "svce"<blob>="dfos"
class: "genp"
attributes:
    "acct"<blob>="not-ours"
`
	if got := parseKeychainDump(strings.NewReader(dump), "dfos"); len(got) != 0 {
		t.Fatalf("attributes leaked across the item boundary: %v", got)
	}
}
