package vault

// Custody of the mnemonic across config directories.
//
// These tests drive the keychain backend against go-keyring's in-memory mock
// (keyring.MockInit), which installs a process-wide provider — so nothing here
// runs with t.Parallel(), and nothing here reaches a real keychain.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

// newKeychainStore is a store whose metadata is in dir and whose mnemonics are
// in the (mocked) OS keychain, namespaced by dir's custody id.
func newKeychainStore(t *testing.T, dir string) *Store {
	t.Helper()
	return Open(dir, &KeychainSecrets{dir: dir})
}

// The finding this file exists for: DFOS_CONFIG scopes the vault metadata
// directory, both of Create's guards read that directory, and the keychain does
// not know directories exist. A scratch profile creating a vault of a name the
// real profile already uses used to write its mnemonic straight over the real
// one — leaving metadata that names fingerprint A in front of phrase B, and
// every key A minted unrecoverable.
func TestASecondConfigDirCannotOverwriteAnotherProfilesMnemonic(t *testing.T) {
	keyring.MockInit()

	realDir := t.TempDir()
	real := newKeychainStore(t, realDir)
	realMeta, realMnemonic, err := real.Create("personal")
	if err != nil {
		t.Fatalf("create the real profile's vault: %v", err)
	}

	// A second config directory, same vault name. This SUCCEEDS — two profiles
	// are allowed the same local label — and must not touch the first.
	scratchDir := t.TempDir()
	scratch := newKeychainStore(t, scratchDir)
	scratchMeta, scratchMnemonic, err := scratch.Create("personal")
	if err != nil {
		t.Fatalf("create the scratch profile's vault: %v", err)
	}
	if scratchMnemonic == realMnemonic {
		t.Fatal("two Create calls produced the same phrase")
	}

	back, err := real.Mnemonic("personal")
	if err != nil {
		t.Fatalf("read the real profile's mnemonic back: %v", err)
	}
	if back != realMnemonic {
		t.Error("the scratch profile overwrote the real profile's recovery phrase")
	}
	if scratchBack, err := scratch.Mnemonic("personal"); err != nil || scratchBack != scratchMnemonic {
		t.Errorf("the scratch profile cannot read its own mnemonic back: %v", err)
	}
	if realMeta.Fingerprint == scratchMeta.Fingerprint {
		t.Error("two vaults over two seeds fingerprint the same")
	}

	// And the accounts are what makes that true.
	realAccount, err := (&KeychainSecrets{dir: realDir}).account("personal")
	if err != nil {
		t.Fatalf("resolve the real account: %v", err)
	}
	scratchAccount, err := (&KeychainSecrets{dir: scratchDir}).account("personal")
	if err != nil {
		t.Fatalf("resolve the scratch account: %v", err)
	}
	if realAccount == scratchAccount {
		t.Fatalf("both profiles resolved to keychain account %s", realAccount)
	}
	for _, account := range []string{realAccount, scratchAccount} {
		if !strings.HasPrefix(account, "vault:") {
			t.Errorf("account %q lost the reserved 'vault:' prefix the keystore filters on", account)
		}
	}
}

// A vault created before custody ids has its phrase under the flat
// "vault:<name>" account. It still opens, and the phrase moves forward into
// this directory's namespace on the first successful read.
func TestALegacyKeychainAccountStillResolvesAndMovesForward(t *testing.T) {
	keyring.MockInit()

	dir := t.TempDir()
	s := newKeychainStore(t, dir)
	_, mnemonic, err := s.Create("personal")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	account, err := (&KeychainSecrets{dir: dir}).account("personal")
	if err != nil {
		t.Fatalf("resolve the account: %v", err)
	}

	// Put the vault back the way an earlier version left it.
	if err := keyring.Delete(keychainService, account); err != nil {
		t.Fatalf("clear the namespaced account: %v", err)
	}
	if err := keyring.Set(keychainService, legacyKeychainAccount("personal"), mnemonic); err != nil {
		t.Fatalf("write the legacy account: %v", err)
	}

	back, err := s.Mnemonic("personal")
	if err != nil {
		t.Fatalf("a vault stored under the legacy account did not resolve: %v", err)
	}
	if back != mnemonic {
		t.Error("the legacy account resolved to the wrong phrase")
	}

	if got, err := keyring.Get(keychainService, account); err != nil || got != mnemonic {
		t.Errorf("the phrase was not filed under the custody-id account: %v", err)
	}
	if _, err := keyring.Get(keychainService, legacyKeychainAccount("personal")); err == nil {
		t.Error("the legacy account survived the migration")
	}

	// And the second read comes from the new account, with no legacy entry left
	// to fall back to.
	if back, err := s.Mnemonic("personal"); err != nil || back != mnemonic {
		t.Errorf("the migrated vault did not read back: %v", err)
	}
}

// The legacy fallback is by name, so it is gated by fingerprint: a scratch
// profile whose own entry is missing must not pick up the real profile's
// pre-migration phrase, and must not move it anywhere.
func TestTheLegacyFallbackIsGatedByFingerprint(t *testing.T) {
	keyring.MockInit()

	dir := t.TempDir()
	s := newKeychainStore(t, dir)
	_, _, err := s.Create("personal")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	account, err := (&KeychainSecrets{dir: dir}).account("personal")
	if err != nil {
		t.Fatalf("resolve the account: %v", err)
	}
	if err := keyring.Delete(keychainService, account); err != nil {
		t.Fatalf("clear the namespaced account: %v", err)
	}

	// Somebody else's phrase, under the flat account, with the same name.
	other, err := NewMnemonic()
	if err != nil {
		t.Fatalf("NewMnemonic: %v", err)
	}
	if err := keyring.Set(keychainService, legacyKeychainAccount("personal"), other); err != nil {
		t.Fatalf("write the legacy account: %v", err)
	}

	if got, err := s.Mnemonic("personal"); err == nil {
		t.Fatalf("a phrase from another profile was adopted by name: %q", got)
	}
	if _, err := keyring.Get(keychainService, legacyKeychainAccount("personal")); err != nil {
		t.Error("the other profile's legacy entry was moved or deleted")
	}
}

// Put is the write of a NEW vault, so an occupied slot is refused rather than
// replaced — on every backend, because they are one custody story.
func TestPutRefusesToOverwriteAnExistingMnemonic(t *testing.T) {
	keyring.MockInit()

	dir := t.TempDir()
	backends := map[string]SecretStore{
		"keychain": &KeychainSecrets{dir: dir},
		"file":     &FileSecrets{dir: t.TempDir()},
		"memory":   NewMemorySecrets(),
	}
	for name, secrets := range backends {
		t.Run(name, func(t *testing.T) {
			if err := secrets.Put("personal", "first phrase"); err != nil {
				t.Fatalf("Put: %v", err)
			}
			err := secrets.Put("personal", "second phrase")
			if !errors.Is(err, ErrSecretExists) {
				t.Fatalf("Put over an existing mnemonic: %v, want ErrSecretExists", err)
			}
			got, err := secrets.Get("personal")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if got != "first phrase" {
				t.Errorf("the stored mnemonic is %q, want the first one", got)
			}
		})
	}
}

// A leftover secret with no metadata beside it stops a create rather than
// overwriting the phrase.
func TestCreateRefusesWhenTheSecretSlotIsAlreadyTaken(t *testing.T) {
	dir := t.TempDir()
	secrets := &FileSecrets{dir: dir}
	if err := secrets.Put("personal", "a phrase this machine cannot explain"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s := Open(dir, secrets)

	_, _, err := s.Create("personal")
	if !errors.Is(err, ErrSecretExists) {
		t.Fatalf("Create over an orphaned secret: %v, want ErrSecretExists", err)
	}
	if got, err := secrets.Get("personal"); err != nil || got != "a phrase this machine cannot explain" {
		t.Errorf("the orphaned phrase was overwritten: %q (%v)", got, err)
	}
}

// The custody id is minted once, survives, and is not a vault.
func TestCustodyIDIsStableAndIsNotAVault(t *testing.T) {
	dir := t.TempDir()
	id, err := CustodyID(dir)
	if err != nil {
		t.Fatalf("CustodyID: %v", err)
	}
	if !custodyIDRE.MatchString(id) {
		t.Fatalf("custody id %q is not 16 hex characters", id)
	}
	again, err := CustodyID(dir)
	if err != nil {
		t.Fatalf("CustodyID (second call): %v", err)
	}
	if again != id {
		t.Fatalf("custody id changed between calls: %s then %s", id, again)
	}
	if other, err := CustodyID(t.TempDir()); err != nil || other == id {
		t.Fatalf("a second directory got custody id %s (%v)", other, err)
	}

	info, err := os.Stat(filepath.Join(dir, custodyIDFile))
	if err != nil {
		t.Fatalf("stat the custody id file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("custody id file mode = %o, want 600", perm)
	}

	s := Open(dir, &FileSecrets{dir: dir})
	if _, _, err := s.Create("personal"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	all, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 || all[0].Name != "personal" {
		t.Errorf("List returned %d vaults, want just 'personal'", len(all))
	}

	// A mangled id is an error, not a silently different namespace: every
	// mnemonic already filed under the real one would read as missing.
	if err := os.WriteFile(filepath.Join(dir, custodyIDFile), []byte("not-an-id\n"), 0o600); err != nil {
		t.Fatalf("mangle the custody id: %v", err)
	}
	if _, err := CustodyID(dir); err == nil {
		t.Error("a mangled custody id was accepted")
	}
}

// A stored phrase that is not the seed the metadata was written from is
// detected before anything derives from it.
func TestAMismatchedStoredPhraseIsRefusedBeforeDeriving(t *testing.T) {
	dir := t.TempDir()
	secrets := &FileSecrets{dir: dir}
	s := Open(dir, secrets)
	meta, _, err := s.Create("personal")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Swap the phrase behind the vault, leaving the metadata as it was.
	other, err := NewMnemonic()
	if err != nil {
		t.Fatalf("NewMnemonic: %v", err)
	}
	if err := secrets.Delete("personal"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := secrets.Put("personal", other); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if _, err := s.Mint("personal", 1); err == nil {
		t.Fatal("Mint derived keys from a phrase this vault was not created from")
	} else if !strings.Contains(err.Error(), meta.Fingerprint) {
		t.Errorf("the mismatch error does not name the recorded fingerprint: %v", err)
	}
	if _, err := s.Mnemonic("personal"); err == nil {
		t.Error("a phrase this vault was not created from was revealed as its backup")
	}
	// The counter did not move: nothing was derived.
	if reloaded, err := s.Load("personal"); err != nil {
		t.Fatalf("Load: %v", err)
	} else if reloaded.NextIndex != 0 {
		t.Errorf("NextIndex = %d after a refused mint, want 0", reloaded.NextIndex)
	}
}

// A phrase stays in the backend it was written to, so a miss names the backend
// that looked and where the phrase more likely is. A vault created with the
// keychain and read under DFOS_NO_KEYCHAIN is the case this exists for.
func TestTheFileBackendsMissNamesTheKeychainUnderDFOSNoKeychain(t *testing.T) {
	t.Setenv("DFOS_NO_KEYCHAIN", "1")
	dir := t.TempDir()

	_, err := (&FileSecrets{dir: dir}).Get("personal")
	if err == nil {
		t.Fatal("Get of a vault with no phrase file succeeded")
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "vault mnemonic not found: personal") {
		t.Errorf("the miss lost its leading text: %q", msg)
	}
	for _, want := range []string{"DFOS_NO_KEYCHAIN", "OS keychain", filepath.Join(dir, "personal.seed")} {
		if !strings.Contains(msg, want) {
			t.Errorf("the miss does not mention %q: %q", want, msg)
		}
	}
}

func TestTheFileBackendsMissWithoutDFOSNoKeychainDoesNotClaimItIsSet(t *testing.T) {
	t.Setenv("DFOS_NO_KEYCHAIN", "")
	dir := t.TempDir()

	_, err := (&FileSecrets{dir: dir}).Get("personal")
	if err == nil {
		t.Fatal("Get of a vault with no phrase file succeeded")
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "vault mnemonic not found: personal") {
		t.Errorf("the miss lost its leading text: %q", msg)
	}
	if strings.Contains(msg, "DFOS_NO_KEYCHAIN") {
		t.Errorf("the miss names DFOS_NO_KEYCHAIN, which is not set: %q", msg)
	}
	if !strings.Contains(msg, "unreachable") {
		t.Errorf("the miss does not say the keychain was unreachable: %q", msg)
	}
}

// A phrase file that is there and cannot be read is not a miss, and must not
// send the operator to the keychain.
func TestAnUnreadablePhraseFileIsNotReportedAsAMiss(t *testing.T) {
	t.Setenv("DFOS_NO_KEYCHAIN", "1")
	dir := t.TempDir()
	// A directory where the file should be: ReadFile fails, and not with
	// ErrNotExist, whatever user the test runs as.
	if err := os.Mkdir(filepath.Join(dir, "personal.seed"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	_, err := (&FileSecrets{dir: dir}).Get("personal")
	if err == nil {
		t.Fatal("Get of an unreadable phrase file succeeded")
	}
	msg := err.Error()
	if strings.Contains(msg, "not found") || strings.Contains(msg, "keychain") {
		t.Errorf("an unreadable phrase file was reported as a miss: %q", msg)
	}
}

// The reverse split: the phrase is a file, the keychain is the backend asked.
// The miss says a phrase file exists, from a stat; without one it says nothing
// extra.
func TestTheKeychainBackendsMissNamesAPhraseFileWhenOneExists(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	secrets := &KeychainSecrets{dir: dir}
	account, err := secrets.account("personal")
	if err != nil {
		t.Fatalf("resolve the account: %v", err)
	}
	leading := "vault mnemonic not found: personal (keychain account " + account + ")"

	_, err = secrets.Get("personal")
	if err == nil {
		t.Fatal("Get of an absent keychain entry succeeded")
	}
	if err.Error() != leading {
		t.Errorf("with no phrase file the miss is %q, want %q", err.Error(), leading)
	}

	if err := (&FileSecrets{dir: dir}).Put("personal", "a phrase written under DFOS_NO_KEYCHAIN"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	_, err = secrets.Get("personal")
	if err == nil {
		t.Fatal("the keychain backend read the file backend's phrase")
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, leading) {
		t.Errorf("the miss lost its leading text: %q", msg)
	}
	for _, want := range []string{filepath.Join(dir, "personal.seed"), "DFOS_NO_KEYCHAIN=1"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the miss does not mention %q: %q", want, msg)
		}
	}
	if strings.Contains(msg, "a phrase written under") {
		t.Errorf("the miss leaked the other backend's phrase: %q", msg)
	}
}
