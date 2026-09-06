package vault

// Where a vault's mnemonic lives. This mirrors internal/keystore exactly — the
// OS keychain when one is reachable, a 0600 file when it is not — because a
// mnemonic is the same kind of secret as a key seed and an operator should not
// have to learn two custody stories for one machine.
//
// It does not reuse keystore.Store: that interface is typed to ed25519 seeds
// (GenerateKey hands back a keypair), and a mnemonic is a string. Bending one
// into the other would hide what is actually stored.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/zalando/go-keyring"
)

const keychainService = "dfos"

// keychainAccount namespaces vault mnemonics inside the same keychain service
// the key seeds use. Key accounts are `key:<publicKeyMultibase>`, and
// `did:dfos:…#key_…` for the ones earlier versions wrote, so this prefix cannot
// collide with one.
//
// The custody id is the middle segment because a keychain is machine-wide while
// a vault directory is not — see custody.go for what that cost before.
func keychainAccount(custodyID, name string) string { return "vault:" + custodyID + ":" + name }

// legacyKeychainAccount is the flat account vault mnemonics were written to
// before custody ids: one namespace for the whole machine, whatever DFOS_CONFIG
// said. It is READ, so a vault created by an earlier version still opens, and
// written only by the migration that moves such a vault forward.
func legacyKeychainAccount(name string) string { return "vault:" + name }

// SecretStore holds vault mnemonics.
type SecretStore interface {
	// Put stores a NEW vault's mnemonic. It refuses to write over one that is
	// already there (ErrSecretExists) rather than replacing it.
	Put(name, mnemonic string) error
	Get(name string) (string, error)
	Delete(name string) error
	// Backend returns a human-readable name for the storage backend.
	Backend() string
}

// ErrSecretExists says the backend already holds a mnemonic under this name.
//
// Put has exactly two callers — `vault create` and `vault import`, both behind
// an "already exists" check on the metadata — so an occupied slot is a
// disagreement between the two halves of a vault, never an update. Overwriting
// is the one operation here that destroys a recovery phrase outright, so the
// write is refused and the caller is told what is in the way.
var ErrSecretExists = errors.New("a mnemonic is already stored under this vault name")

// legacySecrets is implemented by a backend that has an older account namespace
// to fall back to. It is deliberately not part of SecretStore: having a legacy
// namespace is a fact about one backend, and only the keychain has one — the
// file backend has always been scoped to the vault directory it writes into.
//
// The caller accepts what getLegacy returns only after checking that the phrase
// fingerprints the way the vault's own metadata says it should, which is what
// stops one config directory adopting another's phrase by name.
type legacySecrets interface {
	getLegacy(name string) (string, bool)
	migrateLegacy(name, mnemonic string) error
}

// NewSecretStore returns the appropriate backend, following the same probe and
// fallback the keystore does, and honoring the same DFOS_NO_KEYCHAIN escape.
// dir is where the file backend writes if the keychain is unreachable.
func NewSecretStore(dir string) SecretStore {
	if os.Getenv("DFOS_NO_KEYCHAIN") != "" {
		return &FileSecrets{dir: dir}
	}
	probe := "dfos-vault-keychain-probe"
	if err := keyring.Set(keychainService, probe, "probe"); err != nil {
		return &FileSecrets{dir: dir}
	}
	keyring.Delete(keychainService, probe)
	return &KeychainSecrets{dir: dir}
}

// --- OS Keychain ---

// KeychainSecrets stores mnemonics in the OS keychain under accounts namespaced
// by the custody id of dir — the vault directory whose metadata these mnemonics
// are the other half of.
type KeychainSecrets struct {
	dir   string
	once  sync.Once
	id    string
	idErr error
}

func (k *KeychainSecrets) Backend() string { return "keychain" }

// account is this backend's keychain account for a vault name. The custody id
// is read (or minted) once per process: it is one file read, and every account
// in a run sits under the same id.
func (k *KeychainSecrets) account(name string) (string, error) {
	k.once.Do(func() { k.id, k.idErr = CustodyID(k.dir) })
	if k.idErr != nil {
		return "", k.idErr
	}
	return keychainAccount(k.id, name), nil
}

func (k *KeychainSecrets) Put(name, mnemonic string) error {
	account, err := k.account(name)
	if err != nil {
		return err
	}
	switch _, err := keyring.Get(keychainService, account); {
	case err == nil:
		return fmt.Errorf("%w: keychain service %s, account %s", ErrSecretExists, keychainService, account)
	case !errors.Is(err, keyring.ErrNotFound):
		// Absence is what licenses the write, and a keychain that cannot be read
		// has not established it. Stopping here costs a retry; guessing costs a
		// recovery phrase.
		return fmt.Errorf("check the keychain for an existing vault mnemonic (%s): %w", account, err)
	}
	if err := keyring.Set(keychainService, account, mnemonic); err != nil {
		return fmt.Errorf("store vault mnemonic in keychain: %w", err)
	}
	return nil
}

func (k *KeychainSecrets) Get(name string) (string, error) {
	account, err := k.account(name)
	if err != nil {
		return "", err
	}
	m, err := keyring.Get(keychainService, account)
	if err != nil {
		return "", fmt.Errorf("vault mnemonic not found: %s (keychain account %s)", name, account)
	}
	return m, nil
}

func (k *KeychainSecrets) Delete(name string) error {
	account, err := k.account(name)
	if err != nil {
		return err
	}
	// This directory's account and no other. The only caller is the rollback of
	// an adopt that just wrote it, and a delete reaching for the flat legacy
	// account would be one config directory removing a phrase it never stored.
	return keyring.Delete(keychainService, account)
}

func (k *KeychainSecrets) getLegacy(name string) (string, bool) {
	m, err := keyring.Get(keychainService, legacyKeychainAccount(name))
	if err != nil {
		return "", false
	}
	return m, true
}

// migrateLegacy files a phrase found under the flat account under this
// directory's custody id. Set then Delete, in that order: a failure between the
// two leaves the phrase readable in two places, and the other order would leave
// a window where it is readable in none.
func (k *KeychainSecrets) migrateLegacy(name, mnemonic string) error {
	account, err := k.account(name)
	if err != nil {
		return err
	}
	if err := keyring.Set(keychainService, account, mnemonic); err != nil {
		return fmt.Errorf("store vault mnemonic in keychain: %w", err)
	}
	return keyring.Delete(keychainService, legacyKeychainAccount(name))
}

// --- File (<config dir>/vaults/<name>.seed) ---

// FileSecrets writes each mnemonic to its own file at mode 0600 in a 0700
// directory. Same threat model as the keystore's file backend: the protection is
// filesystem permissions and nothing more, and the file grants everything the
// seed grants to anyone who can read it.
type FileSecrets struct {
	dir string
	mu  sync.Mutex
}

func (f *FileSecrets) Backend() string { return "file (" + f.dir + ")" }

func (f *FileSecrets) path(name string) string {
	return filepath.Join(f.dir, name+".seed")
}

func (f *FileSecrets) Put(name, mnemonic string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		return fmt.Errorf("create vault dir: %w", err)
	}
	// O_EXCL rather than a stat followed by a write: refusing to overwrite is the
	// point, so the open is what enforces it.
	file, err := os.OpenFile(f.path(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s", ErrSecretExists, f.path(name))
		}
		return fmt.Errorf("write vault mnemonic: %w", err)
	}
	if _, err := file.WriteString(mnemonic + "\n"); err != nil {
		file.Close()
		return fmt.Errorf("write vault mnemonic: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("write vault mnemonic: %w", err)
	}
	return nil
}

func (f *FileSecrets) Get(name string) (string, error) {
	data, err := os.ReadFile(f.path(name))
	if err != nil {
		return "", fmt.Errorf("vault mnemonic not found: %s", name)
	}
	return strings.TrimSpace(string(data)), nil
}

func (f *FileSecrets) Delete(name string) error {
	return os.Remove(f.path(name))
}

// --- Lazy ---

// lazySecrets defers NewSecretStore until a secret is actually touched.
//
// Probing the OS keychain costs a write/read/delete cycle, and the read-only
// paths — `vault list`, `vault show`, whoami's provenance line — never open a
// mnemonic at all. Every invocation already probes once for the keystore; making
// a metadata read probe a second time would be a cost paid by commands that have
// no business asking the keychain anything.
type lazySecrets struct {
	dir  string
	once sync.Once
	real SecretStore
}

func (l *lazySecrets) get() SecretStore {
	l.once.Do(func() { l.real = NewSecretStore(l.dir) })
	return l.real
}

func (l *lazySecrets) Put(name, mnemonic string) error { return l.get().Put(name, mnemonic) }
func (l *lazySecrets) Get(name string) (string, error) { return l.get().Get(name) }
func (l *lazySecrets) Delete(name string) error        { return l.get().Delete(name) }
func (l *lazySecrets) Backend() string                 { return l.get().Backend() }

// The legacy namespace, forwarded to whichever backend was chosen. Reached only
// after a Get has already missed, so the probe this triggers has happened.
func (l *lazySecrets) getLegacy(name string) (string, bool) {
	if legacy, ok := l.get().(legacySecrets); ok {
		return legacy.getLegacy(name)
	}
	return "", false
}

func (l *lazySecrets) migrateLegacy(name, mnemonic string) error {
	if legacy, ok := l.get().(legacySecrets); ok {
		return legacy.migrateLegacy(name, mnemonic)
	}
	return nil
}

// --- In-Memory (tests only) ---

type MemorySecrets struct {
	mu      sync.Mutex
	entries map[string]string
}

func NewMemorySecrets() *MemorySecrets {
	return &MemorySecrets{entries: make(map[string]string)}
}

func (m *MemorySecrets) Backend() string { return "memory" }

func (m *MemorySecrets) Put(name, mnemonic string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[name]; ok {
		return fmt.Errorf("%w: %s", ErrSecretExists, name)
	}
	m.entries[name] = mnemonic
	return nil
}

func (m *MemorySecrets) Get(name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.entries[name]
	if !ok {
		return "", fmt.Errorf("vault mnemonic not found: %s", name)
	}
	return v, nil
}

func (m *MemorySecrets) Delete(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, name)
	return nil
}
