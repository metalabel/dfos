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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/zalando/go-keyring"
)

const keychainService = "dfos"

// keychainAccount namespaces vault mnemonics inside the same keychain service
// the key seeds use. Key accounts are `did:dfos:…#key_…`, so this prefix cannot
// collide with one.
func keychainAccount(name string) string { return "vault:" + name }

// SecretStore holds vault mnemonics.
type SecretStore interface {
	Put(name, mnemonic string) error
	Get(name string) (string, error)
	Delete(name string) error
	// Backend returns a human-readable name for the storage backend.
	Backend() string
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
	return &KeychainSecrets{}
}

// --- OS Keychain ---

type KeychainSecrets struct{}

func (k *KeychainSecrets) Backend() string { return "keychain" }

func (k *KeychainSecrets) Put(name, mnemonic string) error {
	if err := keyring.Set(keychainService, keychainAccount(name), mnemonic); err != nil {
		return fmt.Errorf("store vault mnemonic in keychain: %w", err)
	}
	return nil
}

func (k *KeychainSecrets) Get(name string) (string, error) {
	m, err := keyring.Get(keychainService, keychainAccount(name))
	if err != nil {
		return "", fmt.Errorf("vault mnemonic not found: %s", name)
	}
	return m, nil
}

func (k *KeychainSecrets) Delete(name string) error {
	return keyring.Delete(keychainService, keychainAccount(name))
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
	if err := os.WriteFile(f.path(name), []byte(mnemonic+"\n"), 0o600); err != nil {
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
