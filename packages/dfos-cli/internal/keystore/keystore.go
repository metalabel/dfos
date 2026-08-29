package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/zalando/go-keyring"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
)

const serviceName = "dfos"

// Store is the interface for key storage.
type Store interface {
	// GenerateKey generates a new ed25519 keypair and stores it.
	GenerateKey(account string) (ed25519.PrivateKey, ed25519.PublicKey, error)
	// PutKey stores a keypair derived elsewhere — today, from a vault's seed.
	// The keystore remains the ONE place private material lives, so every
	// downstream signing path is identical whether the key was generated here or
	// derived from a mnemonic.
	PutKey(account string, priv ed25519.PrivateKey) (ed25519.PublicKey, error)
	// GetPrivateKey retrieves a private key by account.
	GetPrivateKey(account string) (ed25519.PrivateKey, error)
	// HasKey checks if a key exists.
	HasKey(account string) bool
	// RenameKey renames a key from oldAccount to newAccount.
	RenameKey(oldAccount, newAccount string) error
	// DeleteKey removes a key.
	DeleteKey(account string) error
	// Backend returns a human-readable name for the storage backend.
	Backend() string
}

// New returns the appropriate keystore.
//
// Follows the gh CLI pattern:
//   - Default: try OS keychain first
//   - If keychain unavailable: fall back to file-based storage (`keys/` inside
//     the dfos config directory — `~/.dfos/keys/`, or wherever DFOS_CONFIG points)
//   - DFOS_NO_KEYCHAIN=1: skip keychain, use file store directly
func New() Store {
	if os.Getenv("DFOS_NO_KEYCHAIN") != "" {
		return NewFileStore("")
	}
	return newWithKeychainFallback()
}

func newWithKeychainFallback() Store {
	// probe the keychain with a test write/read/delete cycle
	testAccount := "dfos-keychain-probe"
	err := keyring.Set(serviceName, testAccount, "probe")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: OS keychain not available (%v)\n", err)
		fmt.Fprintf(os.Stderr, "         Falling back to file-based key storage at %s/\n", defaultKeyDir())
		return NewFileStore("")
	}
	keyring.Delete(serviceName, testAccount)
	return &KeychainStore{}
}

// --- OS Keychain ---

type KeychainStore struct{}

func (k *KeychainStore) Backend() string { return "keychain" }

func (k *KeychainStore) GenerateKey(account string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	if err := keyring.Set(serviceName, account, hex.EncodeToString(seed)); err != nil {
		return nil, nil, fmt.Errorf("store key in keychain: %w", err)
	}

	return priv, pub, nil
}

func (k *KeychainStore) PutKey(account string, priv ed25519.PrivateKey) (ed25519.PublicKey, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("not an ed25519 private key: %d bytes", len(priv))
	}
	if err := keyring.Set(serviceName, account, hex.EncodeToString(priv.Seed())); err != nil {
		return nil, fmt.Errorf("store key in keychain: %w", err)
	}
	return priv.Public().(ed25519.PublicKey), nil
}

func (k *KeychainStore) GetPrivateKey(account string) (ed25519.PrivateKey, error) {
	seedHex, err := keyring.Get(serviceName, account)
	if err != nil {
		return nil, fmt.Errorf("key not found: %s", account)
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func (k *KeychainStore) HasKey(account string) bool {
	_, err := keyring.Get(serviceName, account)
	return err == nil
}

func (k *KeychainStore) RenameKey(oldAccount, newAccount string) error {
	seedHex, err := keyring.Get(serviceName, oldAccount)
	if err != nil {
		return fmt.Errorf("old key not found: %s", oldAccount)
	}
	if err := keyring.Set(serviceName, newAccount, seedHex); err != nil {
		return err
	}
	return keyring.Delete(serviceName, oldAccount)
}

func (k *KeychainStore) DeleteKey(account string) error {
	return keyring.Delete(serviceName, account)
}

// --- File Store (<config dir>/keys/) ---

// FileStore persists keys as individual files in a directory.
// Each file is named by the account (with path-unsafe chars replaced)
// and contains the hex-encoded 32-byte ed25519 seed.
// Files are created with mode 0600 (owner read/write only).
type FileStore struct {
	dir string
}

// NewFileStore creates a file-based keystore. If dir is empty, it defaults to a
// `keys/` directory inside the dfos config directory — which is `~/.dfos/keys/`
// as before, EXCEPT when DFOS_CONFIG points elsewhere.
//
// It resolves through config.ConfigDir() rather than os.UserHomeDir() because
// the two disagreed: DFOS_CONFIG relocated config.toml and relay.db but left the
// key store in the real home directory, so an invocation aimed at a scratch
// directory still wrote keys into the operator's actual store. Isolation that
// covers some of the state and not the keys is worse than none, because it reads
// as isolation.
func NewFileStore(dir string) *FileStore {
	if dir == "" {
		dir = defaultKeyDir()
	}
	return &FileStore{dir: dir}
}

// defaultKeyDir is where keys live when nothing names a directory.
func defaultKeyDir() string {
	return filepath.Join(config.ConfigDir(), "keys")
}

func (f *FileStore) Backend() string { return "file (" + f.dir + ")" }

func (f *FileStore) ensureDir() error {
	return os.MkdirAll(f.dir, 0o700)
}

func (f *FileStore) keyPath(account string) string {
	// replace path-unsafe characters: # → _ , : → _
	safe := strings.NewReplacer("#", "__", ":", "_").Replace(account)
	return filepath.Join(f.dir, safe)
}

func (f *FileStore) GenerateKey(account string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	if err := f.ensureDir(); err != nil {
		return nil, nil, fmt.Errorf("create keys dir: %w", err)
	}
	if err := os.WriteFile(f.keyPath(account), []byte(hex.EncodeToString(seed)), 0o600); err != nil {
		return nil, nil, fmt.Errorf("write key file: %w", err)
	}

	return priv, pub, nil
}

func (f *FileStore) PutKey(account string, priv ed25519.PrivateKey) (ed25519.PublicKey, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("not an ed25519 private key: %d bytes", len(priv))
	}
	if err := f.ensureDir(); err != nil {
		return nil, fmt.Errorf("create keys dir: %w", err)
	}
	if err := os.WriteFile(f.keyPath(account), []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
		return nil, fmt.Errorf("write key file: %w", err)
	}
	return priv.Public().(ed25519.PublicKey), nil
}

func (f *FileStore) GetPrivateKey(account string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(f.keyPath(account))
	if err != nil {
		return nil, fmt.Errorf("key not found: %s", account)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func (f *FileStore) HasKey(account string) bool {
	_, err := os.Stat(f.keyPath(account))
	return err == nil
}

func (f *FileStore) RenameKey(oldAccount, newAccount string) error {
	data, err := os.ReadFile(f.keyPath(oldAccount))
	if err != nil {
		return fmt.Errorf("old key not found: %s", oldAccount)
	}
	if err := f.ensureDir(); err != nil {
		return err
	}
	if err := os.WriteFile(f.keyPath(newAccount), data, 0o600); err != nil {
		return err
	}
	return os.Remove(f.keyPath(oldAccount))
}

func (f *FileStore) DeleteKey(account string) error {
	return os.Remove(f.keyPath(account))
}

// --- In-Memory (for testing only, not used in production paths) ---

type MemoryStore struct {
	mu   sync.Mutex
	keys map[string]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{keys: make(map[string]string)}
}

func (m *MemoryStore) Backend() string { return "memory" }

func (m *MemoryStore) GenerateKey(account string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	m.mu.Lock()
	m.keys[account] = hex.EncodeToString(seed)
	m.mu.Unlock()

	return priv, pub, nil
}

func (m *MemoryStore) PutKey(account string, priv ed25519.PrivateKey) (ed25519.PublicKey, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("not an ed25519 private key: %d bytes", len(priv))
	}
	m.mu.Lock()
	m.keys[account] = hex.EncodeToString(priv.Seed())
	m.mu.Unlock()
	return priv.Public().(ed25519.PublicKey), nil
}

func (m *MemoryStore) GetPrivateKey(account string) (ed25519.PrivateKey, error) {
	m.mu.Lock()
	seedHex, ok := m.keys[account]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("key not found: %s", account)
	}
	seed, _ := hex.DecodeString(seedHex)
	return ed25519.NewKeyFromSeed(seed), nil
}

func (m *MemoryStore) HasKey(account string) bool {
	m.mu.Lock()
	_, ok := m.keys[account]
	m.mu.Unlock()
	return ok
}

func (m *MemoryStore) RenameKey(oldAccount, newAccount string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	seedHex, ok := m.keys[oldAccount]
	if !ok {
		return fmt.Errorf("old key not found: %s", oldAccount)
	}
	m.keys[newAccount] = seedHex
	delete(m.keys, oldAccount)
	return nil
}

func (m *MemoryStore) DeleteKey(account string) error {
	m.mu.Lock()
	delete(m.keys, account)
	m.mu.Unlock()
	return nil
}
