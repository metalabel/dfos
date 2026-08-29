package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

// Entry is one thing a backend holds.
//
// Account is what the entry answers to — the string every other method on Store
// takes. It is empty ONLY when the backend can prove something is there and
// cannot name it exactly: a file written by the pre-reversible naming scheme
// (see fileName) whose name maps back to more than one possible account. Ref is
// then the backend-scoped handle for that thing, so a caller can report "this
// exists and I cannot name it" instead of guessing at it.
type Entry struct {
	Account string
	Ref     string
}

// Enumerator is implemented by backends that can list what they hold.
//
// It is deliberately NOT part of Store: whether a backend can enumerate is a
// property of the backend, not of key storage. The OS keychain wrappers differ
// on this — macOS can be asked for every item under a service, the
// secret-service and Windows backends this CLI links cannot — and a caller that
// wants a full picture has to know which case it is in rather than be handed a
// short list that looks complete.
type Enumerator interface {
	// Entries lists what this backend holds, with reserved accounts (see
	// IsReservedAccount) already dropped. It returns ErrNoEnumeration when the
	// backend cannot answer the question at all.
	Entries() ([]Entry, error)
}

// ErrNoEnumeration says a backend cannot list its own contents. It is a fact
// about the backend, not a failure: a caller that gets it falls back to naming
// candidate accounts from the other local stores and probing each with HasKey,
// which finds every key something else already knows about and no others.
var ErrNoEnumeration = errors.New("this keystore backend cannot list the keys it holds")

// reservedAccountPrefixes and reservedAccounts name things that live in the same
// backend namespace as key seeds and are NOT key seeds.
//
// Vault mnemonics are the dangerous case: internal/vault/secrets.go stores them
// in the SAME OS keychain service as the seeds ("dfos", under a "vault:<name>"
// account), so anything that enumerates that service sees them. Treating one as
// a key would read a recovery phrase as a hex seed, and DELETING one would
// destroy the phrase every key it minted derives from. The probe accounts are
// the harmless case: a write/read/delete cycle that lost its delete would
// otherwise show up as a key.
//
// The filter lives here, at the one place enumeration produces a list, so no
// caller can forget it.
var (
	reservedAccountPrefixes = []string{"vault:"}
	reservedAccounts        = []string{"dfos-keychain-probe", "dfos-vault-keychain-probe"}
)

// IsReservedAccount reports whether an account names something that is not a
// key seed. Callers that delete should re-check it: the cost of asking twice is
// nothing, and the cost of being wrong once is a lost recovery phrase.
func IsReservedAccount(account string) bool {
	for _, prefix := range reservedAccountPrefixes {
		if strings.HasPrefix(account, prefix) {
			return true
		}
	}
	for _, name := range reservedAccounts {
		if account == name {
			return true
		}
	}
	return false
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

// fileName maps an account to a file name by percent-encoding every byte
// outside [A-Za-z0-9.-]: `did:dfos:abc#key_x` becomes
// `did%3Adfos%3Aabc%23key%5Fx`.
//
// The encoding is REVERSIBLE, and that is the whole point of it. The scheme it
// replaces mangled `#`→`__` and `:`→`_`, which is many-to-one: `pending:key_a`
// and `pending_key:a` both land on `pending_key_a`, so a file name could not be
// read back as the account that produced it. Nothing needed to read it back
// until this store had to be able to say what it holds — a ledger of local key
// material that cannot name its own entries is not a ledger — and a lossy name
// is also a silent overwrite waiting for two accounts that collide.
//
// `_` is escaped rather than kept, so a new-style name never contains one. That
// is what makes the two schemes distinguishable on sight: see legacyFileName.
func fileName(account string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(account); i++ {
		c := account[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '-':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0f])
		}
	}
	return b.String()
}

// accountFromFileName inverts fileName. ok is false for a name the old mangling
// wrote, which is reported rather than guessed at.
func accountFromFileName(name string) (account string, ok bool) {
	// A name holding `_` cannot have come from fileName, which escapes it. It is
	// a pre-reversible file, and the account that produced it is not recoverable
	// from the name — `_` there could have been a `:` or a literal `_`.
	if strings.Contains(name, "_") {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		if name[i] != '%' {
			b.WriteByte(name[i])
			continue
		}
		if i+2 >= len(name) {
			return "", false
		}
		hi, lo := unhex(name[i+1]), unhex(name[i+2])
		if hi < 0 || lo < 0 {
			return "", false
		}
		b.WriteByte(byte(hi<<4 | lo))
		i += 2
	}
	return b.String(), true
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return -1
}

// legacyFileName is the pre-reversible name for an account: `#`→`__`, `:`→`_`.
// Files written under it are still READ — an upgrade must not lose a key — and
// are rewritten under the new name the next time the account is written.
func legacyFileName(account string) string {
	return strings.NewReplacer("#", "__", ":", "_").Replace(account)
}

// keyPath is where an account is WRITTEN.
func (f *FileStore) keyPath(account string) string {
	return filepath.Join(f.dir, fileName(account))
}

func (f *FileStore) legacyKeyPath(account string) string {
	return filepath.Join(f.dir, legacyFileName(account))
}

// resolvePath is where an account is READ from: the current name if it is there,
// otherwise the legacy one. It falls back to the current name so a miss reports
// the path this store would use.
func (f *FileStore) resolvePath(account string) string {
	current := f.keyPath(account)
	if _, err := os.Stat(current); err == nil {
		return current
	}
	legacy := f.legacyKeyPath(account)
	if legacy != current {
		if _, err := os.Stat(legacy); err == nil {
			return legacy
		}
	}
	return current
}

// writeKey writes an account's seed under the current name and drops any legacy
// file for the same account, so one account is never two files.
func (f *FileStore) writeKey(account string, seedHex []byte) error {
	if err := f.ensureDir(); err != nil {
		return fmt.Errorf("create keys dir: %w", err)
	}
	current := f.keyPath(account)
	if err := os.WriteFile(current, seedHex, 0o600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	if legacy := f.legacyKeyPath(account); legacy != current {
		_ = os.Remove(legacy)
	}
	return nil
}

// Entries lists every key file, naming each one's account where the file name
// can be read back. A pre-reversible file name is reported by reference with no
// account, which is the honest answer: something is there, and this store
// cannot say what it is called.
func (f *FileStore) Entries() ([]Entry, error) {
	dirEntries, err := os.ReadDir(f.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read keys dir %s: %w", f.dir, err)
	}
	out := make([]Entry, 0, len(dirEntries))
	for _, e := range dirEntries {
		if e.IsDir() {
			continue
		}
		account, ok := accountFromFileName(e.Name())
		if ok && IsReservedAccount(account) {
			continue
		}
		if !ok {
			account = ""
		}
		out = append(out, Entry{Account: account, Ref: e.Name()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out, nil
}

func (f *FileStore) GenerateKey(account string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	if err := f.writeKey(account, []byte(hex.EncodeToString(seed))); err != nil {
		return nil, nil, err
	}

	return priv, pub, nil
}

func (f *FileStore) PutKey(account string, priv ed25519.PrivateKey) (ed25519.PublicKey, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("not an ed25519 private key: %d bytes", len(priv))
	}
	if err := f.writeKey(account, []byte(hex.EncodeToString(priv.Seed()))); err != nil {
		return nil, err
	}
	return priv.Public().(ed25519.PublicKey), nil
}

func (f *FileStore) GetPrivateKey(account string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(f.resolvePath(account))
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
	_, err := os.Stat(f.resolvePath(account))
	return err == nil
}

func (f *FileStore) RenameKey(oldAccount, newAccount string) error {
	data, err := os.ReadFile(f.resolvePath(oldAccount))
	if err != nil {
		return fmt.Errorf("old key not found: %s", oldAccount)
	}
	if err := f.writeKey(newAccount, data); err != nil {
		return err
	}
	return os.Remove(f.resolvePath(oldAccount))
}

func (f *FileStore) DeleteKey(account string) error {
	return os.Remove(f.resolvePath(account))
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

func (m *MemoryStore) Entries() ([]Entry, error) {
	m.mu.Lock()
	accounts := make([]string, 0, len(m.keys))
	for account := range m.keys {
		if IsReservedAccount(account) {
			continue
		}
		accounts = append(accounts, account)
	}
	m.mu.Unlock()
	sort.Strings(accounts)
	out := make([]Entry, 0, len(accounts))
	for _, account := range accounts {
		out = append(out, Entry{Account: account, Ref: account})
	}
	return out, nil
}

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
