package vault

// A vault is a named seed and nothing more: {name, BIP-39 mnemonic, fingerprint,
// derivation counter}. It binds no identity, scopes no config, and branches no
// accounts. Choosing a seed is a MINT-time concern — the only moment a vault is
// consulted is when new key material is created. Signing never asks a vault
// anything: it resolves the identity, intersects the identity's published auth
// keys with the keys this device holds, and signs. A vault fingerprint recorded
// beside a minted key is provenance for the operator, never an input to
// resolution.
//
// "Vault" is product vocabulary. The word, the mnemonic, the seed, and the
// fingerprint never touch the wire: no operation payload, no signed message, no
// request to a peer carries any of them. Two identities minted from one seed are
// unlinkable to everyone but the holder, and that property is only true because
// nothing local ever leaks upward.

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
)

// nameRE constrains a vault name to something that is both a legible label and a
// safe file name — the metadata and the file-backend mnemonic are both named
// after it, so a name that escapes its directory is not a naming question.
var nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// ValidateName rejects names that cannot be a file or would read as a path.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid vault name %q: 1–64 characters of letters, digits, '.', '_', or '-', starting with a letter or digit", name)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("invalid vault name %q", name)
	}
	return nil
}

// Metadata is the non-secret half of a vault: everything except the mnemonic.
// It lives in a plain 0600 TOML file so an operator can read it, and it holds
// nothing whose disclosure costs anything.
type Metadata struct {
	Name        string `toml:"name" json:"name"`
	Fingerprint string `toml:"fingerprint" json:"fingerprint"`
	CreatedAt   string `toml:"created_at" json:"createdAt"`
	Imported    bool   `toml:"imported,omitempty" json:"imported,omitempty"`
	// NextIndex is the derivation counter: the next index this vault will hand
	// out. It only ever ascends. An index consumed by a mint that then failed is
	// burned rather than reused — a gap is free (a recovery scan walks a gap
	// limit anyway), whereas reusing an index risks two identities sharing a key.
	NextIndex uint32      `toml:"next_index" json:"nextIndex"`
	Minted    []MintedKey `toml:"minted,omitempty" json:"minted,omitempty"`
}

// MintedKey records that one derivation index became one published key. This is
// the provenance trail: it answers "which seed, at which index, produced the key
// this identity signs with", which is what `whoami` reports and what rotation
// reads to stay on the seed that minted the current keys.
type MintedKey struct {
	Index     uint32 `toml:"index" json:"index"`
	DID       string `toml:"did" json:"did"`
	KeyID     string `toml:"key_id" json:"keyId"`
	Role      string `toml:"role" json:"role"`
	PublicKey string `toml:"public_key" json:"publicKey"`
	MintedAt  string `toml:"minted_at" json:"mintedAt"`
}

// Derived is one freshly derived keypair together with the index it came from.
type Derived struct {
	Index   uint32
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// Store is the on-disk set of vaults: metadata files in dir, mnemonics in
// secrets.
type Store struct {
	dir     string
	secrets SecretStore
}

// Open returns a store rooted at dir with mnemonics in secrets.
func Open(dir string, secrets SecretStore) *Store {
	return &Store{dir: dir, secrets: secrets}
}

// Default returns the store this CLI uses: metadata under the dfos config
// directory, mnemonics in whichever secret backend is reachable.
//
// It resolves through config.ConfigDir(), which honors DFOS_CONFIG, rather than
// os.UserHomeDir() — so pointing DFOS_CONFIG at a scratch directory takes the
// vaults with it instead of reaching into the operator's real ones.
func Default() *Store {
	dir := filepath.Join(config.ConfigDir(), "vaults")
	return Open(dir, NewSecretStore(dir))
}

// Dir is where vault metadata lives.
func (s *Store) Dir() string { return s.dir }

// Backend names the mnemonic storage backend, for display alongside the
// keystore's own backend line.
func (s *Store) Backend() string { return s.secrets.Backend() }

func (s *Store) metaPath(name string) string {
	return filepath.Join(s.dir, name+".toml")
}

// Has reports whether a vault of this name exists.
func (s *Store) Has(name string) bool {
	if ValidateName(name) != nil {
		return false
	}
	_, err := os.Stat(s.metaPath(name))
	return err == nil
}

// Create mints a new vault from fresh entropy and returns its metadata along
// with the mnemonic — which the caller shows the operator ONCE and then drops.
// The mnemonic is never returned again except through an explicit reveal.
func (s *Store) Create(name string) (*Metadata, string, error) {
	if err := ValidateName(name); err != nil {
		return nil, "", err
	}
	if s.Has(name) {
		return nil, "", fmt.Errorf("vault '%s' already exists", name)
	}
	mnemonic, err := NewMnemonic()
	if err != nil {
		return nil, "", err
	}
	meta, err := s.adopt(name, mnemonic, false)
	if err != nil {
		return nil, "", err
	}
	return meta, mnemonic, nil
}

// Import adopts a mnemonic the operator already holds, after checking it is
// well-formed English BIP-39 with a valid checksum.
func (s *Store) Import(name, mnemonic string) (*Metadata, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	if s.Has(name) {
		return nil, fmt.Errorf("vault '%s' already exists", name)
	}
	normalized, err := NormalizeMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}
	return s.adopt(name, normalized, true)
}

// adopt stores the mnemonic and writes the initial metadata. The secret is
// written first: metadata pointing at a mnemonic that was never stored would
// describe a vault that cannot derive anything.
func (s *Store) adopt(name, mnemonic string, imported bool) (*Metadata, error) {
	seed, err := MnemonicSeed(mnemonic)
	if err != nil {
		return nil, err
	}
	if err := s.secrets.Put(name, mnemonic); err != nil {
		return nil, err
	}
	meta := &Metadata{
		Name:        name,
		Fingerprint: Fingerprint(seed),
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		Imported:    imported,
		NextIndex:   0,
	}
	if err := s.save(meta); err != nil {
		_ = s.secrets.Delete(name)
		return nil, err
	}
	return meta, nil
}

func (s *Store) save(meta *Metadata) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("create vault dir: %w", err)
	}
	data, err := toml.Marshal(meta)
	if err != nil {
		return err
	}
	return os.WriteFile(s.metaPath(meta.Name), data, 0o600)
}

// Load reads one vault's metadata.
func (s *Store) Load(name string) (*Metadata, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.metaPath(name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no vault named '%s' (see 'dfos vault list')", name)
		}
		return nil, err
	}
	meta := &Metadata{}
	if err := toml.Unmarshal(data, meta); err != nil {
		return nil, fmt.Errorf("parse vault '%s': %w", name, err)
	}
	// The file name is the authority on the name, so a hand-edited or copied
	// metadata file cannot make a vault answer to something it is not filed under.
	meta.Name = name
	return meta, nil
}

// List returns every vault's metadata, name-ordered.
func (s *Store) List() ([]*Metadata, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		names = append(names, strings.TrimSuffix(e.Name(), ".toml"))
	}
	sort.Strings(names)
	out := make([]*Metadata, 0, len(names))
	for _, n := range names {
		meta, err := s.Load(n)
		if err != nil {
			return nil, err
		}
		out = append(out, meta)
	}
	return out, nil
}

// Mnemonic returns a vault's mnemonic. Every caller of this is a deliberate
// reveal or a derivation; nothing prints its result by default.
func (s *Store) Mnemonic(name string) (string, error) {
	if _, err := s.Load(name); err != nil {
		return "", err
	}
	return s.secrets.Get(name)
}

// Mint reserves the next count indices and derives their keypairs.
//
// Reserving is a read-modify-write of the metadata file. Every `dfos` invocation
// that can mutate local state holds the process-wide state lock (see
// internal/statelock) for its whole run, so two dfos processes cannot interleave
// here. A third-party writer editing the TOML underneath a running mint would
// still lose its edit — that is the honest limit of a plain file, and it is the
// same limit config.toml already has.
func (s *Store) Mint(name string, count int) ([]Derived, error) {
	if count <= 0 {
		return nil, fmt.Errorf("mint count must be positive, got %d", count)
	}
	meta, err := s.Load(name)
	if err != nil {
		return nil, err
	}
	mnemonic, err := s.secrets.Get(name)
	if err != nil {
		return nil, err
	}
	seed, err := MnemonicSeed(mnemonic)
	if err != nil {
		return nil, err
	}

	start := meta.NextIndex
	if uint64(start)+uint64(count) > uint64(hardenedOffset) {
		return nil, fmt.Errorf("vault '%s' has exhausted its derivation range", name)
	}
	derived := make([]Derived, 0, count)
	for i := 0; i < count; i++ {
		index := start + uint32(i)
		priv, pub, err := DeriveKey(seed, index)
		if err != nil {
			return nil, err
		}
		derived = append(derived, Derived{Index: index, Private: priv, Public: pub})
	}

	// The counter advances BEFORE the keys are used. If everything downstream
	// fails, the indices are burned; that is deliberate, because handing the same
	// index to two identities is the one outcome worth spending indices to avoid.
	meta.NextIndex = start + uint32(count)
	if err := s.save(meta); err != nil {
		return nil, err
	}
	return derived, nil
}

// Record appends minted-key provenance once the keys are actually published.
func (s *Store) Record(name string, records ...MintedKey) error {
	if len(records) == 0 {
		return nil
	}
	meta, err := s.Load(name)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, r := range records {
		if r.MintedAt == "" {
			r.MintedAt = now
		}
		meta.Minted = append(meta.Minted, r)
	}
	return s.save(meta)
}

// FindMinted locates the vault and index that minted a given (DID, key id)
// pair. This is how `whoami` reports provenance and how rotation stays on the
// seed that minted the identity's current keys. It reads only.
func (s *Store) FindMinted(did, keyID string) (*Metadata, *MintedKey, bool) {
	all, err := s.List()
	if err != nil {
		return nil, nil, false
	}
	for _, meta := range all {
		for i := range meta.Minted {
			if meta.Minted[i].DID == did && meta.Minted[i].KeyID == keyID {
				return meta, &meta.Minted[i], true
			}
		}
	}
	return nil, nil, false
}

// FindMintingVault returns the vault that minted any of an identity's keys, so
// a rotation draws its replacement from the same seed. keyIDs are checked in
// order, so the caller decides which role's provenance is authoritative.
func (s *Store) FindMintingVault(did string, keyIDs []string) (*Metadata, bool) {
	for _, id := range keyIDs {
		if meta, _, ok := s.FindMinted(did, id); ok {
			return meta, true
		}
	}
	return nil, false
}
