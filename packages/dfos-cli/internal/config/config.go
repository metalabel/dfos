package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Config is the top-level configuration. JSON tags mirror the TOML snake_case
// keys so `config list --json` emits the same namespace that `config get`/`set`
// and the on-disk TOML use (round-trippable via jq), not Go PascalCase fields.
type Config struct {
	// DefaultIdentity and DefaultPeer are the config tier of the resolution
	// stack — the last thing consulted, after flags and environment. They are
	// written by ONE thing only, `dfos config set`, and no command updates them
	// as a side effect: nothing follows "last used" or "last created". That is
	// what makes concurrent invocations safe, because there is no pointer for
	// two processes to race on.
	DefaultIdentity string `toml:"default_identity,omitempty" json:"default_identity,omitempty"`
	DefaultPeer     string `toml:"default_peer,omitempty" json:"default_peer,omitempty"`
	// DefaultVault names the vault new key material is minted from when no
	// --vault is given. It sits in the same tier and under the same discipline as
	// the other two — `dfos config set` writes it and nothing else does — with
	// ONE exception, documented at its writer: creating the first vault on a
	// machine that has none may set it, because absence→presence is not a
	// pointer two processes can race on.
	DefaultVault string `toml:"default_vault,omitempty" json:"default_vault,omitempty"`
	// ActiveContext is the removed mutable pointer of the `dfos use` era. It is
	// parsed so an existing config.toml round-trips without losing the line, and
	// it is never consulted by resolution. `dfos whoami` reports it as inert.
	ActiveContext string                    `toml:"active_context,omitempty" json:"active_context,omitempty"`
	Relays        map[string]RelayConfig    `toml:"relays,omitempty" json:"relays,omitempty"`
	Identities    map[string]IdentityConfig `toml:"identities,omitempty" json:"identities,omitempty"`
	Contexts      map[string]ContextConfig  `toml:"contexts,omitempty" json:"contexts,omitempty"`
	// Pointer so an empty Defaults is omitted by both encoders (json omitempty is
	// a no-op on a struct value, which would otherwise render "defaults":{}).
	Defaults *DefaultsConfig `toml:"defaults,omitempty" json:"defaults,omitempty"`
}

// RelayConfig is one registered peer. Its fields come in three kinds, and the
// difference is which of them anything on the network is allowed to write:
//
//   - PIN — DID. The identity this URL must serve for the name to keep meaning
//     what it meant. Written on registration and by `peer repin`, and by nothing
//     else, because a pin a refresh can move is not a pin.
//   - POLICY — Content, Proof, Log, Gossip, ReadThrough, Sync. What THIS machine
//     has decided to do with the peer. Seeded from the peer's advertisement on
//     first registration and owned by the operator from then on; no refresh
//     overwrites them, which is what makes a posture hold.
//   - LABEL — ProfileName. Display only, refreshed freely.
//
// The plane flags sit in policy rather than in a cache because they decide
// behavior: a peer whose Proof or Log says false is not bulk-polled. When they
// were a cache, one `peer info` could silently restore a posture the operator
// had turned off.
type RelayConfig struct {
	URL         string `toml:"url" json:"url"`
	DID         string `toml:"did,omitempty" json:"did,omitempty"`                   // pinned peer identity
	ProfileName string `toml:"profile_name,omitempty" json:"profile_name,omitempty"` // display label from the profile artifact
	// The plane flags: which of the peer's surfaces this machine uses. Seeded
	// from its advertised capabilities at registration; absent means take the
	// peer at its word.
	Content *bool `toml:"content,omitempty" json:"content,omitempty"` // use this peer's document plane
	Proof   *bool `toml:"proof,omitempty" json:"proof,omitempty"`     // use this peer's proof plane
	Log     *bool `toml:"log,omitempty" json:"log,omitempty"`         // use this peer's global operation log
	// The per-peer switches, in the config.toml spelling of the same three
	// switches a `serve --peers` object carries. Absent means the relay
	// library's default, which is on for all three.
	Gossip      *bool `toml:"gossip,omitempty" json:"gossip,omitempty"`             // push newly sequenced ops to this peer
	ReadThrough *bool `toml:"read_through,omitempty" json:"read_through,omitempty"` // fetch from this peer on a local 404
	Sync        *bool `toml:"sync,omitempty" json:"sync,omitempty"`                 // poll this peer's operation log (bulk sync)
}

// BulkSyncDisabledReason reports why this machine must NOT poll a peer's
// operation log, or "" when it may. Bulk sync is the one peer interaction that
// is unbounded in the peer's corpus rather than in what was asked for — every
// chain the peer holds lands in the local store — so it is the one that answers
// to a switch. Explicit single-chain traffic (`identity fetch`, publish, `api
// call`, login) is not gated by anything here.
//
// Three ways to be off, and the reason is carried out so a skipped peer can say
// which one applies rather than looking like a peer that had nothing to send:
//
//   - `sync = false` — the operator's standing posture for this peer.
//   - `proof = false` — this machine does not use the peer's proof plane.
//   - `log = false` — this machine does not use the peer's operation log (a
//     peer that advertises none would answer the pull with a 501 every cycle).
//
// An absent value means on, which is what every config written before the
// switches existed says, and what registration writes for a peer that
// advertises the capability.
func BulkSyncDisabledReason(r RelayConfig) string {
	switch {
	case r.Sync != nil && !*r.Sync:
		return "sync = false"
	case r.Proof != nil && !*r.Proof:
		return "proof = false (this machine does not use the peer's proof plane)"
	case r.Log != nil && !*r.Log:
		return "log = false (this machine does not use the peer's operation log)"
	}
	return ""
}

type IdentityConfig struct {
	DID string `toml:"did" json:"did"`
}

type ContextConfig struct {
	Identity string `toml:"identity" json:"identity"`
	Relay    string `toml:"relay" json:"relay"`
}

type DefaultsConfig struct {
	CredentialTTL string `toml:"credential_ttl,omitempty" json:"credential_ttl,omitempty"`
}

// ResolvedContext is a fully resolved (identity, peer) pair, together with the
// mechanism each half came from. Carrying the source is what lets every signing
// site name its principal out loud instead of acting on an ambient default the
// operator cannot see.
type ResolvedContext struct {
	IdentityName   string
	IdentityDID    string
	IdentitySource string
	RelayName      string
	RelayURL       string
	RelaySource    string
}

// HasIdentity reports whether resolution produced an identity at all. A DID
// passed to --as needs no config registration, so a resolved identity may have
// a DID and no name.
func (r *ResolvedContext) HasIdentity() bool {
	return r != nil && (r.IdentityDID != "" || r.IdentityName != "")
}

// Principal is the human label for the resolved identity: its registered name
// when there is one, otherwise the bare DID.
func (r *ResolvedContext) Principal() string {
	if r == nil {
		return ""
	}
	if r.IdentityName != "" {
		return r.IdentityName
	}
	return r.IdentityDID
}

// The mechanisms of the resolution stack, in the spelling each is reported by.
// The canonical selectors are --as / DFOS_AS / default-identity for the
// identity and --relay / DFOS_RELAY / default-peer for the peer; the rest are
// compat aliases kept working at the tier of the mechanism they alias.
const (
	SourceFlagAs          = "--as"
	SourceFlagIdentity    = "--identity"
	SourceFlagRelay       = "--relay"
	SourceFlagPeer        = "--peer"
	SourceFlagCtx         = "--ctx"
	SourceEnvAs           = "DFOS_AS"
	SourceEnvIdentity     = "DFOS_IDENTITY"
	SourceEnvRelay        = "DFOS_RELAY"
	SourceEnvContext      = "DFOS_CONTEXT"
	SourceDefaultIdentity = "config default-identity"
	SourceDefaultPeer     = "config default-peer"
)

// Overrides carries the per-invocation selectors a command was given. One
// struct rather than positional strings so every signing site passes the same
// thing and no site can quietly grow a variant of the stack.
type Overrides struct {
	As       string // --as <name|did>
	Identity string // --identity, compat alias of --as
	Ctx      string // --ctx, compat alias naming an (identity, peer) pair
	Relay    string // --relay <name>
	Peer     string // --peer, compat alias of --relay
}

// candidate is one rung of the stack: a value and the mechanism that supplied it.
type candidate struct {
	value  string
	source string
}

func firstSet(candidates []candidate) (string, string) {
	for _, c := range candidates {
		if c.value != "" {
			return c.value, c.source
		}
	}
	return "", ""
}

// ConfigDir returns the dfos config directory, respecting DFOS_CONFIG env.
func ConfigDir() string {
	if v := os.Getenv("DFOS_CONFIG"); v != "" {
		return filepath.Dir(v)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".dfos")
}

// ConfigPath returns the path to config.toml.
func ConfigPath() string {
	if v := os.Getenv("DFOS_CONFIG"); v != "" {
		return v
	}
	return filepath.Join(ConfigDir(), "config.toml")
}

// checkConfigPath rejects a config path that names a directory, which is the
// one misconfiguration DFOS_CONFIG invites: everything on disk sits beside
// config.toml, so "point DFOS_CONFIG at a scratch directory" reads as naming
// the directory. The bare syscall error ("is a directory") says what went wrong
// and not what was expected, and the expectation is the whole answer.
func checkConfigPath() error {
	path := ConfigPath()
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return nil
	}
	if os.Getenv("DFOS_CONFIG") != "" {
		return fmt.Errorf("$DFOS_CONFIG must be the config FILE path (e.g. %s), got a directory: %s",
			filepath.Join(path, "config.toml"), path)
	}
	return fmt.Errorf("config path %s is a directory, not a file", path)
}

// Load loads config from disk. Returns empty config if file doesn't exist.
func Load() (*Config, error) {
	if err := checkConfigPath(); err != nil {
		return nil, err
	}
	cfg := &Config{
		Relays:     make(map[string]RelayConfig),
		Identities: make(map[string]IdentityConfig),
		Contexts:   make(map[string]ContextConfig),
	}

	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Relays == nil {
		cfg.Relays = make(map[string]RelayConfig)
	}
	if cfg.Identities == nil {
		cfg.Identities = make(map[string]IdentityConfig)
	}
	if cfg.Contexts == nil {
		cfg.Contexts = make(map[string]ContextConfig)
	}
	return cfg, nil
}

// Save writes config to disk.
func Save(cfg *Config) error {
	if err := checkConfigPath(); err != nil {
		return err
	}
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := toml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigPath(), data, 0o600)
}

// ResolveContext resolves the (identity, peer) pair for ONE invocation from
// flags, environment, and the static config defaults — in that order, and in
// that order only. There is no mutable pointer anywhere in the stack: two
// concurrent invocations carrying different --as values cannot disturb each
// other, because neither writes anything the other reads.
//
// The tiers are:
//
//	identity: --as → --identity → --ctx | DFOS_AS → DFOS_IDENTITY → DFOS_CONTEXT | default-identity
//	peer:     --relay → --peer → --ctx  | DFOS_RELAY → DFOS_CONTEXT              | default-peer
//
// --identity, --peer, --ctx, DFOS_IDENTITY, and DFOS_CONTEXT are compat aliases
// of the canonical selectors and sit at the tier of the mechanism they alias, so
// a flag alias still beats an env var and an env alias still beats the config.
func ResolveContext(cfg *Config, ov Overrides) (*ResolvedContext, error) {
	// The context spec names both halves in one token, so it is read ONCE —
	// from the flag if present, otherwise from the environment — and contributes
	// to both halves at that mechanism's tier. Reading both at once would let a
	// stale DFOS_CONTEXT half-override an explicit --ctx.
	ctxSpec, ctxSource := ov.Ctx, SourceFlagCtx
	if ctxSpec == "" {
		ctxSpec, ctxSource = os.Getenv(SourceEnvContext), SourceEnvContext
	}
	ctxIdentity, ctxPeer, err := splitContextSpec(cfg, ctxSpec)
	if err != nil {
		return nil, err
	}

	identityCands := []candidate{{ov.As, SourceFlagAs}, {ov.Identity, SourceFlagIdentity}}
	peerCands := []candidate{{ov.Relay, SourceFlagRelay}, {ov.Peer, SourceFlagPeer}}
	if ctxSource == SourceFlagCtx {
		identityCands = append(identityCands, candidate{ctxIdentity, SourceFlagCtx})
		peerCands = append(peerCands, candidate{ctxPeer, SourceFlagCtx})
	}
	identityCands = append(identityCands,
		candidate{os.Getenv(SourceEnvAs), SourceEnvAs},
		candidate{os.Getenv(SourceEnvIdentity), SourceEnvIdentity})
	peerCands = append(peerCands, candidate{os.Getenv(SourceEnvRelay), SourceEnvRelay})
	if ctxSource == SourceEnvContext {
		identityCands = append(identityCands, candidate{ctxIdentity, SourceEnvContext})
		peerCands = append(peerCands, candidate{ctxPeer, SourceEnvContext})
	}
	identityCands = append(identityCands, candidate{cfg.DefaultIdentity, SourceDefaultIdentity})
	peerCands = append(peerCands, candidate{cfg.DefaultPeer, SourceDefaultPeer})

	identity, identitySource := firstSet(identityCands)
	peer, peerSource := firstSet(peerCands)

	result := &ResolvedContext{
		IdentityName:   identity,
		IdentitySource: identitySource,
		RelayName:      peer,
		RelaySource:    peerSource,
	}

	// A selector is a name OR a DID. A DID needs no registration in config —
	// that is what makes --as usable against an identity this machine only knows
	// from the wire — so it resolves to itself, picking up a name if one happens
	// to be registered for it.
	if identity != "" {
		if id, ok := cfg.Identities[identity]; ok {
			result.IdentityDID = id.DID
		} else if strings.HasPrefix(identity, "did:") {
			result.IdentityDID = identity
			result.IdentityName = FindIdentityName(cfg, identity)
		}
	}

	if peer != "" {
		r, ok := cfg.Relays[peer]
		if !ok {
			return nil, fmt.Errorf("unknown peer: %s (from %s)", peer, peerSource)
		}
		result.RelayURL = r.URL
	}

	return result, nil
}

// splitContextSpec expands a --ctx / DFOS_CONTEXT token into its two halves: a
// named context, an inline identity@peer pair, or an identity on its own (local
// work with no peer).
func splitContextSpec(cfg *Config, spec string) (identity, peer string, err error) {
	if spec == "" {
		return "", "", nil
	}
	if ctx, ok := cfg.Contexts[spec]; ok {
		return ctx.Identity, ctx.Relay, nil
	}
	if parts := strings.SplitN(spec, "@", 2); len(parts) == 2 {
		return parts[0], parts[1], nil
	}
	if _, ok := cfg.Identities[spec]; ok {
		return spec, "", nil
	}
	if strings.HasPrefix(spec, "did:") {
		return spec, "", nil
	}
	return "", "", fmt.Errorf("unknown context: %s (not a named context, identity@peer pair, or known identity)", spec)
}

// FindIdentityName finds the name for a DID in config.
func FindIdentityName(cfg *Config, did string) string {
	for name, id := range cfg.Identities {
		if id.DID == did {
			return name
		}
	}
	return ""
}
