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

type RelayConfig struct {
	URL         string `toml:"url" json:"url"`
	DID         string `toml:"did,omitempty" json:"did,omitempty"`                   // cached from well-known
	ProfileName string `toml:"profile_name,omitempty" json:"profile_name,omitempty"` // cached from profile artifact
	Content     *bool  `toml:"content,omitempty" json:"content,omitempty"`           // cached capability
	Proof       *bool  `toml:"proof,omitempty" json:"proof,omitempty"`               // cached capability
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

// Load loads config from disk. Returns empty config if file doesn't exist.
func Load() (*Config, error) {
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
