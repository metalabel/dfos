package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Config is the top-level configuration.
type Config struct {
	ActiveContext string                    `toml:"active_context,omitempty"`
	Relays       map[string]RelayConfig    `toml:"relays,omitempty"`
	Identities   map[string]IdentityConfig `toml:"identities,omitempty"`
	Contexts     map[string]ContextConfig  `toml:"contexts,omitempty"`
	Defaults     DefaultsConfig            `toml:"defaults,omitempty"`
}

type RelayConfig struct {
	URL         string `toml:"url"`
	DID         string `toml:"did,omitempty"`          // cached from well-known
	ProfileName string `toml:"profile_name,omitempty"` // cached from profile artifact
	Content     *bool  `toml:"content,omitempty"`      // cached capability
	Proof       *bool  `toml:"proof,omitempty"`        // cached capability
}

type IdentityConfig struct {
	DID string `toml:"did"`
}

type ContextConfig struct {
	Identity string `toml:"identity"`
	Relay    string `toml:"relay"`
}

type DefaultsConfig struct {
	AuthTokenTTL  string `toml:"auth_token_ttl,omitempty"`
	CredentialTTL string `toml:"credential_ttl,omitempty"`
}

// ResolvedContext is a fully resolved (identity, relay) pair.
type ResolvedContext struct {
	IdentityName string
	IdentityDID  string
	RelayName    string
	RelayURL     string
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

// ResolveContext resolves the active context from flags, env, and config.
func ResolveContext(cfg *Config, ctxFlag, identityFlag, relayFlag string) (*ResolvedContext, error) {
	// determine context name
	ctxName := ctxFlag
	if ctxName == "" {
		ctxName = os.Getenv("DFOS_CONTEXT")
	}
	if ctxName == "" {
		ctxName = cfg.ActiveContext
	}

	var identityName, relayName string

	// try explicit context definition first
	if ctxName != "" {
		if ctx, ok := cfg.Contexts[ctxName]; ok {
			identityName = ctx.Identity
			relayName = ctx.Relay
		} else if parts := strings.SplitN(ctxName, "@", 2); len(parts) == 2 {
			// inline context: identity@relay
			identityName = parts[0]
			relayName = parts[1]
		} else if _, ok := cfg.Identities[ctxName]; ok {
			// identity-only context (local work without a relay)
			identityName = ctxName
		} else {
			return nil, fmt.Errorf("unknown context: %s (not a named context, identity@relay pair, or known identity)", ctxName)
		}
	}

	// override with explicit flags/env (higher priority than context)
	if identityFlag != "" {
		identityName = identityFlag
	} else if v := os.Getenv("DFOS_IDENTITY"); v != "" {
		identityName = v
	}
	if relayFlag != "" {
		relayName = relayFlag
	} else if v := os.Getenv("DFOS_RELAY"); v != "" {
		relayName = v
	}

	result := &ResolvedContext{
		IdentityName: identityName,
		RelayName:    relayName,
	}

	// resolve identity DID
	if identityName != "" {
		if id, ok := cfg.Identities[identityName]; ok {
			result.IdentityDID = id.DID
		}
	}

	// resolve relay URL
	if relayName != "" {
		if r, ok := cfg.Relays[relayName]; ok {
			result.RelayURL = r.URL
		} else {
			return nil, fmt.Errorf("unknown relay: %s", relayName)
		}
	}

	return result, nil
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
