package localrelay

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
)

// LocalRelay wraps a relay instance backed by a local SQLite database.
// This is the single integration point between the CLI and the relay library.
type LocalRelay struct {
	Relay    *relay.Relay
	Store    *relay.SQLiteStore
	RelayDID string // the auto-bootstrapped relay identity DID (invisible to user)
}

// Options configures the local relay. All fields are optional — sensible
// defaults are used when omitted.
type Options struct {
	DBPath      string       // override database path (default: ~/.dfos/relay.db)
	ProfileName string       // relay profile name (default: "DFOS CLI")
	ExtraPeers  []string     // additional peer URLs beyond config.toml
}

// Open opens (or creates) the local relay database and bootstraps the relay
// identity. Peer configuration is derived from config.toml relay entries
// plus any extra peers in opts.
func Open(cfg *config.Config, opts *Options) (*LocalRelay, error) {
	if opts == nil {
		opts = &Options{}
	}

	dbPath := opts.DBPath
	if dbPath == "" {
		dbPath = filepath.Join(config.ConfigDir(), "relay.db")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	store, err := relay.NewSQLiteStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open relay store: %w", err)
	}

	// auto-migrate legacy flat-file store if present
	if err := MigrateIfNeeded(store); err != nil {
		store.Close()
		return nil, fmt.Errorf("migration: %w", err)
	}

	profileName := opts.ProfileName
	if profileName == "" {
		profileName = "DFOS CLI"
	}

	// persistent bootstrap — reuse existing key material or generate new
	identity, err := bootstrapPersistent(store, profileName)
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("bootstrap: %w", err)
	}

	// build peer configs from config.toml relay entries + extra peers
	peers := buildPeerConfigs(cfg)
	for _, url := range opts.ExtraPeers {
		if url != "" {
			peers = append(peers, relay.PeerConfig{URL: url})
		}
	}

	// wire up peer client if peers exist
	var peerClient relay.PeerClient
	if len(peers) > 0 {
		peerClient = relay.NewHttpPeerClient()
	}

	r, err := relay.NewRelay(relay.RelayOptions{
		Store:      store,
		Identity:   identity,
		Peers:      peers,
		PeerClient: peerClient,
	})
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("create relay: %w", err)
	}

	return &LocalRelay{Relay: r, Store: store, RelayDID: r.DID()}, nil
}

// Close closes the local relay database.
func (lr *LocalRelay) Close() error {
	return lr.Store.Close()
}

// bootstrapPersistent loads existing relay key material from SQLite or generates
// new keys and persists them. The relay identity is invisible to the user.
func bootstrapPersistent(store *relay.SQLiteStore, profileName string) (*relay.RelayIdentity, error) {
	privBytes, err := store.GetMeta("relay_private_key")
	if err != nil {
		return nil, fmt.Errorf("read relay_private_key: %w", err)
	}
	keyIDBytes, err := store.GetMeta("relay_key_id")
	if err != nil {
		return nil, fmt.Errorf("read relay_key_id: %w", err)
	}
	didBytes, err := store.GetMeta("relay_did")
	if err != nil {
		return nil, fmt.Errorf("read relay_did: %w", err)
	}

	if privBytes != nil && keyIDBytes != nil && didBytes != nil {
		if len(privBytes) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("corrupted relay key material: expected %d bytes, got %d", ed25519.PrivateKeySize, len(privBytes))
		}
		// reuse existing identity — load cached profile artifact from meta.
		// If no cached profile (upgrade from older version), sign once and cache.
		profileJWS := ""
		if profileBytes, err := store.GetMeta("relay_profile_jws"); err == nil && profileBytes != nil {
			profileJWS = string(profileBytes)
		}
		if profileJWS == "" {
			// one-time re-sign for upgrade path
			priv := ed25519.PrivateKey(privBytes)
			keyID := string(keyIDBytes)
			did := string(didBytes)
			identity, err := relay.RebootstrapProfile(store, priv, keyID, did, relay.ProfileConfig{Name: profileName})
			if err != nil {
				return nil, fmt.Errorf("rebootstrap profile: %w", err)
			}
			store.SetMeta("relay_profile_jws", []byte(identity.ProfileArtifactJWS))
			return identity, nil
		}
		return &relay.RelayIdentity{
			DID:                string(didBytes),
			KeyID:              string(keyIDBytes),
			ProfileArtifactJWS: profileJWS,
		}, nil
	}

	// first boot — generate new relay identity
	profile := relay.ProfileConfig{Name: profileName}
	identity, err := relay.BootstrapRelayIdentityWithProfile(store, profile)
	if err != nil {
		return nil, err
	}

	// persist key material
	if err := store.SetMeta("relay_private_key", identity.PrivateKey); err != nil {
		return nil, fmt.Errorf("persist relay_private_key: %w", err)
	}
	if err := store.SetMeta("relay_key_id", []byte(identity.KeyID)); err != nil {
		return nil, fmt.Errorf("persist relay_key_id: %w", err)
	}
	if err := store.SetMeta("relay_did", []byte(identity.DID)); err != nil {
		return nil, fmt.Errorf("persist relay_did: %w", err)
	}
	if err := store.SetMeta("relay_profile_jws", []byte(identity.ProfileArtifactJWS)); err != nil {
		return nil, fmt.Errorf("persist relay_profile_jws: %w", err)
	}

	return identity, nil
}

// buildPeerConfigs converts config.toml relay entries into relay PeerConfig
// structs. All configured relays become peers with default settings.
func buildPeerConfigs(cfg *config.Config) []relay.PeerConfig {
	var peers []relay.PeerConfig
	for _, r := range cfg.Relays {
		if r.URL != "" {
			peers = append(peers, relay.PeerConfig{URL: r.URL})
		}
	}
	return peers
}
