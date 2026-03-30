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
	Relay *relay.Relay
	Store *relay.SQLiteStore
}

// Open opens (or creates) the local relay database and bootstraps the relay
// identity. Peer configuration is derived from config.toml relay entries.
func Open(cfg *config.Config) (*LocalRelay, error) {
	dbPath := filepath.Join(config.ConfigDir(), "relay.db")
	if err := os.MkdirAll(config.ConfigDir(), 0o700); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
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

	// persistent bootstrap — reuse existing key material or generate new
	identity, err := bootstrapPersistent(store)
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("bootstrap: %w", err)
	}

	// build peer configs from config.toml relay entries
	peers := buildPeerConfigs(cfg)

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

	return &LocalRelay{Relay: r, Store: store}, nil
}

// Close closes the local relay database.
func (lr *LocalRelay) Close() error {
	return lr.Store.Close()
}

// bootstrapPersistent loads existing relay key material from SQLite or generates
// new keys and persists them. The relay identity is invisible to the user.
func bootstrapPersistent(store *relay.SQLiteStore) (*relay.RelayIdentity, error) {
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

	profile := relay.ProfileConfig{Name: "DFOS CLI"}

	if privBytes != nil && keyIDBytes != nil && didBytes != nil {
		priv := ed25519.PrivateKey(privBytes)
		keyID := string(keyIDBytes)
		did := string(didBytes)
		return relay.RebootstrapProfile(store, priv, keyID, did, profile)
	}

	// first boot — generate new relay identity
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
