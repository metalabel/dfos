package localrelay

import (
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
)

// LocalRelay wraps a relay instance backed by a local SQLite database.
// This is the single integration point between the CLI and the relay library.
type LocalRelay struct {
	Relay    *relay.Relay
	Store    *relay.SQLiteStore
	RelayDID string // the auto-bootstrapped relay identity DID (invisible to user)
	dbPath   string
}

// Options configures the local relay. All fields are optional — sensible
// defaults are used when omitted.
type Options struct {
	DBPath      string             // override database path (default: ~/.dfos/relay.db)
	ProfileName string             // relay profile name (default: "DFOS CLI")
	ExtraPeers  []relay.PeerConfig // additional peers beyond config.toml
	Write       *bool              // nil/true = accept writes; false = LITE pull-only node
	Index       *bool              // nil/true = serve /index/v0; false = advertise false + 501
	Logger      *slog.Logger       // nil = relay's slog.Default(); CLI passes a quiet one
	// ContentFollow: "eager" = eagerly materialize the document bytes of content
	// chains this relay holds a standing public-read grant for (a follower / cache
	// node). "" or "none" = off (default). See relay.RelayOptions.ContentFollow.
	ContentFollow string
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

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// build peer configs from config.toml relay entries + extra peers
	peers := mergePeerConfigs(buildPeerConfigs(cfg), opts.ExtraPeers, logger)

	// wire up peer client if peers exist
	var peerClient relay.PeerClient
	if len(peers) > 0 {
		peerClient = relay.NewHttpPeerClient()
	}

	r, err := relay.NewRelay(relay.RelayOptions{
		Store:         store,
		Identity:      identity,
		Peers:         peers,
		PeerClient:    peerClient,
		Write:         opts.Write,
		Index:         opts.Index,
		Logger:        opts.Logger,
		ContentFollow: opts.ContentFollow,
	})
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("create relay: %w", err)
	}

	return &LocalRelay{Relay: r, Store: store, RelayDID: r.DID(), dbPath: dbPath}, nil
}

// DBPath returns the SQLite file backing this local relay.
func (lr *LocalRelay) DBPath() string {
	return lr.dbPath
}

// Vacuum compacts the SQLite file without exposing the relay library's private
// database handles. The relay's own driver registration is shared process-wide,
// so a short-lived connection can safely perform this one-shot maintenance.
func (lr *LocalRelay) Vacuum() error {
	db, err := sql.Open("sqlite", lr.dbPath)
	if err != nil {
		return fmt.Errorf("open SQLite maintenance connection: %w", err)
	}
	defer db.Close()
	if _, err := db.Exec("VACUUM"); err != nil {
		return fmt.Errorf("vacuum local relay: %w", err)
	}
	return nil
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

// normalizePeerURL is the identity of a peer for dedup purposes. It matches the
// normalization --peers / PEERS already applies (trim whitespace, then trailing
// slashes), so the same relay named in config.toml and on the command line
// resolves to one key regardless of which spelling each used.
func normalizePeerURL(url string) string {
	return strings.TrimRight(strings.TrimSpace(url), "/")
}

// mergePeerConfigs combines config.toml peers with explicitly supplied ones,
// keeping at most one entry per peer URL.
//
// A duplicate is not merely redundant. Peer state is keyed purely by URL — the
// sync cursor above all — so two entries for one relay share that cursor while
// pulling against it independently, and every push, read-through, and reconcile
// cadence tick for that relay happens twice. The duplicate is also the easiest
// misconfiguration to produce: name a relay in config.toml, then name it again
// in --peers to attach a per-peer flag to it.
//
// That last case is why the LATER definition wins: an explicitly supplied peer
// carries flags (gossip / readThrough / sync) that a config.toml entry cannot
// express, so keeping the config entry would silently discard the operator's
// intent and leave every flag at its default.
func mergePeerConfigs(configPeers, extraPeers []relay.PeerConfig, logger *slog.Logger) []relay.PeerConfig {
	merged := make([]relay.PeerConfig, 0, len(configPeers)+len(extraPeers))
	at := make(map[string]int, len(configPeers)+len(extraPeers))
	from := make(map[string]string, len(configPeers)+len(extraPeers))

	add := func(peer relay.PeerConfig, source string) {
		key := normalizePeerURL(peer.URL)
		if key == "" {
			return
		}
		if i, seen := at[key]; seen {
			logger.Warn("duplicate peer URL — the later definition wins",
				"peer", key,
				"dropped", from[key],
				"kept", source,
			)
			merged[i] = peer
			from[key] = source
			return
		}
		at[key] = len(merged)
		from[key] = source
		merged = append(merged, peer)
	}

	for _, peer := range configPeers {
		add(peer, "config")
	}
	for _, peer := range extraPeers {
		add(peer, "explicit")
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}
