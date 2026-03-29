package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
)

func main() {
	port := envOr("PORT", "8080")
	storeType := envOr("STORE", "sqlite")
	dbPath := envOr("SQLITE_PATH", "/data/relay.db")
	relayName := envOr("RELAY_NAME", "DFOS Relay")
	relayDescription := os.Getenv("RELAY_DESCRIPTION")
	peersEnv := os.Getenv("PEERS")
	resyncOnBoot := os.Getenv("RESYNC") == "true"
	syncIntervalStr := envOr("SYNC_INTERVAL", "30s")

	syncInterval, err := time.ParseDuration(syncIntervalStr)
	if err != nil {
		log.Fatalf("invalid SYNC_INTERVAL %q: %v", syncIntervalStr, err)
	}

	// open store
	var store relay.Store
	var sqliteStore *relay.SQLiteStore
	profile := relay.ProfileConfig{
		Name:        relayName,
		Description: relayDescription,
	}

	switch storeType {
	case "memory":
		memStore := relay.NewMemoryStore()
		store = memStore
		fmt.Println("Using in-memory store")
	default:
		s, err := relay.NewSQLiteStore(dbPath)
		if err != nil {
			log.Fatalf("failed to open SQLite store at %s: %v", dbPath, err)
		}
		defer s.Close()
		sqliteStore = s
		store = s
		fmt.Printf("Using SQLite store at %s\n", dbPath)
	}

	// bootstrap relay identity
	var identity *relay.RelayIdentity
	if sqliteStore != nil {
		identity, err = bootstrapPersistent(sqliteStore, profile)
	} else {
		identity, err = relay.BootstrapRelayIdentityWithProfile(store, profile)
	}
	if err != nil {
		log.Fatalf("bootstrap failed: %v", err)
	}

	// parse peers
	peers := parsePeers(peersEnv)

	// wire up peer client if peers are configured
	var peerClient relay.PeerClient
	if len(peers) > 0 {
		peerClient = relay.NewHttpPeerClient()
	}

	// create relay
	r, err := relay.NewRelay(relay.RelayOptions{
		Store:        store,
		Identity:     identity,
		Peers:        peers,
		PeerClient:   peerClient,
		ResyncOnBoot: resyncOnBoot,
	})
	if err != nil {
		log.Fatalf("failed to create relay: %v", err)
	}

	// resync on boot: reset peer cursors + sequencer so first sync is a full pull
	if resyncOnBoot {
		fmt.Println("RESYNC=true — resetting peer cursors and sequencer for full re-sync")
		store.ResetPeerCursors()
		store.ResetSequencer()
	}

	// log startup
	fmt.Printf("DFOS relay started\n")
	fmt.Printf("  DID:    %s\n", r.DID())
	fmt.Printf("  Port:   %s\n", port)
	if sqliteStore != nil {
		fmt.Printf("  Store:  %s\n", dbPath)
	} else {
		fmt.Printf("  Store:  memory\n")
	}
	fmt.Printf("  Name:   %s\n", relayName)
	if len(peers) > 0 {
		fmt.Printf("  Peers:  %d configured\n", len(peers))
		for _, p := range peers {
			fmt.Printf("    - %s\n", p.URL)
		}
		fmt.Printf("  Sync:   every %s\n", syncInterval)
	}

	// start sync + sequencer tickers
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if len(peers) > 0 && peerClient != nil {
		go syncLoop(ctx, r, syncInterval)
	}

	// background sequencer — processes unsequenced raw ops on a timer
	go sequencerLoop(ctx, r, syncInterval)

	// start HTTP server with graceful shutdown
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: r.Handler(),
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Println("\nshutting down...")
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		srv.Shutdown(shutdownCtx)
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

// bootstrapPersistent loads existing key material from SQLite or generates new
// keys, persists them, and bootstraps the relay identity.
func bootstrapPersistent(store *relay.SQLiteStore, profile relay.ProfileConfig) (*relay.RelayIdentity, error) {
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
		// existing key material — sign fresh profile artifact, reuse DID
		priv := ed25519.PrivateKey(privBytes)
		keyID := string(keyIDBytes)
		did := string(didBytes)
		fmt.Printf("Loaded existing relay identity: %s\n", did)
		return relay.RebootstrapProfile(store, priv, keyID, did, profile)
	}

	// first boot — generate new keys
	fmt.Println("First boot — generating new relay identity")
	identity, err := relay.BootstrapRelayIdentityWithProfile(store, profile)
	if err != nil {
		return nil, err
	}

	// persist key material and DID
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

// parsePeers parses the PEERS env var. Supports comma-separated URLs or a JSON
// array of PeerConfig objects.
func parsePeers(env string) []relay.PeerConfig {
	env = strings.TrimSpace(env)
	if env == "" {
		return nil
	}

	// JSON array
	if strings.HasPrefix(env, "[") {
		var peers []relay.PeerConfig
		if err := json.Unmarshal([]byte(env), &peers); err != nil {
			log.Fatalf("failed to parse PEERS as JSON: %v", err)
		}
		return peers
	}

	// comma-separated URLs — all defaults
	var peers []relay.PeerConfig
	for _, raw := range strings.Split(env, ",") {
		u := strings.TrimSpace(raw)
		if u != "" {
			peers = append(peers, relay.PeerConfig{URL: u})
		}
	}
	return peers
}

// syncLoop runs SyncFromPeers on a ticker until ctx is cancelled.
func syncLoop(ctx context.Context, r *relay.Relay, interval time.Duration) {
	// immediate first sync
	if err := r.SyncFromPeers(); err != nil {
		fmt.Printf("sync error: %v\n", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.SyncFromPeers(); err != nil {
				fmt.Printf("sync error: %v\n", err)
			}
		}
	}
}

// sequencerLoop runs the sequencer on a ticker to process unsequenced raw ops.
func sequencerLoop(ctx context.Context, r *relay.Relay, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.RunSequencerAndGossip()
		}
	}
}

func envOr(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}
