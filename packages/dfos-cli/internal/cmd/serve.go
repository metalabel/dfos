package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/localrelay"
	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	var port string
	var syncInterval string
	var dbPath string
	var relayName string
	var peers string
	var resync bool

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start HTTP server on the local relay",
		Long: `Expose your local relay over HTTP so other peers can sync with you.
Your machine becomes a reachable node in the DFOS network.

All flags support environment variable fallbacks for container deployment:
  PORT, SQLITE_PATH, RELAY_NAME, PEERS, RESYNC, SYNC_INTERVAL`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// env-var fallbacks for container deployment
			if !cmd.Flags().Changed("port") {
				if v := os.Getenv("PORT"); v != "" {
					port = v
				}
			}
			if !cmd.Flags().Changed("db") {
				if v := os.Getenv("SQLITE_PATH"); v != "" {
					dbPath = v
				}
			}
			if !cmd.Flags().Changed("name") {
				if v := os.Getenv("RELAY_NAME"); v != "" {
					relayName = v
				}
			}
			if !cmd.Flags().Changed("peers") {
				if v := os.Getenv("PEERS"); v != "" {
					peers = v
				}
			}
			if !cmd.Flags().Changed("resync") {
				if os.Getenv("RESYNC") == "true" {
					resync = true
				}
			}
			if !cmd.Flags().Changed("sync-interval") {
				if v := os.Getenv("SYNC_INTERVAL"); v != "" {
					syncInterval = v
				}
			}

			interval, err := time.ParseDuration(syncInterval)
			if err != nil {
				return fmt.Errorf("invalid sync interval: %w", err)
			}

			// parse extra peers from flag/env (comma-separated URLs or JSON array)
			var extraPeers []string
			if peers != "" {
				extraPeers = parsePeerURLs(peers)
			}

			// open relay with serve-specific options
			opts := &localrelay.Options{
				DBPath:      dbPath,
				ProfileName: relayName,
				ExtraPeers:  extraPeers,
			}

			// close any existing lazy-opened relay (serve uses its own opts)
			if localRelayInstance != nil {
				localRelayInstance.Close()
				localRelayInstance = nil
			}

			lr, err := localrelay.Open(cfg, opts)
			if err != nil {
				return fmt.Errorf("open relay: %w", err)
			}
			localRelayInstance = lr // so PersistentPostRun closes it

			// resync on boot — reset peer cursors + sequencer for full re-pull
			if resync {
				fmt.Println("RESYNC — resetting peer cursors and sequencer")
				lr.Store.ResetPeerCursors()
				lr.Store.ResetSequencer()
			}

			fmt.Printf("DFOS relay serving\n")
			fmt.Printf("  DID:    %s\n", lr.Relay.DID())
			fmt.Printf("  Port:   %s\n", port)
			fmt.Printf("  Sync:   every %s\n", interval)

			peerCount := len(cfg.Relays) + len(extraPeers)
			if peerCount > 0 {
				fmt.Printf("  Peers:  %d configured\n", peerCount)
				for name, r := range cfg.Relays {
					fmt.Printf("    - %s (%s)\n", name, r.URL)
				}
				for _, u := range extraPeers {
					fmt.Printf("    - %s\n", u)
				}
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// background sync loop
			go func() {
				if err := lr.Relay.SyncFromPeers(); err != nil {
					fmt.Fprintf(os.Stderr, "sync error: %v\n", err)
				}
				ticker := time.NewTicker(interval)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						if err := lr.Relay.SyncFromPeers(); err != nil {
							fmt.Fprintf(os.Stderr, "sync error: %v\n", err)
						}
					}
				}
			}()

			// background sequencer
			go func() {
				ticker := time.NewTicker(interval)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						lr.Relay.RunSequencerAndGossip()
					}
				}
			}()

			srv := &http.Server{
				Addr:    ":" + port,
				Handler: lr.Relay.Handler(),
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
				return fmt.Errorf("server error: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&port, "port", "4444", "Port to listen on (env: PORT)")
	cmd.Flags().StringVar(&syncInterval, "sync-interval", "30s", "Peer sync interval (env: SYNC_INTERVAL)")
	cmd.Flags().StringVar(&dbPath, "db", "", "Database path (env: SQLITE_PATH, default: ~/.dfos/relay.db)")
	cmd.Flags().StringVar(&relayName, "name", "DFOS Relay", "Relay profile name (env: RELAY_NAME)")
	cmd.Flags().StringVar(&peers, "peers", "", "Comma-separated peer URLs or JSON array (env: PEERS)")
	cmd.Flags().BoolVar(&resync, "resync", false, "Reset peer cursors for full re-sync on boot (env: RESYNC)")
	return cmd
}

// parsePeerURLs parses a comma-separated list of URLs or a JSON array of URLs.
func parsePeerURLs(s string) []string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		var urls []string
		if json.Unmarshal([]byte(s), &urls) == nil {
			return urls
		}
	}
	var urls []string
	for _, u := range strings.Split(s, ",") {
		u = strings.TrimSpace(u)
		if u != "" {
			urls = append(urls, u)
		}
	}
	return urls
}
