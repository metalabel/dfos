package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/localrelay"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
	"github.com/spf13/cobra"
)

// contentReconcileIntervalMultiple sets the content-follow backstop cadence as a
// multiple of the sync interval. Per-tick materialization/GC is event-driven (the
// sequencer marks dirty contentIDs; trigger-kicks drain them), so this whole-corpus
// reconcile is only defense-in-depth against a missed mark — it runs deliberately
// slowly so a steady-state follower stays idle between real changes instead of
// re-scanning every chain and re-verifying every grant on each tick.
const contentReconcileIntervalMultiple = 60

func newServeCmd() *cobra.Command {
	var port string
	var syncInterval string
	var dbPath string
	var relayName string
	var peers string
	var resync bool
	var noWrite bool
	var contentFollow string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start HTTP server on the local relay",
		Long: `Expose your local relay over HTTP so other peers can sync with you.
Your machine becomes a reachable node in the DFOS network.

All flags support environment variable fallbacks for container deployment:
  PORT, SQLITE_PATH, RELAY_NAME, PEERS, RESYNC, SYNC_INTERVAL, CONTENT_FOLLOW`,
		// A long-lived daemon must not hold the process-wide state lock (it
		// would block every other dfos invocation for its entire run).
		Annotations: map[string]string{annNoStateLock: "true"},
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
			if !cmd.Flags().Changed("content-follow") {
				if v := os.Getenv("CONTENT_FOLLOW"); v != "" {
					contentFollow = v
				}
			}

			interval, err := time.ParseDuration(syncInterval)
			if err != nil {
				return fmt.Errorf("invalid sync interval: %w", err)
			}

			// content-follow accepts none|eager today ("lazy" is reserved). Reject
			// anything else loudly rather than silently disabling on a typo.
			switch contentFollow {
			case "", "none", "eager":
			default:
				return fmt.Errorf("invalid --content-follow %q (expected: none|eager)", contentFollow)
			}

			// parse extra peers from flag/env (comma-separated URLs or JSON array)
			var extraPeers []string
			if peers != "" {
				extraPeers = parsePeerURLs(peers)
			}

			// set up structured JSON logging for server mode
			slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			})))

			// open relay with serve-specific options
			opts := &localrelay.Options{
				DBPath:        dbPath,
				ProfileName:   relayName,
				ExtraPeers:    extraPeers,
				ContentFollow: contentFollow,
			}
			// LITE pull-only node: reject POST /operations, sync from peers only.
			if noWrite {
				writeDisabled := false
				opts.Write = &writeDisabled
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

			fmt.Printf("DFOS relay serving (%s)\n", relay.Version)
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

			if contentFollow == "eager" {
				// Fast drain (eager mode only): every tick, drain whatever the
				// sequencer marked dirty. The sweeps are near-instant no-ops when the
				// queues are empty (a TryLock + empty-queue check, never a corpus
				// scan), so running them every tick is cheap AND robust — it drains
				// marks made by ANY sequencing path: a peer pull, a gossip-push receive,
				// or a direct client write. A sequence-count-gated trigger missed the
				// last two because those ops are already sequenced before the next tick.
				go func() {
					ticker := time.NewTicker(interval)
					defer ticker.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
							lr.Relay.MaterializeFollowedContent()
							lr.Relay.GCRevokedContent()
						}
					}
				}()

				// Convergent backstop: a boot pass catches up every grant/revocation
				// already synced before the process started, then a slow periodic full
				// reconcile (contentReconcileIntervalMultiple) guarantees convergence
				// regardless of which dirty marks the fast path recorded. Deliberately
				// slow defense-in-depth — a steady-state follower stays idle between
				// real changes. Sequencer-independent: it only acts on chains already in
				// local state, so op-ingest ordering can't race it.
				go func() {
					lr.Relay.ReconcileFollowedContent()
					ticker := time.NewTicker(interval * contentReconcileIntervalMultiple)
					defer ticker.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
							lr.Relay.ReconcileFollowedContent()
						}
					}
				}()
			}

			srv := &http.Server{
				Addr:    ":" + port,
				Handler: lr.Relay.Handler(),
				// Slowloris guard: bound how long a client may take to send the
				// request headers, and how long an idle keep-alive connection
				// may linger. NOT setting ReadTimeout/WriteTimeout — large blob
				// uploads and long /log reads are legitimately slow, and a tight
				// write deadline would truncate them.
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       120 * time.Second,
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
	cmd.Flags().BoolVar(&noWrite, "no-write", false, "LITE pull-only node: reject POST /operations, sync from peers only")
	cmd.Flags().StringVar(&contentFollow, "content-follow", "none", "Materialize granted public content blobs from peers: none|eager (env: CONTENT_FOLLOW)")
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
