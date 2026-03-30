package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	var port string
	var syncInterval string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start HTTP server on the local relay",
		Long:  "Expose your local relay over HTTP so other peers can sync with you. Your machine becomes a reachable node in the DFOS network.",
		RunE: func(cmd *cobra.Command, args []string) error {
			lr, err := getRelay()
			if err != nil {
				return err
			}

			interval, err := time.ParseDuration(syncInterval)
			if err != nil {
				return fmt.Errorf("invalid sync interval: %w", err)
			}

			fmt.Printf("DFOS relay serving\n")
			fmt.Printf("  DID:    %s\n", lr.Relay.DID())
			fmt.Printf("  Port:   %s\n", port)
			fmt.Printf("  Sync:   every %s\n", interval)

			peerCount := len(cfg.Relays)
			if peerCount > 0 {
				fmt.Printf("  Peers:  %d configured\n", peerCount)
				for name, r := range cfg.Relays {
					fmt.Printf("    - %s (%s)\n", name, r.URL)
				}
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// background sync loop
			go func() {
				// immediate first sync
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
	cmd.Flags().StringVar(&port, "port", "4444", "Port to listen on")
	cmd.Flags().StringVar(&syncInterval, "sync-interval", "30s", "Peer sync interval")
	return cmd
}
