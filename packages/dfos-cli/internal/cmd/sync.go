package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newSyncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Sync with all configured peers",
		Long:  "Pull operations from all configured peers and process them through the local relay sequencer.",
		RunE: func(cmd *cobra.Command, args []string) error {
			lr, err := getRelay()
			if err != nil {
				return err
			}

			peerCount := len(cfg.Relays)
			if peerCount == 0 {
				fmt.Println("No peers configured. Use 'dfos peer add <name> <url>'")
				return nil
			}

			fmt.Printf("Syncing with %d peer(s)...\n", peerCount)
			if err := lr.Relay.SyncFromPeers(); err != nil {
				return fmt.Errorf("sync failed: %w", err)
			}

			unsequenced, _ := lr.Store.CountUnsequenced()
			if unsequenced > 0 {
				fmt.Printf("Processing %d pending operations...\n", unsequenced)
				lr.Relay.RunSequencerAndGossip()
			}

			fmt.Println("Sync complete.")
			return nil
		},
	}
}
