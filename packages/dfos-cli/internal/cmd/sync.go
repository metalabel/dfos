package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/localrelay"
	"github.com/spf13/cobra"
)

// skippedPeer is one registered peer this run did not poll, and why.
type skippedPeer struct {
	Peer   string `json:"peer"`
	Reason string `json:"reason"`
}

// syncTargets splits the registered peers into the ones this run polls and the
// ones it skips. Both halves are reported: a skipped peer that said nothing is
// indistinguishable from a peer that had nothing to send, and the whole point
// of the switch is that the operator can see it took effect.
func syncTargets(cfg *config.Config) (targets []string, skipped []skippedPeer) {
	names := make([]string, 0, len(cfg.Relays))
	for name := range cfg.Relays {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if reason := config.BulkSyncDisabledReason(cfg.Relays[name]); reason != "" {
			skipped = append(skipped, skippedPeer{Peer: name, Reason: reason})
			continue
		}
		targets = append(targets, name)
	}
	return targets, skipped
}

// openSyncRelay opens the local relay for one sync run. A named peer narrows
// the peer set to that peer alone, so `sync --peer prod` pulls from prod and
// nothing else; an empty name takes every peer the switches allow.
func openSyncRelay(peerName string) (*localrelay.LocalRelay, error) {
	if peerName == "" {
		return getRelay()
	}
	// serve does the same dance: a command that needs its own relay options
	// closes whatever was lazily opened and owns the instance from there.
	if localRelayInstance != nil {
		localRelayInstance.Close()
		localRelayInstance = nil
	}
	// Gossip stays at its zero value — off. `sync` is a PULL: it takes the named
	// peer's log and sequences it locally. Forwarding what it just pulled on to
	// the rest of the mesh is a relay's job, and this machine is a relay only
	// while `dfos serve` is running.
	lr, err := localrelay.Open(cfg, &localrelay.Options{
		Logger:    quietRelayLogger(),
		OnlyPeers: []string{peerName},
	})
	if err != nil {
		return nil, fmt.Errorf("open local relay: %w", err)
	}
	localRelayInstance = lr // so PersistentPostRun closes it
	return lr, nil
}

func newSyncCmd() *cobra.Command {
	var peerName string
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Pull the operation log from configured peers",
		Long: "Pull operations from configured peers into the local relay and run them through the sequencer.\n\n" +
			"This is the bulk transfer: it takes the peer's whole log, not one chain. It runs against\n" +
			"every registered peer, or against one with --peer, and it skips any peer whose config says\n" +
			"not to poll it (`sync = false`, or a peer that advertises no proof plane or no log).\n" +
			"Explicit single-chain traffic — identity fetch, content fetch, publish, api call, login —\n" +
			"never runs through this command and is never gated by those switches.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// The peer here is an EXPLICIT argument, never a resolved one: a
			// default-peer in config would otherwise silently narrow `dfos sync`
			// from the whole mesh to one relay.
			if peerName != "" {
				if _, ok := cfg.Relays[peerName]; !ok {
					return fmt.Errorf("unknown peer: %s", peerName)
				}
				if reason := config.BulkSyncDisabledReason(cfg.Relays[peerName]); reason != "" {
					return fmt.Errorf("peer '%s' does not bulk-sync: %s in %s", peerName, reason, config.ConfigPath())
				}
			}

			targets, skipped := syncTargets(cfg)
			if peerName != "" {
				targets, skipped = []string{peerName}, nil
			}

			// The relay library pulls by URL, so the pin is checked here rather
			// than at a client the sync path never builds. A peer that changed
			// identity fails the RUN rather than being dropped to a skip line:
			// bulk sync is the unbounded ingest, and "the relay you follow is
			// not the relay you pinned" is not a routine condition to scroll
			// past. Naming another peer with --peer still works meanwhile.
			for _, name := range targets {
				if err := verifyPeerPin(name); err != nil {
					return err
				}
			}

			if len(targets) == 0 {
				status, message := "no_peers", "No peers configured. Use 'dfos peer add <name> <url>'"
				if len(skipped) > 0 {
					status = "all_peers_skipped"
					message = fmt.Sprintf("No peer bulk-syncs: %s", describeSkipped(skipped))
				}
				if jsonFlag {
					outputJSON(map[string]any{"peers": 0, "processed": 0, "skipped": skipped, "status": status})
					return nil
				}
				fmt.Println(message)
				return nil
			}

			lr, err := openSyncRelay(peerName)
			if err != nil {
				return err
			}

			if !jsonFlag {
				fmt.Printf("Syncing with %d peer(s): %s\n", len(targets), strings.Join(targets, ", "))
				if len(skipped) > 0 {
					fmt.Printf("Skipping %d peer(s): %s\n", len(skipped), describeSkipped(skipped))
				}
			}
			if err := lr.Relay.SyncFromPeers(); err != nil {
				return fmt.Errorf("sync failed: %w", err)
			}

			unsequenced, _ := lr.Store.CountUnsequenced()
			if unsequenced > 0 {
				if !jsonFlag {
					fmt.Printf("Processing %d pending operations...\n", unsequenced)
				}
				lr.Relay.RunSequencerAndGossip()
			}

			if jsonFlag {
				outputJSON(map[string]any{
					"peers":     len(targets),
					"synced":    targets,
					"skipped":   skipped,
					"processed": unsequenced,
					"status":    "complete",
				})
				return nil
			}
			fmt.Println("Sync complete.")
			return nil
		},
	}
	// A command-local --peer, shadowing the hidden persistent alias: on every
	// other command that flag names the peer to talk to and falls back through
	// the resolution stack; here it is a filter over the peer set with no
	// fallback tier at all.
	cmd.Flags().StringVar(&peerName, "peer", "", "Sync with this peer only (name)")
	return cmd
}

// describeSkipped renders the skipped peers as "name (reason), name (reason)".
func describeSkipped(skipped []skippedPeer) string {
	parts := make([]string, 0, len(skipped))
	for _, s := range skipped {
		parts = append(parts, fmt.Sprintf("%s (%s)", s.Peer, s.Reason))
	}
	return strings.Join(parts, ", ")
}
