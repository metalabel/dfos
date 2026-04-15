package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/keystore"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/localrelay"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
	"github.com/spf13/cobra"
)

var (
	// persistent flags
	ctxFlag      string
	identityFlag string
	peerFlag     string
	jsonFlag     bool
	yesFlag      bool

	// shared state
	cfg     *config.Config
	keys    keystore.Store
	Version = "dev"

	// lazy-initialized local relay
	localRelayInstance *localrelay.LocalRelay
)

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "dfos",
		Short: "DFOS CLI — local-first relay node for the DFOS protocol",
		Long:  "Command-line interface for the DFOS protocol. Your machine is a relay. Manage identities, content chains, beacons, and credentials. Sync with peers.",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			cfg, err = config.Load()
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			keys = keystore.New()
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if localRelayInstance != nil {
				localRelayInstance.Close()
			}
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&ctxFlag, "ctx", "", "Context (identity@peer)")
	root.PersistentFlags().StringVar(&identityFlag, "identity", "", "Identity name override")
	root.PersistentFlags().StringVar(&peerFlag, "peer", "", "Peer name override")
	root.PersistentFlags().BoolVar(&jsonFlag, "json", false, "Output as JSON")
	root.PersistentFlags().BoolVar(&yesFlag, "yes", false, "Auto-confirm prompts")

	// command groups
	identityGroup := &cobra.Group{ID: "identity", Title: "Identity Commands"}
	contentGroup := &cobra.Group{ID: "content", Title: "Content Commands"}
	beaconGroup := &cobra.Group{ID: "beacon", Title: "Beacon Commands"}
	authGroup := &cobra.Group{ID: "auth", Title: "Auth Commands"}
	peerGroup := &cobra.Group{ID: "peer", Title: "Peer Commands"}
	configGroup := &cobra.Group{ID: "config", Title: "Config Commands"}

	root.AddGroup(identityGroup, contentGroup, beaconGroup, authGroup, peerGroup, configGroup)

	root.AddCommand(newVersionCmd())
	root.AddCommand(newStatusCmd())
	root.AddCommand(newUseCmd())
	root.AddCommand(newIdentityCmd())
	root.AddCommand(newContentCmd())
	root.AddCommand(newCredentialCmd())
	root.AddCommand(newBeaconCmd())
	root.AddCommand(newWitnessCmd())
	root.AddCommand(newCountersigsCmd())
	root.AddCommand(newAuthCmd())
	root.AddCommand(newPeerCmd())
	root.AddCommand(newAPICmd())
	root.AddCommand(newConfigCmd())
	root.AddCommand(newServeCmd())
	root.AddCommand(newSyncCmd())

	return root
}

// getRelay returns the lazily-initialized local relay.
func getRelay() (*localrelay.LocalRelay, error) {
	if localRelayInstance != nil {
		return localRelayInstance, nil
	}
	var err error
	localRelayInstance, err = localrelay.Open(cfg, nil)
	if err != nil {
		return nil, fmt.Errorf("open local relay: %w", err)
	}
	return localRelayInstance, nil
}

// resolveCtx resolves the current context from flags/env/config.
func resolveCtx() (*config.ResolvedContext, error) {
	return config.ResolveContext(cfg, ctxFlag, identityFlag, peerFlag)
}

// requirePeer resolves context and ensures a peer is configured.
func requirePeer(peerOverride string) (*config.ResolvedContext, *client.Client, error) {
	r := peerOverride
	if r == "" {
		r = peerFlag
	}
	ctx, err := config.ResolveContext(cfg, ctxFlag, identityFlag, r)
	if err != nil {
		return nil, nil, err
	}
	if ctx.RelayURL == "" {
		return nil, nil, fmt.Errorf("no peer configured. Use --peer or 'dfos peer add'")
	}
	return ctx, client.New(ctx.RelayURL), nil
}

// requireIdentity resolves and ensures an identity is available in the local relay.
func requireIdentity() (*config.ResolvedContext, *relay.StoredIdentityChain, error) {
	ctx, err := resolveCtx()
	if err != nil {
		return nil, nil, err
	}
	if ctx.IdentityName == "" {
		return nil, nil, fmt.Errorf("no identity configured. Use --identity or 'dfos identity create'")
	}

	lr, err := getRelay()
	if err != nil {
		return nil, nil, err
	}

	// resolve DID from config
	did := ctx.IdentityDID
	if did == "" {
		return nil, nil, fmt.Errorf("identity '%s' not found in config", ctx.IdentityName)
	}

	chain, err := lr.Relay.GetIdentity(did)
	if err != nil {
		return nil, nil, err
	}
	if chain == nil {
		return nil, nil, fmt.Errorf("identity '%s' (%s) not found in local relay", ctx.IdentityName, did)
	}
	if chain.State.IsDeleted {
		return nil, nil, fmt.Errorf("identity '%s' is deleted — cannot sign operations", ctx.IdentityName)
	}
	return ctx, chain, nil
}

// outputJSON outputs a value as JSON.
func outputJSON(v any) {
	data, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(data))
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version info",
		Run: func(cmd *cobra.Command, args []string) {
			if jsonFlag {
				outputJSON(map[string]string{"version": Version})
			} else {
				fmt.Printf("dfos version %s\n", Version)
			}
		},
	}
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show current context, identity, and relay status",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, _ := resolveCtx()

			status := map[string]any{}

			if ctx != nil && ctx.IdentityName != "" {
				lr, relayErr := getRelay()

				var chain *relay.StoredIdentityChain
				if relayErr == nil && ctx.IdentityDID != "" {
					chain, _ = lr.Relay.GetIdentity(ctx.IdentityDID)
				}

				contextStr := ""
				if ctx.IdentityName != "" && ctx.RelayName != "" {
					contextStr = ctx.IdentityName + "@" + ctx.RelayName
				} else if ctx.IdentityName != "" {
					contextStr = ctx.IdentityName + " (local only)"
				}

				if jsonFlag {
					status["context"] = contextStr
					status["identity"] = ctx.IdentityDID
					status["identityName"] = ctx.IdentityName
					status["peer"] = ctx.RelayURL
					status["peerName"] = ctx.RelayName
					if chain != nil {
						status["operations"] = len(chain.Log)
					}
					outputJSON(status)
					return nil
				}

				fmt.Printf("Context:   %s\n", contextStr)
				if chain != nil {
					fmt.Printf("Identity:  %s (%s)\n", chain.DID, ctx.IdentityName)
					totalKeys := len(chain.State.AuthKeys) + len(chain.State.ControllerKeys) + len(chain.State.AssertKeys)
					haveKeys := countKeysInChain(chain)
					fmt.Printf("  Keys:    %d/%d (%s)\n", haveKeys, totalKeys, keys.Backend())
					fmt.Printf("  Chain:   %d operation(s)\n", len(chain.Log))
				} else {
					fmt.Printf("Identity:  %s (%s) — not in local relay\n", ctx.IdentityDID, ctx.IdentityName)
				}
			} else {
				if jsonFlag {
					status["context"] = nil
					status["identity"] = nil
					outputJSON(status)
					return nil
				}
				fmt.Println("No active context. Use 'dfos use <identity@peer>' or 'dfos identity create'")
			}

			if ctx != nil && ctx.RelayURL != "" {
				c := client.New(ctx.RelayURL)
				info, err := c.GetRelayInfo()
				if !jsonFlag {
					label := ctx.RelayURL
					if r, ok := cfg.Relays[ctx.RelayName]; ok && r.ProfileName != "" {
						label = r.ProfileName + " (" + ctx.RelayURL + ")"
					}
					fmt.Printf("Peer:      %s\n", label)
					if err == nil {
						fmt.Printf("  DID:     %s\n", info.DID)
						fmt.Printf("  Version: %s %s\n", info.Protocol, info.Version)
						fmt.Printf("  Content: %s  Proof: %s\n", boolYesNo(info.Content), boolYesNo(info.Proof))
					} else {
						fmt.Printf("  Error:   %s\n", err)
					}
				}
			}
			return nil
		},
	}
}

func newUseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use <identity[@peer]>",
		Short: "Set active context (identity or identity@peer)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := args[0]

			// validate components exist in config
			if _, ok := cfg.Contexts[ctx]; !ok {
				if parts := strings.SplitN(ctx, "@", 2); len(parts) == 2 {
					// identity@relay format
					if _, ok := cfg.Identities[parts[0]]; !ok {
						fmt.Fprintf(os.Stderr, "Warning: identity '%s' not found in config\n", parts[0])
					}
					if _, ok := cfg.Relays[parts[1]]; !ok {
						fmt.Fprintf(os.Stderr, "Warning: relay '%s' not found in config\n", parts[1])
					}
				} else {
					// identity-only (local work without a relay)
					if _, ok := cfg.Identities[ctx]; !ok {
						fmt.Fprintf(os.Stderr, "Warning: identity '%s' not found in config\n", ctx)
					}
				}
			}

			cfg.ActiveContext = ctx
			if err := config.Save(cfg); err != nil {
				return err
			}
			fmt.Printf("Active context set to: %s\n", ctx)
			return nil
		},
	}
}

// helpers

// didFromKid extracts the DID from a KID string (did:dfos:abc#key_123 → did:dfos:abc).
// Returns the full kid if no '#' separator is found.
func didFromKid(kid string) string {
	if idx := strings.Index(kid, "#"); idx > 0 {
		return kid[:idx]
	}
	return kid
}

func countKeysInChain(chain *relay.StoredIdentityChain) int {
	count := 0
	allKeys := append(append(chain.State.AuthKeys, chain.State.ControllerKeys...), chain.State.AssertKeys...)
	for _, k := range allKeys {
		account := chain.DID + "#" + k.ID
		if keys.HasKey(account) {
			count++
		}
	}
	return count
}

func joinComma(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += ", "
		}
		result += s
	}
	return result
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
