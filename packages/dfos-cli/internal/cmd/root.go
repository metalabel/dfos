package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/keystore"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/store"
	"github.com/spf13/cobra"
)

var (
	// persistent flags
	ctxFlag      string
	identityFlag string
	relayFlag    string
	jsonFlag     bool
	yesFlag      bool

	// shared state
	cfg   *config.Config
	keys  keystore.Store
	Version = "dev"
)

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "dfos",
		Short: "DFOS CLI — interact with DFOS protocol relays",
		Long:  "Command-line interface for the DFOS protocol. Manage identities, content chains, beacons, and credentials. Interact with relays.",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			cfg, err = config.Load()
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			keys = keystore.New()
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&ctxFlag, "ctx", "", "Context (identity@relay)")
	root.PersistentFlags().StringVar(&identityFlag, "identity", "", "Identity name override")
	root.PersistentFlags().StringVar(&relayFlag, "relay", "", "Relay name override")
	root.PersistentFlags().BoolVar(&jsonFlag, "json", false, "Output as JSON")
	root.PersistentFlags().BoolVar(&yesFlag, "yes", false, "Auto-confirm prompts")

	// command groups
	identityGroup := &cobra.Group{ID: "identity", Title: "Identity Commands"}
	contentGroup := &cobra.Group{ID: "content", Title: "Content Commands"}
	beaconGroup := &cobra.Group{ID: "beacon", Title: "Beacon Commands"}
	authGroup := &cobra.Group{ID: "auth", Title: "Auth Commands"}
	relayGroup := &cobra.Group{ID: "relay", Title: "Relay Commands"}
	configGroup := &cobra.Group{ID: "config", Title: "Config Commands"}

	root.AddGroup(identityGroup, contentGroup, beaconGroup, authGroup, relayGroup, configGroup)

	root.AddCommand(newVersionCmd())
	root.AddCommand(newStatusCmd())
	root.AddCommand(newUseCmd())
	root.AddCommand(newIdentityCmd())
	root.AddCommand(newContentCmd())
	root.AddCommand(newBeaconCmd())
	root.AddCommand(newWitnessCmd())
	root.AddCommand(newCountersigsCmd())
	root.AddCommand(newAuthCmd())
	root.AddCommand(newRelayCmd())
	root.AddCommand(newAPICmd())
	root.AddCommand(newConfigCmd())

	return root
}

// resolveCtx resolves the current context from flags/env/config.
func resolveCtx() (*config.ResolvedContext, error) {
	return config.ResolveContext(cfg, ctxFlag, identityFlag, relayFlag)
}

// requireRelay resolves context and ensures a relay is configured.
func requireRelay(relayOverride string) (*config.ResolvedContext, *client.Client, error) {
	r := relayOverride
	if r == "" {
		r = relayFlag
	}
	ctx, err := config.ResolveContext(cfg, ctxFlag, identityFlag, r)
	if err != nil {
		return nil, nil, err
	}
	if ctx.RelayURL == "" {
		return nil, nil, fmt.Errorf("no relay configured. Use --relay or 'dfos relay add'")
	}
	return ctx, client.New(ctx.RelayURL), nil
}

// requireIdentity resolves and ensures an identity is available.
func requireIdentity() (*config.ResolvedContext, *store.StoredIdentity, error) {
	ctx, err := resolveCtx()
	if err != nil {
		return nil, nil, err
	}
	if ctx.IdentityName == "" {
		return nil, nil, fmt.Errorf("no identity configured. Use --identity or 'dfos identity create'")
	}

	id, err := store.FindIdentityByName(ctx.IdentityName)
	if err != nil {
		return nil, nil, err
	}
	if id == nil {
		// try by DID
		if ctx.IdentityDID != "" {
			id, err = store.LoadIdentity(ctx.IdentityDID)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	if id == nil {
		return nil, nil, fmt.Errorf("identity '%s' not found in local store", ctx.IdentityName)
	}
	if id.State.IsDeleted {
		return nil, nil, fmt.Errorf("identity '%s' is deleted — cannot sign operations", ctx.IdentityName)
	}
	return ctx, id, nil
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
				id, _ := store.FindIdentityByName(ctx.IdentityName)
				contextStr := ""
				if ctx.IdentityName != "" && ctx.RelayName != "" {
					contextStr = ctx.IdentityName + "@" + ctx.RelayName
				}

				if jsonFlag {
					status["context"] = contextStr
					status["identity"] = ctx.IdentityDID
					status["identityName"] = ctx.IdentityName
					status["relay"] = ctx.RelayURL
					status["relayName"] = ctx.RelayName
					if id != nil {
						status["origin"] = id.Local.Origin
						status["publishedTo"] = id.Local.PublishedTo
						status["operations"] = len(id.Log)
					}
					outputJSON(status)
					return nil
				}

				fmt.Printf("Context:   %s\n", contextStr)
				if id != nil {
					fmt.Printf("Identity:  %s (%s)\n", id.DID, ctx.IdentityName)

					published := "unpublished"
					if len(id.Local.PublishedTo) > 0 {
						published = fmt.Sprintf("published (%s)", joinComma(id.Local.PublishedTo))
					}
					fmt.Printf("  Status:  %s\n", published)

					totalKeys := len(id.State.AuthKeys) + len(id.State.ControllerKeys) + len(id.State.AssertKeys)
					haveKeys := countKeysInKeychain(id)
					fmt.Printf("  Keys:    %d/%d (%s)\n", haveKeys, totalKeys, keys.Backend())
					fmt.Printf("  Chain:   %d operation(s)\n", len(id.Log))
				} else {
					fmt.Printf("Identity:  %s (%s) — not in local store\n", ctx.IdentityDID, ctx.IdentityName)
				}
			} else {
				if jsonFlag {
					status["context"] = nil
					status["identity"] = nil
					outputJSON(status)
					return nil
				}
				fmt.Println("No active context. Use 'dfos use <identity@relay>' or 'dfos identity create'")
			}

			if ctx != nil && ctx.RelayURL != "" {
				c := client.New(ctx.RelayURL)
				info, err := c.GetRelayInfo()
				if !jsonFlag {
					label := ctx.RelayURL
					if r, ok := cfg.Relays[ctx.RelayName]; ok && r.ProfileName != "" {
						label = r.ProfileName + " (" + ctx.RelayURL + ")"
					}
					fmt.Printf("Relay:     %s\n", label)
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
		Use:   "use <context>",
		Short: "Set active context (identity@relay)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg.ActiveContext = args[0]
			if err := config.Save(cfg); err != nil {
				return err
			}
			fmt.Printf("Active context set to: %s\n", args[0])
			return nil
		},
	}
}

// helpers

func countKeysInKeychain(id *store.StoredIdentity) int {
	count := 0
	allKeys := append(append(id.State.AuthKeys, id.State.ControllerKeys...), id.State.AssertKeys...)
	for _, k := range allKeys {
		account := id.DID + "#" + k.ID
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
