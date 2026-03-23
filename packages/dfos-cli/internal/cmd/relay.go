package cmd

import (
	"fmt"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/spf13/cobra"
)

func newRelayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "relay",
		Short:   "Manage named relays",
		GroupID: "relay",
	}
	cmd.AddCommand(newRelayAddCmd())
	cmd.AddCommand(newRelayRemoveCmd())
	cmd.AddCommand(newRelayListCmd())
	cmd.AddCommand(newRelayInfoCmd())
	return cmd
}

func newRelayAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <name> <url>",
		Short: "Register a named relay",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, url := args[0], args[1]
			cfg.Relays[name] = config.RelayConfig{URL: url}
			if err := config.Save(cfg); err != nil {
				return err
			}
			if jsonFlag {
				outputJSON(map[string]string{"name": name, "url": url})
			} else {
				fmt.Printf("Relay '%s' added: %s\n", name, url)
			}
			return nil
		},
	}
}

func newRelayRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Unregister a relay",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if _, ok := cfg.Relays[name]; !ok {
				return fmt.Errorf("unknown relay: %s", name)
			}
			delete(cfg.Relays, name)
			if err := config.Save(cfg); err != nil {
				return err
			}
			fmt.Printf("Relay '%s' removed\n", name)
			return nil
		},
	}
}

func newRelayListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured relays",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(cfg.Relays) == 0 {
				if jsonFlag {
					fmt.Println("[]")
				} else {
					fmt.Println("No relays configured. Use 'dfos relay add <name> <url>'")
				}
				return nil
			}

			if jsonFlag {
				items := []map[string]string{}
				for name, r := range cfg.Relays {
					items = append(items, map[string]string{"name": name, "url": r.URL})
				}
				outputJSON(items)
				return nil
			}

			fmt.Printf("%-12s %s\n", "NAME", "URL")
			for name, r := range cfg.Relays {
				fmt.Printf("%-12s %s\n", name, r.URL)
			}
			return nil
		},
	}
}

func newRelayInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info [name]",
		Short: "Show relay metadata",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			relayName := ""
			if len(args) > 0 {
				relayName = args[0]
			}
			_, c, err := requireRelay(relayName)
			if err != nil {
				return err
			}

			rn := relayName
			if rn == "" {
				ctx, _ := resolveCtx()
				if ctx != nil {
					rn = ctx.RelayName
				}
			}

			info, err := c.GetRelayInfo()
			if err != nil {
				return err
			}

			// cache relay DID
			if rn != "" {
				if r, ok := cfg.Relays[rn]; ok && r.DID != info.DID {
					r.DID = info.DID
					cfg.Relays[rn] = r
					config.Save(cfg)
				}
			}

			if jsonFlag {
				outputJSON(info)
			} else {
				fmt.Printf("DID:      %s\n", info.DID)
				fmt.Printf("Protocol: %s\n", info.Protocol)
				fmt.Printf("Version:  %s\n", info.Version)
			}
			return nil
		},
	}
}

// getRelayClient gets a client for a named relay.
func getRelayClient(name string) (*client.Client, string, error) {
	r, ok := cfg.Relays[name]
	if !ok {
		return nil, "", fmt.Errorf("unknown relay: %s", name)
	}
	return client.New(r.URL), name, nil
}

// getRelayDID returns the cached relay DID, or fetches and caches it.
func getRelayDID(relayName string, c *client.Client) (string, error) {
	if r, ok := cfg.Relays[relayName]; ok && r.DID != "" {
		return r.DID, nil
	}
	info, err := c.GetRelayInfo()
	if err != nil {
		return "", fmt.Errorf("get relay info: %w", err)
	}
	// cache it
	if r, ok := cfg.Relays[relayName]; ok {
		r.DID = info.DID
		cfg.Relays[relayName] = r
		config.Save(cfg)
	}
	return info.DID, nil
}
