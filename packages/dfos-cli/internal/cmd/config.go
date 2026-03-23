package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/spf13/cobra"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "config",
		Short:   "Manage CLI configuration",
		GroupID: "config",
	}
	cmd.AddCommand(newConfigListCmd())
	cmd.AddCommand(newConfigGetCmd())
	cmd.AddCommand(newConfigSetCmd())
	return cmd
}

func newConfigListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show full configuration",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			data, _ := json.MarshalIndent(cfg, "", "  ")
			fmt.Println(string(data))
			return nil
		},
	}
}

func newConfigGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <key>",
		Short: "Get a config value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			switch key {
			case "active_context":
				fmt.Println(cfg.ActiveContext)
			default:
				return fmt.Errorf("unknown config key: %s", key)
			}
			return nil
		},
	}
}

func newConfigSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a config value",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, value := args[0], args[1]
			switch key {
			case "active_context":
				cfg.ActiveContext = value
			case "defaults.auth_token_ttl":
				cfg.Defaults.AuthTokenTTL = value
			case "defaults.credential_ttl":
				cfg.Defaults.CredentialTTL = value
			default:
				return fmt.Errorf("unknown config key: %s", key)
			}
			return config.Save(cfg)
		},
	}
}
