package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

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
		Use:     "list",
		Short:   "Show full configuration",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			data, _ := json.MarshalIndent(cfg, "", "  ")
			fmt.Println(string(data))
			return nil
		},
	}
}

// configKeys are the writable keys, in the spelling `dfos config set` documents.
// Dash and underscore forms both resolve here, so the CLI spelling and the TOML
// key never diverge into two things a user has to remember.
var configKeys = []string{"default-identity", "default-peer", "default-vault", "defaults.credential_ttl"}

// normalizeConfigKey folds a key to its canonical dashed spelling.
func normalizeConfigKey(key string) string {
	if key == "defaults.credential_ttl" || key == "defaults.credential-ttl" {
		return "defaults.credential_ttl"
	}
	return strings.ReplaceAll(key, "_", "-")
}

func unknownConfigKey(key string) error {
	return fmt.Errorf("unknown config key: %s (known keys: %s)", key, strings.Join(configKeys, ", "))
}

func newConfigGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <key>",
		Short: "Get a config value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := normalizeConfigKey(args[0])
			var value string
			switch key {
			case "default-identity":
				value = cfg.DefaultIdentity
			case "default-peer":
				value = cfg.DefaultPeer
			case "default-vault":
				value = cfg.DefaultVault
			case "defaults.credential_ttl":
				if cfg.Defaults != nil {
					value = cfg.Defaults.CredentialTTL
				}
			default:
				return unknownConfigKey(args[0])
			}
			if jsonFlag {
				outputJSON(map[string]string{key: value})
			} else {
				fmt.Println(value)
			}
			return nil
		},
	}
}

// newConfigSetCmd is the ONLY writer of the config tier of the resolution
// stack. Nothing else updates default-identity or default-peer — no command
// follows "last used" or "last created" — which is precisely why two concurrent
// invocations carrying different --as values cannot interfere with each other.
func newConfigSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a config value",
		Long: "Write one config value. `default-identity` and `default-peer` are the config tier of the " +
			"resolution stack — the fallback consulted after --as/--relay and DFOS_AS/DFOS_RELAY. " +
			"`default-vault` is the same tier for minting: the vault new keys are derived from when no " +
			"--vault is given. This command is the only thing that writes them, with one exception: " +
			"creating the first vault on a machine with none sets default-vault, because there is nothing " +
			"there to displace.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, value := normalizeConfigKey(args[0]), args[1]
			switch key {
			case "default-identity":
				cfg.DefaultIdentity = value
			case "default-peer":
				if _, ok := cfg.Relays[value]; !ok {
					return fmt.Errorf("unknown peer: %s (register it with 'dfos peer add %s <url>')", value, value)
				}
				cfg.DefaultPeer = value
			case "default-vault":
				if !getVaults().Has(value) {
					return fmt.Errorf("no vault named '%s' (create one with 'dfos vault create %s')", value, value)
				}
				cfg.DefaultVault = value
			case "defaults.credential_ttl":
				if cfg.Defaults == nil {
					cfg.Defaults = &config.DefaultsConfig{}
				}
				cfg.Defaults.CredentialTTL = value
			default:
				return unknownConfigKey(args[0])
			}
			return config.Save(cfg)
		},
	}
}
