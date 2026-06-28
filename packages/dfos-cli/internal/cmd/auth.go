package cmd

import (
	"fmt"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/spf13/cobra"
)

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "auth",
		Short:   "Authentication management",
		GroupID: "auth",
	}
	cmd.AddCommand(newAuthTokenCmd())
	cmd.AddCommand(newAuthStatusCmd())
	return cmd
}

func newAuthTokenCmd() *cobra.Command {
	var ttl string

	cmd := &cobra.Command{
		Use:   "token",
		Short: "Mint a short-lived auth token (stdout)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, chain, err := requireIdentity()
			if err != nil {
				return err
			}

			if ctx.RelayURL == "" {
				return fmt.Errorf("no peer configured for auth token audience")
			}

			kid, err := selectHeldKey(chain.DID, chain.State.AuthKeys, "auth")
			if err != nil {
				return err
			}
			privKey, err := keys.GetPrivateKey(kid)
			if err != nil {
				return err
			}

			dur, err := time.ParseDuration(ttl)
			if err != nil {
				return fmt.Errorf("invalid --ttl %q: %w (use Go duration units like 5m, 1h, 24h — note day units like \"1d\" are not supported)", ttl, err)
			}

			c := client.New(ctx.RelayURL)
			info, err := c.GetRelayInfo()
			if err != nil {
				return fmt.Errorf("get peer info: %w", err)
			}

			token, err := protocol.CreateAuthToken(chain.DID, info.DID, kid, dur, privKey)
			if err != nil {
				return err
			}

			if jsonFlag {
				outputJSON(map[string]string{"token": token})
			} else {
				fmt.Print(token)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&ttl, "ttl", "5m", "Token TTL (e.g., 5m, 1h)")
	return cmd
}

func newAuthStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show current auth state",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, _ := resolveCtx()
			if ctx == nil || ctx.IdentityName == "" {
				if jsonFlag {
					outputJSON(map[string]any{"authenticated": false})
					return nil
				}
				fmt.Println("Not authenticated. Use 'dfos identity create --name <name>' first.")
				return nil
			}

			if jsonFlag {
				outputJSON(map[string]any{
					"authenticated": true,
					"identity":      ctx.IdentityDID,
					"name":          ctx.IdentityName,
					"peer":          ctx.RelayURL,
				})
				return nil
			}

			fmt.Printf("Identity: %s (%s)\n", ctx.IdentityDID, ctx.IdentityName)
			if ctx.RelayURL != "" {
				fmt.Printf("Peer:     %s (%s)\n", ctx.RelayURL, ctx.RelayName)
			}
			return nil
		},
	}
}
