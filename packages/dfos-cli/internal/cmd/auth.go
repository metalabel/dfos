package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/spf13/cobra"
)

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "auth",
		Short:   "Authentication management",
		GroupID: "auth",
	}
	cmd.AddCommand(newAuthProofCmd())
	cmd.AddCommand(newAuthStatusCmd())
	return cmd
}

func newAuthProofCmd() *cobra.Command {
	var bodyFile string
	var peerName string
	var jti bool

	cmd := &cobra.Command{
		Use:   "proof <METHOD> <path>",
		Short: "Sign an identity proof for one request (stdout)",
		Long: `Sign an identity proof for ONE exact request against a peer and print it.

A proof binds one method, host, path, and body, and the relay accepts it only
within a short window of its issued-at — so it authorizes that request and
nothing else, and it goes stale in about a minute. Sign one per request, at the
moment you make it.

The path must be exactly what goes on the request line, query string included:
"/signing/v0/requests?limit=10" and "/signing/v0/requests" are different
requests and need different proofs.

Write-shaped surfaces — POST /proof/v1/operations and PUT blob — require --jti.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			method := strings.ToUpper(args[0])
			path := args[1]
			if !strings.HasPrefix(path, "/") {
				return fmt.Errorf("path must begin with / (got %q)", path)
			}

			ctx, chain, err := requireIdentity()
			if err != nil {
				return err
			}

			peerURL := ctx.RelayURL
			if peerName != "" {
				peer, ok := cfg.Relays[peerName]
				if !ok {
					return fmt.Errorf("unknown peer: %s", peerName)
				}
				peerURL = peer.URL
			}
			if peerURL == "" {
				return fmt.Errorf("no peer configured — a proof binds the peer's host, so pass --peer <name>")
			}

			var body []byte
			if bodyFile != "" {
				if bodyFile == "-" {
					body, err = io.ReadAll(os.Stdin)
				} else {
					body, err = os.ReadFile(bodyFile)
				}
				if err != nil {
					return fmt.Errorf("read body: %w", err)
				}
			}

			kid, err := selectHeldKey(chain.DID, chain.State.AuthKeys, "auth")
			if err != nil {
				return err
			}
			privKey, err := keys.GetPrivateKey(kid)
			if err != nil {
				return err
			}

			c := client.New(peerURL)
			authorization, err := c.AuthorizationFor(
				&client.Signer{Kid: kid, PrivateKey: privKey}, method, path, body, jti)
			if err != nil {
				return err
			}
			proof := strings.TrimPrefix(authorization, "DFOS ")

			if jsonFlag {
				outputJSON(map[string]string{"proof": proof, "authorization": authorization})
			} else {
				fmt.Println(proof)
				fmt.Printf("Authorization: %s\n", authorization)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&bodyFile, "body", "", "Request body from file (use - for stdin)")
	cmd.Flags().StringVar(&peerName, "peer", "", "Peer to bind the proof to (default: the active context's peer)")
	cmd.Flags().BoolVar(&jti, "jti", false, "Attach a random jti — required on write-shaped surfaces")
	return cmd
}

func newAuthStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show current auth state",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, ctxErr := resolveCtx()
			if ctx == nil || ctx.IdentityName == "" {
				if jsonFlag {
					out := map[string]any{"authenticated": false}
					if cfg.ActiveContext != "" {
						out["activeContext"] = cfg.ActiveContext
						if ctxErr != nil {
							out["error"] = ctxErr.Error()
						}
					}
					outputJSON(out)
					return nil
				}
				if cfg.ActiveContext != "" {
					reason := "names an unknown identity or peer"
					if ctxErr != nil {
						reason = ctxErr.Error()
					}
					fmt.Printf("Not authenticated. Active context '%s' cannot be resolved: %s\n", cfg.ActiveContext, reason)
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
