package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/store"
	"github.com/spf13/cobra"
)

func newAPICmd() *cobra.Command {
	var auth bool
	var body string
	var bodyFile string
	var includeHeaders bool
	var headerFlags []string

	cmd := &cobra.Command{
		Use:   "api <METHOD> <path>",
		Short: "Raw HTTP request to relay",
		Long:  "Make raw HTTP requests to the active relay. Use --auth to auto-inject auth tokens.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			method := strings.ToUpper(args[0])
			path := args[1]

			ctx, _ := resolveCtx()
			if ctx == nil || ctx.RelayURL == "" {
				return fmt.Errorf("no relay configured")
			}

			c := client.New(ctx.RelayURL)
			headers := map[string]string{}

			// parse -H flags
			for _, h := range headerFlags {
				parts := strings.SplitN(h, ":", 2)
				if len(parts) == 2 {
					headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}

			// auto-auth
			if auth {
				id, err := resolveIdentityForAPI(ctx)
				if err != nil {
					return err
				}

				authKeyID := id.State.AuthKeys[0].ID
				kid := id.DID + "#" + authKeyID
				privKey, err := keys.GetPrivateKey(id.DID + "#" + authKeyID)
				if err != nil {
					return err
				}

				info, err := c.GetRelayInfo()
				if err != nil {
					return err
				}

				token, err := protocol.CreateAuthToken(id.DID, info.DID, kid, 5*time.Minute, privKey)
				if err != nil {
					return err
				}
				headers["Authorization"] = "Bearer " + token
			}

			// resolve body
			var bodyBytes []byte
			if body != "" {
				bodyBytes = []byte(body)
				if _, ok := headers["Content-Type"]; !ok {
					headers["Content-Type"] = "application/json"
				}
			} else if bodyFile != "" {
				var err error
				if bodyFile == "-" {
					bodyBytes, err = io.ReadAll(os.Stdin)
				} else {
					bodyBytes, err = os.ReadFile(bodyFile)
				}
				if err != nil {
					return fmt.Errorf("read body: %w", err)
				}
				if _, ok := headers["Content-Type"]; !ok {
					headers["Content-Type"] = "application/json"
				}
			}

			status, respHeaders, respBody, err := c.DoRaw(method, path, bodyBytes, headers)
			if err != nil {
				return err
			}

			if includeHeaders {
				fmt.Printf("HTTP %d\n", status)
				for k, v := range respHeaders {
					for _, val := range v {
						fmt.Printf("%s: %s\n", k, val)
					}
				}
				fmt.Println()
			}

			// try to pretty-print JSON
			ct := respHeaders.Get("Content-Type")
			if strings.Contains(ct, "json") {
				var parsed any
				if json.Unmarshal(respBody, &parsed) == nil {
					pretty, _ := json.MarshalIndent(parsed, "", "  ")
					fmt.Println(string(pretty))
					return nil
				}
			}

			os.Stdout.Write(respBody)
			if len(respBody) > 0 && respBody[len(respBody)-1] != '\n' {
				fmt.Println()
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&auth, "auth", false, "Auto-inject auth token")
	cmd.Flags().StringVar(&body, "body", "", "Request body (JSON string)")
	cmd.Flags().StringVar(&bodyFile, "body-file", "", "Request body from file (use - for stdin)")
	cmd.Flags().BoolVarP(&includeHeaders, "include", "i", false, "Include response headers")
	cmd.Flags().StringArrayVarP(&headerFlags, "header", "H", nil, "Additional headers (key: value)")

	return cmd
}

func resolveIdentityForAPI(ctx *config.ResolvedContext) (*store.StoredIdentity, error) {
	if ctx.IdentityName == "" {
		return nil, fmt.Errorf("--auth requires an identity. Use --identity or set a context")
	}
	id, _ := store.FindIdentityByName(ctx.IdentityName)
	if id == nil && ctx.IdentityDID != "" {
		id, _ = store.LoadIdentity(ctx.IdentityDID)
	}
	if id == nil {
		return nil, fmt.Errorf("identity '%s' not found", ctx.IdentityName)
	}
	if len(id.State.AuthKeys) == 0 {
		return nil, fmt.Errorf("identity has no auth keys")
	}
	return id, nil
}
