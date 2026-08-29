package cmd

// Raw relay passthrough — `dfos relay call <METHOD> <path>`.
//
// The command is registered as `call` under the peer group, whose `relay` alias
// supplies the documented spelling (the same arrangement `relay gc` already
// uses). `dfos api <METHOD> <path>` is the deprecated legacy spelling and
// forwards into runRelayCall from api.go, so both spellings run one
// implementation and emit identical output.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
	"github.com/spf13/cobra"
)

// relayCallFlags is the flag set of the raw passthrough. It is a struct so the
// deprecated `api` spelling binds the very same flags without redeclaring them.
type relayCallFlags struct {
	auth           bool
	body           string
	bodyFile       string
	includeHeaders bool
	headers        []string
}

func (f *relayCallFlags) bind(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&f.auth, "auth", false, "Sign an identity proof for this request")
	cmd.Flags().StringVar(&f.body, "body", "", "Request body (JSON string)")
	cmd.Flags().StringVar(&f.bodyFile, "body-file", "", "Request body from file (use - for stdin)")
	cmd.Flags().BoolVarP(&f.includeHeaders, "include", "i", false, "Include response headers")
	cmd.Flags().StringArrayVarP(&f.headers, "header", "H", nil, "Additional headers (key: value)")
}

func newRelayCallCmd() *cobra.Command {
	f := &relayCallFlags{}

	cmd := &cobra.Command{
		Use:   "call <METHOD> <path>",
		Short: "Raw HTTP request to peer",
		Long:  "Make raw HTTP requests to the active peer. Use --auth to sign an identity proof for the request.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRelayCall(f, args, "dfos relay call")
		},
	}

	f.bind(cmd)
	return cmd
}

// runRelayCall performs the passthrough. invocation is the spelling the user
// typed ("dfos relay call" or the deprecated "dfos api"), used only so the
// usage hint echoes the command they actually ran.
func runRelayCall(f *relayCallFlags, args []string, invocation string) error {
	method := strings.ToUpper(args[0])
	path := args[1]

	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
	default:
		return fmt.Errorf("invalid HTTP method %q\nusage: %s <METHOD> <path> (e.g. %s GET /proof/v1/stats)", args[0], invocation, invocation)
	}

	ctx, err := resolveCtx()
	if err != nil {
		return err
	}
	if ctx.RelayURL == "" {
		return errNoPeer()
	}

	c := client.New(ctx.RelayURL)
	headers := map[string]string{}

	for _, h := range f.headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	var bodyBytes []byte
	if f.body != "" {
		bodyBytes = []byte(f.body)
		if _, ok := headers["Content-Type"]; !ok {
			headers["Content-Type"] = "application/json"
		}
	} else if f.bodyFile != "" {
		var err error
		if f.bodyFile == "-" {
			bodyBytes, err = io.ReadAll(os.Stdin)
		} else {
			bodyBytes, err = os.ReadFile(f.bodyFile)
		}
		if err != nil {
			return fmt.Errorf("read body: %w", err)
		}
		if _, ok := headers["Content-Type"]; !ok {
			headers["Content-Type"] = "application/json"
		}
	}

	// The proof binds THIS request — its method, path, and body — so it is
	// signed after the body is in hand, never before. A jti always rides
	// along: write-shaped routes require it, read-shaped routes ignore it,
	// so attaching one keeps --auth correct on every route.
	if f.auth {
		chain, err := resolveIdentityForRelayCall(ctx)
		if err != nil {
			return err
		}

		signer, err := selectHeldKey(chain.DID, chain.State.AuthKeys, "auth")
		if err != nil {
			return err
		}
		privKey, err := keys.GetPrivateKey(signer.Account)
		if err != nil {
			return err
		}

		authorization, err := c.AuthorizationFor(
			&client.Signer{Kid: signer.KID, PrivateKey: privKey}, method, path, bodyBytes, true)
		if err != nil {
			return err
		}
		headers["Authorization"] = authorization
	}

	status, respHeaders, respBody, err := c.DoRaw(method, path, bodyBytes, headers)
	if err != nil {
		return err
	}

	if f.includeHeaders {
		fmt.Printf("HTTP %d\n", status)
		for k, v := range respHeaders {
			for _, val := range v {
				fmt.Printf("%s: %s\n", k, val)
			}
		}
		fmt.Println()
	}

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
}

// resolveIdentityForRelayCall resolves the principal --auth signs as. It runs
// the same stack, refuses anonymously with the same three-mechanism error, and
// announces the principal the same way as every other signing site — --auth is
// a signing site, and a raw passthrough is exactly where a silently-ambient
// identity would do the most damage.
func resolveIdentityForRelayCall(ctx *config.ResolvedContext) (*relay.StoredIdentityChain, error) {
	if !ctx.HasIdentity() {
		return nil, errNoIdentity()
	}
	lr, err := getRelay()
	if err != nil {
		return nil, err
	}
	did := ctx.IdentityDID
	if did == "" {
		return nil, fmt.Errorf("identity '%s' not found in config (from %s)", ctx.IdentityName, ctx.IdentitySource)
	}
	chain, err := lr.Relay.GetIdentity(did)
	if err != nil || chain == nil {
		return nil, fmt.Errorf("identity '%s' not found in local relay", ctx.Principal())
	}
	if len(chain.State.AuthKeys) == 0 {
		return nil, fmt.Errorf("identity '%s' has no auth keys", ctx.Principal())
	}
	announceSigner(ctx)
	return chain, nil
}
