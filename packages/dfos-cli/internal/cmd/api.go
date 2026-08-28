package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newAPICmd is the deprecated legacy spelling of `dfos relay call`. It is a
// command with its own RunE rather than an alias of the passthrough: cobra
// dispatches a matching subcommand before it reaches RunE, so `api` can carry
// subcommands while this legacy raw form — an uppercase HTTP method and a path
// as the two bare arguments — keeps working. The passthrough itself lives in
// relay.go; this forwards to it, so both spellings produce identical output.
func newAPICmd() *cobra.Command {
	f := &relayCallFlags{}

	cmd := &cobra.Command{
		Use:   "api <METHOD> <path>",
		Short: "Raw HTTP request to peer (deprecated: use 'relay call')",
		Long:  "Deprecated spelling of 'dfos relay call'. Make raw HTTP requests to the active peer. Use --auth to sign an identity proof for the request.",
		// Cobra prints one line to stderr — `Command "api" is deprecated,
		// use "dfos relay call <METHOD> <path>"` — before this runs.
		Deprecated: `use "dfos relay call <METHOD> <path>"`,
		Args:       cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return fmt.Errorf("usage: dfos api <METHOD> <path> (e.g. dfos api GET /proof/v1/stats)")
			}
			return runRelayCall(f, args, "dfos api")
		},
	}

	f.bind(cmd)
	return cmd
}
