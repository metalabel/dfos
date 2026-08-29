package cmd

// `dfos api` — a generic client for any host that advertises the API-AUTH
// OpenAPI convention.
//
// `api add` registers a host or a document under a local name and caches the
// OpenAPI document it finds; `api call` reads that cached document to decide
// which request an operation names and which authentication artifact it needs.
// Nothing here is specific to the canonical deployment: the convention is the
// whole interface, so a fork or a self-hosted API registers and calls the same way.
//
// `dfos api <METHOD> <path>` remains the deprecated raw passthrough it has
// always been — the parent command carries its own RunE for the two-bare-argument
// form, and cobra dispatches a matching subcommand before ever reaching it.

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/apispec"
	"github.com/spf13/cobra"
)

// apiStoreForTests overrides the registry location. Nil in every real run.
var apiStoreForTests *apispec.Store

func apiStore() *apispec.Store {
	if apiStoreForTests != nil {
		return apiStoreForTests
	}
	return apispec.NewStore()
}

// apiFetcherForTests overrides the document fetcher. Nil in every real run.
var apiFetcherForTests apispec.Fetcher

func apiFetcher() apispec.Fetcher {
	if apiFetcherForTests != nil {
		return apiFetcherForTests
	}
	return apispec.HTTPFetcher()
}

// legacyDeprecation is the line the raw `dfos api <METHOD> <path>` form prints,
// byte-identical to the one cobra emitted when the whole command was marked
// Deprecated. The marker moved off the command itself so `api` — and therefore
// `api add` / `list` / `rm` / `refresh` / `call` — appears in help at all; a
// deprecated command is hidden from it, subcommands and all.
const legacyDeprecation = `Command "api" is deprecated, use "dfos relay call <METHOD> <path>"` + "\n"

func newAPICmd() *cobra.Command {
	f := &relayCallFlags{}

	cmd := &cobra.Command{
		Use:     "api",
		Short:   "Call any API that advertises the DFOS OpenAPI convention",
		GroupID: "auth",
		Long: "Register an API by host or OpenAPI document, then call its operations by name.\n\n" +
			"The document says which authentication artifact each route needs — anonymous, an identity " +
			"proof, or a request proof with the credential it binds — and this client signs accordingly. " +
			"The document is discovery, never authority: the host's own verdict decides every request.\n\n" +
			"'dfos api <METHOD> <path>' is the deprecated raw passthrough to the active peer; " +
			"'dfos relay call' is its spelling.\n\n" +
			"Normative spec: https://protocol.dfos.com/api-auth",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return fmt.Errorf("usage: dfos api <METHOD> <path> (e.g. dfos api GET /proof/v1/stats)\n" +
					"       dfos api add|list|rm|refresh|call    (see 'dfos api --help')")
			}
			cmd.Printf(legacyDeprecation)
			return runRelayCall(f, args, "dfos api")
		},
	}

	f.bind(cmd)
	cmd.AddCommand(newAPIAddCmd())
	cmd.AddCommand(newAPIListCmd())
	cmd.AddCommand(newAPIRemoveCmd())
	cmd.AddCommand(newAPIRefreshCmd())
	cmd.AddCommand(newAPICallCmd())
	return cmd
}

func newAPIAddCmd() *cobra.Command {
	var file string

	cmd := &cobra.Command{
		Use:   "add <name> [host-or-url]",
		Short: "Register an API under a local name and cache its OpenAPI document",
		Long: `Register an API under a local name.

The source takes three forms:

  api.dfos.com                      a host — ask it where its document is
  https://api.dfos.com/openapi.json a document URL — fetch exactly that
  --file ./openapi.json             a document on disk

A bare host (or a scheme and host with no path) is DISCOVERED: the host's
/.well-known/dfos-relay is read for an 'openapi' member, and /openapi.json is
assumed when it advertises none. A URL carrying a path names the document
outright.

The document is fetched, parsed, and validated here, so a source that is not an
OpenAPI document fails at registration rather than on some later call. What is
cached is a snapshot; 'dfos api refresh' re-runs this same resolution.`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := apispec.ValidateName(name); err != nil {
				return err
			}
			source := ""
			if len(args) == 2 {
				source = args[1]
			}
			registration, err := fetchAndStore(name, source, file)
			if err != nil {
				return err
			}
			return reportRegistration("Registered", registration)
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "Read the OpenAPI document from a local path instead of a host")
	return cmd
}

func newAPIRefreshCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "refresh <name>",
		Short: "Refetch a registered API's OpenAPI document",
		Long: "Re-run the resolution the registration was made with and replace the cached document.\n\n" +
			"Resolution runs from the SOURCE, not from the document URL that was cached: a host that " +
			"moves its document is followed, because the document was always discovery rather than an " +
			"address this client owns.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			existing, err := apiStore().Get(args[0])
			if err != nil {
				return err
			}
			file := ""
			source := existing.Source
			if existing.Kind == apispec.KindFile {
				file, source = existing.Source, ""
			}
			registration, err := fetchAndStore(existing.Name, source, file)
			if err != nil {
				return err
			}
			return reportRegistration("Refreshed", registration)
		},
	}
}

// fetchAndStore resolves a source into a document and writes both the document
// and its registration.
func fetchAndStore(name, source, file string) (apispec.Registration, error) {
	resolution, err := apispec.Resolve(source, file, apiFetcher())
	if err != nil {
		return apispec.Registration{}, err
	}
	recordedSource := source
	if recordedSource == "" {
		recordedSource = resolution.Document
	}
	registration := apispec.Registration{
		Name:       name,
		Source:     recordedSource,
		Document:   resolution.Document,
		Kind:       resolution.Kind,
		Origin:     resolution.Origin,
		FetchedAt:  time.Now().UTC().Truncate(time.Second),
		Title:      resolution.Doc.Title(),
		Version:    resolution.Doc.InfoVersion(),
		OpenAPI:    resolution.Doc.Version(),
		Operations: len(resolution.Doc.Operations()),
	}
	if err := apiStore().Put(registration, resolution.Data); err != nil {
		return apispec.Registration{}, err
	}
	return registration, nil
}

func reportRegistration(verb string, r apispec.Registration) error {
	if jsonFlag {
		outputJSON(r)
		return nil
	}
	fmt.Printf("%s '%s' — %s\n", verb, r.Name, r.Document)
	if r.Title != "" {
		fmt.Printf("  %s %s (OpenAPI %s)\n", r.Title, r.Version, r.OpenAPI)
	}
	fmt.Printf("  %d operation(s), found by %s\n", r.Operations, r.Kind)
	return nil
}

type apiListItem struct {
	apispec.Registration
	AgeSeconds int64 `json:"ageSeconds"`
	Stale      bool  `json:"stale"`
}

func newAPIListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List registered APIs and how old their cached documents are",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			registrations, err := apiStore().List()
			if err != nil {
				return err
			}
			now := time.Now()
			items := make([]apiListItem, 0, len(registrations))
			for _, r := range registrations {
				items = append(items, apiListItem{
					Registration: r,
					AgeSeconds:   int64(r.Age(now).Seconds()),
					Stale:        r.Stale(now),
				})
			}
			if jsonFlag {
				outputJSON(items)
				return nil
			}
			if len(items) == 0 {
				fmt.Println("No APIs registered. 'dfos api add <name> <host-or-url>' registers one.")
				return nil
			}
			fmt.Printf("%-16s  %-10s  %-6s  %-14s  %s\n", "NAME", "AGE", "OPS", "FOUND BY", "DOCUMENT")
			for _, item := range items {
				age := humanAge(item.Age(now))
				if item.Stale {
					age += " *"
				}
				fmt.Printf("%-16s  %-10s  %-6d  %-14s  %s\n",
					item.Name, age, item.Operations, item.Kind, item.Document)
			}
			for _, item := range items {
				if item.Stale {
					fmt.Printf("\n* past %s old — 'dfos api refresh <name>' refetches.\n",
						humanAge(apispec.StaleAfter))
					break
				}
			}
			return nil
		},
	}
}

func newAPIRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rm <name>",
		Short:   "Unregister an API and drop its cached document",
		Aliases: []string{"remove"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := apiStore().Remove(args[0]); err != nil {
				return err
			}
			if jsonFlag {
				outputJSON(map[string]string{"removed": args[0]})
				return nil
			}
			fmt.Printf("Unregistered '%s'\n", args[0])
			return nil
		},
	}
}

// loadAPI reads a registration and its cached document, and says out loud when
// the document is old.
//
// The staleness line is a DISCLOSURE, never a refusal and never a refetch: a
// stale document still describes the call, the host's own verdict still decides
// it, and a call that surprise-networked to refresh a cache would make its own
// timing and failure modes unreadable.
func loadAPI(name string) (apispec.Registration, *apispec.Doc, error) {
	registration, err := apiStore().Get(name)
	if err != nil {
		return apispec.Registration{}, nil, err
	}
	data, err := apiStore().Document(name)
	if err != nil {
		return apispec.Registration{}, nil, err
	}
	doc, err := apispec.Parse(data)
	if err != nil {
		return apispec.Registration{}, nil, fmt.Errorf("the cached document for %q does not parse: %w — 'dfos api refresh %s' refetches it", name, err, name)
	}
	if age := registration.Age(time.Now()); registration.Stale(time.Now()) {
		fmt.Fprintf(os.Stderr, "spec for %s is %s old — 'dfos api refresh %s'\n", name, humanAge(age), name)
	}
	return registration, doc, nil
}

// humanAge renders a duration at the coarsest unit that still says something.
func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// parseKeyValues reads repeated `name=value` flags into a map. The value may
// itself contain '=' — only the first one separates.
func parseKeyValues(pairs []string, flag string) (map[string]string, error) {
	out := map[string]string{}
	for _, pair := range pairs {
		name, value, found := strings.Cut(pair, "=")
		if !found || name == "" {
			return nil, fmt.Errorf("%s %q is not name=value", flag, pair)
		}
		out[name] = value
	}
	return out, nil
}
