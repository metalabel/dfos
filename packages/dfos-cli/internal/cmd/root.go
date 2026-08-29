package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/keystore"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/localrelay"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/statelock"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/vault"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
	"github.com/spf13/cobra"
)

var (
	// persistent flags. --as and --relay are the canonical selectors; --ctx,
	// --identity, and --peer are compat aliases of the same resolver, hidden in
	// help and documented as aliases.
	asFlag       string
	relayFlag    string
	ctxFlag      string
	identityFlag string
	peerFlag     string
	jsonFlag     bool
	quietFlag    bool

	// shared state
	cfg     *config.Config
	keys    keystore.Store
	Version = "dev"

	// signerAnnounced keeps the resolved-principal line to ONE per invocation:
	// several commands resolve the signer more than once (re-reading the chain
	// after an operation), and repeating the line would be noise, not disclosure.
	signerAnnounced bool

	// lazy-initialized local relay
	localRelayInstance *localrelay.LocalRelay

	// lazy-initialized vault store. Opening it probes the OS keychain, and most
	// invocations never mint anything, so it is opened on first use rather than
	// alongside the keystore in PersistentPreRunE.
	vaultStore *vault.Store
)

// annNoStateLock marks a command that must NOT take the process-wide state
// lock — set it on long-lived daemons (e.g. serve) that would otherwise hold
// the lock for their entire run and block every other dfos invocation.
const annNoStateLock = "dfos:no_state_lock"

// JSONFlag reports whether --json was requested. Used by main to render a
// top-level command error as JSON instead of a plain line.
func JSONFlag() bool { return jsonFlag }

// ExitCodeError carries a process exit status for a command that has ALREADY
// reported its outcome on stdout and must not print an error line on top of it.
// `identity verify-binding` maps its verdict to a status (bound 0, broken 1,
// stale 2, no-claim 0) so scripts branch on the exit code instead of parsing
// output; main recognizes this type and exits with Code, printing nothing.
type ExitCodeError struct{ Code int }

func (e *ExitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

// CodedError carries a stable machine-readable reason alongside an error's
// prose. The prose is written for the operator reading a terminal and changes
// when a better sentence is found; the code is what a script branches on, so it
// does not. --json renders both.
type CodedError struct {
	// Reason is the stable identifier, kebab-case and namespaced by what failed.
	Reason string
	// Fields are additional machine-readable facts about this failure. Keys are
	// merged into the JSON document beside "error" and "reason".
	Fields map[string]string
	Err    error
}

func (e *CodedError) Error() string { return e.Err.Error() }
func (e *CodedError) Unwrap() error { return e.Err }

// ErrorJSON renders a top-level command error as the document --json emits for
// it: always the prose under "error", plus a "reason" code and any extra fields
// when the error carries them. Used by main on the error path.
func ErrorJSON(err error) map[string]string {
	doc := map[string]string{"error": err.Error()}
	var coded *CodedError
	if errors.As(err, &coded) {
		doc["reason"] = coded.Reason
		for k, v := range coded.Fields {
			// "error" and "reason" are the document's own, never overwritten by a
			// field that happens to share the name.
			if k == "error" || k == "reason" {
				continue
			}
			doc[k] = v
		}
	}
	return doc
}

// skipStateLock reports whether a command should NOT take the state lock:
// commands explicitly opted out (daemons), and cobra's own completion/help
// machinery, which never mutate local state and must stay non-blocking (shell
// tab-completion invokes __complete constantly).
func skipStateLock(cmd *cobra.Command) bool {
	if cmd.Annotations[annNoStateLock] == "true" {
		return true
	}
	switch cmd.Name() {
	case "completion", "help", cobra.ShellCompRequestCmd, cobra.ShellCompNoDescRequestCmd:
		return true
	}
	return false
}

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:     "dfos",
		Short:   "DFOS CLI — local-first relay node for the DFOS protocol",
		Long:    "Command-line interface for the DFOS protocol. Your machine is a relay. Manage identities, content chains, and credentials. Sync with peers.",
		Version: Version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Serialize concurrent `dfos` invocations that mutate local state
			// (config.toml, keystore) so they don't clobber each other. Taken
			// BEFORE config is loaded so the whole load→modify→save is atomic
			// across processes. Skipped for daemons and completion (see
			// skipStateLock); released automatically on process exit.
			if !skipStateLock(cmd) {
				if err := statelock.Acquire(); err != nil {
					return fmt.Errorf("acquire state lock: %w", err)
				}
			}
			var err error
			cfg, err = config.Load()
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			keys = keystore.New()
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if localRelayInstance != nil {
				localRelayInstance.Close()
			}
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&asFlag, "as", "", "Identity to act as (name or did:dfos:…)")
	root.PersistentFlags().StringVar(&relayFlag, "relay", "", "Peer to talk to (name) — a command's own --peer flag takes precedence for that command; see its help for what it selects")
	root.PersistentFlags().BoolVar(&jsonFlag, "json", false, "Output as JSON")
	root.PersistentFlags().BoolVarP(&quietFlag, "quiet", "q", false, "Suppress the resolved-principal line on signing commands")

	// Compat aliases. They resolve through the same stack at the same tier as
	// the mechanism they alias; they are hidden so help teaches one spelling.
	root.PersistentFlags().StringVar(&ctxFlag, "ctx", "", "Context (identity@peer) — alias of --as/--relay")
	root.PersistentFlags().StringVar(&identityFlag, "identity", "", "Identity name — alias of --as")
	root.PersistentFlags().StringVar(&peerFlag, "peer", "", "Peer name — alias of --relay")
	for _, alias := range []string{"ctx", "identity", "peer"} {
		_ = root.PersistentFlags().MarkHidden(alias)
	}

	// command groups
	identityGroup := &cobra.Group{ID: "identity", Title: "Identity Commands"}
	contentGroup := &cobra.Group{ID: "content", Title: "Content Commands"}
	authGroup := &cobra.Group{ID: "auth", Title: "Auth Commands"}
	peerGroup := &cobra.Group{ID: "peer", Title: "Peer Commands"}
	configGroup := &cobra.Group{ID: "config", Title: "Config Commands"}

	root.AddGroup(identityGroup, contentGroup, authGroup, peerGroup, configGroup)

	root.AddCommand(newVersionCmd())
	root.AddCommand(newStatusCmd())
	root.AddCommand(newWhoamiCmd())
	root.AddCommand(newUseTombstoneCmd())
	root.AddCommand(newIdentityCmd())
	root.AddCommand(newVaultCmd())
	root.AddCommand(newKeysCmd())
	root.AddCommand(newRecoverCmd())
	root.AddCommand(newContentCmd())
	root.AddCommand(newCredentialCmd())
	root.AddCommand(newCredsCmd())
	root.AddCommand(newWitnessCmd())
	root.AddCommand(newCountersigsCmd())
	root.AddCommand(newOperationCmd())
	root.AddCommand(newAuthCmd())
	root.AddCommand(newLoginCmd())
	root.AddCommand(newPeerCmd())
	root.AddCommand(newAPICmd())
	root.AddCommand(newConfigCmd())
	root.AddCommand(newServeCmd())
	root.AddCommand(newSyncCmd())
	root.AddCommand(newSkillCmd())

	return root
}

// getVaults returns the lazily-initialized vault store.
func getVaults() *vault.Store {
	if vaultStore == nil {
		vaultStore = vault.Default()
	}
	return vaultStore
}

// quietRelayLogger is the logger every one-shot CLI command opens its embedded
// relay with. That relay's INFO chatter ("ingest complete", "peer sync fetched
// ops") is pure noise on a terminal, so the happy path is silent at Warn while
// genuine warnings and errors still surface. (`serve` opens its own at INFO.)
func quietRelayLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// getRelay returns the lazily-initialized local relay every one-shot command
// reads and writes through.
//
// It opens with gossip off (localrelay.Options.Gossip's zero value). A one-shot
// command writes LOCALLY; sending is the explicit path — `content publish`, a
// `--peer` argument, `login`. Without that, ingesting an operation would run the
// sequencer, and the sequencer would push the operation to every registered peer
// as a side effect of the local write, in goroutines racing process exit, with
// the command reporting publishedTo:null the whole time.
func getRelay() (*localrelay.LocalRelay, error) {
	if localRelayInstance != nil {
		return localRelayInstance, nil
	}
	var err error
	localRelayInstance, err = localrelay.Open(cfg, &localrelay.Options{Logger: quietRelayLogger()})
	if err != nil {
		return nil, fmt.Errorf("open local relay: %w", err)
	}
	return localRelayInstance, nil
}

// overrides packages this invocation's selectors for the shared resolver. Every
// site that needs a principal goes through here — there are no site-local
// variants of the stack.
func overrides() config.Overrides {
	return config.Overrides{As: asFlag, Identity: identityFlag, Ctx: ctxFlag, Relay: relayFlag, Peer: peerFlag}
}

// resolveCtx resolves the current (identity, peer) pair from flags/env/config.
func resolveCtx() (*config.ResolvedContext, error) {
	return config.ResolveContext(cfg, overrides())
}

// requirePeer resolves the pair and ensures a peer is configured. peerOverride
// is a command-local --peer flag, which sits at the flag tier like the global one.
func requirePeer(peerOverride string) (*config.ResolvedContext, *client.Client, error) {
	ov := overrides()
	if peerOverride != "" {
		ov.Peer = peerOverride
	}
	ctx, err := config.ResolveContext(cfg, ov)
	if err != nil {
		return nil, nil, err
	}
	if ctx.RelayURL == "" {
		return nil, nil, errNoPeer()
	}
	// Same gate getPeerClient applies: a resolved peer name means the identity
	// config pinned to that name, not merely the URL parked under it.
	if err := verifyPeerPin(ctx.RelayName); err != nil {
		return nil, nil, err
	}
	c := client.New(ctx.RelayURL)
	c.Peer = ctx.RelayName
	return ctx, c, nil
}

// errNoIdentity is the distinguishable "anonymous, and this command cannot be"
// error. It names all three mechanisms because the fix is always one of exactly
// three things, and a signing command that fell back to some ambient default
// instead would be the failure this stack exists to prevent.
func errNoIdentity() error {
	return fmt.Errorf("no identity to sign with — name one:\n" +
		"  --as <name|did>                             for this invocation\n" +
		"  DFOS_AS=<name|did>                          for this environment\n" +
		"  dfos config set default-identity <name|did> as the standing default")
}

// errNoPeer is the peer-side twin of errNoIdentity, same three-mechanism shape.
func errNoPeer() error {
	return fmt.Errorf("no peer to talk to — name one:\n" +
		"  --relay <name>                          for this invocation\n" +
		"  DFOS_RELAY=<name>                       for this environment\n" +
		"  dfos config set default-peer <name>     as the standing default\n" +
		"Register a peer first with 'dfos peer add <name> <url>'.")
}

// announceSigner echoes the resolved principal, and the mechanism it resolved
// through, to stderr before anything is signed. Signing under an identity the
// operator did not see named is the ambient-authority failure this whole stack
// is built against, so the line is on by default and off only under --quiet.
// stderr keeps it out of --json's single stdout document.
func announceSigner(ctx *config.ResolvedContext) {
	if quietFlag || signerAnnounced || !ctx.HasIdentity() {
		return
	}
	signerAnnounced = true
	label := ctx.Principal()
	if ctx.IdentityName != "" && ctx.IdentityDID != "" {
		label = fmt.Sprintf("%s (%s)", ctx.IdentityName, ctx.IdentityDID)
	}
	fmt.Fprintf(os.Stderr, "Signing as %s — via %s\n", label, ctx.IdentitySource)
}

// requireIdentity resolves the signing principal and ensures its chain is
// available in the local relay. This is the choke point every signing command
// passes through: it resolves once, announces once, and refuses anonymously.
func requireIdentity() (*config.ResolvedContext, *relay.StoredIdentityChain, error) {
	ctx, err := resolveCtx()
	if err != nil {
		return nil, nil, err
	}
	if !ctx.HasIdentity() {
		return nil, nil, errNoIdentity()
	}
	if ctx.IdentityDID == "" {
		return nil, nil, fmt.Errorf("identity '%s' not found in config (from %s)", ctx.IdentityName, ctx.IdentitySource)
	}
	return loadSigningChain(ctx)
}

// requireIdentityTarget is requireIdentity with an optional TYPED target in
// front of the resolution stack: `identity update <name> --rotate-auth` acts on
// <name>, not on whatever --as / DFOS_AS / default-identity happens to resolve
// to. A positional target is the most explicit statement of intent the command
// line has, so it outranks every ambient tier — and the announce line names
// "positional argument" as the mechanism, so which identity is about to be
// signed for is never inferred from a default the operator cannot see.
//
// With no positional, resolution is exactly requireIdentity's.
func requireIdentityTarget(args []string) (*config.ResolvedContext, *relay.StoredIdentityChain, error) {
	if len(args) == 0 {
		return requireIdentity()
	}
	did, err := resolveIdentityDID(args[0])
	if err != nil {
		return nil, nil, err
	}
	// Only the identity half is overridden. The peer half still resolves
	// through the ordinary stack, so --peer/--relay keep working alongside a
	// typed target.
	ctx := &config.ResolvedContext{}
	if resolved, err := resolveCtx(); err == nil && resolved != nil {
		ctx.RelayName, ctx.RelayURL, ctx.RelaySource = resolved.RelayName, resolved.RelayURL, resolved.RelaySource
	}
	ctx.IdentityDID = did
	ctx.IdentityName = config.FindIdentityName(cfg, did)
	ctx.IdentitySource = config.SourcePositionalTarget
	return loadSigningChain(ctx)
}

// loadSigningChain is the shared tail of both: fetch the chain, refuse a
// missing or deleted one, and announce the principal before anything is signed.
func loadSigningChain(ctx *config.ResolvedContext) (*config.ResolvedContext, *relay.StoredIdentityChain, error) {
	lr, err := getRelay()
	if err != nil {
		return nil, nil, err
	}
	chain, err := lr.Relay.GetIdentity(ctx.IdentityDID)
	if err != nil {
		return nil, nil, err
	}
	if chain == nil {
		return nil, nil, fmt.Errorf("identity '%s' not found in local relay", ctx.Principal())
	}
	if chain.State.IsDeleted {
		return nil, nil, fmt.Errorf("identity '%s' is deleted — cannot sign operations", ctx.Principal())
	}
	announceSigner(ctx)
	return ctx, chain, nil
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
	var showStore bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show current context, identity, and relay status",
		RunE: func(cmd *cobra.Command, args []string) error {
			var store *localStoreStatus
			if showStore {
				var err error
				store, err = readLocalStoreStatus()
				if err != nil {
					return err
				}
			}
			ctx, ctxErr := resolveCtx()

			// No usable identity: distinguish a BROKEN selector (something was
			// named but won't resolve) from nothing-selected, instead of telling
			// a user with identities that they have none.
			if !ctx.HasIdentity() {
				if ctxErr != nil {
					if jsonFlag {
						out := map[string]any{"resolved": false, "error": ctxErr.Error()}
						if store != nil {
							out["store"] = store
						}
						outputJSON(out)
						return nil
					}
					fmt.Printf("Cannot resolve a context: %s\n", ctxErr)
					fmt.Printf("Add the peer via 'dfos peer add <name> <url>', or run 'dfos identity list'.\n")
					printLocalStoreStatus(store)
					return nil
				}
				if jsonFlag {
					out := map[string]any{"context": nil, "resolved": false, "identity": nil}
					if store != nil {
						out["store"] = store
					}
					outputJSON(out)
					return nil
				}
				if len(cfg.Identities) == 0 {
					fmt.Println("No identity selected. Use 'dfos identity create --name <name>' to begin.")
				} else {
					fmt.Println("No identity selected. Pass --as <name|did>, set DFOS_AS, or run 'dfos config set default-identity <name|did>' (see 'dfos identity list').")
				}
				printLocalStoreStatus(store)
				return nil
			}

			lr, relayErr := getRelay()
			var chain *relay.StoredIdentityChain
			if relayErr == nil && ctx.IdentityDID != "" {
				chain, _ = lr.Relay.GetIdentity(ctx.IdentityDID)
			}

			contextStr := ctx.Principal() + " (local only)"
			if ctx.RelayName != "" {
				contextStr = ctx.Principal() + "@" + ctx.RelayName
			}

			// Fetch peer health once; both the JSON and human paths render it.
			var info *client.RelayInfo
			var infoErr error
			if ctx.RelayURL != "" {
				info, infoErr = client.New(ctx.RelayURL).GetRelayInfo()
			}

			if jsonFlag {
				status := map[string]any{
					"context":      contextStr,
					"resolved":     true,
					"identity":     ctx.IdentityDID,
					"identityName": ctx.IdentityName,
					"peer":         ctx.RelayURL,
					"peerName":     ctx.RelayName,
				}
				if chain != nil {
					status["operations"] = len(chain.Log)
				}
				if ctx.RelayURL != "" {
					relayObj := map[string]any{"reachable": infoErr == nil}
					if infoErr == nil {
						relayObj["did"] = info.DID
						relayObj["protocol"] = info.Protocol
						relayObj["version"] = info.Version
						relayObj["content"] = info.Content
						relayObj["proof"] = info.Proof
						relayObj["write"] = info.Write
					} else {
						relayObj["error"] = infoErr.Error()
					}
					status["relay"] = relayObj
				}
				if store != nil {
					status["store"] = store
				}
				outputJSON(status)
				return nil
			}

			fmt.Printf("Context:   %s\n", contextStr)
			if chain != nil {
				fmt.Printf("Identity:  %s (%s)\n", chain.DID, ctx.Principal())
				totalKeys := len(distinctKeyIDs(chain))
				haveKeys := countKeysInChain(chain)
				fmt.Printf("  Keys:    %d/%d (%s)\n", haveKeys, totalKeys, keys.Backend())
				fmt.Printf("  Chain:   %d operation(s)\n", len(chain.Log))
			} else {
				fmt.Printf("Identity:  %s (%s) — not in local relay\n", ctx.IdentityDID, ctx.Principal())
			}
			fmt.Printf("  Via:     %s\n", ctx.IdentitySource)

			if ctx.RelayURL != "" {
				label := ctx.RelayURL
				if r, ok := cfg.Relays[ctx.RelayName]; ok && r.ProfileName != "" {
					label = r.ProfileName + " (" + ctx.RelayURL + ")"
				}
				fmt.Printf("Peer:      %s\n", label)
				if infoErr == nil {
					fmt.Printf("  DID:     %s\n", info.DID)
					fmt.Printf("  Version: %s %s\n", info.Protocol, info.Version)
					fmt.Printf("  Content: %s  Proof: %s  Write: %s\n", boolYesNo(info.Content), boolYesNo(info.Proof), boolYesNo(info.Write))
				} else {
					fmt.Printf("  Error:   %s\n", infoErr)
				}
			}
			printLocalStoreStatus(store)
			return nil
		},
	}
	cmd.Flags().BoolVar(&showStore, "store", false, "Also show local relay store statistics")
	return cmd
}

type localStoreStatus struct {
	Path         string         `json:"path"`
	SizeBytes    int64          `json:"sizeBytes"`
	OpCount      int            `json:"opCount"`
	CountsByKind map[string]int `json:"countsByKind"`
	Unsequenced  int            `json:"unsequenced"`
}

func readLocalStoreStatus() (*localStoreStatus, error) {
	lr, err := getRelay()
	if err != nil {
		return nil, err
	}
	stats, err := lr.Store.RelayStats()
	if err != nil {
		return nil, fmt.Errorf("read local relay stats: %w", err)
	}
	unsequenced, err := lr.Store.CountUnsequenced()
	if err != nil {
		return nil, fmt.Errorf("count pending local relay operations: %w", err)
	}
	info, err := os.Stat(lr.DBPath())
	if err != nil {
		return nil, fmt.Errorf("stat local relay database: %w", err)
	}
	return &localStoreStatus{
		Path:         lr.DBPath(),
		SizeBytes:    info.Size(),
		OpCount:      stats.OpCount,
		CountsByKind: stats.CountsByKind,
		Unsequenced:  unsequenced,
	}, nil
}

func printLocalStoreStatus(store *localStoreStatus) {
	if store == nil {
		return
	}
	fmt.Printf("Store:     %s\n", store.Path)
	fmt.Printf("  Size:    %d byte(s)\n", store.SizeBytes)
	fmt.Printf("  Ops:     %d operation(s)\n", store.OpCount)
	fmt.Printf("  Pending: %d raw operation(s)\n", store.Unsequenced)
	fmt.Printf("  Kinds:   identity=%d content=%d artifact=%d credential=%d countersign=%d revocation=%d\n",
		store.CountsByKind["identity"], store.CountsByKind["content"], store.CountsByKind["artifact"],
		store.CountsByKind["credential"], store.CountsByKind["countersign"], store.CountsByKind["revocation"])
}

// newUseTombstoneCmd is what is left of `dfos use`. The command is gone: there
// is no mutable active context to set, because a pointer two processes both
// read and one of them writes is a race, and running parallel agents under
// different identities is the normal case now. The tombstone exists only so the
// removal reads as a removal — a bare "unknown command" would leave an operator
// guessing where the mechanism went — and it is hidden from help so nothing
// teaches it. It signs nothing, writes nothing, and always fails.
func newUseTombstoneCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "use [identity[@peer]]",
		Hidden: true,
		Args:   cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("`dfos use` is removed — there is no mutable active context to set.\n" +
				"Select an identity per invocation with --as <name|did> or DFOS_AS, or set the standing default with 'dfos config set default-identity <name|did>'.")
		},
	}
}

// helpers

// didFromKid extracts the DID from a KID string (did:dfos:abc#key_123 → did:dfos:abc).
// Returns the full kid if no '#' separator is found.
func didFromKid(kid string) string {
	if idx := strings.Index(kid, "#"); idx > 0 {
		return kid[:idx]
	}
	return kid
}

// distinctChainKeys returns the unique keys across all role sets, in
// controller→auth→assert order. The production shape is ONE physical key bound to
// all three roles — that is what `identity create` mints — so counting per-role
// membership made a single-key identity read "0/3" (or "3/3"); tallies dedupe by
// id and report it as "0/1" / "1/1".
func distinctChainKeys(chain *relay.StoredIdentityChain) []protocol.MultikeyPublicKey {
	seen := map[string]bool{}
	var out []protocol.MultikeyPublicKey
	add := func(set []protocol.MultikeyPublicKey) {
		for _, k := range set {
			if !seen[k.ID] {
				seen[k.ID] = true
				out = append(out, k)
			}
		}
	}
	add(chain.State.ControllerKeys)
	add(chain.State.AuthKeys)
	add(chain.State.AssertKeys)
	return out
}

// distinctKeyIDs is distinctChainKeys reduced to ids, for display.
func distinctKeyIDs(chain *relay.StoredIdentityChain) []string {
	dk := distinctChainKeys(chain)
	ids := make([]string, 0, len(dk))
	for _, k := range dk {
		ids = append(ids, k.ID)
	}
	return ids
}

// countKeysInChain counts the distinct keys this device actually holds.
func countKeysInChain(chain *relay.StoredIdentityChain) int {
	count := 0
	for _, k := range distinctChainKeys(chain) {
		if holdsDeclaredKey(chain.DID, k) {
			count++
		}
	}
	return count
}

// selectHeldKey returns the first key in set whose private material this device
// holds locally — its kid for the signature, and the account its seed is under.
// This is the spine of multi-device 1-of-N availability: any one held key in a
// role set is enough to act, so the signer side iterates the published set and
// picks the first one this device actually has. role is used only for the error
// message. Returns an error (never panics) when the set is empty or this device
// holds none of the keys.
func selectHeldKey(did string, set []protocol.MultikeyPublicKey, role string) (heldKey, error) {
	for _, k := range set {
		if account, held := heldKeyAccount(did, k.ID, k.PublicKeyMultibase); held {
			return heldKey{KID: did + "#" + k.ID, Account: account, PublicKey: k.PublicKeyMultibase}, nil
		}
	}
	return heldKey{}, fmt.Errorf("no held %s key for %s on this device (holds none of %d published %s key(s))", role, did, len(set), role)
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
