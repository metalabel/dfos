package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/localrelay"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
	"github.com/spf13/cobra"
)

// contentReconcileIntervalMultiple sets the content-follow backstop cadence as a
// multiple of the sync interval. Per-tick materialization/GC is event-driven (the
// sequencer marks dirty contentIDs; trigger-kicks drain them), so this whole-corpus
// reconcile is only defense-in-depth against a missed mark — it runs deliberately
// slowly so a steady-state follower stays idle between real changes instead of
// re-scanning every chain and re-verifying every grant on each tick.
const contentReconcileIntervalMultiple = 60

func newServeCmd() *cobra.Command {
	var port string
	var syncInterval string
	var dbPath string
	var relayName string
	var peers string
	var resync bool
	var noWrite bool
	var noIndex bool
	var contentFollow string
	var authority string
	var ingestion string
	var gossipProof bool
	var noSync bool

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start HTTP server on the local relay",
		Long: `Expose your local relay over HTTP so other peers can sync with you.
Your machine becomes a reachable node in the DFOS network.

Authenticated routes — blob upload, non-public blob download, the mailbox poll —
consume an identity proof bound to this relay's own host. Set --authority to the
host callers reach you at, or those routes answer 503: the binding is yours to
declare and is never read off a request.

All flags support environment variable fallbacks for container deployment:
  PORT, SQLITE_PATH, RELAY_NAME, PEERS, RESYNC, NO_SYNC, SYNC_INTERVAL,
  CONTENT_FOLLOW, INDEX, WRITE, AUTHORITY, INGESTION, GOSSIP_PROOF`,
		// A long-lived daemon must not hold the process-wide state lock (it
		// would block every other dfos invocation for its entire run).
		Annotations: map[string]string{annNoStateLock: "true"},
		RunE: func(cmd *cobra.Command, args []string) error {
			// env-var fallbacks for container deployment
			if !cmd.Flags().Changed("port") {
				if v := os.Getenv("PORT"); v != "" {
					port = v
				}
			}
			if !cmd.Flags().Changed("db") {
				if v := os.Getenv("SQLITE_PATH"); v != "" {
					dbPath = v
				}
			}
			if !cmd.Flags().Changed("name") {
				if v := os.Getenv("RELAY_NAME"); v != "" {
					relayName = v
				}
			}
			if !cmd.Flags().Changed("peers") {
				if v := os.Getenv("PEERS"); v != "" {
					peers = v
				}
			}
			if !cmd.Flags().Changed("resync") {
				if os.Getenv("RESYNC") == "true" {
					resync = true
				}
			}
			if !cmd.Flags().Changed("sync-interval") {
				if v := os.Getenv("SYNC_INTERVAL"); v != "" {
					syncInterval = v
				}
			}
			if !cmd.Flags().Changed("content-follow") {
				if v := os.Getenv("CONTENT_FOLLOW"); v != "" {
					contentFollow = v
				}
			}
			if !cmd.Flags().Changed("no-index") {
				if os.Getenv("INDEX") == "false" {
					noIndex = true
				}
			}
			if !cmd.Flags().Changed("authority") {
				if v := os.Getenv("AUTHORITY"); v != "" {
					authority = v
				}
			}
			if !cmd.Flags().Changed("ingestion") {
				if v := os.Getenv("INGESTION"); v != "" {
					ingestion = v
				}
			}
			if !cmd.Flags().Changed("gossip-proof") {
				if os.Getenv("GOSSIP_PROOF") == "true" {
					gossipProof = true
				}
			}
			if !cmd.Flags().Changed("no-sync") {
				if os.Getenv("NO_SYNC") == "true" {
					noSync = true
				}
			}
			// WRITE=false, not NO_WRITE=true, because this flag toggles an
			// ADVERTISED CAPABILITY: the well-known's capabilities.write, exactly
			// as INDEX=false toggles capabilities.index. NO_SYNC keeps its negative
			// form because syncing is a local behavior with no capability to name.
			if !cmd.Flags().Changed("no-write") {
				if os.Getenv("WRITE") == "false" {
					noWrite = true
				}
			}

			interval, err := time.ParseDuration(syncInterval)
			if err != nil {
				return fmt.Errorf("invalid sync interval: %w", err)
			}

			// Reject an unknown admission mode loudly rather than silently
			// serving a different one than the operator asked for.
			switch ingestion {
			case "", relay.IngestionOpen, relay.IngestionProofRequired, relay.IngestionClosed:
			default:
				return fmt.Errorf("invalid --ingestion %q (expected: open|proof-required|closed)", ingestion)
			}

			// content-follow accepts none|eager today ("lazy" is reserved). Reject
			// anything else loudly rather than silently disabling on a typo.
			switch contentFollow {
			case "", "none", "eager":
			default:
				return fmt.Errorf("invalid --content-follow %q (expected: none|eager)", contentFollow)
			}

			// parse extra peers from flag/env (comma-separated URLs, a JSON array
			// of URLs, or a JSON array of per-peer objects)
			extraPeers, err := parsePeers(peers)
			if err != nil {
				return fmt.Errorf("invalid --peers/PEERS: %w", err)
			}

			// set up structured JSON logging for server mode
			slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			})))

			// open relay with serve-specific options
			opts := &localrelay.Options{
				DBPath:        dbPath,
				ProfileName:   relayName,
				ExtraPeers:    extraPeers,
				ContentFollow: contentFollow,
				Authority:     authority,
				Ingestion:     ingestion,
				// The one command that gossips. `serve` is the mesh participant:
				// relaying what it sequences is what makes it a node rather than a
				// private store, so here each peer's own `gossip` switch decides.
				// Every one-shot command opens the same relay with this false, and
				// a local write stays local.
				Gossip: true,
			}
			if gossipProof {
				opts.GossipIdentityProof = &gossipProof
			}
			// LITE pull-only node: reject POST /operations, sync from peers only.
			if noWrite {
				writeDisabled := false
				opts.Write = &writeDisabled
			}
			if noIndex {
				indexDisabled := false
				opts.Index = &indexDisabled
			}

			// The pin, before the loop that runs on it. `serve` is the one command
			// that talks to peers continuously, in every direction, for as long as
			// the process lives — so its registered peers get exactly the treatment
			// `dfos sync` gives them: an unpinned entry is pinned to whoever answers
			// first, and a pin that moved refuses the boot rather than starting a
			// mesh node against a relay that is not the one this machine registered.
			// Config writes live here and only here; the relay library enforces the
			// pin it is handed and never mints one.
			if err := verifyConfiguredPeerPins(); err != nil {
				return err
			}

			// close any existing lazy-opened relay (serve uses its own opts)
			if localRelayInstance != nil {
				localRelayInstance.Close()
				localRelayInstance = nil
			}

			lr, err := localrelay.Open(cfg, opts)
			if err != nil {
				return fmt.Errorf("open relay: %w", err)
			}
			localRelayInstance = lr // so PersistentPostRun closes it

			// resync on boot — reset peer cursors + sequencer for full re-pull
			if resync {
				fmt.Println("RESYNC — resetting peer cursors and sequencer")
				lr.Store.ResetPeerCursors()
				lr.Store.ResetSequencer()
			}

			fmt.Printf("DFOS relay serving (%s)\n", relay.Version)
			fmt.Printf("  DID:    %s\n", lr.Relay.DID())
			fmt.Printf("  Port:   %s\n", port)
			if noSync {
				fmt.Printf("  Sync:   OFF (--no-sync) — this node pulls from no peer\n")
			} else {
				fmt.Printf("  Sync:   every %s\n", interval)
			}
			if authority != "" {
				fmt.Printf("  Host:   %s\n", authority)
			} else {
				fmt.Printf("  Host:   (unset — authenticated routes answer 503; pass --authority)\n")
			}
			if ingestion != "" {
				fmt.Printf("  Ingest: %s\n", ingestion)
			}

			// The peer banner. "Peers: N configured" alone said nothing about what
			// this boot is about to DO with them, and the first thing it does is
			// pull every one of their logs. What gets synced is named here, before
			// the sync loop starts, because a boot that drags a peer's whole corpus
			// onto the machine should have announced it was going to.
			peerCount := len(cfg.Relays) + len(extraPeers)
			if peerCount > 0 {
				fmt.Printf("  Peers:  %d configured\n", peerCount)
				var willSync []string
				names := make([]string, 0, len(cfg.Relays))
				for name := range cfg.Relays {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					r := cfg.Relays[name]
					pc := localrelay.PeerConfigFor(r)
					fmt.Printf("    - %s (%s)%s\n", name, r.URL, peerFlagSuffix(pc))
					if syncEnabled(pc) {
						willSync = append(willSync, name)
					}
				}
				for _, p := range extraPeers {
					fmt.Printf("    - %s%s\n", p.URL, peerFlagSuffix(p))
					if syncEnabled(p) {
						willSync = append(willSync, p.URL)
					}
				}
				switch {
				case noSync:
					fmt.Printf("  Pull:   none — --no-sync, so this node serves what it already holds\n")
				case len(willSync) == 0:
					fmt.Printf("  Pull:   none — every configured peer has sync turned off\n")
				default:
					fmt.Printf("  Pull:   will sync %d peer(s) now and every %s: %s\n",
						len(willSync), interval, strings.Join(willSync, ", "))
				}
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// background sync loop. --no-sync starts no loop at all: a node that
			// pulls nothing still serves, still ingests submissions, and still
			// gossips what it sequenced — it just does not reach for a peer's log.
			if !noSync {
				go func() {
					if err := lr.Relay.SyncFromPeers(); err != nil {
						fmt.Fprintf(os.Stderr, "sync error: %v\n", err)
					}
					ticker := time.NewTicker(interval)
					defer ticker.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
							if err := lr.Relay.SyncFromPeers(); err != nil {
								fmt.Fprintf(os.Stderr, "sync error: %v\n", err)
							}
						}
					}
				}()
			}

			// background sequencer
			go func() {
				ticker := time.NewTicker(interval)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						lr.Relay.RunSequencerAndGossip()
					}
				}
			}()

			if contentFollow == "eager" {
				// Fast drain (eager mode only): every tick, drain whatever the
				// sequencer marked dirty. The sweeps are near-instant no-ops when the
				// queues are empty (a TryLock + empty-queue check, never a corpus
				// scan), so running them every tick is cheap AND robust — it drains
				// marks made by ANY sequencing path: a peer pull, a gossip-push receive,
				// or a direct client write. A sequence-count-gated trigger missed the
				// last two because those ops are already sequenced before the next tick.
				go func() {
					ticker := time.NewTicker(interval)
					defer ticker.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
							lr.Relay.MaterializeFollowedContent()
							lr.Relay.GCRevokedContent()
						}
					}
				}()

				// Convergent backstop: a boot pass catches up every grant/revocation
				// already synced before the process started, then a slow periodic full
				// reconcile (contentReconcileIntervalMultiple) guarantees convergence
				// regardless of which dirty marks the fast path recorded. Deliberately
				// slow defense-in-depth — a steady-state follower stays idle between
				// real changes. Sequencer-independent: it only acts on chains already in
				// local state, so op-ingest ordering can't race it.
				go func() {
					lr.Relay.ReconcileFollowedContent()
					ticker := time.NewTicker(interval * contentReconcileIntervalMultiple)
					defer ticker.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
							lr.Relay.ReconcileFollowedContent()
						}
					}
				}()
			}

			srv := &http.Server{
				Addr:    ":" + port,
				Handler: lr.Relay.Handler(),
				// Slowloris guard: bound how long a client may take to send the
				// request headers, and how long an idle keep-alive connection
				// may linger. NOT setting ReadTimeout/WriteTimeout — large blob
				// uploads and long /log reads are legitimately slow, and a tight
				// write deadline would truncate them.
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       120 * time.Second,
			}

			go func() {
				sigCh := make(chan os.Signal, 1)
				signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
				<-sigCh
				fmt.Println("\nshutting down...")
				cancel()
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer shutdownCancel()
				srv.Shutdown(shutdownCtx)
			}()

			if err := srv.ListenAndServe(); err != http.ErrServerClosed {
				return fmt.Errorf("server error: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&port, "port", "4444", "Port to listen on (env: PORT)")
	cmd.Flags().StringVar(&syncInterval, "sync-interval", "30s", "Peer sync interval (env: SYNC_INTERVAL)")
	cmd.Flags().StringVar(&dbPath, "db", "", "Database path (env: SQLITE_PATH, default: ~/.dfos/relay.db)")
	cmd.Flags().StringVar(&relayName, "name", "DFOS Relay", "Relay profile name (env: RELAY_NAME)")
	cmd.Flags().StringVar(&peers, "peers", "", "Peer URLs: comma-separated, a JSON array of URLs, or a JSON array of {url,gossip,readThrough,sync} objects (env: PEERS)")
	cmd.Flags().BoolVar(&resync, "resync", false, "Reset peer cursors for full re-sync on boot (env: RESYNC)")
	cmd.Flags().BoolVar(&noSync, "no-sync", false, "Do not pull any peer's log: serve and ingest, but boot local-only (env: NO_SYNC=true)")
	cmd.Flags().BoolVar(&noWrite, "no-write", false, "LITE pull-only node: reject POST /operations, sync from peers only (env: WRITE=false)")
	cmd.Flags().BoolVar(&noIndex, "no-index", false, "Disable /index/v0 routes: advertise index:false and return 501 (env: INDEX=false)")
	cmd.Flags().StringVar(&contentFollow, "content-follow", "none", "Materialize granted public content blobs from peers: none|eager (env: CONTENT_FOLLOW)")
	cmd.Flags().StringVar(&authority, "authority", "", "This relay's own host[:port] — the host identity proofs bind (env: AUTHORITY; unset: authenticated routes answer 503)")
	cmd.Flags().StringVar(&ingestion, "ingestion", "", "Admission mode for POST /operations: open|proof-required|closed (env: INGESTION, default: open, or closed with --no-write)")
	cmd.Flags().BoolVar(&gossipProof, "gossip-proof", false, "Sign gossip-out pushes with this relay's identity proof (env: GOSSIP_PROOF)")
	return cmd
}

// peerSpec is the JSON object form of one entry in --peers / PEERS. It mirrors
// relay.PeerConfig's per-peer switches; a nil flag means "default" (enabled).
//
// DID is the identity pin: the DID this peer must keep serving for the entry to
// go on meaning the relay it was written against. Only the object form can carry
// one, because only the object form says anything about a peer beyond its
// address — a bare URL, in either of the other two spellings, makes no claim
// about identity and stays unpinned.
type peerSpec struct {
	URL         string `json:"url"`
	DID         string `json:"did"`
	Gossip      *bool  `json:"gossip"`
	ReadThrough *bool  `json:"readThrough"`
	Sync        *bool  `json:"sync"`
}

// parsePeers parses --peers / PEERS into peer configs. Three accepted forms:
//
//	https://a.example,https://b.example            comma-separated URLs
//	["https://a.example","https://b.example"]      JSON array of URLs
//	[{"url":"https://a.example","gossip":false}]   JSON array of per-peer objects
//
// The object form additionally carries `did`, the peer's identity pin.
//
// Anything starting with "[" is JSON and MUST parse as JSON: the earlier silent
// fallback to comma-splitting turned a malformed (or object-form) array into a
// list of garbage "peers" that then failed every sync tick for the life of the
// process. Peer URLs are validated here so a bad config fails at boot, loudly,
// instead of becoming a permanent error loop.
func parsePeers(s string) ([]relay.PeerConfig, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}

	var peers []relay.PeerConfig
	if strings.HasPrefix(s, "[") {
		var entries []json.RawMessage
		if err := json.Unmarshal([]byte(s), &entries); err != nil {
			return nil, fmt.Errorf("not a valid JSON array: %w", err)
		}
		for i, entry := range entries {
			trimmed := strings.TrimSpace(string(entry))
			if strings.HasPrefix(trimmed, `"`) {
				var u string
				if err := json.Unmarshal(entry, &u); err != nil {
					return nil, fmt.Errorf("peer %d: %w", i, err)
				}
				peers = append(peers, relay.PeerConfig{URL: strings.TrimSpace(u)})
				continue
			}
			// Unknown fields are rejected rather than ignored — a typo'd flag
			// would otherwise silently keep the default (enabled), which is the
			// exact failure this function exists to prevent.
			dec := json.NewDecoder(strings.NewReader(trimmed))
			dec.DisallowUnknownFields()
			var spec peerSpec
			if err := dec.Decode(&spec); err != nil {
				return nil, fmt.Errorf("peer %d: %w", i, err)
			}
			peers = append(peers, relay.PeerConfig{
				URL:         strings.TrimSpace(spec.URL),
				DID:         strings.TrimSpace(spec.DID),
				Gossip:      spec.Gossip,
				ReadThrough: spec.ReadThrough,
				Sync:        spec.Sync,
			})
		}
	} else {
		for _, u := range strings.Split(s, ",") {
			if u = strings.TrimSpace(u); u != "" {
				peers = append(peers, relay.PeerConfig{URL: u})
			}
		}
		// An explicit "[]" legitimately means "no peers"; a non-empty
		// comma-separated value that yields none is a typo, not an intent.
		if len(peers) == 0 {
			return nil, fmt.Errorf("no peer URLs in %q", s)
		}
	}

	for i := range peers {
		// Trailing slashes would make every peer path "…//proof/v1/log".
		peers[i].URL = strings.TrimRight(peers[i].URL, "/")
		if err := validatePeerURL(peers[i].URL); err != nil {
			return nil, fmt.Errorf("peer %d: %w", i, err)
		}
	}
	return peers, nil
}

// validatePeerURL rejects anything that is not an absolute http(s) base URL.
// Peer URLs are concatenated with request paths (peerURL + "/proof/v1/log"),
// so a relative or scheme-less value yields a request that can never succeed —
// and so does a query or fragment, which would swallow the appended path
// ("https://relay.example?t=x" + "/proof/v1/log" requests "/" with a garbage
// query). Both are the permanent-error-loop failure this validation exists to
// prevent, so both are rejected at boot.
func validatePeerURL(raw string) error {
	if raw == "" {
		return errors.New("empty peer URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid peer URL %q: %w", raw, err)
	}
	if u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("invalid peer URL %q: want an absolute http(s) URL", raw)
	}
	// Checked against the raw string so a bare "?" or "#" (which parse to empty
	// RawQuery/Fragment) is caught too.
	if strings.ContainsAny(raw, "?#") {
		return fmt.Errorf("invalid peer URL %q: want a base URL with no query or fragment", raw)
	}
	return nil
}

// verifyConfiguredPeerPins runs the pin gate over every registered peer `serve`
// is about to run its loop against, in sorted name order so the boot output (and
// the first failure on a machine with several moved pins) is the same on every
// run.
//
// Every peer, not just the sync-eligible ones: a peer with `sync = false` is
// still gossiped to and still read through, and both of those reach the peer.
// The `--peers` entries are deliberately NOT here — they are supplied for this
// run and carry their pin inline, so there is no config.toml entry to trust on
// first use and nothing to write.
func verifyConfiguredPeerPins() error {
	names := make([]string, 0, len(cfg.Relays))
	for name := range cfg.Relays {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if cfg.Relays[name].URL == "" {
			continue
		}
		if err := verifyPeerPin(name); err != nil {
			return err
		}
	}
	return nil
}

// syncEnabled reports whether this peer is one `serve` will pull a log from. A
// nil switch means on, which is what a config entry written without the key and
// a --peers URL with no object form both say.
func syncEnabled(p relay.PeerConfig) bool {
	return p.Sync == nil || *p.Sync
}

// peerFlagSuffix renders a peer's non-default switches for the boot banner, so
// a `"gossip":false` in PEERS is visible at startup instead of silently applied.
func peerFlagSuffix(p relay.PeerConfig) string {
	var off []string
	if p.Gossip != nil && !*p.Gossip {
		off = append(off, "gossip")
	}
	if p.ReadThrough != nil && !*p.ReadThrough {
		off = append(off, "readThrough")
	}
	if p.Sync != nil && !*p.Sync {
		off = append(off, "sync")
	}
	if len(off) == 0 {
		return ""
	}
	return " (disabled: " + strings.Join(off, ", ") + ")"
}
