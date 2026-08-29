package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/spf13/cobra"
)

func newPeerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "peer",
		Short:   "Manage named peers (remote relays)",
		Aliases: []string{"relay"},
		GroupID: "peer",
	}
	cmd.AddCommand(newPeerAddCmd())
	cmd.AddCommand(newPeerRepinCmd())
	cmd.AddCommand(newPeerRemoveCmd())
	cmd.AddCommand(newPeerListCmd())
	cmd.AddCommand(newPeerInfoCmd())
	cmd.AddCommand(newRelayCallCmd())
	cmd.AddCommand(newRelayGCCmd())
	return cmd
}

type relayGCResult struct {
	Path       string `json:"path"`
	SizeBefore int64  `json:"sizeBefore"`
	SizeAfter  int64  `json:"sizeAfter"`
}

func newRelayGCCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "gc",
		Short: "Reclaim revoked follower blobs and compact the local relay database",
		RunE: func(cmd *cobra.Command, args []string) error {
			lr, err := getRelay()
			if err != nil {
				return err
			}
			before, err := os.Stat(lr.DBPath())
			if err != nil {
				return fmt.Errorf("stat local relay database before GC: %w", err)
			}

			// This is the same follower-blob GC sweep serve invokes. Its API does
			// not report a removal count, and it is a no-op unless this relay was
			// opened in eager content-follow mode.
			lr.Relay.GCRevokedContent()
			if err := lr.Vacuum(); err != nil {
				return err
			}

			after, err := os.Stat(lr.DBPath())
			if err != nil {
				return fmt.Errorf("stat local relay database after GC: %w", err)
			}
			result := relayGCResult{Path: lr.DBPath(), SizeBefore: before.Size(), SizeAfter: after.Size()}
			if jsonFlag {
				outputJSON(result)
			} else {
				fmt.Printf("Local relay GC complete: %s\n", result.Path)
				fmt.Printf("  Before: %d byte(s)\n", result.SizeBefore)
				fmt.Printf("  After:  %d byte(s)\n", result.SizeAfter)
			}
			return nil
		},
	}
}

// newPeerAddCmd registers a peer. Registration is metadata and posture — it
// fetches the peer's well-known and writes the entry. It does NOT pull the
// peer's log: a fresh registration never drags a corpus onto the machine as a
// side effect of being named. `dfos sync` is the command that pulls, and it
// answers to the switches this command writes.
func newPeerAddCmd() *cobra.Command {
	var noSync bool
	cmd := &cobra.Command{
		Use:   "add <name> <url>",
		Short: "Register a named peer (fetches and verifies metadata)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, url := args[0], args[1]

			rc := config.RelayConfig{URL: url}
			// Re-registering a peer refreshes its metadata; it does not silently
			// discard the posture the operator set for it. --no-sync is the one
			// thing that rewrites the sync switch here (--no-sync=false turns it
			// back on explicitly).
			if existing, ok := cfg.Relays[name]; ok {
				rc.Gossip, rc.ReadThrough, rc.Sync = existing.Gossip, existing.ReadThrough, existing.Sync
			}
			if cmd.Flags().Changed("no-sync") {
				enabled := !noSync
				rc.Sync = &enabled
			}

			c := client.New(url)
			info, err := c.GetRelayInfo()
			if err != nil {
				cfg.Relays[name] = rc
				if err := config.Save(cfg); err != nil {
					return err
				}
				if jsonFlag {
					outputJSON(map[string]any{
						"name":     name,
						"url":      url,
						"verified": false,
						"warning":  err.Error(),
						"sync":     config.BulkSyncDisabledReason(rc) == "",
					})
				} else {
					fmt.Printf("Peer '%s' added: %s\n", name, url)
					fmt.Printf("  Warning: could not verify peer: %s\n", err)
					printPeerSyncPosture(name, rc)
				}
				return nil
			}

			// Registering over an existing entry refreshes it. It does not MOVE
			// the pin: the same URL answering as a different DID is either a
			// re-keyed relay or a different relay, and which one it is decides
			// whether to trust it. `peer repin` is that decision, made out loud.
			// A changed URL is a new registration, so its pin is written fresh.
			if existing, ok := cfg.Relays[name]; ok &&
				existing.DID != "" && existing.DID != info.DID &&
				samePeerURL(existing.URL, url) {
				return errPeerPinMismatch(name, existing.DID, info.DID)
			}

			rc.DID = info.DID
			rc.Content = &info.Content
			rc.Proof = &info.Proof
			rc.Log = &info.Capabilities.Log

			profileName, profileValid := verifyPeerProfile(c, info)
			if profileName != "" {
				rc.ProfileName = profileName
			}

			cfg.Relays[name] = rc
			if err := config.Save(cfg); err != nil {
				return err
			}

			if jsonFlag {
				outputJSON(map[string]any{
					"name":         name,
					"url":          url,
					"did":          info.DID,
					"profileName":  profileName,
					"content":      info.Content,
					"proof":        info.Proof,
					"log":          info.Capabilities.Log,
					"write":        info.Write,
					"verified":     true,
					"profileValid": profileValid,
					"sync":         config.BulkSyncDisabledReason(rc) == "",
				})
			} else {
				label := info.DID
				if profileName != "" {
					label = profileName
				}
				fmt.Printf("Peer '%s' added: %s\n", name, url)
				fmt.Printf("  DID:     %s\n", info.DID)
				if profileName != "" {
					fmt.Printf("  Profile: %s\n", profileName)
				}
				fmt.Printf("  Content: %s\n", boolYesNo(info.Content))
				fmt.Printf("  Proof:   %s\n", boolYesNo(info.Proof))
				fmt.Printf("  Log:     %s\n", boolYesNo(info.Capabilities.Log))
				fmt.Printf("  Write:   %s\n", boolYesNo(info.Write))
				printPeerSyncPosture(name, rc)
				if profileValid {
					fmt.Printf("  Status:  verified (%s)\n", label)
				} else if info.Profile != "" {
					fmt.Printf("  Status:  profile signature could not be verified\n")
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&noSync, "no-sync", false, "Register without bulk log sync: write sync = false for this peer")
	return cmd
}

// printPeerSyncPosture states, at registration, whether this peer will be
// bulk-pulled — the thing that decides whether `dfos sync` drags the peer's
// whole corpus onto this machine. Printed either way: a posture that is only
// visible when it is unusual is a posture nobody checks.
func printPeerSyncPosture(name string, rc config.RelayConfig) {
	if reason := config.BulkSyncDisabledReason(rc); reason != "" {
		fmt.Printf("  Sync:    disabled — %s in %s\n", reason, config.ConfigPath())
		fmt.Printf("           Explicit fetches (identity fetch, publish, api call, login) are unaffected.\n")
		return
	}
	fmt.Printf("  Sync:    enabled — 'dfos sync --peer %s' pulls this peer's whole log\n", name)
}

// newPeerRepinCmd is the ONLY way a pin moves. Everything else either writes a
// pin where there was none (registration) or refuses to act against one that no
// longer matches — so the moment this machine starts trusting a different relay
// identity under a familiar name is a moment the operator chose.
func newPeerRepinCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "repin <name>",
		Short: "Pin a peer to the identity it serves now",
		Long: "Fetch a registered peer's well-known and pin its DID, replacing whatever DID was " +
			"pinned before. Run it when a peer legitimately changed identity, or to pin an entry " +
			"that was written by hand and has no `did` line.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			r, ok := cfg.Relays[name]
			if !ok {
				return fmt.Errorf("unknown peer: %s", name)
			}
			c, err := peerClientFor(name)
			if err != nil {
				return err
			}
			info, err := c.GetRelayInfo()
			if err != nil {
				return fmt.Errorf("fetch peer well-known: %w", err)
			}

			previous := r.DID
			r.DID = info.DID
			cfg.Relays[name] = r
			if err := config.Save(cfg); err != nil {
				return err
			}
			// The pin the process already checked is stale now.
			delete(peerPinChecks, name)

			if jsonFlag {
				outputJSON(map[string]any{
					"name":     name,
					"url":      r.URL,
					"did":      info.DID,
					"previous": previous,
					"changed":  previous != info.DID,
				})
				return nil
			}
			switch {
			case previous == "":
				fmt.Printf("Peer '%s' pinned to %s\n", name, info.DID)
			case previous == info.DID:
				fmt.Printf("Peer '%s' already pinned to %s\n", name, info.DID)
			default:
				fmt.Printf("Peer '%s' repinned\n", name)
				fmt.Printf("  was: %s\n", previous)
				fmt.Printf("  now: %s\n", info.DID)
			}
			return nil
		},
	}
}

func newPeerRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Unregister a peer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if _, ok := cfg.Relays[name]; !ok {
				return fmt.Errorf("unknown peer: %s", name)
			}
			delete(cfg.Relays, name)
			if err := config.Save(cfg); err != nil {
				return err
			}
			if jsonFlag {
				outputJSON(map[string]string{"removed": name})
				return nil
			}
			fmt.Printf("Peer '%s' removed\n", name)
			return nil
		},
	}
}

func newPeerListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List configured peers",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(cfg.Relays) == 0 {
				if jsonFlag {
					fmt.Println("[]")
				} else {
					fmt.Println("No peers configured. Use 'dfos peer add <name> <url>'")
				}
				return nil
			}

			activePeer := ""
			if ctx, err := resolveCtx(); err == nil && ctx != nil {
				activePeer = ctx.RelayName
			}

			names := make([]string, 0, len(cfg.Relays))
			for name := range cfg.Relays {
				names = append(names, name)
			}
			sort.Strings(names)

			if jsonFlag {
				items := []map[string]any{}
				for _, name := range names {
					r := cfg.Relays[name]
					item := map[string]any{
						"name":   name,
						"url":    r.URL,
						"active": name == activePeer,
					}
					if r.DID != "" {
						item["did"] = r.DID
					}
					if r.ProfileName != "" {
						item["profileName"] = r.ProfileName
					}
					if r.Content != nil {
						item["content"] = *r.Content
					}
					if r.Proof != nil {
						item["proof"] = *r.Proof
					}
					if r.Log != nil {
						item["log"] = *r.Log
					}
					item["sync"] = config.BulkSyncDisabledReason(r) == ""
					items = append(items, item)
				}
				outputJSON(items)
				return nil
			}

			nameW := 4
			profileW := 7
			for _, name := range names {
				if len(name)+2 > nameW {
					nameW = len(name) + 2
				}
				r := cfg.Relays[name]
				if len(r.ProfileName) > profileW {
					profileW = len(r.ProfileName)
				}
			}

			fmt.Printf("  %-*s  %-*s  %-7s  %-5s  %-4s  %s\n", nameW, "NAME", profileW, "PROFILE", "CONTENT", "PROOF", "SYNC", "URL")
			for _, name := range names {
				r := cfg.Relays[name]
				prefix := "  "
				if name == activePeer {
					prefix = "* "
				}
				profile := "-"
				if r.ProfileName != "" {
					profile = r.ProfileName
				}
				content := "-"
				if r.Content != nil {
					content = boolYesNo(*r.Content)
				}
				proof := "-"
				if r.Proof != nil {
					proof = boolYesNo(*r.Proof)
				}
				// SYNC is the effective answer, not the raw switch: it says whether
				// `dfos sync` will pull this peer's whole log, whichever of the
				// three reasons decided it.
				sync := boolYesNo(config.BulkSyncDisabledReason(r) == "")
				fmt.Printf("%s%-*s  %-*s  %-7s  %-5s  %-4s  %s\n", prefix, nameW, name, profileW, profile, content, proof, sync, r.URL)
			}
			return nil
		},
	}
}

func newPeerInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info [name]",
		Short: "Inspect and verify a peer",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			peerName := ""
			if len(args) > 0 {
				peerName = args[0]
			}
			// Deliberately NOT requirePeer: this command's job is to report the
			// peer's state, including a pin that no longer matches. Refusing to
			// look would be refusing to answer the question being asked.
			rn := peerName
			if rn == "" {
				ctx, err := resolveCtx()
				if err != nil {
					return err
				}
				if ctx == nil || ctx.RelayName == "" {
					return errNoPeer()
				}
				rn = ctx.RelayName
			}
			c, err := peerClientFor(rn)
			if err != nil {
				return err
			}

			info, err := c.GetRelayInfo()
			if err != nil {
				return err
			}

			identityResp, identityErr := c.GetIdentityState(info.DID)
			profileName, profileValid := verifyPeerProfile(c, info)

			// Refresh the CACHE — capabilities and profile name. The pin is not
			// cache: overwriting it here would mean a relay could change identity
			// and have the evidence erased by the command you ran to check.
			cached := config.RelayConfig{}
			pinned := ""
			if r, ok := cfg.Relays[rn]; ok {
				pinned = r.DID
				r.Content = &info.Content
				r.Proof = &info.Proof
				r.Log = &info.Capabilities.Log
				if profileName != "" {
					r.ProfileName = profileName
				}
				cfg.Relays[rn] = r
				cached = r
				config.Save(cfg)
			}
			pinMatches := pinned != "" && pinned == info.DID

			if jsonFlag {
				result := map[string]any{
					"did":      info.DID,
					"protocol": info.Protocol,
					"version":  info.Version,
					"content":  info.Content,
					"proof":    info.Proof,
					"log":      info.Capabilities.Log,
					"write":    info.Write,
					"sync":     config.BulkSyncDisabledReason(cached) == "",
					"pin": map[string]any{
						"pinned":   pinned,
						"matches":  pinMatches,
						"mismatch": pinned != "" && !pinMatches,
					},
					"profile": map[string]any{
						"present": info.Profile != "",
						"name":    profileName,
						"valid":   profileValid,
					},
				}
				if identityResp != nil {
					result["identity"] = map[string]any{
						"resolved":       true,
						"isDeleted":      identityResp.State.IsDeleted,
						"headCID":        identityResp.HeadCID,
						"controllerKeys": len(identityResp.State.ControllerKeys),
						"authKeys":       len(identityResp.State.AuthKeys),
						"assertKeys":     len(identityResp.State.AssertKeys),
					}
				} else {
					result["identity"] = map[string]any{
						"resolved": false,
						"error":    identityErr.Error(),
					}
				}
				outputJSON(result)
				return nil
			}

			label := info.DID
			if profileName != "" {
				label = profileName
			}
			fmt.Printf("Peer:      %s\n", label)
			fmt.Printf("DID:       %s\n", info.DID)
			fmt.Printf("URL:       %s\n", cfg.Relays[rn].URL)
			fmt.Printf("Protocol:  %s %s\n", info.Protocol, info.Version)
			fmt.Println()

			fmt.Println("Pin:")
			switch {
			case pinned == "":
				fmt.Printf("  unpinned — 'dfos peer repin %s' pins this peer to the DID above\n", rn)
			case pinMatches:
				fmt.Printf("  matches — this peer still serves the DID config pins it to\n")
			default:
				fmt.Printf("  MISMATCH — config pins %s\n", pinned)
				fmt.Printf("  Commands that act through '%s' refuse until 'dfos peer repin %s'\n", rn, rn)
			}
			fmt.Println()

			fmt.Println("Capabilities:")
			fmt.Printf("  content: %s\n", boolYesNo(info.Content))
			fmt.Printf("  proof:   %s\n", boolYesNo(info.Proof))
			fmt.Printf("  log:     %s\n", boolYesNo(info.Capabilities.Log))
			fmt.Printf("  write:   %s\n", boolYesNo(info.Write))
			fmt.Println()

			fmt.Println("Bulk sync:")
			if reason := config.BulkSyncDisabledReason(cached); reason != "" {
				fmt.Printf("  disabled — %s in %s\n", reason, config.ConfigPath())
			} else {
				fmt.Printf("  enabled — 'dfos sync --peer %s' pulls this peer's whole log\n", rn)
			}
			fmt.Println()

			fmt.Println("Identity:")
			if identityResp != nil {
				status := "active"
				if identityResp.State.IsDeleted {
					status = "deleted"
				}
				fmt.Printf("  status:  %s\n", status)
				fmt.Printf("  head:    %s\n", identityResp.HeadCID)
				fmt.Printf("  keys:    %d controller, %d auth, %d assert\n",
					len(identityResp.State.ControllerKeys), len(identityResp.State.AuthKeys), len(identityResp.State.AssertKeys))
			} else {
				fmt.Printf("  error:   %s\n", identityErr)
			}
			fmt.Println()

			fmt.Println("Profile:")
			if info.Profile == "" {
				fmt.Println("  not present")
			} else if profileValid {
				fmt.Printf("  name:    %s\n", profileName)
				fmt.Printf("  status:  verified (signature valid against HEAD key state)\n")
			} else {
				fmt.Printf("  status:  present but could not verify signature\n")
			}

			return nil
		},
	}
}

// helpers

func verifyPeerProfile(c *client.Client, info *client.RelayInfo) (name string, valid bool) {
	if info.Profile == "" {
		return "", false
	}
	parts := strings.SplitN(info.Profile, ".", 3)
	if len(parts) != 3 {
		return "", false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", false
	}
	content, _ := payload["content"].(map[string]any)
	profileName, _ := content["name"].(string)
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return profileName, false
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return profileName, false
	}
	kid, _ := header["kid"].(string)
	if kid == "" {
		return profileName, false
	}
	hashIdx := strings.Index(kid, "#")
	if hashIdx < 0 {
		return profileName, false
	}
	keyFragment := kid[hashIdx+1:]
	resp, err := c.GetIdentityState(info.DID)
	if err != nil {
		return profileName, false
	}
	var multibase string
	for _, k := range append(resp.State.ControllerKeys, resp.State.AuthKeys...) {
		if k.ID == keyFragment {
			multibase = k.PublicKeyMultibase
			break
		}
	}
	if multibase == "" {
		return profileName, false
	}
	publicKey, err := dfos.DecodeMultikey(multibase)
	if err != nil {
		return profileName, false
	}
	_, _, err = dfos.VerifyJWS(info.Profile, publicKey)
	if err != nil {
		return profileName, false
	}
	return profileName, true
}

// samePeerURL reports whether two spellings name the same peer, applying the
// trailing-slash/whitespace normalization the peer set is keyed by.
func samePeerURL(a, b string) bool {
	return strings.TrimRight(strings.TrimSpace(a), "/") == strings.TrimRight(strings.TrimSpace(b), "/")
}

func boolYesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// getPeerClient gets a client for a named peer, after checking the peer is
// still the identity config pinned it to.
func getPeerClient(name string) (*client.Client, string, error) {
	r, ok := cfg.Relays[name]
	if !ok {
		return nil, "", fmt.Errorf("unknown peer: %s", name)
	}
	if err := verifyPeerPin(name); err != nil {
		return nil, "", err
	}
	return client.New(r.URL), name, nil
}

// peerClientFor builds a client for a named peer WITHOUT the pin check. It is
// for the two commands whose subject is the pin itself: `peer info` reports a
// mismatch rather than refusing over it, and `peer repin` exists to move it.
func peerClientFor(name string) (*client.Client, error) {
	r, ok := cfg.Relays[name]
	if !ok {
		return nil, fmt.Errorf("unknown peer: %s", name)
	}
	return client.New(r.URL), nil
}

// peerPinChecks memoizes the well-known fetch per peer name for the life of the
// process, so a command that builds two clients for one peer pays one
// round-trip. A one-shot CLI invocation is the whole session.
var peerPinChecks = map[string]error{}

// verifyPeerPin checks that a peer still serves the DID config.toml pinned it
// to. The pin is what makes a peer name mean an identity rather than an
// address: without it, a URL that starts answering as a different relay is
// indistinguishable from the relay you registered.
//
// Two cases are deliberately NOT failures:
//
//   - No pin. An entry with no `did` is unpinned by choice, and nothing here
//     writes one: a pin is acquired by a deliberate act (`peer add`, which
//     registers, or `peer repin`), never by first contact, so an unpinned entry
//     can never start failing at a moment nobody chose.
//   - Unreachable. A well-known that cannot be fetched is not evidence of a
//     changed identity, and turning an offline peer into a pin error would
//     report the wrong thing. The operation the caller was about to run fails
//     on its own, in its own words.
func verifyPeerPin(name string) error {
	r, ok := cfg.Relays[name]
	if !ok || r.DID == "" {
		return nil
	}
	if err, checked := peerPinChecks[name]; checked {
		return err
	}
	info, err := client.New(r.URL).GetRelayInfo()
	if err != nil {
		peerPinChecks[name] = nil
		return nil
	}
	var result error
	if info.DID != r.DID {
		result = errPeerPinMismatch(name, r.DID, info.DID)
	}
	peerPinChecks[name] = result
	return result
}

// errPeerPinMismatch names both DIDs and the one command that resolves it. A
// pin that moved is either a relay that re-keyed or a different relay answering
// at that URL, and the CLI cannot tell those apart — the operator can.
func errPeerPinMismatch(name, pinned, live string) error {
	return fmt.Errorf("peer '%s' is not the relay this machine pinned:\n"+
		"  pinned: %s (%s)\n"+
		"  serves: %s\n"+
		"  'dfos peer repin %s' accepts the new identity", name, pinned, config.ConfigPath(), live, name)
}
