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
			// discard the posture the operator set for it. Every policy field
			// carries over, and --no-sync is the one thing here that rewrites one
			// (--no-sync=false turns it back on explicitly).
			existing, reRegistration := cfg.Relays[name]
			if reRegistration {
				rc.Gossip, rc.ReadThrough, rc.Sync = existing.Gossip, existing.ReadThrough, existing.Sync
				rc.Content, rc.Proof, rc.Log = existing.Content, existing.Proof, existing.Log
			}
			if cmd.Flags().Changed("no-sync") {
				enabled := !noSync
				rc.Sync = &enabled
			}

			c := client.New(url)
			c.Peer = name
			info, err := c.GetRelayInfo()
			if err != nil {
				cfg.Relays[name] = rc
				if err := config.Save(cfg); err != nil {
					return err
				}
				if jsonFlag {
					outputJSON(map[string]any{
						"name":      name,
						"url":       url,
						"reachable": false,
						"warning":   err.Error(),
						"sync":      config.BulkSyncDisabledReason(rc) == "",
					})
				} else {
					fmt.Printf("Peer '%s' added: %s\n", name, url)
					fmt.Printf("  Warning: %s\n", err)
					fmt.Printf("           Registered unverified — no DID pinned, no capabilities recorded.\n")
					printPeerSyncPosture(name, rc)
				}
				return nil
			}

			// Registering over an existing entry refreshes it. It does not MOVE
			// the pin: the same URL answering as a different DID is either a
			// re-keyed relay or a different relay, and which one it is decides
			// whether to trust it. `peer repin` is that decision, made out loud.
			// A changed URL is a new registration, so its pin is written fresh.
			sameRelay := reRegistration && samePeerURL(existing.URL, url)
			if sameRelay && existing.DID != "" && existing.DID != info.DID {
				return errPeerPinMismatch(name, existing.DID, info.DID)
			}

			rc.DID = info.DID
			// Seed the plane posture from what the peer advertises — but only on
			// a FIRST registration. After that the fields are the operator's
			// answer to "what do I use this peer for", and a refresh that
			// overwrote them would silently undo a posture (the exact bug where
			// one `peer info` turned bulk sync back on).
			if !sameRelay {
				rc.Content, rc.Proof, rc.Log = &info.Content, &info.Proof, &info.Capabilities.Log
			}

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
					"name":        name,
					"url":         url,
					"did":         info.DID,
					"profileName": profileName,
					// What the peer says of itself, and separately what this
					// machine has configured. Collapsing the two is how a
					// posture becomes invisible.
					"advertises": map[string]any{
						"content": info.Content,
						"proof":   info.Proof,
						"log":     info.Capabilities.Log,
						"write":   info.Write,
					},
					"content":          boolValue(rc.Content, info.Content),
					"proof":            boolValue(rc.Proof, info.Proof),
					"log":              boolValue(rc.Log, info.Capabilities.Log),
					"sync":             config.BulkSyncDisabledReason(rc) == "",
					"reachable":        true,
					"profileSignature": profileSignatureWord(info.Profile, profileValid),
				})
			} else {
				fmt.Printf("Peer '%s' added: %s\n", name, url)
				fmt.Printf("  DID:     %s\n", info.DID)
				if profileName != "" {
					fmt.Printf("  Profile: %s\n", profileName)
				}
				fmt.Printf("  Advertises: content %s, proof %s, log %s, write %s\n",
					boolYesNo(info.Content), boolYesNo(info.Proof),
					boolYesNo(info.Capabilities.Log), boolYesNo(info.Write))
				fmt.Printf("  Configured: content %s, proof %s, log %s\n",
					boolConfigured(rc.Content), boolConfigured(rc.Proof), boolConfigured(rc.Log))
				printPeerSyncPosture(name, rc)
				// Scoped deliberately: what a valid signature establishes is that
				// the profile blob was signed by a key in this DID's HEAD state.
				// It says nothing about whether that DID is the one you meant —
				// that is the pin's job, and calling this "verified" full stop
				// implied a guarantee it never made.
				switch {
				case profileValid:
					fmt.Printf("  Profile signature: valid against %s HEAD key state\n", info.DID)
				case info.Profile != "":
					fmt.Printf("  Profile signature: could not be verified\n")
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

			// This command inspects. The ONLY thing it writes is the display
			// label, because everything else in the entry is either the
			// operator's policy (the plane flags and the switches — an inspection
			// that rewrote those would silently undo a posture) or the pin, whose
			// whole purpose is to survive a peer that changed identity. Both were
			// overwritten here before, which made `peer info` the one command that
			// could quietly restore the state you ran it to check.
			configured := cfg.Relays[rn]
			pinned := configured.DID
			if configured.ProfileName != profileName && profileName != "" {
				configured.ProfileName = profileName
				cfg.Relays[rn] = configured
				if err := config.Save(cfg); err != nil {
					return err
				}
			}
			pinMatches := pinned != "" && pinned == info.DID

			if jsonFlag {
				result := map[string]any{
					"did":      info.DID,
					"protocol": info.Protocol,
					"version":  info.Version,
					// advertises is the peer's claim; the top-level content/proof/
					// log are this machine's configured posture. They are separate
					// keys because they answer different questions and a reader
					// that conflated them would report a posture it does not have.
					"advertises": map[string]any{
						"content": info.Content,
						"proof":   info.Proof,
						"log":     info.Capabilities.Log,
						"write":   info.Write,
					},
					"content": boolValue(configured.Content, info.Content),
					"proof":   boolValue(configured.Proof, info.Proof),
					"log":     boolValue(configured.Log, info.Capabilities.Log),
					"write":   info.Write,
					"sync":    config.BulkSyncDisabledReason(configured) == "",
					"pin": map[string]any{
						"pinned":   pinned,
						"matches":  pinMatches,
						"mismatch": pinned != "" && !pinMatches,
					},
					"profile": map[string]any{
						"present":        info.Profile != "",
						"name":           profileName,
						"signatureValid": profileValid,
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
				if pinned != "" && !pinMatches {
					return &ExitCodeError{Code: 1}
				}
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

			// Two columns, never one. The left is the peer's claim about itself;
			// the right is what this machine has decided to use it for. They
			// disagree exactly when an operator has set a posture, which is the
			// moment collapsing them would hide the thing they set.
			fmt.Println("Planes:")
			fmt.Printf("  %-9s %-12s %s\n", "", "advertises", "configured")
			fmt.Printf("  %-9s %-12s %s\n", "content:", boolYesNo(info.Content), boolConfigured(configured.Content))
			fmt.Printf("  %-9s %-12s %s\n", "proof:", boolYesNo(info.Proof), boolConfigured(configured.Proof))
			fmt.Printf("  %-9s %-12s %s\n", "log:", boolYesNo(info.Capabilities.Log), boolConfigured(configured.Log))
			fmt.Printf("  %-9s %-12s %s\n", "write:", boolYesNo(info.Write), "—")
			fmt.Println()

			fmt.Println("Bulk sync:")
			if reason := config.BulkSyncDisabledReason(configured); reason != "" {
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
			// Scoped wording: a valid signature establishes that the profile blob
			// was signed by a key in THIS DID's HEAD state. It does not establish
			// that this DID is the one you meant to talk to — that is the pin
			// above, and a bare "verified" here read as if it covered both.
			if info.Profile == "" {
				fmt.Println("  not present")
			} else if profileValid {
				fmt.Printf("  name:      %s\n", profileName)
				fmt.Printf("  signature: valid against %s HEAD key state\n", info.DID)
			} else {
				fmt.Printf("  signature: present but could not be verified\n")
			}

			// The report is complete either way; the status distinguishes it. A
			// mismatch is a refusal everywhere else, so a script that inspects
			// before acting must be able to branch on it here too.
			if pinned != "" && !pinMatches {
				return &ExitCodeError{Code: 1}
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

// boolConfigured renders an operator-owned flag: "yes"/"no" when set, and a dash
// when absent, because absent is not "no" — it is "this machine has said nothing
// and takes the peer at its word".
func boolConfigured(v *bool) string {
	if v == nil {
		return "— (default)"
	}
	return boolYesNo(*v)
}

// boolValue resolves an operator-owned flag against the fallback that applies
// when it is unset.
func boolValue(v *bool, fallback bool) bool {
	if v == nil {
		return fallback
	}
	return *v
}

// profileSignatureWord names what was checked, and only that: the profile blob's
// signature against the serving DID's HEAD key state.
func profileSignatureWord(profile string, valid bool) string {
	switch {
	case profile == "":
		return "absent"
	case valid:
		return "valid"
	default:
		return "unverified"
	}
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
	c := client.New(r.URL)
	c.Peer = name
	return c, name, nil
}

// peerClientFor builds a client for a named peer WITHOUT the pin check. It is
// for the two commands whose subject is the pin itself: `peer info` reports a
// mismatch rather than refusing over it, and `peer repin` exists to move it.
func peerClientFor(name string) (*client.Client, error) {
	r, ok := cfg.Relays[name]
	if !ok {
		return nil, fmt.Errorf("unknown peer: %s", name)
	}
	c := client.New(r.URL)
	c.Peer = name
	return c, nil
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
// An entry with no pin is trusted on first use and pinned then — the peer is
// whoever answered the first time this machine spoke to it, and every later
// invocation is checked against that. The write is announced, because a
// trust decision this machine makes on the operator's behalf is one they are
// entitled to see happen.
//
// A well-known that cannot be fetched is NOT a failure: it is not evidence of a
// changed identity, and turning an offline peer into a pin error would report
// the wrong thing. The operation the caller was about to run fails on its own,
// in its own words. Nothing is pinned from a contact that did not happen.
func verifyPeerPin(name string) error {
	r, ok := cfg.Relays[name]
	if !ok || r.URL == "" {
		return nil
	}
	if err, checked := peerPinChecks[name]; checked {
		return err
	}
	c := client.New(r.URL)
	c.Peer = name
	info, err := c.GetRelayInfo()
	if err != nil {
		peerPinChecks[name] = nil
		return nil
	}

	if r.DID == "" {
		r.DID = info.DID
		cfg.Relays[name] = r
		if err := config.Save(cfg); err != nil {
			return err
		}
		// stderr, so --json stdout stays one document.
		fmt.Fprintf(os.Stderr, "Pinned peer '%s' to %s on first contact ('dfos peer repin %s' to change).\n",
			name, info.DID, name)
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
