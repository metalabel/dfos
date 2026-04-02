package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
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
	cmd.AddCommand(newPeerRemoveCmd())
	cmd.AddCommand(newPeerListCmd())
	cmd.AddCommand(newPeerInfoCmd())
	return cmd
}

func newPeerAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <name> <url>",
		Short: "Register a named peer (fetches and verifies metadata)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, url := args[0], args[1]

			rc := config.RelayConfig{URL: url}

			c := client.New(url)
			info, err := c.GetRelayInfo()
			if err != nil {
				cfg.Relays[name] = rc
				if err := config.Save(cfg); err != nil {
					return err
				}
				if jsonFlag {
					outputJSON(map[string]any{"name": name, "url": url, "verified": false, "warning": err.Error()})
				} else {
					fmt.Printf("Peer '%s' added: %s\n", name, url)
					fmt.Printf("  Warning: could not verify peer: %s\n", err)
				}
				return nil
			}

			rc.DID = info.DID
			rc.Content = &info.Content
			rc.Proof = &info.Proof

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
					"verified":     true,
					"profileValid": profileValid,
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
				if profileValid {
					fmt.Printf("  Status:  verified (%s)\n", label)
				} else if info.Profile != "" {
					fmt.Printf("  Status:  profile signature could not be verified\n")
				}
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

			fmt.Printf("  %-*s  %-*s  %-7s  %-5s  %s\n", nameW, "NAME", profileW, "PROFILE", "CONTENT", "PROOF", "URL")
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
				fmt.Printf("%s%-*s  %-*s  %-7s  %-5s  %s\n", prefix, nameW, name, profileW, profile, content, proof, r.URL)
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
			_, c, err := requirePeer(peerName)
			if err != nil {
				return err
			}

			rn := peerName
			if rn == "" {
				ctx, _ := resolveCtx()
				if ctx != nil {
					rn = ctx.RelayName
				}
			}

			info, err := c.GetRelayInfo()
			if err != nil {
				return err
			}

			identityResp, identityErr := c.GetIdentityState(info.DID)
			profileName, profileValid := verifyPeerProfile(c, info)

			// cache metadata
			if rn != "" {
				if r, ok := cfg.Relays[rn]; ok {
					r.DID = info.DID
					r.Content = &info.Content
					r.Proof = &info.Proof
					if profileName != "" {
						r.ProfileName = profileName
					}
					cfg.Relays[rn] = r
					config.Save(cfg)
				}
			}

			if jsonFlag {
				result := map[string]any{
					"did":      info.DID,
					"protocol": info.Protocol,
					"version":  info.Version,
					"content":  info.Content,
					"proof":    info.Proof,
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
			if rn != "" {
				r := cfg.Relays[rn]
				fmt.Printf("URL:       %s\n", r.URL)
			}
			fmt.Printf("Protocol:  %s %s\n", info.Protocol, info.Version)
			fmt.Println()

			fmt.Println("Capabilities:")
			fmt.Printf("  content: %s\n", boolYesNo(info.Content))
			fmt.Printf("  proof:   %s\n", boolYesNo(info.Proof))
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

func boolYesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// getPeerClient gets a client for a named peer.
func getPeerClient(name string) (*client.Client, string, error) {
	r, ok := cfg.Relays[name]
	if !ok {
		return nil, "", fmt.Errorf("unknown peer: %s", name)
	}
	return client.New(r.URL), name, nil
}

// getPeerDID returns the cached peer DID, or fetches and caches it.
func getPeerDID(peerName string, c *client.Client) (string, error) {
	if r, ok := cfg.Relays[peerName]; ok && r.DID != "" {
		return r.DID, nil
	}
	info, err := c.GetRelayInfo()
	if err != nil {
		return "", fmt.Errorf("get peer info: %w", err)
	}
	if r, ok := cfg.Relays[peerName]; ok {
		r.DID = info.DID
		cfg.Relays[peerName] = r
		config.Save(cfg)
	}
	return info.DID, nil
}
