package cmd

import (
	"fmt"
	"strings"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
	"github.com/spf13/cobra"
)

func newIdentityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "identity",
		Short:   "Manage DID identities",
		Aliases: []string{"id"},
		GroupID: "identity",
	}
	cmd.AddCommand(newIdentityCreateCmd())
	cmd.AddCommand(newIdentityListCmd())
	cmd.AddCommand(newIdentityShowCmd())
	cmd.AddCommand(newIdentityKeysCmd())
	cmd.AddCommand(newIdentityUpdateCmd())
	cmd.AddCommand(newIdentityDeleteCmd())
	cmd.AddCommand(newIdentityPublishCmd())
	cmd.AddCommand(newIdentityFetchCmd())
	cmd.AddCommand(newIdentityRemoveCmd())
	return cmd
}

func newIdentityCreateCmd() *cobra.Command {
	var name string
	var peerName string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new identity (generate keys + sign genesis)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}

			// check name isn't taken in config
			if _, ok := cfg.Identities[name]; ok {
				return fmt.Errorf("identity name '%s' already exists", name)
			}

			lr, err := getRelay()
			if err != nil {
				return err
			}

			// generate controller key
			controllerKeyID := protocol.GenerateKeyID()
			controllerPriv, controllerPub, err := keys.GenerateKey("pending:" + controllerKeyID)
			if err != nil {
				return fmt.Errorf("generate controller key: %w", err)
			}
			controllerMK := protocol.NewMultikeyPublicKey(controllerKeyID, controllerPub)

			// generate auth key
			authKeyID := protocol.GenerateKeyID()
			_, authPub, err := keys.GenerateKey("pending:" + authKeyID)
			if err != nil {
				return fmt.Errorf("generate auth key: %w", err)
			}
			authMK := protocol.NewMultikeyPublicKey(authKeyID, authPub)

			// sign genesis
			jwsToken, did, opCID, err := protocol.SignIdentityCreate(
				[]protocol.MultikeyPublicKey{controllerMK},
				[]protocol.MultikeyPublicKey{authMK},
				nil,
				controllerKeyID,
				controllerPriv,
			)
			if err != nil {
				return fmt.Errorf("sign genesis: %w", err)
			}

			// rename keys from pending to final
			if err := keys.RenameKey("pending:"+controllerKeyID, did+"#"+controllerKeyID); err != nil {
				return fmt.Errorf("rename controller key: %w", err)
			}
			if err := keys.RenameKey("pending:"+authKeyID, did+"#"+authKeyID); err != nil {
				return fmt.Errorf("rename auth key: %w", err)
			}

			// ingest into local relay
			results := lr.Relay.Ingest([]string{jwsToken})
			if len(results) > 0 && results[0].Status == "rejected" {
				return fmt.Errorf("local relay rejected: %s", results[0].Error)
			}

			// push to peer if specified — do this before saving config so a
			// peer rejection doesn't leave an orphaned name mapping
			var publishedTo []string
			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn != "" {
				c, _, err := getPeerClient(rn)
				if err != nil {
					return err
				}
				peerResults, err := c.SubmitOperations([]string{jwsToken})
				if err != nil {
					return fmt.Errorf("submit to peer: %w", err)
				}
				if len(peerResults) > 0 && peerResults[0].Status == "rejected" {
					return fmt.Errorf("peer rejected: %s", peerResults[0].Error)
				}
				publishedTo = append(publishedTo, rn)
			}

			// register name in config only after all operations succeed
			cfg.Identities[name] = config.IdentityConfig{DID: did}
			if rn != "" && cfg.ActiveContext == "" {
				cfg.ActiveContext = name + "@" + rn
			}
			if err := config.Save(cfg); err != nil {
				return err
			}

			if jsonFlag {
				outputJSON(map[string]any{
					"did":           did,
					"name":          name,
					"operationCID":  opCID,
					"controllerKey": controllerKeyID,
					"authKey":       authKeyID,
					"publishedTo":   publishedTo,
				})
			} else {
				fmt.Printf("Identity created:\n")
				fmt.Printf("  Name:           %s\n", name)
				fmt.Printf("  DID:            %s\n", did)
				fmt.Printf("  Controller key: %s  (%s)\n", controllerKeyID, keys.Backend())
				fmt.Printf("  Auth key:       %s  (%s)\n", authKeyID, keys.Backend())
				if len(publishedTo) > 0 {
					fmt.Printf("  Published to:   %s\n", joinComma(publishedTo))
				} else {
					fmt.Printf("  Status:         local only. Use 'dfos identity publish' to push to a peer.\n")
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Human-readable name for this identity (required)")
	cmd.Flags().StringVar(&peerName, "peer", "", "Push to this peer immediately")
	return cmd
}

func newIdentityUpdateCmd() *cobra.Command {
	var peerName string
	var rotateAuth bool
	var rotateController bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update identity (rotate keys)",
		Long:  "Sign an identity update operation. Use --rotate-auth or --rotate-controller to generate new keys and rotate out the old ones.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !rotateAuth && !rotateController {
				return fmt.Errorf("specify --rotate-auth and/or --rotate-controller")
			}

			_, chain, err := requireIdentity()
			if err != nil {
				return err
			}

			lr, err := getRelay()
			if err != nil {
				return err
			}

			if len(chain.State.ControllerKeys) == 0 {
				return fmt.Errorf("identity has no controller keys")
			}
			controllerKeyID := chain.State.ControllerKeys[0].ID
			controllerPriv, err := keys.GetPrivateKey(chain.DID + "#" + controllerKeyID)
			if err != nil {
				return fmt.Errorf("controller key not in keychain: %w", err)
			}

			// determine head CID
			lastToken := chain.Log[len(chain.Log)-1]
			h, _, err := protocol.DecodeJWSUnsafe(lastToken)
			if err != nil {
				return fmt.Errorf("decode last operation: %w", err)
			}
			previousCID := h.CID

			newAuthKeys := chain.State.AuthKeys
			newControllerKeys := chain.State.ControllerKeys
			newAssertKeys := chain.State.AssertKeys
			var rotatedKeys []string

			if rotateAuth {
				newAuthKeyID := protocol.GenerateKeyID()
				_, newAuthPub, err := keys.GenerateKey(chain.DID + "#" + newAuthKeyID)
				if err != nil {
					return fmt.Errorf("generate new auth key: %w", err)
				}
				newAuthKeys = []protocol.MultikeyPublicKey{protocol.NewMultikeyPublicKey(newAuthKeyID, newAuthPub)}
				rotatedKeys = append(rotatedKeys, "auth:"+newAuthKeyID)
			}

			if rotateController {
				newControllerKeyID := protocol.GenerateKeyID()
				_, newControllerPub, err := keys.GenerateKey(chain.DID + "#" + newControllerKeyID)
				if err != nil {
					return fmt.Errorf("generate new controller key: %w", err)
				}
				newControllerKeys = []protocol.MultikeyPublicKey{protocol.NewMultikeyPublicKey(newControllerKeyID, newControllerPub)}
				rotatedKeys = append(rotatedKeys, "controller:"+newControllerKeyID)
			}

			kid := chain.DID + "#" + controllerKeyID
			jwsToken, opCID, err := protocol.SignIdentityUpdate(
				previousCID,
				newControllerKeys, newAuthKeys, newAssertKeys,
				kid, controllerPriv,
			)
			if err != nil {
				return fmt.Errorf("sign update: %w", err)
			}

			// ingest into local relay
			results := lr.Relay.Ingest([]string{jwsToken})
			if len(results) > 0 && results[0].Status == "rejected" {
				return fmt.Errorf("local relay rejected: %s", results[0].Error)
			}

			// push to peer if specified
			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn != "" {
				c, _, err := getPeerClient(rn)
				if err != nil {
					return err
				}
				peerResults, err := c.SubmitOperations([]string{jwsToken})
				if err != nil {
					return fmt.Errorf("submit: %w", err)
				}
				if len(peerResults) > 0 && peerResults[0].Status == "rejected" {
					return fmt.Errorf("peer rejected: %s", peerResults[0].Error)
				}
			}

			if jsonFlag {
				outputJSON(map[string]any{
					"did":          chain.DID,
					"operationCID": opCID,
					"rotatedKeys":  rotatedKeys,
				})
			} else {
				fmt.Printf("Identity updated:\n")
				fmt.Printf("  DID:            %s\n", chain.DID)
				fmt.Printf("  Operation CID:  %s\n", opCID)
				fmt.Printf("  Operations:     %d\n", len(chain.Log)+1)
				for _, rk := range rotatedKeys {
					fmt.Printf("  New key:        %s\n", rk)
				}
				fmt.Printf("  Old keys remain in keychain for chain re-verification.\n")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&peerName, "peer", "", "Push to this peer immediately")
	cmd.Flags().BoolVar(&rotateAuth, "rotate-auth", false, "Generate new auth key and rotate out old one(s)")
	cmd.Flags().BoolVar(&rotateController, "rotate-controller", false, "Generate new controller key and rotate out old one(s)")
	return cmd
}

func newIdentityDeleteCmd() *cobra.Command {
	var peerName string

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Permanently delete an identity (sign delete operation)",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, chain, err := requireIdentity()
			if err != nil {
				return err
			}

			lr, err := getRelay()
			if err != nil {
				return err
			}

			if len(chain.State.ControllerKeys) == 0 {
				return fmt.Errorf("identity has no controller keys")
			}
			controllerKeyID := chain.State.ControllerKeys[0].ID
			controllerPriv, err := keys.GetPrivateKey(chain.DID + "#" + controllerKeyID)
			if err != nil {
				return fmt.Errorf("controller key not in keychain: %w", err)
			}

			lastToken := chain.Log[len(chain.Log)-1]
			h, _, err := protocol.DecodeJWSUnsafe(lastToken)
			if err != nil {
				return fmt.Errorf("decode last operation: %w", err)
			}

			kid := chain.DID + "#" + controllerKeyID
			jwsToken, opCID, err := protocol.SignIdentityDelete(h.CID, kid, controllerPriv)
			if err != nil {
				return fmt.Errorf("sign delete: %w", err)
			}

			results := lr.Relay.Ingest([]string{jwsToken})
			if len(results) > 0 && results[0].Status == "rejected" {
				return fmt.Errorf("local relay rejected: %s", results[0].Error)
			}

			// push to peer
			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn != "" {
				c, _, err := getPeerClient(rn)
				if err != nil {
					return err
				}
				peerResults, err := c.SubmitOperations([]string{jwsToken})
				if err != nil {
					return fmt.Errorf("submit: %w", err)
				}
				if len(peerResults) > 0 && peerResults[0].Status == "rejected" {
					return fmt.Errorf("peer rejected: %s", peerResults[0].Error)
				}
			}

			if jsonFlag {
				outputJSON(map[string]any{"did": chain.DID, "operationCID": opCID, "deleted": true})
			} else {
				fmt.Printf("Identity deleted:\n")
				fmt.Printf("  DID:            %s\n", chain.DID)
				fmt.Printf("  Operation CID:  %s\n", opCID)
				fmt.Printf("  This identity can no longer sign operations.\n")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&peerName, "peer", "", "Push to this peer immediately")
	return cmd
}

func newIdentityListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List all known identities",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			lr, err := getRelay()
			if err != nil {
				return err
			}

			allChains, err := lr.Store.ListIdentityChains()
			if err != nil {
				return err
			}
			// filter out the invisible relay identity
			var chains []relay.StoredIdentityChain
			for _, c := range allChains {
				if c.DID != lr.RelayDID {
					chains = append(chains, c)
				}
			}
			if len(chains) == 0 {
				if jsonFlag {
					fmt.Println("[]")
				} else {
					fmt.Println("No identities. Use 'dfos identity create --name <name>'")
				}
				return nil
			}

			if jsonFlag {
				outputJSON(chains)
				return nil
			}

			fmt.Printf("%-10s %-36s %-6s %s\n", "NAME", "DID", "KEYS", "OPS")
			for _, chain := range chains {
				name := config.FindIdentityName(cfg, chain.DID)
				if name == "" {
					name = "-"
				}
				totalKeys := len(chain.State.AuthKeys) + len(chain.State.ControllerKeys) + len(chain.State.AssertKeys)
				haveKeys := countKeysInChain(&chain)
				fmt.Printf("%-10s %-36s %d/%-3d %d\n",
					name, chain.DID, haveKeys, totalKeys, len(chain.Log))
			}
			return nil
		},
	}
}

func newIdentityShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show [name|did]",
		Short: "Show identity state",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lr, err := getRelay()
			if err != nil {
				return err
			}

			var chain *relay.StoredIdentityChain

			if len(args) > 0 {
				did := resolveIdentityDID(args[0])
				chain, _ = lr.Relay.GetIdentity(did)
			} else {
				_, chain2, err := requireIdentity()
				if err != nil {
					return err
				}
				chain = chain2
			}

			if chain == nil {
				return fmt.Errorf("identity not found")
			}

			if jsonFlag {
				outputJSON(chain)
				return nil
			}

			name := config.FindIdentityName(cfg, chain.DID)
			fmt.Printf("DID:         %s\n", chain.DID)
			if name != "" {
				fmt.Printf("Name:        %s\n", name)
			}
			totalKeys := len(chain.State.AuthKeys) + len(chain.State.ControllerKeys) + len(chain.State.AssertKeys)
			haveKeys := countKeysInChain(chain)
			fmt.Printf("Keys:        %d/%d (%s)\n", haveKeys, totalKeys, keys.Backend())
			fmt.Printf("Operations:  %d\n", len(chain.Log))
			fmt.Printf("Deleted:     %v\n", chain.State.IsDeleted)
			return nil
		},
	}
}

func newIdentityKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keys [name|did]",
		Short: "Show key state and keychain availability",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lr, err := getRelay()
			if err != nil {
				return err
			}

			var chain *relay.StoredIdentityChain
			if len(args) > 0 {
				did := resolveIdentityDID(args[0])
				chain, _ = lr.Relay.GetIdentity(did)
			} else {
				_, chain2, _ := requireIdentity()
				chain = chain2
			}
			if chain == nil {
				return fmt.Errorf("identity not found")
			}

			if jsonFlag {
				type keyInfo struct {
					ID       string `json:"id"`
					Role     string `json:"role"`
					Keychain bool   `json:"keychain"`
				}
				var items []keyInfo
				for _, k := range chain.State.ControllerKeys {
					items = append(items, keyInfo{k.ID, "controller", keys.HasKey(chain.DID + "#" + k.ID)})
				}
				for _, k := range chain.State.AuthKeys {
					items = append(items, keyInfo{k.ID, "auth", keys.HasKey(chain.DID + "#" + k.ID)})
				}
				for _, k := range chain.State.AssertKeys {
					items = append(items, keyInfo{k.ID, "assert", keys.HasKey(chain.DID + "#" + k.ID)})
				}
				outputJSON(items)
				return nil
			}

			name := config.FindIdentityName(cfg, chain.DID)
			label := chain.DID
			if name != "" {
				label = chain.DID + " (" + name + ")"
			}
			fmt.Printf("Identity: %s\n\n", label)
			fmt.Printf("%-30s %-12s %s\n", "KEY ID", "ROLE", "KEYCHAIN")
			printKeys := func(mkKeys []protocol.MultikeyPublicKey, role string) {
				for _, k := range mkKeys {
					has := "-"
					if keys.HasKey(chain.DID + "#" + k.ID) {
						has = "present"
					}
					fmt.Printf("%-30s %-12s %s\n", k.ID, role, has)
				}
			}
			printKeys(chain.State.ControllerKeys, "controller")
			printKeys(chain.State.AuthKeys, "auth")
			printKeys(chain.State.AssertKeys, "assert")
			return nil
		},
	}
}

func newIdentityPublishCmd() *cobra.Command {
	var peerName string
	return &cobra.Command{
		Use:   "publish [name|did]",
		Short: "Push identity chain to a peer",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lr, err := getRelay()
			if err != nil {
				return err
			}

			var chain *relay.StoredIdentityChain
			if len(args) > 0 {
				did := resolveIdentityDID(args[0])
				chain, _ = lr.Relay.GetIdentity(did)
			} else {
				_, chain2, _ := requireIdentity()
				chain = chain2
			}
			if chain == nil {
				return fmt.Errorf("identity not found")
			}

			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn == "" {
				ctx, _ := resolveCtx()
				if ctx != nil {
					rn = ctx.RelayName
				}
			}
			if rn == "" {
				return fmt.Errorf("--peer is required")
			}

			c, _, err := getPeerClient(rn)
			if err != nil {
				return err
			}

			peerResults, err := c.SubmitOperations(chain.Log)
			if err != nil {
				return fmt.Errorf("submit: %w", err)
			}

			hasRejection := false
			for _, r := range peerResults {
				if r.Status == "rejected" {
					hasRejection = true
					fmt.Printf("  Operation %s: %s (%s)\n", r.CID, r.Status, r.Error)
				}
			}
			if hasRejection {
				return fmt.Errorf("peer rejected one or more operations")
			}

			if jsonFlag {
				outputJSON(map[string]any{"status": "published", "peer": rn, "operations": len(peerResults)})
			} else {
				fmt.Printf("Identity published to '%s' (%d operation(s))\n", rn, len(peerResults))
			}
			return nil
		},
	}
}

func newIdentityFetchCmd() *cobra.Command {
	var name string
	var peerName string

	cmd := &cobra.Command{
		Use:   "fetch <did|name>",
		Short: "Download identity chain from peer into local relay",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			did := resolveIdentityDID(target)

			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn == "" {
				ctx, _ := resolveCtx()
				if ctx != nil {
					rn = ctx.RelayName
				}
			}
			if rn == "" {
				return fmt.Errorf("--peer is required for fetch")
			}

			c, _, err := getPeerClient(rn)
			if err != nil {
				return err
			}

			data, err := c.GetIdentity(did)
			if err != nil {
				return fmt.Errorf("fetch identity: %w", err)
			}

			// extract log from response
			log, _ := toStringSlice(data["log"])

			// ingest into local relay
			lr, err := getRelay()
			if err != nil {
				return err
			}
			results := lr.Relay.Ingest(log)
			for _, r := range results {
				if r.Status == "rejected" {
					fmt.Printf("  Warning: operation %s rejected: %s\n", r.CID, r.Error)
				}
			}

			// register in config if named
			if name != "" {
				cfg.Identities[name] = config.IdentityConfig{DID: did}
				config.Save(cfg)
			}

			if jsonFlag {
				outputJSON(map[string]any{"did": did, "name": name, "operations": len(log)})
			} else {
				fmt.Printf("Fetched identity: %s (%d operations)\n", did, len(log))
				if name != "" {
					fmt.Printf("  Name: %s\n", name)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Local name for this identity")
	cmd.Flags().StringVar(&peerName, "peer", "", "Peer to fetch from")
	return cmd
}

func newIdentityRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove an identity name from config (data stays in relay)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			idCfg, ok := cfg.Identities[name]
			if !ok {
				return fmt.Errorf("identity '%s' not found in config", name)
			}

			delete(cfg.Identities, name)
			if cfg.ActiveContext != "" {
				parts := strings.SplitN(cfg.ActiveContext, "@", 2)
				if len(parts) > 0 && parts[0] == name {
					cfg.ActiveContext = ""
				}
			}
			config.Save(cfg)

			if jsonFlag {
				outputJSON(map[string]string{"removed": name, "did": idCfg.DID})
			} else {
				fmt.Printf("Removed identity name '%s' (%s) from config\n", name, idCfg.DID)
				fmt.Printf("  Data remains in local relay. Keys remain in keychain.\n")
			}
			return nil
		},
	}
}

// helpers

func resolveIdentityDID(nameOrDID string) string {
	if idCfg, ok := cfg.Identities[nameOrDID]; ok {
		return idCfg.DID
	}
	if len(nameOrDID) > 4 && nameOrDID[:4] != "did:" {
		return "did:dfos:" + nameOrDID
	}
	return nameOrDID
}

func toStringSlice(v any) ([]string, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	result := make([]string, len(arr))
	for i, item := range arr {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		result[i] = s
	}
	return result, true
}

// publishIdentityIfNeeded ensures the identity's chain is on the peer before
// publishing content or beacons. Submits the full identity log — duplicates
// are idempotent on the peer side.
func publishIdentityIfNeeded(chain *relay.StoredIdentityChain, peerName string, c *client.Client) error {
	results, err := c.SubmitOperations(chain.Log)
	if err != nil {
		return fmt.Errorf("publish identity to '%s': %w", peerName, err)
	}
	for _, r := range results {
		if r.Status == "rejected" {
			return fmt.Errorf("peer rejected identity op: %s", r.Error)
		}
	}
	return nil
}
