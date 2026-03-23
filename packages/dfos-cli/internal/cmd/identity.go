package cmd

import (
	"fmt"
	"strings"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/protocol"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/store"
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
	cmd.AddCommand(newIdentityPublishCmd())
	cmd.AddCommand(newIdentityFetchCmd())
	cmd.AddCommand(newIdentityRemoveCmd())
	return cmd
}

func newIdentityCreateCmd() *cobra.Command {
	var name string
	var relayName string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new identity (generate keys + sign genesis)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}

			// check name isn't taken
			existing, _ := store.FindIdentityByName(name)
			if existing != nil {
				return fmt.Errorf("identity name '%s' already exists", name)
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
				nil, // no assert keys
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

			// store locally
			storedID := &store.StoredIdentity{
				DID: did,
				Log: []string{jwsToken},
				State: protocol.IdentityState{
					DID:            did,
					IsDeleted:      false,
					AuthKeys:       []protocol.MultikeyPublicKey{authMK},
					AssertKeys:     nil,
					ControllerKeys: []protocol.MultikeyPublicKey{controllerMK},
				},
				Local: store.LocalMeta{
					Name:   name,
					Origin: "created",
				},
			}

			// register in config
			cfg.Identities[name] = config.IdentityConfig{DID: did}

			// publish to relay if --relay specified
			if relayName != "" {
				c, rn, err := getRelayClient(relayName)
				if err != nil {
					return err
				}
				results, err := c.SubmitOperations([]string{jwsToken})
				if err != nil {
					return fmt.Errorf("submit to relay: %w", err)
				}
				if len(results) > 0 && results[0].Status != "accepted" {
					return fmt.Errorf("relay rejected: %s", results[0].Error)
				}
				storedID.Local.PublishedTo = []string{rn}

				// set active context if none set
				if cfg.ActiveContext == "" {
					cfg.ActiveContext = name + "@" + relayName
				}
			}

			if err := store.SaveIdentity(storedID); err != nil {
				return err
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
					"publishedTo":   storedID.Local.PublishedTo,
				})
			} else {
				fmt.Printf("Identity created:\n")
				fmt.Printf("  Name:           %s\n", name)
				fmt.Printf("  DID:            %s\n", did)
				fmt.Printf("  Controller key: %s  (%s)\n", controllerKeyID, keys.Backend())
				fmt.Printf("  Auth key:       %s  (%s)\n", authKeyID, keys.Backend())
				if len(storedID.Local.PublishedTo) > 0 {
					fmt.Printf("  Published to:   %s\n", joinComma(storedID.Local.PublishedTo))
				} else {
					fmt.Printf("  Status:         local only. Use 'dfos identity publish' to submit to a relay.\n")
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Human-readable name for this identity (required)")
	cmd.Flags().StringVar(&relayName, "relay", "", "Publish to this relay immediately")
	return cmd
}

func newIdentityListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List all known identities",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			ids, err := store.ListIdentities()
			if err != nil {
				return err
			}
			if len(ids) == 0 {
				if jsonFlag {
					fmt.Println("[]")
				} else {
					fmt.Println("No identities. Use 'dfos identity create --name <name>'")
				}
				return nil
			}

			if jsonFlag {
				outputJSON(ids)
				return nil
			}

			fmt.Printf("%-10s %-36s %-6s %-10s %s\n", "NAME", "DID", "KEYS", "ORIGIN", "PUBLISHED")
			for _, id := range ids {
				totalKeys := len(id.State.AuthKeys) + len(id.State.ControllerKeys) + len(id.State.AssertKeys)
				haveKeys := countKeysInKeychain(id)
				published := "—"
				if len(id.Local.PublishedTo) > 0 {
					published = joinComma(id.Local.PublishedTo)
				}
				if id.Local.Origin == "created" && len(id.Local.PublishedTo) == 0 {
					published = "(unpublished)"
				}
				fmt.Printf("%-10s %-36s %d/%-3d %-10s %s\n",
					id.Local.Name, id.DID, haveKeys, totalKeys, id.Local.Origin, published)
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
			var id *store.StoredIdentity

			if len(args) > 0 {
				id, _ = store.FindIdentityByName(args[0])
				if id == nil {
					did := args[0]
					if len(did) > 4 && did[:4] != "did:" {
						did = "did:dfos:" + did
					}
					id, _ = store.LoadIdentity(did)
				}
			} else {
				_, id2, err := requireIdentity()
				if err != nil {
					return err
				}
				id = id2
			}

			if id == nil {
				return fmt.Errorf("identity not found")
			}

			if jsonFlag {
				outputJSON(id)
				return nil
			}

			fmt.Printf("DID:         %s\n", id.DID)
			fmt.Printf("Name:        %s\n", id.Local.Name)
			fmt.Printf("Origin:      %s\n", id.Local.Origin)
			totalKeys := len(id.State.AuthKeys) + len(id.State.ControllerKeys) + len(id.State.AssertKeys)
			haveKeys := countKeysInKeychain(id)
			fmt.Printf("Keys:        %d/%d (%s)\n", haveKeys, totalKeys, keys.Backend())
			fmt.Printf("Operations:  %d\n", len(id.Log))
			fmt.Printf("Deleted:     %v\n", id.State.IsDeleted)
			if len(id.Local.PublishedTo) > 0 {
				fmt.Printf("Published:   %s\n", joinComma(id.Local.PublishedTo))
			} else {
				fmt.Printf("Published:   (unpublished)\n")
			}
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
			var id *store.StoredIdentity
			if len(args) > 0 {
				id, _ = store.FindIdentityByName(args[0])
			} else {
				_, id2, _ := requireIdentity()
				id = id2
			}
			if id == nil {
				return fmt.Errorf("identity not found")
			}

			if jsonFlag {
				type keyInfo struct {
					ID       string `json:"id"`
					Role     string `json:"role"`
					Keychain bool   `json:"keychain"`
				}
				var items []keyInfo
				for _, k := range id.State.ControllerKeys {
					items = append(items, keyInfo{k.ID, "controller", keys.HasKey(id.DID + "#" + k.ID)})
				}
				for _, k := range id.State.AuthKeys {
					items = append(items, keyInfo{k.ID, "auth", keys.HasKey(id.DID + "#" + k.ID)})
				}
				for _, k := range id.State.AssertKeys {
					items = append(items, keyInfo{k.ID, "assert", keys.HasKey(id.DID + "#" + k.ID)})
				}
				outputJSON(items)
				return nil
			}

			fmt.Printf("Identity: %s (%s)\n\n", id.DID, id.Local.Name)
			fmt.Printf("%-30s %-12s %s\n", "KEY ID", "ROLE", "KEYCHAIN")
			printKeys := func(mkKeys []protocol.MultikeyPublicKey, role string) {
				for _, k := range mkKeys {
					has := "—"
					if keys.HasKey(id.DID + "#" + k.ID) {
						has = "present"
					}
					fmt.Printf("%-30s %-12s %s\n", k.ID, role, has)
				}
			}
			printKeys(id.State.ControllerKeys, "controller")
			printKeys(id.State.AuthKeys, "auth")
			printKeys(id.State.AssertKeys, "assert")
			return nil
		},
	}
}

func newIdentityPublishCmd() *cobra.Command {
	var relayName string
	return &cobra.Command{
		Use:   "publish [name]",
		Short: "Submit identity chain to a relay",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var id *store.StoredIdentity
			if len(args) > 0 {
				id, _ = store.FindIdentityByName(args[0])
			} else {
				_, id2, _ := requireIdentity()
				id = id2
			}
			if id == nil {
				return fmt.Errorf("identity not found")
			}

			rn := relayName
			if rn == "" {
				rn = relayFlag
			}
			if rn == "" {
				ctx, _ := resolveCtx()
				if ctx != nil {
					rn = ctx.RelayName
				}
			}
			if rn == "" {
				return fmt.Errorf("--relay is required")
			}

			c, _, err := getRelayClient(rn)
			if err != nil {
				return err
			}

			results, err := c.SubmitOperations(id.Log)
			if err != nil {
				return fmt.Errorf("submit: %w", err)
			}

			allAccepted := true
			for _, r := range results {
				if r.Status != "accepted" {
					allAccepted = false
					fmt.Printf("  Operation %s: %s (%s)\n", r.CID, r.Status, r.Error)
				}
			}

			if allAccepted {
				if !contains(id.Local.PublishedTo, rn) {
					id.Local.PublishedTo = append(id.Local.PublishedTo, rn)
					store.SaveIdentity(id)
				}
				if jsonFlag {
					outputJSON(map[string]any{"status": "published", "relay": rn, "operations": len(results)})
				} else {
					fmt.Printf("Identity published to '%s' (%d operation(s) accepted)\n", rn, len(results))
				}
			}
			return nil
		},
	}
}

func newIdentityFetchCmd() *cobra.Command {
	var name string
	var relayName string

	cmd := &cobra.Command{
		Use:   "fetch <did|name>",
		Short: "Download identity chain from relay to local store",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			did := target

			// check if it's a name of a known identity
			if existing, _ := store.FindIdentityByName(target); existing != nil {
				did = existing.DID
				if name == "" {
					name = existing.Local.Name
				}
			}
			if len(did) > 4 && did[:4] != "did:" {
				did = "did:dfos:" + did
			}

			rn := relayName
			if rn == "" {
				rn = relayFlag
			}
			if rn == "" {
				ctx, _ := resolveCtx()
				if ctx != nil {
					rn = ctx.RelayName
				}
			}
			if rn == "" {
				return fmt.Errorf("--relay is required for fetch")
			}

			c, _, err := getRelayClient(rn)
			if err != nil {
				return err
			}

			data, err := c.GetIdentity(did)
			if err != nil {
				return fmt.Errorf("fetch identity: %w", err)
			}

			// parse response
			log, _ := toStringSlice(data["log"])
			state := parseIdentityState(data["state"])

			storedID := &store.StoredIdentity{
				DID:   did,
				Log:   log,
				State: state,
				Local: store.LocalMeta{
					Name:   name,
					Origin: "fetched",
				},
			}

			if err := store.SaveIdentity(storedID); err != nil {
				return err
			}

			// register in config if named
			if name != "" {
				cfg.Identities[name] = config.IdentityConfig{DID: did}
				config.Save(cfg)
			}

			if jsonFlag {
				outputJSON(map[string]any{"did": did, "name": name, "operations": len(log), "origin": "fetched"})
			} else {
				fmt.Printf("Fetched identity: %s\n", did)
				fmt.Printf("  Operations: %d\n", len(log))
				if name != "" {
					fmt.Printf("  Name:       %s\n", name)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Local name for this identity")
	cmd.Flags().StringVar(&relayName, "relay", "", "Relay to fetch from")
	return cmd
}

func newIdentityRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove an identity from local store (keys stay in keychain)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			id, _ := store.FindIdentityByName(name)
			if id == nil {
				return fmt.Errorf("identity '%s' not found in local store", name)
			}

			if err := store.DeleteIdentity(id.DID); err != nil {
				return err
			}

			// remove from config
			delete(cfg.Identities, name)
			if cfg.ActiveContext != "" {
				// clear active context if it references this identity
				parts := strings.SplitN(cfg.ActiveContext, "@", 2)
				if len(parts) > 0 && parts[0] == name {
					cfg.ActiveContext = ""
				}
			}
			config.Save(cfg)

			if jsonFlag {
				outputJSON(map[string]string{"removed": name, "did": id.DID})
			} else {
				fmt.Printf("Removed identity '%s' (%s) from local store\n", name, id.DID)
				fmt.Printf("  Keys remain in keychain. To delete keys, use Keychain Access or:\n")
				allKeys := append(append(id.State.AuthKeys, id.State.ControllerKeys...), id.State.AssertKeys...)
				for _, k := range allKeys {
					fmt.Printf("    security delete-generic-password -s dfos -a \"%s#%s\"\n", id.DID, k.ID)
				}
			}
			return nil
		},
	}
}

// helpers

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

func parseIdentityState(v any) protocol.IdentityState {
	m, ok := v.(map[string]any)
	if !ok {
		return protocol.IdentityState{}
	}
	state := protocol.IdentityState{}
	if d, ok := m["did"].(string); ok {
		state.DID = d
	}
	if d, ok := m["isDeleted"].(bool); ok {
		state.IsDeleted = d
	}
	state.AuthKeys = parseMultikeyArray(m["authKeys"])
	state.AssertKeys = parseMultikeyArray(m["assertKeys"])
	state.ControllerKeys = parseMultikeyArray(m["controllerKeys"])
	return state
}

func parseMultikeyArray(v any) []protocol.MultikeyPublicKey {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var result []protocol.MultikeyPublicKey
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		mk := protocol.MultikeyPublicKey{}
		if id, ok := m["id"].(string); ok {
			mk.ID = id
		}
		if t, ok := m["type"].(string); ok {
			mk.Type = t
		}
		if p, ok := m["publicKeyMultibase"].(string); ok {
			mk.PublicKeyMultibase = p
		}
		result = append(result, mk)
	}
	return result
}

// publishIdentityIfNeeded checks if identity is published to the relay and publishes if needed.
func publishIdentityIfNeeded(id *store.StoredIdentity, relayName string, c *client.Client) error {
	if contains(id.Local.PublishedTo, relayName) {
		return nil
	}

	if !yesFlag {
		fmt.Printf("Identity '%s' has not been published to relay '%s'.\n", id.Local.Name, relayName)
		fmt.Printf("Publish now? This is required to continue. Use --yes to auto-confirm.\n")
		return fmt.Errorf("identity not published to relay '%s'. Re-run with --yes to auto-publish", relayName)
	}

	fmt.Printf("Publishing identity to '%s'... ", relayName)
	results, err := c.SubmitOperations(id.Log)
	if err != nil {
		return fmt.Errorf("submit: %w", err)
	}
	for _, r := range results {
		if r.Status != "accepted" {
			return fmt.Errorf("relay rejected: %s", r.Error)
		}
	}
	if !contains(id.Local.PublishedTo, relayName) {
		id.Local.PublishedTo = append(id.Local.PublishedTo, relayName)
		store.SaveIdentity(id)
	}
	fmt.Println("accepted")
	return nil
}
