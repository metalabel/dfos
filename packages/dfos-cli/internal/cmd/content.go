package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/store"
	"github.com/spf13/cobra"
)

func newContentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "content",
		Short:   "Manage content chains",
		GroupID: "content",
	}
	cmd.AddCommand(newContentCreateCmd())
	cmd.AddCommand(newContentListCmd())
	cmd.AddCommand(newContentShowCmd())
	cmd.AddCommand(newContentDownloadCmd())
	cmd.AddCommand(newContentPublishCmd())
	cmd.AddCommand(newContentFetchCmd())
	cmd.AddCommand(newContentLogCmd())
	cmd.AddCommand(newContentGrantCmd())
	cmd.AddCommand(newContentUpdateCmd())
	cmd.AddCommand(newContentDeleteCmd())
	cmd.AddCommand(newContentVerifyCmd())
	cmd.AddCommand(newContentRemoveCmd())
	return cmd
}

func newContentCreateCmd() *cobra.Command {
	var note string
	var relayName string
	var noSchemaWarn bool

	cmd := &cobra.Command{
		Use:   "create <file|->",
		Short: "Create a content chain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// resolve identity
			ctx, id, err := requireIdentity()
			if err != nil {
				return err
			}

			// read document
			var docBytes []byte
			if args[0] == "-" {
				docBytes, err = io.ReadAll(os.Stdin)
			} else {
				docBytes, err = os.ReadFile(args[0])
			}
			if err != nil {
				return fmt.Errorf("read document: %w", err)
			}

			// parse as JSON
			var doc any
			if err := json.Unmarshal(docBytes, &doc); err != nil {
				return fmt.Errorf("document must be valid JSON: %w", err)
			}

			// check $schema
			if !noSchemaWarn {
				if docMap, ok := doc.(map[string]any); ok {
					if _, has := docMap["$schema"]; !has {
						fmt.Fprintln(os.Stderr, "Warning: document has no $schema field (use --no-schema-warn to suppress)")
					}
				}
			}

			// compute document CID
			documentCID, _, err := protocol.DocumentCID(doc)
			if err != nil {
				return fmt.Errorf("compute document CID: %w", err)
			}

			// find auth key
			if len(id.State.AuthKeys) == 0 {
				return fmt.Errorf("identity has no auth keys")
			}
			authKeyID := id.State.AuthKeys[0].ID
			kid := id.DID + "#" + authKeyID
			privKey, err := keys.GetPrivateKey(id.DID + "#" + authKeyID)
			if err != nil {
				return fmt.Errorf("auth key not in keychain: %w", err)
			}

			// sign content create
			jwsToken, contentID, opCID, err := protocol.SignContentCreate(id.DID, documentCID, kid, note, privKey)
			if err != nil {
				return fmt.Errorf("sign content: %w", err)
			}

			// store blob locally
			blobPath, err := store.SaveBlob(contentID, docBytes)
			if err != nil {
				return fmt.Errorf("save blob: %w", err)
			}

			// store content chain
			docCIDPtr := &documentCID
			sc := &store.StoredContent{
				ContentID:  contentID,
				GenesisCID: opCID,
				Log:        []string{jwsToken},
				State: protocol.ContentState{
					ContentID:          contentID,
					GenesisCID:         opCID,
					HeadCID:            opCID,
					IsDeleted:          false,
					CurrentDocumentCID: docCIDPtr,
					Length:             1,
					CreatorDID:         id.DID,
				},
				Local: store.LocalMeta{
					Origin:   "created",
					BlobPath: blobPath,
				},
			}

			// determine relay
			rn := relayName
			if rn == "" {
				rn = relayFlag
			}
			if rn == "" && ctx.RelayName != "" {
				// don't auto-publish, just note the relay in context
			}

			// publish if relay specified
			if rn != "" {
				c, _, err := getRelayClient(rn)
				if err != nil {
					return err
				}

				// ensure identity is published
				if err := publishIdentityIfNeeded(id, rn, c); err != nil {
					return err
				}

				results, err := c.SubmitOperations([]string{jwsToken})
				if err != nil {
					return fmt.Errorf("submit: %w", err)
				}
				if len(results) > 0 && results[0].Status != "accepted" {
					return fmt.Errorf("relay rejected: %s", results[0].Error)
				}

				// upload blob
				info, err := c.GetRelayInfo()
				if err != nil {
					return fmt.Errorf("get relay info: %w", err)
				}
				authToken, err := protocol.CreateAuthToken(id.DID, info.DID, kid, 5*time.Minute, privKey)
				if err != nil {
					return fmt.Errorf("create auth token: %w", err)
				}
				if err := c.UploadBlob(contentID, opCID, docBytes, authToken); err != nil {
					return fmt.Errorf("upload blob: %w", err)
				}

				sc.Local.PublishedTo = []string{rn}
			}

			if err := store.SaveContent(sc); err != nil {
				return err
			}

			if jsonFlag {
				outputJSON(map[string]any{
					"contentId":   contentID,
					"documentCID": documentCID,
					"operationCID": opCID,
					"creatorDID":  id.DID,
					"publishedTo": sc.Local.PublishedTo,
				})
			} else {
				fmt.Printf("Content created:\n")
				fmt.Printf("  Content ID:   %s\n", contentID)
				fmt.Printf("  Document CID: %s\n", documentCID)
				if len(sc.Local.PublishedTo) > 0 {
					fmt.Printf("  Published to: %s\n", joinComma(sc.Local.PublishedTo))
				} else {
					fmt.Printf("  Status:       local only. Use 'dfos content publish' to submit to a relay.\n")
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&note, "note", "", "Operation note")
	cmd.Flags().StringVar(&relayName, "relay", "", "Publish to this relay immediately")
	cmd.Flags().BoolVar(&noSchemaWarn, "no-schema-warn", false, "Suppress $schema warning")
	return cmd
}

func newContentListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List all locally stored content chains",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			chains, err := store.ListContent()
			if err != nil {
				return err
			}
			if len(chains) == 0 {
				if jsonFlag {
					fmt.Println("[]")
				} else {
					fmt.Println("No content chains. Use 'dfos content create <file>'")
				}
				return nil
			}

			if jsonFlag {
				outputJSON(chains)
				return nil
			}

			fmt.Printf("%-24s %-36s %-4s %-10s %s\n", "CONTENT ID", "CREATOR", "OPS", "ORIGIN", "PUBLISHED")
			for _, c := range chains {
				creatorName := config.FindIdentityName(cfg, c.State.CreatorDID)
				creator := c.State.CreatorDID
				if creatorName != "" {
					creator = creatorName
				}
				published := "—"
				if len(c.Local.PublishedTo) > 0 {
					published = joinComma(c.Local.PublishedTo)
				} else if c.Local.Origin == "created" {
					published = "(unpublished)"
				}
				fmt.Printf("%-24s %-36s %-4d %-10s %s\n",
					c.ContentID, creator, c.State.Length, c.Local.Origin, published)
			}
			return nil
		},
	}
}

func newContentShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <contentId>",
		Short: "Show content chain state",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contentID := args[0]
			sc, err := store.LoadContent(contentID)
			if err != nil {
				return err
			}
			if sc == nil {
				return fmt.Errorf("content chain '%s' not found in local store", contentID)
			}

			if jsonFlag {
				outputJSON(sc)
				return nil
			}

			fmt.Printf("Content ID:   %s\n", sc.ContentID)
			fmt.Printf("Creator:      %s\n", sc.State.CreatorDID)
			fmt.Printf("Operations:   %d\n", sc.State.Length)
			if sc.State.CurrentDocumentCID != nil {
				fmt.Printf("Current Doc:  %s\n", *sc.State.CurrentDocumentCID)
			}
			fmt.Printf("Deleted:      %v\n", sc.State.IsDeleted)
			fmt.Printf("Origin:       %s\n", sc.Local.Origin)
			if len(sc.Local.PublishedTo) > 0 {
				fmt.Printf("Published:    %s\n", joinComma(sc.Local.PublishedTo))
			}
			return nil
		},
	}
}

func newContentDownloadCmd() *cobra.Command {
	var outputFile string
	var credential string
	var relayName string
	var ref string

	cmd := &cobra.Command{
		Use:   "download <contentId>",
		Short: "Download content blob",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contentID := args[0]

			// resolve identity for access control
			ctx, id, err := requireIdentity()
			if err != nil {
				return err
			}

			// try local blob — enforce same access rules as relay:
			// creator can read without credential, everyone else needs one
			// skip local fallback if --ref is specified or content is deleted
			sc, _ := store.LoadContent(contentID)
			if sc != nil && ref == "" && !sc.State.IsDeleted {
				isCreator := id.DID == sc.State.CreatorDID
				if isCreator {
					blob, err := store.LoadBlob(contentID)
					if err == nil {
						return writeBlob(blob, outputFile)
					}
				}
				// non-creator with credential and local blob → verify locally
				if !isCreator && credential != "" {
					blob, blobErr := store.LoadBlob(contentID)
					if blobErr == nil {
						if _, err := verifyCredentialLocally(credential, sc.State.CreatorDID, id.DID, contentID); err == nil {
							return writeBlob(blob, outputFile)
						}
						// verification failed — fall through to relay
					}
				}
				// not the creator and no credential → don't serve local blob
				if !isCreator && credential == "" {
					return fmt.Errorf("DFOSContentRead credential required (you are not the content creator)")
				}
			}

			rn := relayName
			if rn == "" {
				rn = relayFlag
			}
			if rn == "" {
				rn = ctx.RelayName
			}
			if rn == "" {
				return fmt.Errorf("--relay is required for remote download")
			}

			c, _, err := getRelayClient(rn)
			if err != nil {
				return err
			}

			// get auth key
			if len(id.State.AuthKeys) == 0 {
				return fmt.Errorf("identity has no auth keys")
			}
			authKeyID := id.State.AuthKeys[0].ID
			kid := id.DID + "#" + authKeyID
			privKey, err := keys.GetPrivateKey(id.DID + "#" + authKeyID)
			if err != nil {
				return fmt.Errorf("auth key not in keychain: %w", err)
			}

			info, err := c.GetRelayInfo()
			if err != nil {
				return err
			}
			authToken, err := protocol.CreateAuthToken(id.DID, info.DID, kid, 5*time.Minute, privKey)
			if err != nil {
				return err
			}

			blob, _, err := c.DownloadBlob(contentID, authToken, credential, ref)
			if err != nil {
				return fmt.Errorf("download: %w", err)
			}

			return writeBlob(blob, outputFile)
		},
	}
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write to file instead of stdout")
	cmd.Flags().StringVar(&credential, "credential", "", "DFOSContentRead VC-JWT credential")
	cmd.Flags().StringVar(&relayName, "relay", "", "Relay to download from")
	cmd.Flags().StringVar(&ref, "ref", "", "Download blob at specific operation CID (historical version)")
	return cmd
}

func newContentPublishCmd() *cobra.Command {
	var relayName string
	return &cobra.Command{
		Use:   "publish <contentId>",
		Short: "Submit content chain + blob to a relay",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contentID := args[0]
			sc, err := store.LoadContent(contentID)
			if err != nil || sc == nil {
				return fmt.Errorf("content chain '%s' not found", contentID)
			}

			_, id, err := requireIdentity()
			if err != nil {
				return err
			}

			rn := relayName
			if rn == "" {
				rn = relayFlag
			}
			if rn == "" {
				return fmt.Errorf("--relay is required")
			}

			c, _, err := getRelayClient(rn)
			if err != nil {
				return err
			}

			// ensure identity is published first
			if err := publishIdentityIfNeeded(id, rn, c); err != nil {
				return err
			}

			// submit operations
			results, err := c.SubmitOperations(sc.Log)
			if err != nil {
				return fmt.Errorf("submit: %w", err)
			}
			for _, r := range results {
				if r.Status != "accepted" {
					return fmt.Errorf("relay rejected: %s", r.Error)
				}
			}

			// upload blob if we have it (use the head operation CID)
			if sc.State.CurrentDocumentCID != nil {
				blob, err := store.LoadBlob(contentID)
				if err == nil {
					authKeyID := id.State.AuthKeys[0].ID
					kid := id.DID + "#" + authKeyID
					privKey, _ := keys.GetPrivateKey(id.DID + "#" + authKeyID)

					info, _ := c.GetRelayInfo()
					authToken, _ := protocol.CreateAuthToken(id.DID, info.DID, kid, 5*time.Minute, privKey)
					c.UploadBlob(contentID, sc.State.HeadCID, blob, authToken)
				}
			}

			if !contains(sc.Local.PublishedTo, rn) {
				sc.Local.PublishedTo = append(sc.Local.PublishedTo, rn)
				store.SaveContent(sc)
			}

			if jsonFlag {
				outputJSON(map[string]any{"status": "published", "relay": rn, "contentId": contentID})
			} else {
				fmt.Printf("Content '%s' published to '%s'\n", contentID, rn)
			}
			return nil
		},
	}
}

func newContentFetchCmd() *cobra.Command {
	var relayName string
	cmd := &cobra.Command{
		Use:   "fetch <contentId>",
		Short: "Download content chain from relay to local store",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contentID := args[0]
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

			data, err := c.GetContent(contentID)
			if err != nil {
				return fmt.Errorf("fetch content: %w", err)
			}

			log, _ := toStringSlice(data["log"])
			state := parseContentState(data["state"])
			genesisCID, _ := data["genesisCID"].(string)

			sc := &store.StoredContent{
				ContentID:  contentID,
				GenesisCID: genesisCID,
				Log:        log,
				State:      state,
				Local: store.LocalMeta{
					Origin: "fetched",
				},
			}

			if err := store.SaveContent(sc); err != nil {
				return err
			}

			if jsonFlag {
				outputJSON(map[string]any{"contentId": contentID, "operations": len(log), "origin": "fetched"})
			} else {
				fmt.Printf("Fetched content: %s (%d operations)\n", contentID, len(log))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&relayName, "relay", "", "Relay to fetch from")
	return cmd
}

func newContentLogCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "log <contentId>",
		Short: "Show operation history",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contentID := args[0]
			sc, err := store.LoadContent(contentID)
			if err != nil || sc == nil {
				return fmt.Errorf("content chain '%s' not found", contentID)
			}

			if jsonFlag {
				type opInfo struct {
					Index int    `json:"index"`
					CID   string `json:"cid,omitempty"`
					Type  string `json:"type,omitempty"`
				}
				var ops []opInfo
				for i, token := range sc.Log {
					h, p, _ := protocol.DecodeJWSUnsafe(token)
					op := opInfo{Index: i}
					if h != nil {
						op.CID = h.CID
					}
					if p != nil {
						if t, ok := p["type"].(string); ok {
							op.Type = t
						}
					}
					ops = append(ops, op)
				}
				outputJSON(ops)
				return nil
			}

			fmt.Printf("Content: %s (%d operations)\n\n", contentID, len(sc.Log))
			for i, token := range sc.Log {
				h, p, _ := protocol.DecodeJWSUnsafe(token)
				opType := "?"
				if p != nil {
					if t, ok := p["type"].(string); ok {
						opType = t
					}
				}
				cid := ""
				if h != nil {
					cid = h.CID
				}
				fmt.Printf("  [%d] %s  %s\n", i, opType, cid)
			}
			return nil
		},
	}
}

func newContentGrantCmd() *cobra.Command {
	var read, write bool
	var ttl string
	var scopeContentID string
	var noScope bool

	cmd := &cobra.Command{
		Use:   "grant <contentId> <did>",
		Short: "Issue a read or write credential",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			contentID := args[0]
			subjectDID := args[1]

			if !read && !write {
				return fmt.Errorf("specify --read or --write")
			}

			_, id, err := requireIdentity()
			if err != nil {
				return err
			}

			credType := "DFOSContentRead"
			if write {
				credType = "DFOSContentWrite"
			}

			dur, err := time.ParseDuration(ttl)
			if err != nil {
				dur = 24 * time.Hour
			}

			if len(id.State.AuthKeys) == 0 {
				return fmt.Errorf("identity has no auth keys")
			}
			authKeyID := id.State.AuthKeys[0].ID
			kid := id.DID + "#" + authKeyID
			privKey, err := keys.GetPrivateKey(id.DID + "#" + authKeyID)
			if err != nil {
				return fmt.Errorf("auth key not in keychain: %w", err)
			}

			scope := contentID
			if noScope {
				scope = ""
			} else if scopeContentID != "" {
				scope = scopeContentID
			}

			token, err := protocol.CreateCredential(id.DID, subjectDID, kid, credType, dur, scope, privKey)
			if err != nil {
				return fmt.Errorf("create credential: %w", err)
			}

			if jsonFlag {
				outputJSON(map[string]any{
					"credential": token,
					"type":       credType,
					"issuer":     id.DID,
					"subject":    subjectDID,
					"contentId":  scope,
					"expiresIn":  dur.String(),
				})
			} else {
				fmt.Printf("Credential issued (%s, expires in %s):\n  %s\n", credType, dur, token)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&read, "read", false, "Issue DFOSContentRead credential")
	cmd.Flags().BoolVar(&write, "write", false, "Issue DFOSContentWrite credential")
	cmd.Flags().StringVar(&ttl, "ttl", "24h", "Credential TTL")
	cmd.Flags().StringVar(&scopeContentID, "scope", "", "Scope credential to specific content ID")
	cmd.Flags().BoolVar(&noScope, "broad", false, "Issue broad credential (not scoped to any content ID)")
	return cmd
}

func newContentUpdateCmd() *cobra.Command {
	var note string
	var relayName string
	var authorization string
	var baseDocumentCID string

	cmd := &cobra.Command{
		Use:   "update <contentId> <file|->",
		Short: "Update content chain with new document",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			contentID := args[0]
			sc, err := store.LoadContent(contentID)
			if err != nil || sc == nil {
				return fmt.Errorf("content chain '%s' not found", contentID)
			}

			if sc.State.IsDeleted {
				return fmt.Errorf("content chain is deleted — cannot update")
			}

			_, id, err := requireIdentity()
			if err != nil {
				return err
			}

			// read document
			var docBytes []byte
			if args[1] == "-" {
				docBytes, err = io.ReadAll(os.Stdin)
			} else {
				docBytes, err = os.ReadFile(args[1])
			}
			if err != nil {
				return fmt.Errorf("read document: %w", err)
			}

			var doc any
			if err := json.Unmarshal(docBytes, &doc); err != nil {
				return fmt.Errorf("document must be valid JSON: %w", err)
			}

			documentCID, _, err := protocol.DocumentCID(doc)
			if err != nil {
				return err
			}

			authKeyID := id.State.AuthKeys[0].ID
			kid := id.DID + "#" + authKeyID
			privKey, err := keys.GetPrivateKey(id.DID + "#" + authKeyID)
			if err != nil {
				return err
			}

			jwsToken, opCID, err := protocol.SignContentUpdateWithOptions(
				id.DID, sc.State.HeadCID, documentCID, kid, privKey,
				protocol.ContentUpdateOptions{
					Note:            note,
					BaseDocumentCID: baseDocumentCID,
					Authorization:   authorization,
				},
			)
			if err != nil {
				return err
			}

			sc.Log = append(sc.Log, jwsToken)
			sc.State.HeadCID = opCID
			sc.State.CurrentDocumentCID = &documentCID
			sc.State.Length++

			store.SaveBlob(contentID, docBytes)

			// publish if relay
			rn := relayName
			if rn == "" {
				rn = relayFlag
			}
			if rn != "" {
				c, _, err := getRelayClient(rn)
				if err != nil {
					return err
				}
				results, err := c.SubmitOperations([]string{jwsToken})
				if err != nil {
					return err
				}
				if len(results) > 0 && results[0].Status != "accepted" {
					return fmt.Errorf("relay rejected: %s", results[0].Error)
				}

				info, _ := c.GetRelayInfo()
				authToken, _ := protocol.CreateAuthToken(id.DID, info.DID, kid, 5*time.Minute, privKey)
				c.UploadBlob(contentID, opCID, docBytes, authToken)
			}

			store.SaveContent(sc)

			if jsonFlag {
				outputJSON(map[string]any{"contentId": contentID, "operationCID": opCID, "documentCID": documentCID})
			} else {
				fmt.Printf("Content updated:\n  Operation CID: %s\n  Document CID:  %s\n", opCID, documentCID)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&note, "note", "", "Operation note")
	cmd.Flags().StringVar(&relayName, "relay", "", "Publish to this relay immediately")
	cmd.Flags().StringVar(&authorization, "authorization", "", "DFOSContentWrite VC-JWT for delegated writes")
	cmd.Flags().StringVar(&baseDocumentCID, "base-document-cid", "", "CID of the base document this update is derived from")
	return cmd
}

func newContentDeleteCmd() *cobra.Command {
	var note string
	var relayName string
	var authorization string

	cmd := &cobra.Command{
		Use:   "delete <contentId>",
		Short: "Permanently delete a content chain (sign delete operation)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contentID := args[0]
			sc, err := store.LoadContent(contentID)
			if err != nil || sc == nil {
				return fmt.Errorf("content chain '%s' not found", contentID)
			}

			if sc.State.IsDeleted {
				return fmt.Errorf("content chain is already deleted")
			}

			_, id, err := requireIdentity()
			if err != nil {
				return err
			}

			if len(id.State.AuthKeys) == 0 {
				return fmt.Errorf("identity has no auth keys")
			}
			authKeyID := id.State.AuthKeys[0].ID
			kid := id.DID + "#" + authKeyID
			privKey, err := keys.GetPrivateKey(id.DID + "#" + authKeyID)
			if err != nil {
				return fmt.Errorf("auth key not in keychain: %w", err)
			}

			jwsToken, opCID, err := protocol.SignContentDelete(id.DID, sc.State.HeadCID, kid, note, authorization, privKey)
			if err != nil {
				return fmt.Errorf("sign delete: %w", err)
			}

			// update local state
			sc.Log = append(sc.Log, jwsToken)
			sc.State.HeadCID = opCID
			sc.State.IsDeleted = true
			sc.State.CurrentDocumentCID = nil
			sc.State.Length++

			// publish if relay specified
			rn := relayName
			if rn == "" {
				rn = relayFlag
			}
			if rn != "" {
				c, _, err := getRelayClient(rn)
				if err != nil {
					return err
				}
				results, err := c.SubmitOperations([]string{jwsToken})
				if err != nil {
					return fmt.Errorf("submit: %w", err)
				}
				if len(results) > 0 && results[0].Status != "accepted" {
					return fmt.Errorf("relay rejected: %s", results[0].Error)
				}
			}

			store.SaveContent(sc)

			if jsonFlag {
				outputJSON(map[string]any{"contentId": contentID, "operationCID": opCID, "deleted": true})
			} else {
				fmt.Printf("Content deleted:\n")
				fmt.Printf("  Content ID:     %s\n", contentID)
				fmt.Printf("  Operation CID:  %s\n", opCID)
				fmt.Printf("  This content chain can no longer be extended.\n")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&note, "note", "", "Operation note")
	cmd.Flags().StringVar(&relayName, "relay", "", "Publish to this relay immediately")
	cmd.Flags().StringVar(&authorization, "authorization", "", "DFOSContentWrite VC-JWT for delegated deletes")
	return cmd
}

func newContentVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <contentId>",
		Short: "Re-verify content chain integrity locally",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contentID := args[0]
			sc, _ := store.LoadContent(contentID)
			if sc == nil {
				return fmt.Errorf("content chain '%s' not found. Use 'dfos content fetch' first.", contentID)
			}

			result := map[string]any{
				"valid":     true,
				"contentId": contentID,
				"operations": len(sc.Log),
			}

			// verify each operation's CID matches
			cidsVerified := 0
			sigsVerified := 0
			for i, token := range sc.Log {
				h, p, err := protocol.DecodeJWSUnsafe(token)
				if err != nil {
					result["valid"] = false
					result["error"] = fmt.Sprintf("operation %d: %v", i, err)
					break
				}

				// re-derive CID
				_, _, cidStr, err := protocol.DagCborCID(p)
				if err != nil {
					result["valid"] = false
					result["error"] = fmt.Sprintf("operation %d: CID derivation failed", i)
					break
				}
				if cidStr != h.CID {
					result["valid"] = false
					result["error"] = fmt.Sprintf("operation %d: CID mismatch (got %s, expected %s)", i, cidStr, h.CID)
					break
				}
				cidsVerified++

				// verify signature if we have the key
				kid := h.Kid
				hashIdx := strings.Index(kid, "#")
				if hashIdx >= 0 {
					did := kid[:hashIdx]
					keyID := kid[hashIdx+1:]
					storedID, _ := store.LoadIdentity(did)
					if storedID != nil {
						allKeys := append(append(storedID.State.AuthKeys, storedID.State.ControllerKeys...), storedID.State.AssertKeys...)
						for _, k := range allKeys {
							if k.ID == keyID {
								pubBytes, err := protocol.DecodeMultikey(k.PublicKeyMultibase)
								if err == nil {
									_, _, verifyErr := protocol.VerifyJWS(token, pubBytes)
									if verifyErr != nil {
										result["valid"] = false
										result["error"] = fmt.Sprintf("operation %d: signature verification failed", i)
									} else {
										sigsVerified++
									}
								}
								break
							}
						}
					}
				}
			}

			result["cidsVerified"] = cidsVerified
			result["signaturesVerified"] = sigsVerified
			result["creatorDID"] = sc.State.CreatorDID

			if jsonFlag {
				outputJSON(result)
			} else {
				if result["valid"].(bool) {
					fmt.Printf("Content chain '%s' is valid.\n", contentID)
					fmt.Printf("  Operations:      %d\n", len(sc.Log))
					fmt.Printf("  CIDs verified:   %d\n", cidsVerified)
					fmt.Printf("  Sigs verified:   %d\n", sigsVerified)
					fmt.Printf("  Creator:         %s\n", sc.State.CreatorDID)
				} else {
					fmt.Printf("Content chain '%s' FAILED verification.\n", contentID)
					fmt.Printf("  Error: %s\n", result["error"])
				}
			}
			return nil
		},
	}
}

func newContentRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <contentId>",
		Short: "Remove a content chain from local store",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contentID := args[0]
			sc, _ := store.LoadContent(contentID)
			if sc == nil {
				return fmt.Errorf("content chain '%s' not found in local store", contentID)
			}

			if err := store.DeleteContent(contentID); err != nil {
				return err
			}
			store.DeleteBlob(contentID)

			if jsonFlag {
				outputJSON(map[string]string{"removed": contentID})
			} else {
				fmt.Printf("Removed content '%s' from local store\n", contentID)
			}
			return nil
		},
	}
}

// helpers

func writeBlob(data []byte, outputFile string) error {
	if outputFile != "" {
		if err := os.WriteFile(outputFile, data, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Saved to %s (%d bytes)\n", outputFile, len(data))
		return nil
	}
	_, err := os.Stdout.Write(data)
	return err
}

// verifyCredentialLocally verifies a VC-JWT credential using the creator's
// identity from the local store. Returns the verified credential or an error.
func verifyCredentialLocally(credential, creatorDID, subjectDID, contentID string) (*protocol.VerifiedCredential, error) {
	// decode credential to get kid (issuer key reference)
	header, _, err := protocol.DecodeJWTUnsafe(credential)
	if err != nil {
		return nil, fmt.Errorf("decode credential: %w", err)
	}
	kid, ok := header["kid"]
	if !ok || kid == "" {
		return nil, fmt.Errorf("credential has no kid")
	}

	// kid must be a DID URL — extract the DID and key ID
	hashIdx := strings.Index(kid, "#")
	if hashIdx < 0 {
		return nil, fmt.Errorf("credential kid is not a DID URL")
	}
	kidDID := kid[:hashIdx]
	keyID := kid[hashIdx+1:]

	// the issuer DID should match the creator DID
	if kidDID != creatorDID {
		return nil, fmt.Errorf("credential issuer does not match content creator")
	}

	// load the creator's identity from local store
	creatorIdentity, err := store.LoadIdentity(creatorDID)
	if err != nil || creatorIdentity == nil {
		return nil, fmt.Errorf("creator identity not in local store")
	}

	// find the issuer's public key in the creator's key state
	allKeys := append(append(creatorIdentity.State.AuthKeys, creatorIdentity.State.ControllerKeys...), creatorIdentity.State.AssertKeys...)
	var pubBytes []byte
	for _, k := range allKeys {
		if k.ID == keyID {
			pubBytes, err = protocol.DecodeMultikey(k.PublicKeyMultibase)
			if err != nil {
				return nil, fmt.Errorf("decode issuer public key: %w", err)
			}
			break
		}
	}
	if pubBytes == nil {
		return nil, fmt.Errorf("issuer key not found in creator identity")
	}

	// verify the credential
	vc, err := protocol.VerifyCredential(credential, pubBytes, subjectDID, "DFOSContentRead")
	if err != nil {
		return nil, fmt.Errorf("credential verification failed: %w", err)
	}

	// check content scope: if credential has a contentId, it must match
	if vc.ContentID != "" && vc.ContentID != contentID {
		return nil, fmt.Errorf("credential scoped to different content (%s)", vc.ContentID)
	}

	return vc, nil
}

func parseContentState(v any) protocol.ContentState {
	m, ok := v.(map[string]any)
	if !ok {
		return protocol.ContentState{}
	}
	state := protocol.ContentState{}
	if s, ok := m["contentId"].(string); ok {
		state.ContentID = s
	}
	if s, ok := m["genesisCID"].(string); ok {
		state.GenesisCID = s
	}
	if s, ok := m["headCID"].(string); ok {
		state.HeadCID = s
	}
	if b, ok := m["isDeleted"].(bool); ok {
		state.IsDeleted = b
	}
	if s, ok := m["currentDocumentCID"].(string); ok {
		state.CurrentDocumentCID = &s
	}
	if f, ok := m["length"].(float64); ok {
		state.Length = int(f)
	}
	if s, ok := m["creatorDID"].(string); ok {
		state.CreatorDID = s
	}
	return state
}
