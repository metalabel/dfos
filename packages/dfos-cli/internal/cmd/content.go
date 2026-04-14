package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/localrelay"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
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
	var peerName string
	var noSchemaWarn bool

	cmd := &cobra.Command{
		Use:   "create <file|->",
		Short: "Create a content chain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, chain, err := requireIdentity()
			if err != nil {
				return err
			}

			lr, err := getRelay()
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

			var doc any
			if err := json.Unmarshal(docBytes, &doc); err != nil {
				return fmt.Errorf("document must be valid JSON: %w", err)
			}

			if !noSchemaWarn {
				if docMap, ok := doc.(map[string]any); ok {
					if _, has := docMap["$schema"]; !has {
						fmt.Fprintln(os.Stderr, "Warning: document has no $schema field (use --no-schema-warn to suppress)")
					}
				}
			}

			documentCID, _, err := protocol.DocumentCID(doc)
			if err != nil {
				return fmt.Errorf("compute document CID: %w", err)
			}

			if len(chain.State.AuthKeys) == 0 {
				return fmt.Errorf("identity has no auth keys")
			}
			authKeyID := chain.State.AuthKeys[0].ID
			kid := chain.DID + "#" + authKeyID
			privKey, err := keys.GetPrivateKey(chain.DID + "#" + authKeyID)
			if err != nil {
				return fmt.Errorf("auth key not in keychain: %w", err)
			}

			jwsToken, contentID, opCID, err := protocol.SignContentCreate(chain.DID, documentCID, kid, note, privKey)
			if err != nil {
				return fmt.Errorf("sign content: %w", err)
			}

			// ingest into local relay
			results := lr.Relay.Ingest([]string{jwsToken})
			if len(results) > 0 && results[0].Status == "rejected" {
				return fmt.Errorf("local relay rejected: %s", results[0].Error)
			}

			// store blob in relay
			lr.Store.PutBlob(relay.BlobKey{CreatorDID: chain.DID, DocumentCID: documentCID}, docBytes)

			// push to peer if specified
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
				if err := publishIdentityIfNeeded(chain, rn, c); err != nil {
					return err
				}
				peerResults, err := c.SubmitOperations([]string{jwsToken})
				if err != nil {
					return fmt.Errorf("submit: %w", err)
				}
				if len(peerResults) > 0 && peerResults[0].Status == "rejected" {
					return fmt.Errorf("peer rejected: %s", peerResults[0].Error)
				}

				// upload blob to peer
				info, err := c.GetRelayInfo()
				if err != nil {
					return fmt.Errorf("get peer info: %w", err)
				}
				authToken, err := protocol.CreateAuthToken(chain.DID, info.DID, kid, 5*time.Minute, privKey)
				if err != nil {
					return fmt.Errorf("create auth token: %w", err)
				}
				if err := c.UploadBlob(contentID, opCID, docBytes, authToken); err != nil {
					return fmt.Errorf("upload blob: %w", err)
				}

				publishedTo = append(publishedTo, rn)
			}

			if jsonFlag {
				outputJSON(map[string]any{
					"contentId":    contentID,
					"documentCID":  documentCID,
					"operationCID": opCID,
					"creatorDID":   chain.DID,
					"publishedTo":  publishedTo,
				})
			} else {
				fmt.Printf("Content created:\n")
				fmt.Printf("  Content ID:   %s\n", contentID)
				fmt.Printf("  Document CID: %s\n", documentCID)
				if len(publishedTo) > 0 {
					fmt.Printf("  Published to: %s\n", joinComma(publishedTo))
				} else {
					fmt.Printf("  Status:       local only. Use 'dfos content publish' to push to a peer.\n")
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&note, "note", "", "Operation note")
	cmd.Flags().StringVar(&peerName, "peer", "", "Push to this peer immediately")
	cmd.Flags().BoolVar(&noSchemaWarn, "no-schema-warn", false, "Suppress $schema warning")
	return cmd
}

func newContentListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List all locally stored content chains",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			lr, err := getRelay()
			if err != nil {
				return err
			}

			chains, err := lr.Store.ListContentChains()
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

			fmt.Printf("%-24s %-36s %-4s\n", "CONTENT ID", "CREATOR", "OPS")
			for _, c := range chains {
				creatorName := config.FindIdentityName(cfg, c.State.CreatorDID)
				creator := c.State.CreatorDID
				if creatorName != "" {
					creator = creatorName
				}
				fmt.Printf("%-24s %-36s %-4d\n",
					c.ContentID, creator, c.State.Length)
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
			lr, err := getRelay()
			if err != nil {
				return err
			}

			chain, err := lr.Relay.GetContent(contentID)
			if err != nil {
				return err
			}
			if chain == nil {
				return fmt.Errorf("content chain '%s' not found", contentID)
			}

			if jsonFlag {
				outputJSON(chain)
				return nil
			}

			fmt.Printf("Content ID:   %s\n", chain.ContentID)
			fmt.Printf("Creator:      %s\n", chain.State.CreatorDID)
			fmt.Printf("Operations:   %d\n", chain.State.Length)
			if chain.State.CurrentDocumentCID != nil {
				fmt.Printf("Current Doc:  %s\n", *chain.State.CurrentDocumentCID)
			}
			fmt.Printf("Deleted:      %v\n", chain.State.IsDeleted)
			return nil
		},
	}
}

func newContentDownloadCmd() *cobra.Command {
	var outputFile string
	var credential string
	var peerName string
	var ref string

	cmd := &cobra.Command{
		Use:   "download <contentId>",
		Short: "Download content blob",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contentID := args[0]

			ctx, chain, err := requireIdentity()
			if err != nil {
				return err
			}

			lr, err := getRelay()
			if err != nil {
				return err
			}

			// try local blob first
			contentChain, _ := lr.Relay.GetContent(contentID)
			if contentChain != nil && ref == "" && !contentChain.State.IsDeleted && contentChain.State.CurrentDocumentCID != nil {
				isCreator := chain.DID == contentChain.State.CreatorDID
				blobKey := relay.BlobKey{
					CreatorDID:  contentChain.State.CreatorDID,
					DocumentCID: *contentChain.State.CurrentDocumentCID,
				}
				if isCreator {
					blob, _ := lr.Store.GetBlob(blobKey)
					if blob != nil {
						return writeBlob(blob, outputFile)
					}
				}
				// non-creator with credential — try local verification
				if !isCreator && credential != "" {
					blob, _ := lr.Store.GetBlob(blobKey)
					if blob != nil {
						if verifyCredentialLocally(lr, credential, contentChain.State.CreatorDID, chain.DID, contentID) == nil {
							return writeBlob(blob, outputFile)
						}
						// verification failed — fall through to peer
					}
				}
				if !isCreator && credential == "" {
					return fmt.Errorf("read credential required (you are not the content creator)")
				}
			}

			// fall through to peer download
			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn == "" {
				rn = ctx.RelayName
			}
			if rn == "" {
				return fmt.Errorf("--peer is required for remote download")
			}

			c, _, err := getPeerClient(rn)
			if err != nil {
				return err
			}

			if len(chain.State.AuthKeys) == 0 {
				return fmt.Errorf("identity has no auth keys")
			}
			authKeyID := chain.State.AuthKeys[0].ID
			kid := chain.DID + "#" + authKeyID
			privKey, err := keys.GetPrivateKey(chain.DID + "#" + authKeyID)
			if err != nil {
				return fmt.Errorf("auth key not in keychain: %w", err)
			}

			info, err := c.GetRelayInfo()
			if err != nil {
				return err
			}
			authToken, err := protocol.CreateAuthToken(chain.DID, info.DID, kid, 5*time.Minute, privKey)
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
	cmd.Flags().StringVar(&credential, "credential", "", "DFOS read credential JWS")
	cmd.Flags().StringVar(&peerName, "peer", "", "Peer to download from")
	cmd.Flags().StringVar(&ref, "ref", "", "Download blob at specific operation CID (historical version)")
	return cmd
}

func newContentPublishCmd() *cobra.Command {
	var peerName string
	return &cobra.Command{
		Use:   "publish <contentId>",
		Short: "Push content chain + blob to a peer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contentID := args[0]

			lr, err := getRelay()
			if err != nil {
				return err
			}
			contentChain, err := lr.Relay.GetContent(contentID)
			if err != nil || contentChain == nil {
				return fmt.Errorf("content chain '%s' not found", contentID)
			}

			_, idChain, err := requireIdentity()
			if err != nil {
				return err
			}

			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn == "" {
				return fmt.Errorf("--peer is required")
			}

			c, _, err := getPeerClient(rn)
			if err != nil {
				return err
			}

			if err := publishIdentityIfNeeded(idChain, rn, c); err != nil {
				return err
			}

			peerResults, err := c.SubmitOperations(contentChain.Log)
			if err != nil {
				return fmt.Errorf("submit: %w", err)
			}
			for _, r := range peerResults {
				if r.Status == "rejected" {
					return fmt.Errorf("peer rejected: %s", r.Error)
				}
			}

			// upload blob if we have it
			if contentChain.State.CurrentDocumentCID != nil {
				blob, _ := lr.Store.GetBlob(relay.BlobKey{
					CreatorDID:  contentChain.State.CreatorDID,
					DocumentCID: *contentChain.State.CurrentDocumentCID,
				})
				if blob != nil && len(idChain.State.AuthKeys) > 0 {
					authKeyID := idChain.State.AuthKeys[0].ID
					kid := idChain.DID + "#" + authKeyID
					privKey, _ := keys.GetPrivateKey(idChain.DID + "#" + authKeyID)
					info, _ := c.GetRelayInfo()
					authToken, _ := protocol.CreateAuthToken(idChain.DID, info.DID, kid, 5*time.Minute, privKey)
					c.UploadBlob(contentID, contentChain.State.HeadCID, blob, authToken)
				}
			}

			if jsonFlag {
				outputJSON(map[string]any{"status": "published", "peer": rn, "contentId": contentID})
			} else {
				fmt.Printf("Content '%s' published to '%s'\n", contentID, rn)
			}
			return nil
		},
	}
}

func newContentFetchCmd() *cobra.Command {
	var peerName string
	cmd := &cobra.Command{
		Use:   "fetch <contentId>",
		Short: "Download content chain from peer into local relay",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contentID := args[0]
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

			data, err := c.GetContent(contentID)
			if err != nil {
				return fmt.Errorf("fetch content: %w", err)
			}

			log, _ := toStringSlice(data["log"])

			lr, err := getRelay()
			if err != nil {
				return err
			}

			// fetch creator identity first — ingestion needs it for key resolution
			if len(log) > 0 {
				_, p, _ := protocol.DecodeJWSUnsafe(log[0])
				if p != nil {
					if kid, ok := p["kid"].(string); ok {
						if idx := strings.Index(kid, "#"); idx > 0 {
							creatorDID := kid[:idx]
							fetchAndIngestIdentity(lr, c, creatorDID)
						}
					}
					// also try the did field in the payload (content create has it)
					if creatorDID, ok := p["did"].(string); ok && strings.HasPrefix(creatorDID, "did:dfos:") {
						fetchAndIngestIdentity(lr, c, creatorDID)
					}
				}
			}

			results := lr.Relay.Ingest(log)
			for _, r := range results {
				if r.Status == "rejected" {
					fmt.Printf("  Warning: operation %s rejected: %s\n", r.CID, r.Error)
				}
			}

			if len(log) == 0 {
				if jsonFlag {
					outputJSON(map[string]any{"contentId": contentID, "operations": 0, "warning": "content not found on peer"})
				} else {
					fmt.Fprintf(os.Stderr, "Warning: content '%s' not found on peer (0 operations fetched)\n", contentID)
				}
				return nil
			}

			if jsonFlag {
				outputJSON(map[string]any{"contentId": contentID, "operations": len(log)})
			} else {
				fmt.Printf("Fetched content: %s (%d operations)\n", contentID, len(log))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&peerName, "peer", "", "Peer to fetch from")
	return cmd
}

func newContentLogCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "log <contentId>",
		Short: "Show operation history",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contentID := args[0]
			lr, err := getRelay()
			if err != nil {
				return err
			}
			chain, err := lr.Relay.GetContent(contentID)
			if err != nil || chain == nil {
				return fmt.Errorf("content chain '%s' not found", contentID)
			}

			if jsonFlag {
				type opInfo struct {
					Index  int    `json:"index"`
					CID    string `json:"cid,omitempty"`
					Type   string `json:"type,omitempty"`
					Signer string `json:"signer,omitempty"`
				}
				var ops []opInfo
				for i, token := range chain.Log {
					h, p, _ := protocol.DecodeJWSUnsafe(token)
					op := opInfo{Index: i}
					if h != nil {
						op.CID = h.CID
						op.Signer = didFromKid(h.Kid)
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

			fmt.Printf("Content: %s (%d operations)\n\n", contentID, len(chain.Log))
			for i, token := range chain.Log {
				h, p, _ := protocol.DecodeJWSUnsafe(token)
				opType := "?"
				if p != nil {
					if t, ok := p["type"].(string); ok {
						opType = t
					}
				}
				cid := ""
				signer := ""
				if h != nil {
					cid = h.CID
					signer = didFromKid(h.Kid)
				}
				if signer != "" {
					fmt.Printf("  [%d] %-8s %s  (%s)\n", i, opType, cid, signer)
				} else {
					fmt.Printf("  [%d] %-8s %s\n", i, opType, cid)
				}
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

			_, chain, err := requireIdentity()
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

			if len(chain.State.AuthKeys) == 0 {
				return fmt.Errorf("identity has no auth keys")
			}
			authKeyID := chain.State.AuthKeys[0].ID
			kid := chain.DID + "#" + authKeyID
			privKey, err := keys.GetPrivateKey(chain.DID + "#" + authKeyID)
			if err != nil {
				return fmt.Errorf("auth key not in keychain: %w", err)
			}

			scope := contentID
			if noScope {
				scope = ""
			} else if scopeContentID != "" {
				scope = scopeContentID
			}

			token, err := protocol.CreateCredential(chain.DID, subjectDID, kid, credType, dur, scope, privKey)
			if err != nil {
				return fmt.Errorf("create credential: %w", err)
			}

			if jsonFlag {
				outputJSON(map[string]any{
					"credential": token,
					"type":       credType,
					"issuer":     chain.DID,
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
	cmd.Flags().BoolVar(&read, "read", false, "Issue DFOS read credential")
	cmd.Flags().BoolVar(&write, "write", false, "Issue DFOS write credential")
	cmd.Flags().StringVar(&ttl, "ttl", "24h", "Credential TTL")
	cmd.Flags().StringVar(&scopeContentID, "scope", "", "Scope credential to specific content ID")
	cmd.Flags().BoolVar(&noScope, "broad", false, "Issue broad credential (not scoped to any content ID)")
	return cmd
}

func newContentUpdateCmd() *cobra.Command {
	var note string
	var peerName string
	var authorization string
	var baseDocumentCID string

	cmd := &cobra.Command{
		Use:   "update <contentId> <file|->",
		Short: "Update content chain with new document",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			contentID := args[0]

			lr, err := getRelay()
			if err != nil {
				return err
			}
			contentChain, err := lr.Relay.GetContent(contentID)
			if err != nil || contentChain == nil {
				return fmt.Errorf("content chain '%s' not found", contentID)
			}
			if contentChain.State.IsDeleted {
				return fmt.Errorf("content chain is deleted — cannot update")
			}

			_, idChain, err := requireIdentity()
			if err != nil {
				return err
			}

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

			authKeyID := idChain.State.AuthKeys[0].ID
			kid := idChain.DID + "#" + authKeyID
			privKey, err := keys.GetPrivateKey(idChain.DID + "#" + authKeyID)
			if err != nil {
				return err
			}

			jwsToken, opCID, err := protocol.SignContentUpdateWithOptions(
				idChain.DID, contentChain.State.HeadCID, documentCID, kid, privKey,
				protocol.ContentUpdateOptions{
					Note:            note,
					BaseDocumentCID: baseDocumentCID,
					Authorization:   authorization,
				},
			)
			if err != nil {
				return err
			}

			results := lr.Relay.Ingest([]string{jwsToken})
			if len(results) > 0 && results[0].Status == "rejected" {
				return fmt.Errorf("local relay rejected: %s", results[0].Error)
			}

			lr.Store.PutBlob(relay.BlobKey{CreatorDID: contentChain.State.CreatorDID, DocumentCID: documentCID}, docBytes)

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
					return err
				}
				if len(peerResults) > 0 && peerResults[0].Status == "rejected" {
					return fmt.Errorf("peer rejected: %s", peerResults[0].Error)
				}
				info, _ := c.GetRelayInfo()
				authToken, _ := protocol.CreateAuthToken(idChain.DID, info.DID, kid, 5*time.Minute, privKey)
				c.UploadBlob(contentID, opCID, docBytes, authToken)
			}

			if jsonFlag {
				outputJSON(map[string]any{"contentId": contentID, "operationCID": opCID, "documentCID": documentCID})
			} else {
				fmt.Printf("Content updated:\n  Operation CID: %s\n  Document CID:  %s\n", opCID, documentCID)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&note, "note", "", "Operation note")
	cmd.Flags().StringVar(&peerName, "peer", "", "Push to this peer immediately")
	cmd.Flags().StringVar(&authorization, "authorization", "", "DFOS write credential for delegated writes")
	cmd.Flags().StringVar(&baseDocumentCID, "base-document-cid", "", "CID of the base document this update is derived from")
	return cmd
}

func newContentDeleteCmd() *cobra.Command {
	var note string
	var peerName string
	var authorization string

	cmd := &cobra.Command{
		Use:   "delete <contentId>",
		Short: "Permanently delete a content chain (sign delete operation)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contentID := args[0]

			lr, err := getRelay()
			if err != nil {
				return err
			}
			contentChain, err := lr.Relay.GetContent(contentID)
			if err != nil || contentChain == nil {
				return fmt.Errorf("content chain '%s' not found", contentID)
			}
			if contentChain.State.IsDeleted {
				return fmt.Errorf("content chain is already deleted")
			}

			_, idChain, err := requireIdentity()
			if err != nil {
				return err
			}

			if len(idChain.State.AuthKeys) == 0 {
				return fmt.Errorf("identity has no auth keys")
			}
			authKeyID := idChain.State.AuthKeys[0].ID
			kid := idChain.DID + "#" + authKeyID
			privKey, err := keys.GetPrivateKey(idChain.DID + "#" + authKeyID)
			if err != nil {
				return fmt.Errorf("auth key not in keychain: %w", err)
			}

			jwsToken, opCID, err := protocol.SignContentDelete(idChain.DID, contentChain.State.HeadCID, kid, note, authorization, privKey)
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
	cmd.Flags().StringVar(&peerName, "peer", "", "Push to this peer immediately")
	cmd.Flags().StringVar(&authorization, "authorization", "", "DFOS write credential for delegated deletes")
	return cmd
}

func newContentVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <contentId>",
		Short: "Re-verify content chain integrity locally",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contentID := args[0]
			lr, err := getRelay()
			if err != nil {
				return err
			}
			chain, _ := lr.Relay.GetContent(contentID)
			if chain == nil {
				return fmt.Errorf("content chain '%s' not found. Use 'dfos content fetch' first.", contentID)
			}

			result := map[string]any{
				"valid":      true,
				"contentId":  contentID,
				"operations": len(chain.Log),
			}

			cidsVerified := 0
			sigsVerified := 0
			for i, token := range chain.Log {
				h, p, err := protocol.DecodeJWSUnsafe(token)
				if err != nil {
					result["valid"] = false
					result["error"] = fmt.Sprintf("operation %d: %v", i, err)
					break
				}

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

				kid := h.Kid
				hashIdx := strings.Index(kid, "#")
				if hashIdx >= 0 {
					did := kid[:hashIdx]
					keyID := kid[hashIdx+1:]
					storedChain, _ := lr.Relay.GetIdentity(did)
					if storedChain != nil {
						allKeys := append(append(storedChain.State.AuthKeys, storedChain.State.ControllerKeys...), storedChain.State.AssertKeys...)
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

			// collect unique signers in stable order
			var signers []string
			seen := make(map[string]bool)
			for _, token := range chain.Log {
				h, _, _ := protocol.DecodeJWSUnsafe(token)
				if h != nil && h.Kid != "" {
					did := didFromKid(h.Kid)
					if !seen[did] {
						seen[did] = true
						signers = append(signers, did)
					}
				}
			}

			result["cidsVerified"] = cidsVerified
			result["signaturesVerified"] = sigsVerified
			result["creatorDID"] = chain.State.CreatorDID
			result["signers"] = signers

			if jsonFlag {
				outputJSON(result)
			} else {
				if result["valid"].(bool) {
					fmt.Printf("Content chain '%s' is valid.\n", contentID)
					fmt.Printf("  Operations:      %d\n", len(chain.Log))
					fmt.Printf("  CIDs verified:   %d\n", cidsVerified)
					fmt.Printf("  Sigs verified:   %d\n", sigsVerified)
					fmt.Printf("  Creator:         %s\n", chain.State.CreatorDID)
					if len(signers) > 1 {
						fmt.Printf("  Signers:\n")
						for _, s := range signers {
							label := s
							if s == chain.State.CreatorDID {
								label += " (creator)"
							}
							if name := config.FindIdentityName(cfg, s); name != "" {
								label += " (" + name + ")"
							}
							fmt.Printf("    - %s\n", label)
						}
					}
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
		Short: "Sign a protocol-level content deletion",
		Long:  "Content data in the local relay cannot be selectively un-ingested. Use 'dfos content delete' to sign a protocol-level deletion operation.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Content data lives in the local relay and cannot be selectively removed.\n")
			fmt.Printf("Use 'dfos content delete %s' to sign a protocol-level deletion.\n", args[0])
			return nil
		},
	}
}

// helpers

// fetchAndIngestIdentity fetches an identity chain from a peer and ingests it
// into the local relay. Used to ensure creator identities are available before
// ingesting content that references them.
func fetchAndIngestIdentity(lr *localrelay.LocalRelay, c *client.Client, did string) {
	// skip if already local
	existing, _ := lr.Relay.GetIdentity(did)
	if existing != nil {
		return
	}
	data, err := c.GetIdentity(did)
	if err != nil {
		return
	}
	log, ok := toStringSlice(data["log"])
	if !ok || len(log) == 0 {
		return
	}
	lr.Relay.Ingest(log)
}

// verifyCredentialLocally verifies a DFOS credential using the creator's
// identity from the local relay.
func verifyCredentialLocally(lr *localrelay.LocalRelay, credential, creatorDID, subjectDID, contentID string) error {
	header, _, err := protocol.DecodeJWTUnsafe(credential)
	if err != nil {
		return err
	}
	kid, ok := header["kid"]
	if !ok || kid == "" {
		return fmt.Errorf("credential has no kid")
	}
	hashIdx := strings.Index(kid, "#")
	if hashIdx < 0 {
		return fmt.Errorf("credential kid is not a DID URL")
	}
	kidDID := kid[:hashIdx]
	keyID := kid[hashIdx+1:]
	if kidDID != creatorDID {
		return fmt.Errorf("credential issuer does not match content creator")
	}
	creatorChain, err := lr.Relay.GetIdentity(creatorDID)
	if err != nil || creatorChain == nil {
		return fmt.Errorf("creator identity not in local relay")
	}
	allKeys := append(append(creatorChain.State.AuthKeys, creatorChain.State.ControllerKeys...), creatorChain.State.AssertKeys...)
	var pubBytes []byte
	for _, k := range allKeys {
		if k.ID == keyID {
			pubBytes, err = protocol.DecodeMultikey(k.PublicKeyMultibase)
			if err != nil {
				return err
			}
			break
		}
	}
	if pubBytes == nil {
		return fmt.Errorf("issuer key not found in creator identity")
	}
	vc, err := protocol.VerifyCredential(credential, pubBytes, subjectDID, "DFOSContentRead")
	if err != nil {
		return err
	}
	if vc.ContentID != "" && vc.ContentID != contentID {
		return fmt.Errorf("credential scoped to different content")
	}
	return nil
}

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
