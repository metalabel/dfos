package cmd

import (
	"fmt"
	"time"

	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/spf13/cobra"
)

func newCredentialCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "credential",
		Aliases: []string{"cred"},
		Short:   "Manage DFOS credentials",
		GroupID: "content",
	}
	cmd.AddCommand(newCredentialGrantCmd())
	cmd.AddCommand(newCredentialRevokeCmd())
	return cmd
}

func newCredentialGrantCmd() *cobra.Command {
	var read, write bool
	var ttl string
	var scopeContentID string
	var noScope bool
	var peerName string

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

			action := "read"
			if write {
				action = "write"
			}

			dur, err := time.ParseDuration(ttl)
			if err != nil {
				return fmt.Errorf("invalid --ttl %q: %w (use Go duration units like 5m, 1h, 24h — note day units like \"1d\" are not supported)", ttl, err)
			}
			if dur <= 0 {
				return fmt.Errorf("--ttl must be positive, got %q (a non-positive TTL mints an already-expired credential)", ttl)
			}

			kid, err := selectHeldKey(chain.DID, chain.State.AuthKeys, "auth")
			if err != nil {
				return err
			}
			privKey, err := keys.GetPrivateKey(kid)
			if err != nil {
				return fmt.Errorf("auth key not in keychain: %w", err)
			}

			scope := contentID
			if noScope {
				scope = "*"
			} else if scopeContentID != "" {
				scope = scopeContentID
			}
			resource := "chain:" + scope

			token, err := protocol.CreateCredential(chain.DID, subjectDID, kid, resource, action, dur, privKey)
			if err != nil {
				return fmt.Errorf("create credential: %w", err)
			}

			// Surface the credential's CID (its content address) so the holder can
			// `dfos credential revoke <credentialCID>` without hand-decoding the JWS.
			credentialCID := ""
			if h, _, derr := protocol.DecodeJWSUnsafe(token); derr == nil {
				credentialCID = h.CID
			}

			// Ingest into the local relay so this machine reflects the grant it just
			// issued, then push to a peer if one is named (local --peer or the global
			// flag). A PUBLIC standing grant (aud "*") only takes effect once a relay
			// ingests it — minting alone leaves it inert — so publishing is what makes
			// `dfos credential grant ... <peer>` actually authorize reads there.
			lr, err := getRelay()
			if err != nil {
				return err
			}
			if results := lr.Relay.Ingest([]string{token}); len(results) > 0 && results[0].Status == "rejected" {
				return fmt.Errorf("local relay rejected: %s", results[0].Error)
			}

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
				// the peer must hold the issuer's identity chain to verify the grant's
				// signature, so push it first (no-op if already present).
				if err := publishIdentityIfNeeded(chain, rn, c); err != nil {
					return err
				}
				peerResults, err := c.SubmitOperations([]string{token})
				if err != nil {
					return fmt.Errorf("submit: %w", err)
				}
				if len(peerResults) > 0 && peerResults[0].Status == "rejected" {
					return fmt.Errorf("peer rejected: %s", peerResults[0].Error)
				}
				publishedTo = append(publishedTo, rn)
			}

			if jsonFlag {
				outputJSON(map[string]any{
					"credential":    token,
					"credentialCID": credentialCID,
					"action":        action,
					"resource":      resource,
					"issuer":        chain.DID,
					"audience":      subjectDID,
					"expiresIn":     dur.String(),
					"publishedTo":   publishedTo,
				})
			} else {
				fmt.Printf("Credential issued (%s %s, expires in %s):\n  CID: %s\n  %s\n", action, resource, dur, credentialCID, token)
				if len(publishedTo) > 0 {
					fmt.Printf("  Published to: %s\n", joinComma(publishedTo))
				} else {
					fmt.Printf("  Status:       local only. Pass --peer <name> to publish (a public grant only authorizes reads once a relay ingests it).\n")
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&read, "read", false, "Issue DFOS read credential")
	cmd.Flags().BoolVar(&write, "write", false, "Issue DFOS write credential")
	cmd.Flags().StringVar(&ttl, "ttl", "24h", "Credential TTL")
	cmd.Flags().StringVar(&scopeContentID, "scope", "", "Scope credential to specific content ID")
	cmd.Flags().BoolVar(&noScope, "broad", false, "Issue wildcard credential covering all content")
	cmd.Flags().StringVar(&peerName, "peer", "", "Publish the credential to this peer immediately")
	return cmd
}

func newCredentialRevokeCmd() *cobra.Command {
	var peerName string

	cmd := &cobra.Command{
		Use:   "revoke <credentialCID>",
		Short: "Revoke a credential",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			credentialCID := args[0]

			_, chain, err := requireIdentity()
			if err != nil {
				return err
			}

			lr, err := getRelay()
			if err != nil {
				return err
			}

			kid, err := selectHeldKey(chain.DID, chain.State.AuthKeys, "auth")
			if err != nil {
				return err
			}
			privKey, err := keys.GetPrivateKey(kid)
			if err != nil {
				return fmt.Errorf("auth key not in keychain: %w", err)
			}

			jwsToken, revocationCID, err := protocol.SignRevocation(chain.DID, credentialCID, kid, privKey)
			if err != nil {
				return fmt.Errorf("sign revocation: %w", err)
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
			}

			if jsonFlag {
				outputJSON(map[string]any{
					"revocationCID": revocationCID,
					"credentialCID": credentialCID,
					"issuerDID":     chain.DID,
				})
			} else {
				fmt.Printf("Credential revoked:\n")
				fmt.Printf("  Revocation CID:  %s\n", revocationCID)
				fmt.Printf("  Credential CID:  %s\n", credentialCID)
				fmt.Printf("  Issuer DID:      %s\n", chain.DID)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&peerName, "peer", "", "Push to this peer immediately")
	return cmd
}
