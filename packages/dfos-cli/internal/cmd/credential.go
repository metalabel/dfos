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
				scope = "*"
			} else if scopeContentID != "" {
				scope = scopeContentID
			}
			resource := "chain:" + scope

			token, err := protocol.CreateCredential(chain.DID, subjectDID, kid, resource, action, dur, privKey)
			if err != nil {
				return fmt.Errorf("create credential: %w", err)
			}

			if jsonFlag {
				outputJSON(map[string]any{
					"credential": token,
					"action":     action,
					"resource":   resource,
					"issuer":     chain.DID,
					"audience":   subjectDID,
					"expiresIn":  dur.String(),
				})
			} else {
				fmt.Printf("Credential issued (%s %s, expires in %s):\n  %s\n", action, resource, dur, token)
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

			if len(chain.State.AuthKeys) == 0 {
				return fmt.Errorf("identity has no auth keys")
			}
			authKeyID := chain.State.AuthKeys[0].ID
			kid := chain.DID + "#" + authKeyID
			privKey, err := keys.GetPrivateKey(chain.DID + "#" + authKeyID)
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
