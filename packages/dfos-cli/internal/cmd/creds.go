package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/spf13/cobra"
)

type storedCredentialListItem struct {
	SubjectDID string `json:"subjectDid"`
	ClientDID  string `json:"clientDid"`
	ObtainedAt string `json:"obtainedAt"`
	Expiry     *int64 `json:"expiry"`
	Expired    bool   `json:"expired"`
	fileName   string
}

func newCredsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "creds",
		Short:   "Manage locally stored login credentials",
		GroupID: "auth",
	}
	cmd.AddCommand(newCredsListCmd())
	cmd.AddCommand(newCredsShowCmd())
	cmd.AddCommand(newCredsRemoveCmd())
	return cmd
}

func newCredsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List locally stored login credentials",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			items, err := listStoredCredentials(time.Now())
			if err != nil {
				return err
			}
			if len(items) == 0 {
				if jsonFlag {
					outputJSON([]storedCredentialListItem{})
				} else {
					fmt.Println("No login credentials stored. Use 'dfos login [name|did]' to sign in.")
				}
				return nil
			}

			if jsonFlag {
				outputJSON(items)
				return nil
			}

			fmt.Printf("%-48s  %-48s  %-24s  %-24s  %s\n", "SUBJECT DID", "CLIENT DID", "OBTAINED AT", "EXPIRY", "STATUS")
			for _, item := range items {
				expiry := "-"
				status := ""
				if item.Expiry != nil {
					expiry = time.Unix(*item.Expiry, 0).UTC().Format("2006-01-02 15:04:05 UTC")
				}
				if item.Expired {
					status = "EXPIRED"
				}
				fmt.Printf("%-48s  %-48s  %-24s  %-24s  %s\n", item.SubjectDID, item.ClientDID, item.ObtainedAt, expiry, status)
			}
			return nil
		},
	}
}

func newCredsShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name|did>",
		Short: "Show a stored login credential and its decoded claims",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			did, err := resolveIdentityDID(args[0])
			if err != nil {
				return err
			}
			record, err := readStoredCredential(credentialPath(did))
			if err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("no stored login credential for %s", did)
				}
				return err
			}
			_, claims, err := protocol.DecodeJWSUnsafe(record.Credential)
			if err != nil {
				return fmt.Errorf("decode stored credential for %s: %w", did, err)
			}

			if jsonFlag {
				outputJSON(map[string]any{
					"subjectDid":  record.SubjectDID,
					"clientDid":   record.ClientDID,
					"clientKeyId": record.ClientKeyID,
					"credential":  record.Credential,
					"obtainedAt":  record.ObtainedAt,
					"claims":      claims,
				})
				return nil
			}

			fmt.Printf("Subject DID:   %s\n", record.SubjectDID)
			fmt.Printf("Client DID:    %s\n", record.ClientDID)
			fmt.Printf("Client key ID: %s\n", record.ClientKeyID)
			fmt.Printf("Obtained at:   %s\n", record.ObtainedAt)
			fmt.Printf("Credential:    %s\n", record.Credential)
			fmt.Println("Claims:")
			claimsJSON, _ := json.MarshalIndent(claims, "  ", "  ")
			fmt.Printf("  %s\n", claimsJSON)
			return nil
		},
	}
}

func newCredsRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rm <name|did>",
		Short:   "Remove a locally stored login credential",
		Aliases: []string{"remove"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			did, err := resolveIdentityDID(args[0])
			if err != nil {
				return err
			}
			if err := os.Remove(credentialPath(did)); err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("no stored login credential for %s", did)
				}
				return fmt.Errorf("remove stored login credential for %s: %w", did, err)
			}
			if jsonFlag {
				outputJSON(map[string]any{"removed": did})
			} else {
				fmt.Printf("Removed stored login credential for %s\n", did)
			}
			return nil
		},
	}
}

func listStoredCredentials(now time.Time) ([]storedCredentialListItem, error) {
	entries, err := os.ReadDir(credentialStoreDir())
	if err != nil {
		if os.IsNotExist(err) {
			return []storedCredentialListItem{}, nil
		}
		return nil, fmt.Errorf("read credential store: %w", err)
	}

	items := make([]storedCredentialListItem, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		record, err := readStoredCredential(filepath.Join(credentialStoreDir(), entry.Name()))
		if err != nil {
			return nil, err
		}
		expiry := decodeCredentialExpiry(record.Credential)
		items = append(items, storedCredentialListItem{
			SubjectDID: record.SubjectDID,
			ClientDID:  record.ClientDID,
			ObtainedAt: record.ObtainedAt,
			Expiry:     expiry,
			Expired:    expiry != nil && now.Unix() >= *expiry,
			fileName:   entry.Name(),
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].SubjectDID == items[j].SubjectDID {
			return items[i].fileName < items[j].fileName
		}
		return items[i].SubjectDID < items[j].SubjectDID
	})
	return items, nil
}

func readStoredCredential(path string) (storedLoginCredential, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return storedLoginCredential{}, err
	}
	var record storedLoginCredential
	if err := json.Unmarshal(data, &record); err != nil {
		return storedLoginCredential{}, fmt.Errorf("parse stored login credential %s: %w", filepath.Base(path), err)
	}
	return record, nil
}

func decodeCredentialExpiry(token string) *int64 {
	_, claims, err := protocol.DecodeJWSUnsafe(strings.TrimSpace(token))
	if err != nil {
		return nil
	}
	expiry, ok := claims["exp"].(int64)
	if !ok {
		return nil
	}
	return &expiry
}
