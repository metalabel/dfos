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
	// Hosts is every `api:<host>` the credential names — the hosts `api call`
	// will select it for. Two records for one subject differ here and nowhere
	// else visible, which is why the column exists.
	Hosts      []string `json:"hosts"`
	ObtainedAt string   `json:"obtainedAt"`
	Expiry     *int64   `json:"expiry"`
	Expired    bool     `json:"expired"`
	fileName   string
}

// path is the file this item was read from. The store holds one file per
// (subject, host), so a subject is no longer enough to name one.
func (i storedCredentialListItem) path() string {
	return filepath.Join(credentialStoreDir(), i.fileName)
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

			fmt.Printf("%-48s  %-32s  %-48s  %-24s  %-24s  %s\n", "SUBJECT DID", "HOSTS", "CLIENT DID", "OBTAINED AT", "EXPIRY", "STATUS")
			for _, item := range items {
				expiry := "-"
				status := ""
				hosts := "-"
				if item.Expiry != nil {
					expiry = time.Unix(*item.Expiry, 0).UTC().Format("2006-01-02 15:04:05 UTC")
				}
				if item.Expired {
					status = "EXPIRED"
				}
				if len(item.Hosts) > 0 {
					hosts = strings.Join(item.Hosts, ",")
				}
				fmt.Printf("%-48s  %-32s  %-48s  %-24s  %-24s  %s\n",
					item.SubjectDID, hosts, item.ClientDID, item.ObtainedAt, expiry, status)
			}
			return nil
		},
	}
}

func newCredsShowCmd() *cobra.Command {
	var host string
	cmd := &cobra.Command{
		Use:   "show <name|did>",
		Short: "Show a stored login credential and its decoded claims",
		Long: "Show one stored login credential. A subject can hold one per API host, so --host <host> " +
			"names which when there is more than one; with a single stored credential it is not needed.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			did, err := resolveIdentityDID(args[0])
			if err != nil {
				return err
			}
			_, record, err := selectStoredCredential(did, host)
			if err != nil {
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
	cmd.Flags().StringVar(&host, "host", "", "Which stored credential to show, by the API host it names")
	return cmd
}

func newCredsRemoveCmd() *cobra.Command {
	var host string
	cmd := &cobra.Command{
		Use:   "rm <name|did>",
		Short: "Remove a locally stored login credential",
		Long: "Remove one stored login credential. A subject can hold one per API host, so --host <host> " +
			"names which when there is more than one; removing them all would take one credential the user " +
			"named and discard several they did not.",
		Aliases: []string{"remove"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			did, err := resolveIdentityDID(args[0])
			if err != nil {
				return err
			}
			path, _, err := selectStoredCredential(did, host)
			if err != nil {
				return err
			}
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("remove stored login credential for %s: %w", did, err)
			}
			if jsonFlag {
				outputJSON(map[string]any{"removed": did, "path": path})
			} else {
				fmt.Printf("Removed stored login credential for %s (%s)\n", did, filepath.Base(path))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Which stored credential to remove, by the API host it names")
	return cmd
}

// selectStoredCredential picks ONE of a subject's stored credentials, and
// refuses to guess when the subject holds several.
//
// The store holds one file per (subject, host), so a subject alone stopped being
// an address the moment a second login could land beside the first. host filters
// on the credential's own `api:<host>` attenuation — the same string `api call`
// selects on — so what the user types here is what they would type there.
func selectStoredCredential(did, host string) (string, storedLoginCredential, error) {
	paths, records, unreadable, err := credentialFilesForSubject(did)
	if err != nil {
		return "", storedLoginCredential{}, err
	}
	if len(records) == 0 {
		// "None" is a claim about the whole store, so it is only made about a
		// store that was wholly read. A file that would not parse might be the
		// one being asked for, and saying nothing is stored would be answering
		// with a gap.
		if len(unreadable) > 0 {
			return "", storedLoginCredential{}, fmt.Errorf("no stored login credential for %s among the files that could be read — %s did not parse, so this answer is partial",
				did, credentialFileList(unreadable))
		}
		return "", storedLoginCredential{}, fmt.Errorf("no stored login credential for %s", did)
	}

	wanted := strings.TrimSpace(host)
	if wanted == "" && len(records) == 1 {
		return paths[0], records[0], nil
	}

	var hosts []string
	var matches []int
	for i, record := range records {
		named := credentialAPIHosts(record.Credential)
		hosts = append(hosts, credentialHostsLabel(named))
		for _, name := range named {
			if wanted != "" && strings.EqualFold(name, wanted) {
				matches = append(matches, i)
				break
			}
		}
	}
	switch {
	case wanted == "":
		return "", storedLoginCredential{}, fmt.Errorf("%s holds %d stored credentials (for %s) — name which one with --host <host>",
			did, len(records), strings.Join(hosts, ", "))
	case len(matches) == 0:
		return "", storedLoginCredential{}, fmt.Errorf("no stored credential for %s names host %s (it holds %s)",
			did, wanted, strings.Join(hosts, ", "))
	case len(matches) > 1:
		// Two files, one host: only a hand-edited store produces this, and
		// picking one of them is the guess this function exists not to make.
		return "", storedLoginCredential{}, fmt.Errorf("%d stored credentials for %s name host %s — the store in %s holds more than one file for that pair",
			len(matches), did, wanted, credentialStoreDir())
	}
	return paths[matches[0]], records[matches[0]], nil
}

// credentialFileList names files by their basename: the directory is already
// said elsewhere in every message that uses this, and the operator's next move
// is to open one of them.
func credentialFileList(paths []string) string {
	names := make([]string, len(paths))
	for i, path := range paths {
		names[i] = filepath.Base(path)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// credentialHostsLabel renders what one stored credential is spendable against.
func credentialHostsLabel(hosts []string) string {
	if len(hosts) == 0 {
		return "no api host"
	}
	return strings.Join(hosts, "+")
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
			Hosts:      credentialAPIHosts(record.Credential),
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
