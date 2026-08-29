package cmd

// `dfos whoami` — the full answer to "what will this shell do if I sign
// something right now".
//
// Every other surface answers a slice of it: `status` reports the chain and the
// peer's health, `identity keys` reports key availability, `creds list` reports
// stored credentials. whoami answers the question an operator actually has
// before running a signing command, in the order the resolution stack runs, and
// it answers honestly: each section has an explicit no-such-thing state rather
// than an omission. Nothing here signs, and nothing here writes.

import (
	"fmt"
	"strings"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/vault"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/spf13/cobra"
)

type whoamiSigningKey struct {
	Available    bool   `json:"available"`
	KID          string `json:"kid,omitempty"`
	Backend      string `json:"backend"`
	PublishedAll int    `json:"publishedAuthKeys"`
	Held         int    `json:"heldAuthKeys"`
	Reason       string `json:"reason,omitempty"`
	// Vault is where this key came from, when a vault minted it. It is local
	// provenance: an answer to "which phrase, at which index, covers this key",
	// not an input to anything. Signing resolved this key without asking a vault
	// a thing, and none of this is ever published.
	Vault *whoamiVault `json:"vault,omitempty"`
}

type whoamiVault struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	Index       uint32 `json:"index"`
	Path        string `json:"derivationPath"`
}

type whoamiCredential struct {
	SubjectDID string `json:"subjectDid"`
	Issuer     string `json:"issuer,omitempty"`
	Audience   string `json:"audience,omitempty"`
	Expires    string `json:"expires,omitempty"`
	Expired    bool   `json:"expired"`
	Mine       bool   `json:"mine"`
}

type whoamiResult struct {
	Identity        *whoamiIdentity    `json:"identity"`
	SigningKey      whoamiSigningKey   `json:"signingKey"`
	Credentials     []whoamiCredential `json:"credentials"`
	Peer            *whoamiPeer        `json:"peer"`
	LegacyActiveCtx string             `json:"legacyActiveContext,omitempty"`
}

type whoamiIdentity struct {
	Name    string `json:"name,omitempty"`
	DID     string `json:"did,omitempty"`
	Source  string `json:"source"`
	InChain bool   `json:"inLocalRelay"`
	Deleted bool   `json:"deleted"`
}

type whoamiPeer struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Source string `json:"source"`
}

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "whoami",
		Short:   "Show the resolved identity, signing key, credentials, and peer",
		GroupID: "auth",
		Long: "Report what this invocation would act as: which identity resolved and through which " +
			"mechanism, whether this device holds a key that can sign for it, which login credentials " +
			"are stored locally, and which peer requests would go to. Reads only.",
		RunE: func(cmd *cobra.Command, args []string) error {
			result := whoamiResult{Credentials: []whoamiCredential{}, LegacyActiveCtx: cfg.ActiveContext}

			ctx, ctxErr := resolveCtx()
			result.SigningKey = whoamiSigningKey{Backend: keys.Backend()}

			if ctx.HasIdentity() {
				id := &whoamiIdentity{Name: ctx.IdentityName, DID: ctx.IdentityDID, Source: ctx.IdentitySource}
				result.Identity = id
				if ctx.IdentityDID == "" {
					result.SigningKey.Reason = fmt.Sprintf("identity %q is not registered in config", ctx.IdentityName)
				} else if lr, err := getRelay(); err != nil {
					result.SigningKey.Reason = fmt.Sprintf("local relay unavailable: %v", err)
				} else if chain, err := lr.Relay.GetIdentity(ctx.IdentityDID); err != nil || chain == nil {
					result.SigningKey.Reason = "identity chain is not in the local relay"
				} else {
					id.InChain = true
					id.Deleted = chain.State.IsDeleted
					result.SigningKey.PublishedAll = len(chain.State.AuthKeys)
					for _, k := range chain.State.AuthKeys {
						if holdsDeclaredKey(chain.DID, k) {
							result.SigningKey.Held++
							if result.SigningKey.KID == "" {
								result.SigningKey.KID = chain.DID + "#" + k.ID
							}
						}
					}
					result.SigningKey.Available = result.SigningKey.KID != ""
					if result.SigningKey.Available {
						keyID := result.SigningKey.KID[strings.Index(result.SigningKey.KID, "#")+1:]
						if meta, rec, ok := getVaults().FindMinted(chain.DID, keyID); ok {
							result.SigningKey.Vault = &whoamiVault{
								Name:        meta.Name,
								Fingerprint: meta.Fingerprint,
								Index:       rec.Index,
								Path:        vault.DerivationPath(rec.Index),
							}
						}
					}
					if !result.SigningKey.Available {
						result.SigningKey.Reason = fmt.Sprintf("this device holds none of the %d published auth key(s)",
							result.SigningKey.PublishedAll)
					}
				}
			}

			if ctx != nil && ctx.RelayURL != "" {
				result.Peer = &whoamiPeer{Name: ctx.RelayName, URL: ctx.RelayURL, Source: ctx.RelaySource}
			}

			// Credentials are stored one file per (subject, host); what each is
			// spendable against is read out of the artifact itself rather than
			// invented from the file name, which is only a slot.
			stored, credErr := listStoredCredentials(time.Now())
			for _, item := range stored {
				entry := whoamiCredential{
					SubjectDID: item.SubjectDID,
					Expired:    item.Expired,
					Mine:       result.Identity != nil && item.SubjectDID == result.Identity.DID,
				}
				if item.Expiry != nil {
					entry.Expires = time.Unix(*item.Expiry, 0).UTC().Format("2006-01-02 15:04:05 UTC")
				}
				if record, err := readStoredCredential(item.path()); err == nil {
					if _, claims, err := protocol.DecodeJWSUnsafe(record.Credential); err == nil {
						entry.Issuer, _ = claims["iss"].(string)
						entry.Audience, _ = claims["aud"].(string)
					}
				}
				result.Credentials = append(result.Credentials, entry)
			}

			if jsonFlag {
				outputJSON(result)
				return nil
			}
			printWhoami(result, ctxErr, credErr)
			return nil
		},
	}
}

func printWhoami(r whoamiResult, ctxErr, credErr error) {
	if r.Identity == nil {
		fmt.Println("Identity:    none selected")
		if ctxErr != nil {
			fmt.Printf("  Error:     %s\n", ctxErr)
		}
		fmt.Println("  Select:    --as <name|did>, DFOS_AS=<name|did>, or 'dfos config set default-identity <name|did>'")
	} else {
		label := r.Identity.DID
		if r.Identity.Name != "" && r.Identity.DID != "" {
			label = fmt.Sprintf("%s (%s)", r.Identity.Name, r.Identity.DID)
		} else if r.Identity.DID == "" {
			label = r.Identity.Name + " — not registered in config"
		}
		fmt.Printf("Identity:    %s\n", label)
		fmt.Printf("  Via:       %s\n", r.Identity.Source)
		if r.Identity.Deleted {
			fmt.Printf("  State:     deleted — cannot sign operations\n")
		}
	}

	if r.SigningKey.Available {
		fmt.Printf("Signing key: %s (%s)\n", r.SigningKey.KID, r.SigningKey.Backend)
		if r.SigningKey.PublishedAll > 1 {
			fmt.Printf("  Held:      %d of %d published auth key(s)\n", r.SigningKey.Held, r.SigningKey.PublishedAll)
		}
		if v := r.SigningKey.Vault; v != nil {
			fmt.Printf("  Vault:     %s [%s] at %s\n", v.Name, v.Fingerprint, v.Path)
		} else {
			fmt.Printf("  Vault:     none — this key was generated standalone\n")
		}
	} else if r.Identity == nil {
		fmt.Printf("Signing key: none — no identity selected (backend %s)\n", r.SigningKey.Backend)
	} else {
		fmt.Printf("Signing key: not held — %s (backend %s)\n", r.SigningKey.Reason, r.SigningKey.Backend)
	}

	if credErr != nil {
		fmt.Printf("Credentials: unreadable — %s\n", credErr)
	} else if len(r.Credentials) == 0 {
		fmt.Println("Credentials: none stored — 'dfos login [name|did] --scope <scope>' obtains one")
	} else {
		fmt.Printf("Credentials: %d stored in %s\n", len(r.Credentials), credentialStoreDir())
		for _, c := range r.Credentials {
			marker := " "
			if c.Mine {
				marker = "*"
			}
			host := c.Audience
			if host == "" {
				host = "unknown audience"
			}
			state := "valid"
			if c.Expired {
				state = "EXPIRED"
			}
			if c.Expires == "" {
				state = "no readable expiry"
			}
			fmt.Printf("  %s %s  aud %s  %s\n", marker, c.SubjectDID, host, state)
		}
	}

	if r.Peer == nil {
		fmt.Println("Peer:        none selected")
		fmt.Println("  Select:    --relay <name>, DFOS_RELAY=<name>, or 'dfos config set default-peer <name>'")
	} else {
		fmt.Printf("Peer:        %s (%s)\n", r.Peer.Name, r.Peer.URL)
		fmt.Printf("  Via:       %s\n", r.Peer.Source)
	}

	if r.LegacyActiveCtx != "" {
		fmt.Printf("\nconfig.toml carries active_context = %q. It is inert: resolution never reads it.\n", r.LegacyActiveCtx)
		fmt.Printf("Set a standing default with 'dfos config set default-identity <name|did>'.\n")
	}
}
