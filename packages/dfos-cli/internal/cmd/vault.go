package cmd

// `dfos vault` — a vault is a named seed, and that is the whole of it:
// {name, BIP-39 mnemonic, fingerprint, derivation counter}. It binds no
// identity, scopes no configuration, and holds no peers. Its one job is to be
// the source new key material is derived from, at the one moment that matters:
// mint time.
//
// Nothing about a vault reaches the wire. The word, the mnemonic, the seed, and
// the fingerprint stay on this machine — no operation payload, no signed
// message, and no request to a peer carries any of them. Identities minted from
// one seed are unlinkable to everyone but their holder, and that holds only
// because nothing local leaks upward.

import (
	"golang.org/x/term"

	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/vault"
)

func newVaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "vault",
		Short:   "Manage seed vaults that new keys are minted from",
		GroupID: "identity",
		Long: "A vault is a named BIP-39 seed. New identity keys are derived from it at mint time, so a " +
			"written-down mnemonic covers every key it minted. Signing never consults a vault: it resolves " +
			"the identity and uses the key this device holds. Nothing about a vault leaves this machine.",
	}
	cmd.AddCommand(newVaultCreateCmd())
	cmd.AddCommand(newVaultImportCmd())
	cmd.AddCommand(newVaultListCmd())
	cmd.AddCommand(newVaultShowCmd())
	return cmd
}

// resolveVault picks the vault new key material is minted from: the flag, then
// the config default. There is no environment tier and no "last used" — a seed
// is the most consequential choice the CLI makes, and it is made explicitly or
// from a value the operator wrote down in config.
//
// Returns ("", "", nil) when nothing is selected and none is required, which is
// the vault-less path: keys generated straight into the keystore, exactly as
// before vaults existed.
func resolveVault(vaultFlag string, noVault bool) (name, source string, err error) {
	if noVault {
		if vaultFlag != "" {
			return "", "", fmt.Errorf("--vault and --no-vault are mutually exclusive")
		}
		return "", "--no-vault", nil
	}
	if vaultFlag != "" {
		if !getVaults().Has(vaultFlag) {
			return "", "", fmt.Errorf("no vault named '%s' (see 'dfos vault list')", vaultFlag)
		}
		return vaultFlag, "--vault", nil
	}
	if cfg.DefaultVault != "" {
		if !getVaults().Has(cfg.DefaultVault) {
			return "", "", fmt.Errorf("config default-vault names '%s', which does not exist (see 'dfos vault list')", cfg.DefaultVault)
		}
		return cfg.DefaultVault, "config default-vault", nil
	}
	return "", "", nil
}

// adoptFirstVaultAsDefault points default-vault at a newly created vault when
// the machine had none and no default was set.
//
// This is the ONE side-effecting write to the config tier in the whole CLI, and
// it is deliberate: the rule the resolution stack enforces is that no command
// MOVES a default, because a pointer one process writes and another reads is a
// race. Absence→presence is not that. There is nothing to displace, no other
// invocation can be reading a different value, and the alternative is telling an
// operator who has exactly one vault to name it every single time.
func adoptFirstVaultAsDefault(name string) (bool, error) {
	if cfg.DefaultVault != "" {
		return false, nil
	}
	existing, err := getVaults().List()
	if err != nil {
		return false, err
	}
	if len(existing) != 1 || existing[0].Name != name {
		return false, nil
	}
	cfg.DefaultVault = name
	return true, config.Save(cfg)
}

func newVaultCreateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create <name>",
		Short: "Generate a new seed vault and print its mnemonic once",
		Long: "Generate a 24-word BIP-39 mnemonic from system entropy, store it, and print it ONCE. " +
			"The mnemonic goes to stderr, never to stdout and never into --json output, so a redirected " +
			"or piped invocation does not write a seed into a file by accident. " +
			"'dfos vault show <name> --reveal-mnemonic' prints it again on demand, to stderr by the same rule.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			meta, mnemonic, err := getVaults().Create(name)
			if err != nil {
				return err
			}
			adopted, err := adoptFirstVaultAsDefault(name)
			if err != nil {
				return err
			}

			printMnemonicBlock(os.Stderr, name, mnemonic)

			if jsonFlag {
				outputJSON(map[string]any{
					"name":           meta.Name,
					"fingerprint":    meta.Fingerprint,
					"derivationPath": vault.DerivationPath(0),
					"nextIndex":      meta.NextIndex,
					"backend":        getVaults().Backend(),
					"defaultVault":   adopted,
				})
				return nil
			}

			fmt.Printf("Vault created:\n")
			fmt.Printf("  Name:            %s\n", meta.Name)
			fmt.Printf("  Fingerprint:     %s\n", meta.Fingerprint)
			fmt.Printf("  Derivation:      %s\n", vault.DerivationPath(0))
			fmt.Printf("  Mnemonic:        %s\n", getVaults().Backend())
			if adopted {
				fmt.Printf("  Default vault:   %s — the only vault on this machine\n", meta.Name)
			} else {
				fmt.Printf("  Mint from it:    --vault %s, or 'dfos config set default-vault %s'\n", meta.Name, meta.Name)
			}
			return nil
		},
	}
}

func newVaultImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import <name>",
		Short: "Adopt an existing BIP-39 mnemonic as a vault",
		Long: "Read a mnemonic from the terminal or from stdin, check it against the BIP-39 English " +
			"wordlist and its checksum, and store it under a name. On a terminal the phrase is read " +
			"WITHOUT ECHO — nothing appears as it is typed, and nothing of it stays in the scrollback. " +
			"The mnemonic is never an argument: " +
			"argv lands in shell history and is readable in the process list. A phrase some vault on " +
			"this machine already holds is refused by fingerprint, and the refusal names that vault: " +
			"one seed, one vault, because two vaults over one phrase mint identical keys.",
		// The one argument this command takes is a NAME, and the near-miss worth
		// spending a custom Args func on is the operator who typed the PHRASE
		// where the name goes. `accepts 1 arg(s), received 24` does not tell them
		// what just happened to their seed.
		//
		// Neither message reproduces a single word of what was passed. An error
		// lands in the scrollback, in a CI log, and in whatever is recording the
		// session, so echoing argv back would copy the phrase into one more place
		// at the exact moment it is already exposed — and the phrase is precisely
		// what the operator must now assume someone else can read.
		Args: func(cmd *cobra.Command, args []string) error {
			switch len(args) {
			case 1:
				return nil
			case 0:
				return fmt.Errorf("vault import needs a NAME — a local label for the vault, not the phrase:\n" +
					"  dfos vault import <name>\n" +
					"The recovery phrase is never an argument: it is prompted without echo, or piped on stdin.")
			default:
				return fmt.Errorf("vault import takes one argument — a local NAME for the vault, not the phrase.\n" +
					"If those words were the recovery phrase, they are now in this shell's history and\n" +
					"were visible in the process list: treat the phrase as exposed.\n" +
					"The phrase is prompted without echo, or piped on stdin — never argv.")
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := vault.ValidateName(name); err != nil {
				return err
			}
			if getVaults().Has(name) {
				return fmt.Errorf("vault '%s' already exists", name)
			}

			mnemonic, err := readMnemonic(cmd.InOrStdin())
			if err != nil {
				return err
			}
			meta, err := getVaults().Import(name, mnemonic)
			if err != nil {
				return err
			}
			adopted, err := adoptFirstVaultAsDefault(name)
			if err != nil {
				return err
			}

			if jsonFlag {
				outputJSON(map[string]any{
					"name":           meta.Name,
					"fingerprint":    meta.Fingerprint,
					"derivationPath": vault.DerivationPath(0),
					"nextIndex":      meta.NextIndex,
					"backend":        getVaults().Backend(),
					"defaultVault":   adopted,
				})
				return nil
			}

			fmt.Printf("Vault imported:\n")
			fmt.Printf("  Name:            %s\n", meta.Name)
			fmt.Printf("  Fingerprint:     %s\n", meta.Fingerprint)
			fmt.Printf("  Derivation:      %s\n", vault.DerivationPath(0))
			fmt.Printf("  Mnemonic:        %s\n", getVaults().Backend())
			if adopted {
				fmt.Printf("  Default vault:   %s — the only vault on this machine\n", meta.Name)
			}
			// The counter starts at 0 for an imported seed. Keys this seed minted
			// on another machine are not known here, so say it rather than let the
			// operator infer a history the metadata does not have.
			fmt.Printf("  Counter:         0 — this machine has no record of keys this seed minted elsewhere\n")
			// And say what that costs, because a zero counter reads like a fresh
			// vault and is not one. An import is by definition a phrase that has
			// existed somewhere else; minting from index 0 against a seed another
			// machine has already spent indices on hands two unrelated identities
			// the same private key, with nothing on either chain to show it.
			// 'recover' is what raises the counter past what the network can prove
			// the seed spent, so it goes before the first mint, not after.
			fmt.Printf("  Other holders of this phrase may have minted keys this machine cannot see. Run\n")
			fmt.Printf("  'dfos recover --vault %s' before minting from it — a mint from an unknown\n", meta.Name)
			fmt.Printf("  counter can reuse an index another machine already spent.\n")
			return nil
		},
	}
}

type vaultListEntry struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	NextIndex   uint32 `json:"nextIndex"`
	MintedKeys  int    `json:"mintedKeys"`
	Default     bool   `json:"default"`
	Imported    bool   `json:"imported,omitempty"`
}

func newVaultListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List seed vaults",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			all, err := getVaults().List()
			if err != nil {
				return err
			}
			entries := make([]vaultListEntry, 0, len(all))
			for _, meta := range all {
				entries = append(entries, vaultListEntry{
					Name:        meta.Name,
					Fingerprint: meta.Fingerprint,
					NextIndex:   meta.NextIndex,
					MintedKeys:  len(meta.Minted),
					Default:     meta.Name == cfg.DefaultVault,
					Imported:    meta.Imported,
				})
			}

			if jsonFlag {
				outputJSON(entries)
				return nil
			}
			if len(entries) == 0 {
				fmt.Println("No vaults. Use 'dfos vault create <name>' to make one.")
				return nil
			}
			fmt.Printf("%-3s %-20s %-12s %-9s %s\n", "", "NAME", "FINGERPRINT", "NEXT", "KEYS")
			for _, e := range entries {
				marker := " "
				if e.Default {
					marker = "*"
				}
				fmt.Printf("%-3s %-20s %-12s %-9d %d\n", marker, e.Name, e.Fingerprint, e.NextIndex, e.MintedKeys)
			}
			if cfg.DefaultVault != "" {
				fmt.Printf("\n* default-vault — new keys mint from it unless --vault names another.\n")
			} else {
				fmt.Printf("\nNo default vault. Set one with 'dfos config set default-vault <name>'.\n")
			}
			return nil
		},
	}
}

func newVaultShowCmd() *cobra.Command {
	var reveal bool
	cmd := &cobra.Command{
		Use:   "show <name>",
		Short: "Show a vault's fingerprint, counter, and minted keys",
		Long: "Report one vault: its fingerprint, its derivation counter, and every key it minted. " +
			"The mnemonic is NOT printed. --reveal-mnemonic prints it to stderr, behind a typed " +
			"confirmation, for writing down a backup — the same route 'vault create' takes, so a " +
			"redirected or piped invocation does not write a seed into a file by accident.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			meta, err := getVaults().Load(name)
			if err != nil {
				return err
			}

			var mnemonic string
			if reveal {
				if err := confirmReveal(cmd.InOrStdin(), name); err != nil {
					return err
				}
				if mnemonic, err = getVaults().Mnemonic(name); err != nil {
					return err
				}
			}

			if jsonFlag {
				// The mnemonic is not a field of this document under any flag.
				// --json is a stream something redirects into a file, and the
				// one invariant the phrase has is that it never lands in one.
				outputJSON(map[string]any{
					"name":           meta.Name,
					"fingerprint":    meta.Fingerprint,
					"createdAt":      meta.CreatedAt,
					"imported":       meta.Imported,
					"nextIndex":      meta.NextIndex,
					"derivationPath": vault.DerivationPath(meta.NextIndex),
					"backend":        getVaults().Backend(),
					"default":        meta.Name == cfg.DefaultVault,
					"minted":         meta.Minted,
				})
				if reveal {
					printMnemonicBlock(os.Stderr, meta.Name, mnemonic)
				}
				return nil
			}

			fmt.Printf("Vault:         %s\n", meta.Name)
			fmt.Printf("  Fingerprint: %s\n", meta.Fingerprint)
			fmt.Printf("  Created:     %s\n", meta.CreatedAt)
			if meta.Imported {
				fmt.Printf("  Origin:      imported mnemonic\n")
			}
			fmt.Printf("  Mnemonic:    %s (not shown — 'dfos vault show %s --reveal-mnemonic')\n", getVaults().Backend(), meta.Name)
			fmt.Printf("  Next index:  %d (%s)\n", meta.NextIndex, vault.DerivationPath(meta.NextIndex))
			if meta.Name == cfg.DefaultVault {
				fmt.Printf("  Default:     yes — new keys mint from this vault\n")
			}
			if len(meta.Minted) == 0 {
				fmt.Printf("  Minted keys: none\n")
			} else {
				fmt.Printf("  Minted keys: %d\n", len(meta.Minted))
				for _, m := range meta.Minted {
					fmt.Printf("    %-4d %-26s %s#%s\n", m.Index, joinComma(m.RoleList()), m.DID, m.KeyID)
				}
			}
			if reveal {
				printMnemonicBlock(os.Stderr, meta.Name, mnemonic)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&reveal, "reveal-mnemonic", false, "Print the mnemonic to stderr, after a typed confirmation")
	return cmd
}

// printMnemonicBlock renders the one moment a mnemonic is on screen. It is
// fenced and labeled because the whole value of the words is that someone copies
// them onto paper, and an unmarked line of 24 words scrolls past unread.
func printMnemonicBlock(w io.Writer, name, mnemonic string) {
	fmt.Fprintf(w, "\n┌─ RECOVERY PHRASE for vault '%s' ───────────────────────────\n", name)
	for _, line := range wrapWords(mnemonic, 6) {
		fmt.Fprintf(w, "│  %s\n", line)
	}
	fmt.Fprintf(w, "└────────────────────────────────────────────────────────────\n")
	fmt.Fprintf(w, "Write these words down, in order, somewhere offline.\n")
	fmt.Fprintf(w, "Anyone with them holds every key this vault mints. There is no support desk that can\n")
	fmt.Fprintf(w, "recover them for you, and no copy anywhere but this machine.\n\n")
}

// wrapWords groups a mnemonic into numbered rows of n words, which is how a
// person transcribing it keeps their place.
func wrapWords(mnemonic string, n int) []string {
	words := strings.Fields(mnemonic)
	var lines []string
	for i := 0; i < len(words); i += n {
		end := min(i+n, len(words))
		lines = append(lines, fmt.Sprintf("%2d. %s", i+1, strings.Join(words[i:end], "  ")))
	}
	return lines
}

// readMnemonic reads a mnemonic from stdin — a NO-ECHO prompt on a terminal, a
// piped line otherwise. It is never read from argv: an argument lands in shell
// history and is visible to every process on the box while the command runs.
//
// On a terminal the phrase is read with the echo bit off, which is the posture
// every wallet takes for the same reason: a phrase typed in clear text stays in
// the scrollback, in tmux's history, in whatever is recording the session, and
// over the shoulder of whoever is standing there. Piping remains the way to
// script an import; it stopped being the way to avoid an echo.
//
// A terminal that will not give up its echo bit is a hard failure rather than a
// quiet fall-through to echoing input. The whole point of the prompt is that the
// phrase does not appear, so a prompt that cannot promise that does not run.
func readMnemonic(in io.Reader) (string, error) {
	if stdinIsInteractive() {
		fmt.Fprintf(os.Stderr, "Paste the recovery phrase (12–24 words), then press enter.\n")
		fmt.Fprintf(os.Stderr, "It is NOT echoed — the terminal will look like nothing is happening.\n")
		fmt.Fprintf(os.Stderr, "Phrase: ")
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read mnemonic without echoing it: %w\n"+
				"This terminal would not turn its echo off, and the phrase is not worth typing in clear text.\n"+
				"Pipe it instead: printf '%%s' \"$PHRASE\" | dfos vault import <name>", err)
		}
		mnemonic := strings.TrimSpace(string(raw))
		if mnemonic == "" {
			return "", fmt.Errorf("no mnemonic given")
		}
		return mnemonic, nil
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && (err != io.EOF || strings.TrimSpace(line) == "") {
		return "", fmt.Errorf("read mnemonic: %w", err)
	}
	mnemonic := strings.TrimSpace(line)
	if mnemonic == "" {
		return "", fmt.Errorf("no mnemonic given")
	}
	return mnemonic, nil
}

// confirmReveal is the barrier in front of printing a seed. Typing the vault's
// name is deliberately more work than typing "y": the point is that the operator
// looks at what is about to appear on their screen and in their scrollback.
func confirmReveal(in io.Reader, name string) error {
	fmt.Fprintf(os.Stderr, "About to print the recovery phrase for vault '%s' in clear text.\n", name)
	fmt.Fprintf(os.Stderr, "It will remain in this terminal's scrollback and in anything recording this session.\n")
	fmt.Fprintf(os.Stderr, "Type the vault name to continue: ")
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("read confirmation: %w", err)
	}
	if strings.TrimSpace(line) != name {
		return fmt.Errorf("confirmation did not match — nothing was printed")
	}
	return nil
}
