package vault

// The custody id is what makes a mnemonic belong to ONE vault directory.
//
// Vault metadata is scoped by DFOS_CONFIG — it is a file under
// <config dir>/vaults — but an OS keychain is a single machine-wide namespace
// with no notion of a config directory at all. Under the flat account name this
// package used to write ("vault:<name>") the two halves of a vault disagreed:
// an invocation aimed at a scratch directory passed both of the vault's guards
// (neither the "already exists" stat nor the one-seed-one-vault fingerprint
// scan can see outside its own directory) and then wrote its new mnemonic over
// the real profile's phrase of the same name. The real metadata still named
// fingerprint A; the phrase behind it was B, and every key A minted was
// unrecoverable.
//
// So the account carries the directory's identity: "vault:<custody id>:<name>",
// where the custody id is 16 random hex characters minted once per vault
// directory and kept beside the metadata. Two directories cannot collide,
// because two ids do not. The id is random rather than derived from the path so
// that moving or renaming a config directory takes its mnemonics with it.
//
// The id is not a secret and protects nothing on its own: it names a namespace.
// Losing it is what costs — the file is the only thing that says which keychain
// entries this directory's vaults are behind — so it lives at mode 0600 beside
// the metadata whose backup it belongs in.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	// custodyIDFile has no extension, so it is not a vault: List() reads
	// `*.toml` and the file backend writes `*.seed`, and neither can see it.
	custodyIDFile  = "custody-id"
	custodyIDBytes = 8
)

var custodyIDRE = regexp.MustCompile(`^[0-9a-f]{16}$`)

// CustodyID returns dir's custody id, minting and persisting one the first time
// it is asked for. Every vault directory has one, including a directory that
// has no vaults yet — the id is created by the first write that needs a
// keychain account, not by any command of its own.
func CustodyID(dir string) (string, error) {
	path := filepath.Join(dir, custodyIDFile)
	id, ok, err := readCustodyID(path)
	if err != nil {
		return "", err
	}
	if ok {
		return id, nil
	}
	buf := make([]byte, custodyIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate vault custody id: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create vault dir: %w", err)
	}
	// O_EXCL, so two processes arriving here together cannot both believe they
	// minted the id: the loser reads the winner's file instead of writing a
	// second one over it. An id that changed under a running process would
	// strand every mnemonic already filed under the first one.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			id, ok, readErr := readCustodyID(path)
			if readErr != nil {
				return "", readErr
			}
			if ok {
				return id, nil
			}
		}
		return "", fmt.Errorf("write vault custody id: %w", err)
	}
	id = hex.EncodeToString(buf)
	if _, err := f.WriteString(id + "\n"); err != nil {
		f.Close()
		return "", fmt.Errorf("write vault custody id: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("write vault custody id: %w", err)
	}
	return id, nil
}

// readCustodyID reads the id at path. A missing file is not an error — it is
// the first-run case — but an unreadable one is: the id names the keychain
// namespace this directory's mnemonics live under, so guessing at a mangled
// file would look for phrases somewhere they are not and report them missing.
func readCustodyID(path string) (string, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read vault custody id (%s): %w", path, err)
	}
	id := strings.TrimSpace(string(data))
	if !custodyIDRE.MatchString(id) {
		return "", false, fmt.Errorf("vault custody id at %s is not 16 hex characters — it names the keychain namespace this directory's mnemonics are stored under, and a mnemonic cannot be found without it", path)
	}
	return id, true, nil
}
