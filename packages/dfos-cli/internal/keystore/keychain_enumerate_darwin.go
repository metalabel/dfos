//go:build darwin

package keystore

import (
	"bytes"
	"fmt"
	"os/exec"
)

// The absolute path go-keyring itself invokes, spelled the same way here so the
// listing and the get/set/delete it is a listing OF come from one binary.
const execPathSecurity = "/usr/bin/security"

// Entries lists the accounts the macOS keychain holds under the "dfos" service.
//
// /usr/bin/security is the same tool the keychain backend already drives for
// every get, set, and delete, and `dump-keychain` is its only listing verb: it
// prints ATTRIBUTES for the default keychain's items — no secrets, so it
// neither unlocks anything nor prompts — which is then filtered to this
// service. The alternative is the Security framework via cgo, which would cost
// this CLI its pure-Go cross-compiled builds for one maintenance command.
//
// The accounts are parsed, not probed. A caller that will act on one — print
// it, delete it — should read it first: a read through this same backend is the
// proof that the account is really here and really a key seed, and it is a read
// the caller already needs to make.
func (k *KeychainStore) Entries() ([]Entry, error) {
	cmd := exec.Command(execPathSecurity, "dump-keychain")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	// A dump can exit non-zero on a keychain it could not open while still
	// having printed every item from the ones it could. Output beats status.
	if err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("%w: %s: %v", ErrNoEnumeration, execPathSecurity, err)
	}
	accounts := parseKeychainDump(&stdout, serviceName)
	entries := make([]Entry, 0, len(accounts))
	for _, account := range accounts {
		entries = append(entries, Entry{Account: account, Ref: account})
	}
	return entries, nil
}
