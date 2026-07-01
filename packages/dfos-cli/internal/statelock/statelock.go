// Package statelock provides a cross-process advisory lock over the DFOS
// config directory.
//
// The CLI keeps mutable local state in two places that are NOT safe for
// concurrent writes from multiple `dfos` processes:
//
//   - config.toml — every mutating command does a load → modify → save. Two
//     processes that overlap both read the old file and the last writer wins,
//     silently dropping the other's change (e.g. concurrent `identity create`
//     published fine to the relay but most name→DID mappings never landed).
//   - the keystore — `identity create` mints keys under a "pending:" account
//     then renames them to their final DID-scoped account. Concurrent access
//     to the OS keychain (go-keyring) races and the just-written pending key
//     transiently isn't found, so ~1-in-8 creates failed with
//     "rename key: old key not found".
//
// Acquire serializes those sections by taking an exclusive advisory lock on
// <config-dir>/.lock before the config is loaded, held for the life of the
// process. The lock is released automatically when the process exits (the OS
// drops the flock when the fd closes / the process dies), which also makes it
// crash-safe — a killed process never leaves a stale lock behind.
package statelock

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
)

// held is kept open for the process lifetime; the OS releases the advisory
// lock when this fd is closed (i.e. on process exit).
var held *os.File

// Acquire takes the process-wide DFOS state lock, blocking until it is
// available. It is a no-op if this process already holds it, so it is safe to
// call from more than one code path per invocation. The lock is released
// automatically on process exit; callers do not release it.
func Acquire() error {
	if held != nil {
		return nil
	}

	dir := config.ConfigDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}

	// Try to grab it without blocking first; if another dfos process holds it,
	// tell the user why we're waiting, then block until it's our turn.
	if err := tryLock(f); err != nil {
		fmt.Fprintln(os.Stderr, "waiting for another dfos process to finish...")
		if err := lock(f); err != nil {
			f.Close()
			return fmt.Errorf("acquire lock: %w", err)
		}
	}

	held = f
	return nil
}
