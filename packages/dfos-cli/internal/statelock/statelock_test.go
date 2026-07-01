package statelock

import (
	"os"
	"path/filepath"
	"testing"
)

// reset drops the process-held lock so an independent test can take a fresh
// one. Production code never releases (the OS reclaims it on process exit).
func reset() {
	if held != nil {
		held.Close()
		held = nil
	}
}

// setupConfigDir points DFOS_CONFIG at a temp dir so tests don't touch ~/.dfos.
func setupConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DFOS_CONFIG", filepath.Join(dir, "config.toml"))
	t.Cleanup(reset)
	return dir
}

// TestAcquireIsExclusive proves a second, independent holder of the lock file
// cannot take it while this process holds it — the property that serializes
// concurrent `dfos` processes.
func TestAcquireIsExclusive(t *testing.T) {
	dir := setupConfigDir(t)

	if err := Acquire(); err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	// A second open of the same lock file is a distinct lock owner (as a
	// separate process would be); a non-blocking grab must fail.
	other, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open lock file: %v", err)
	}
	defer other.Close()

	if err := tryLock(other); err == nil {
		t.Fatal("expected the lock to be held, but a second holder acquired it")
	}
}

// TestAcquireIdempotent verifies calling Acquire twice in one process is a
// no-op the second time (multiple code paths may call it).
func TestAcquireIdempotent(t *testing.T) {
	setupConfigDir(t)

	if err := Acquire(); err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	if err := Acquire(); err != nil {
		t.Fatalf("second Acquire should be a no-op: %v", err)
	}
}

// TestReacquireAfterRelease verifies the lock is grantable again once the
// holder goes away (mirrors flock release on process exit).
func TestReacquireAfterRelease(t *testing.T) {
	dir := setupConfigDir(t)

	if err := Acquire(); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	reset() // simulate the holding process exiting

	other, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open lock file: %v", err)
	}
	defer other.Close()

	if err := tryLock(other); err != nil {
		t.Fatalf("expected lock to be free after release, got: %v", err)
	}
}
