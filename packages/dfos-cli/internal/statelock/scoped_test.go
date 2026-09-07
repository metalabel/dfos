package statelock

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScopedLockReleasesOnlyItsOwnAcquisition(t *testing.T) {
	for _, alreadyHeld := range []bool{false, true} {
		t.Run(map[bool]string{false: "scoped", true: "process"}[alreadyHeld], func(t *testing.T) {
			dir := setupConfigDir(t)
			if alreadyHeld {
				if err := Acquire(); err != nil {
					t.Fatal(err)
				}
			}
			release, err := AcquireScoped()
			if err != nil {
				t.Fatal(err)
			}
			other, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			if err := tryLock(other); err == nil {
				t.Fatal("scoped section is unlocked")
			}
			release()
			err = tryLock(other)
			if alreadyHeld && err == nil {
				t.Fatal("released process lock")
			}
			if !alreadyHeld && err != nil {
				t.Fatalf("scoped lock remains held: %v", err)
			}
		})
	}
}
