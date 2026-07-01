//go:build !windows

package statelock

import (
	"os"

	"golang.org/x/sys/unix"
)

// tryLock attempts a non-blocking exclusive lock.
func tryLock(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

// lock takes a blocking exclusive lock.
func lock(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX)
}
