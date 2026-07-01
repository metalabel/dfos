//go:build windows

package statelock

import (
	"os"

	"golang.org/x/sys/windows"
)

// tryLock attempts a non-blocking exclusive lock over the whole file.
func tryLock(f *os.File) error {
	return windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, new(windows.Overlapped),
	)
}

// lock takes a blocking exclusive lock over the whole file.
func lock(f *os.File) error {
	return windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0, 1, 0, new(windows.Overlapped),
	)
}
