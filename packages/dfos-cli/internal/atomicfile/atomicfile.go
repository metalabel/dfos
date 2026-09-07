package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write atomically replaces a private file and syncs it and its directory.
func Write(path string, data []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create a temp file in %s: %w", dir, err)
	}
	tempPath := temp.Name()
	// Removed on every failure path; a no-op once the rename has taken the name.
	defer os.Remove(tempPath)

	// Explicit rather than relying on CreateTemp's 0600, because the mode of a
	// file holding a credential is not a detail to inherit from umask.
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("set permissions on %s: %w", tempPath, err)
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("write %s: %w", tempPath, err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tempPath, err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
