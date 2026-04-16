// Package update checks for new CLI versions via the GitHub Releases API.
//
// The check is non-blocking: it runs in a background goroutine with a short
// timeout and caches results for 24 hours. If the check fails or times out,
// it is silently ignored.
package update

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
)

const (
	releasesURL   = "https://api.github.com/repos/metalabel/dfos/releases/latest"
	checkInterval = 24 * time.Hour
	httpTimeout   = 2 * time.Second
	cacheFile     = "version-check.json"
)

type cachedCheck struct {
	LatestVersion string `json:"latest_version"`
	CheckedAt     int64  `json:"checked_at"`
}

type githubRelease struct {
	TagName string `json:"tag_name"`
}

// CheckAndNotify checks for a newer version and prints a message to stderr
// if one is available. It is designed to be called from a goroutine — it
// blocks for at most httpTimeout and writes the result to a cache file.
//
// The done channel is closed when the check completes (or is skipped).
func CheckAndNotify(currentVersion string, done chan struct{}) {
	defer close(done)

	if shouldSkip(currentVersion) {
		return
	}

	configDir := configDir()
	cachePath := filepath.Join(configDir, cacheFile)

	// check cache first
	if cached, err := readCache(cachePath); err == nil {
		if time.Since(time.Unix(cached.CheckedAt, 0)) < checkInterval {
			// cache is fresh — just print if newer
			if isNewer(cached.LatestVersion, currentVersion) {
				printNotice(currentVersion, cached.LatestVersion)
			}
			return
		}
	}

	// fetch from GitHub
	latest, err := fetchLatest()
	if err != nil {
		return
	}

	// write cache
	_ = writeCache(cachePath, &cachedCheck{
		LatestVersion: latest,
		CheckedAt:     time.Now().Unix(),
	})

	if isNewer(latest, currentVersion) {
		printNotice(currentVersion, latest)
	}
}

func shouldSkip(version string) bool {
	if version == "dev" {
		return true
	}
	if os.Getenv("DFOS_NO_UPDATE_CHECK") == "1" {
		return true
	}
	if !isatty.IsTerminal(os.Stderr.Fd()) && !isatty.IsCygwinTerminal(os.Stderr.Fd()) {
		return true
	}
	return false
}

func fetchLatest() (string, error) {
	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Get(releasesURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}

	return strings.TrimPrefix(release.TagName, "v"), nil
}

func readCache(path string) (*cachedCheck, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c cachedCheck
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func writeCache(path string, c *cachedCheck) error {
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func configDir() string {
	if v := os.Getenv("DFOS_CONFIG"); v != "" {
		return filepath.Dir(v)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".dfos")
}

// isNewer returns true if latest is a higher version than current.
// Compares dot-separated numeric segments (e.g., "0.10.0" > "0.9.0").
func isNewer(latest, current string) bool {
	if latest == "" || current == "" {
		return false
	}
	lParts := strings.Split(latest, ".")
	cParts := strings.Split(current, ".")

	for i := 0; i < len(lParts) && i < len(cParts); i++ {
		l, lErr := strconv.Atoi(lParts[i])
		c, cErr := strconv.Atoi(cParts[i])
		if lErr != nil || cErr != nil {
			// fall back to string comparison for non-numeric segments
			if lParts[i] > cParts[i] {
				return true
			}
			if lParts[i] < cParts[i] {
				return false
			}
			continue
		}
		if l > c {
			return true
		}
		if l < c {
			return false
		}
	}
	return len(lParts) > len(cParts)
}

func printNotice(current, latest string) {
	fmt.Fprintf(os.Stderr, "\nUpdate available: v%s → v%s\n", current, latest)
	if isHomebrew() {
		fmt.Fprintf(os.Stderr, "Run: brew upgrade metalabel/tap/dfos\n\n")
	} else {
		fmt.Fprintf(os.Stderr, "Run: curl -sSL https://protocol.dfos.com/install.sh | sh\n\n")
	}
}

// isHomebrew returns true if the running binary is inside a Homebrew prefix.
// Homebrew installs to a Cellar directory regardless of platform:
//   - Apple Silicon macOS: /opt/homebrew/Cellar/
//   - Intel macOS: /usr/local/Cellar/
//   - Linux: /home/linuxbrew/.linuxbrew/Cellar/
func isHomebrew() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		resolved = exe
	}
	return strings.Contains(resolved, "/Cellar/")
}
