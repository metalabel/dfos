package apispec

// The local registry of APIs this machine knows how to call: a name, where its
// OpenAPI document came from, when it was last fetched, and the cached document
// itself.
//
// Registration is the ONLY network call `api call` makes beyond the call itself.
// A cached document goes stale visibly (see Registration.Stale) and never
// silently refetches mid-call: a command that surprise-networked while making a
// request would make the request's own timing and failure modes unreadable.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
)

// StaleAfter is the age past which `api call` says out loud that the cached
// document is old. It is a disclosure horizon, not an expiry: a stale document
// still describes the call, and the host's own verdict still decides it.
const StaleAfter = 24 * time.Hour

// SourceKind records how a registration's document URL was arrived at, so
// `api list` can say whether a host advertised it or the conventional path was
// assumed.
type SourceKind string

const (
	// KindFile is a document read from a local path (`--file`).
	KindFile SourceKind = "file"
	// KindDirect is a document URL the user named outright.
	KindDirect SourceKind = "direct"
	// KindWellKnown is a document URL a relay advertised in its well-known
	// response's `openapi` member.
	KindWellKnown SourceKind = "well-known"
	// KindConventional is `/openapi.json` on the named host, assumed after the
	// well-known probe found no advertisement.
	KindConventional SourceKind = "conventional"
)

// Registration is one registered API.
type Registration struct {
	Name string `json:"name"`
	// Source is what the user typed. Refresh re-runs resolution from THIS, not
	// from Document — a host that moves its document is followed, because the
	// document was always discovery rather than an address we own.
	Source string `json:"source"`
	// Document is the URL (or path) the document was actually read from.
	Document string     `json:"document"`
	Kind     SourceKind `json:"kind"`
	// Origin is the API's base origin, used to resolve a relative server URL.
	Origin    string    `json:"origin,omitempty"`
	FetchedAt time.Time `json:"fetchedAt"`
	Title     string    `json:"title,omitempty"`
	Version   string    `json:"version,omitempty"`
	OpenAPI   string    `json:"openapi,omitempty"`
	// Operations is the operation count at fetch time — a cheap "is this the
	// document I think it is" for `api list`.
	Operations int `json:"operations"`
}

// Age is how long ago the document was fetched.
func (r Registration) Age(now time.Time) time.Duration { return now.Sub(r.FetchedAt) }

// Stale reports whether the cached document has passed the disclosure horizon.
func (r Registration) Stale(now time.Time) bool { return r.Age(now) > StaleAfter }

// Store is the on-disk registry.
type Store struct{ dir string }

// NewStore opens the registry under the dfos config directory.
func NewStore() *Store { return &Store{dir: filepath.Join(config.ConfigDir(), "apis")} }

// NewStoreIn opens a registry rooted at an explicit directory. Tests use it.
func NewStoreIn(dir string) *Store { return &Store{dir: dir} }

func (s *Store) indexPath() string { return filepath.Join(s.dir, "registry.json") }
func (s *Store) specPath(n string) string {
	return filepath.Join(s.dir, "specs", n+".json")
}

// nameRule is what a local API name may be. Deliberately narrow: the name is a
// filename component and a command-line token, and a name that needed quoting or
// escaping in either place would be a papercut in every later invocation.
var nameRule = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// ValidateName refuses a name that cannot be a filename or a clean argument.
func ValidateName(name string) error {
	if !nameRule.MatchString(name) {
		return fmt.Errorf("invalid API name %q — use letters, digits, '.', '_', and '-' (1-64 characters, starting with a letter or digit)", name)
	}
	return nil
}

type index struct {
	APIs map[string]Registration `json:"apis"`
}

func (s *Store) load() (*index, error) {
	data, err := os.ReadFile(s.indexPath())
	if err != nil {
		if os.IsNotExist(err) {
			return &index{APIs: map[string]Registration{}}, nil
		}
		return nil, fmt.Errorf("read %s: %w", s.indexPath(), err)
	}
	var idx index
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("parse %s: %w (delete it to start a fresh registry)", s.indexPath(), err)
	}
	if idx.APIs == nil {
		idx.APIs = map[string]Registration{}
	}
	return &idx, nil
}

func (s *Store) save(idx *index) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", s.dir, err)
	}
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.indexPath(), append(data, '\n'))
}

// List returns every registration, name-ordered.
func (s *Store) List() ([]Registration, error) {
	idx, err := s.load()
	if err != nil {
		return nil, err
	}
	out := make([]Registration, 0, len(idx.APIs))
	for _, r := range idx.APIs {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Get returns one registration.
func (s *Store) Get(name string) (Registration, error) {
	idx, err := s.load()
	if err != nil {
		return Registration{}, err
	}
	r, ok := idx.APIs[name]
	if !ok {
		return Registration{}, fmt.Errorf("no API named %q is registered — 'dfos api add %s <host-or-url>' registers one, 'dfos api list' shows what is", name, name)
	}
	return r, nil
}

// Put writes a registration and its document together. The document lands first,
// so an index entry never names a spec file that is not there.
func (s *Store) Put(r Registration, document []byte) error {
	if err := ValidateName(r.Name); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.specPath(r.Name)), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(s.specPath(r.Name)), err)
	}
	if err := writeFileAtomic(s.specPath(r.Name), document); err != nil {
		return err
	}
	idx, err := s.load()
	if err != nil {
		return err
	}
	idx.APIs[r.Name] = r
	return s.save(idx)
}

// Remove unregisters an API and drops its cached document.
func (s *Store) Remove(name string) error {
	idx, err := s.load()
	if err != nil {
		return err
	}
	if _, ok := idx.APIs[name]; !ok {
		return fmt.Errorf("no API named %q is registered", name)
	}
	delete(idx.APIs, name)
	if err := s.save(idx); err != nil {
		return err
	}
	if err := os.Remove(s.specPath(name)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove the cached document for %q: %w", name, err)
	}
	return nil
}

// Document reads back the cached OpenAPI document bytes.
func (s *Store) Document(name string) ([]byte, error) {
	data, err := os.ReadFile(s.specPath(name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("the cached document for %q is missing — 'dfos api refresh %s' refetches it", name, name)
		}
		return nil, err
	}
	return data, nil
}

// writeFileAtomic writes through a temp file in the same directory and renames
// it into place, so a reader (or a crash) never observes a half-written file and
// a symlink dropped at the path is replaced rather than followed.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create a temp file in %s: %w", dir, err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("set permissions on %s: %w", tempPath, err)
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("write %s: %w", tempPath, err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tempPath, err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
