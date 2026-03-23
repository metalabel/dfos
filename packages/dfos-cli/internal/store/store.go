package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/protocol"
)

// LocalMeta tracks local provenance of a stored entity.
type LocalMeta struct {
	Name        string   `json:"name,omitempty"`
	Origin      string   `json:"origin"` // "created" or "fetched"
	PublishedTo []string `json:"publishedTo,omitempty"`
	BlobPath    string   `json:"blobPath,omitempty"`
}

// StoredIdentity is a locally stored identity chain.
type StoredIdentity struct {
	DID   string                 `json:"did"`
	Log   []string               `json:"log"`
	State protocol.IdentityState `json:"state"`
	Local LocalMeta              `json:"local"`
}

// StoredContent is a locally stored content chain.
type StoredContent struct {
	ContentID  string                `json:"contentId"`
	GenesisCID string                `json:"genesisCID"`
	Log        []string              `json:"log"`
	State      protocol.ContentState `json:"state"`
	Local      LocalMeta             `json:"local"`
}

// StoredBeacon is a locally stored beacon.
type StoredBeacon struct {
	DID       string         `json:"did"`
	JWSToken  string         `json:"jwsToken"`
	BeaconCID string         `json:"beaconCID"`
	Payload   map[string]any `json:"payload"`
	Local     LocalMeta      `json:"local"`
}

// StoreDir returns the store directory.
func StoreDir() string {
	return filepath.Join(config.ConfigDir(), "store")
}

func identitiesDir() string { return filepath.Join(StoreDir(), "identities") }
func contentDir() string    { return filepath.Join(StoreDir(), "content") }
func beaconsDir() string    { return filepath.Join(StoreDir(), "beacons") }
func blobsDir() string      { return filepath.Join(StoreDir(), "blobs") }

func ensureDir(dir string) error { return os.MkdirAll(dir, 0o700) }

// didToFilename converts did:dfos:xxx to xxx.
func didToFilename(did string) string {
	return strings.TrimPrefix(did, "did:dfos:")
}

// --- Identity ---

func SaveIdentity(id *StoredIdentity) error {
	dir := identitiesDir()
	if err := ensureDir(dir); err != nil {
		return err
	}
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, didToFilename(id.DID)+".json"), data, 0o600)
}

func LoadIdentity(did string) (*StoredIdentity, error) {
	data, err := os.ReadFile(filepath.Join(identitiesDir(), didToFilename(did)+".json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var id StoredIdentity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, err
	}
	return &id, nil
}

func ListIdentities() ([]*StoredIdentity, error) {
	dir := identitiesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var result []*StoredIdentity
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var id StoredIdentity
		if err := json.Unmarshal(data, &id); err != nil {
			continue
		}
		result = append(result, &id)
	}
	return result, nil
}

func DeleteIdentity(did string) error {
	return os.Remove(filepath.Join(identitiesDir(), didToFilename(did)+".json"))
}

func FindIdentityByName(name string) (*StoredIdentity, error) {
	ids, err := ListIdentities()
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if id.Local.Name == name {
			return id, nil
		}
	}
	return nil, nil
}

// --- Content ---

func SaveContent(c *StoredContent) error {
	dir := contentDir()
	if err := ensureDir(dir); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, c.ContentID+".json"), data, 0o600)
}

func LoadContent(contentID string) (*StoredContent, error) {
	data, err := os.ReadFile(filepath.Join(contentDir(), contentID+".json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var c StoredContent
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func ListContent() ([]*StoredContent, error) {
	dir := contentDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var result []*StoredContent
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var c StoredContent
		if err := json.Unmarshal(data, &c); err != nil {
			continue
		}
		result = append(result, &c)
	}
	return result, nil
}

// --- Beacons ---

func SaveBeacon(b *StoredBeacon) error {
	dir := beaconsDir()
	if err := ensureDir(dir); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, didToFilename(b.DID)+".json"), data, 0o600)
}

func LoadBeacon(did string) (*StoredBeacon, error) {
	data, err := os.ReadFile(filepath.Join(beaconsDir(), didToFilename(did)+".json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var b StoredBeacon
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// --- Blobs ---

func SaveBlob(contentID string, data []byte) (string, error) {
	dir := blobsDir()
	if err := ensureDir(dir); err != nil {
		return "", err
	}
	path := filepath.Join(dir, contentID+".bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func LoadBlob(contentID string) ([]byte, error) {
	path := filepath.Join(blobsDir(), contentID+".bin")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("blob not found for content %s", contentID)
		}
		return nil, err
	}
	return data, nil
}

func DeleteContent(contentID string) error {
	return os.Remove(filepath.Join(contentDir(), contentID+".json"))
}

func DeleteBlob(contentID string) {
	os.Remove(filepath.Join(blobsDir(), contentID+".bin"))
}
