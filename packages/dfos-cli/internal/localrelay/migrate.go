package localrelay

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
)

// MigrateIfNeeded checks for a legacy flat-file store and migrates its
// contents into the relay database. Called once during Open before the relay
// is fully initialized.
func MigrateIfNeeded(store *relay.SQLiteStore) error {
	storeDir := filepath.Join(config.ConfigDir(), "store")
	dbPath := filepath.Join(config.ConfigDir(), "relay.db")

	// only migrate if legacy store exists and relay.db is fresh
	if _, err := os.Stat(storeDir); os.IsNotExist(err) {
		return nil
	}
	if _, err := os.Stat(dbPath); err != nil {
		return nil // relay.db doesn't exist yet — let Open create it first
	}

	// check if we already migrated
	marker, err := store.GetMeta("migration_done")
	if err != nil {
		return err
	}
	if marker != nil {
		return nil
	}

	fmt.Println("Migrating legacy store to relay.db...")

	idCount, err := migrateIdentities(store, storeDir)
	if err != nil {
		return fmt.Errorf("migrate identities: %w", err)
	}

	contentCount, err := migrateContent(store, storeDir)
	if err != nil {
		return fmt.Errorf("migrate content: %w", err)
	}

	beaconCount, err := migrateBeacons(store, storeDir)
	if err != nil {
		return fmt.Errorf("migrate beacons: %w", err)
	}

	// mark migration complete
	if err := store.SetMeta("migration_done", []byte("true")); err != nil {
		return err
	}

	fmt.Printf("Migration complete: %d identities, %d content chains, %d beacons\n",
		idCount, contentCount, beaconCount)

	// rename legacy store
	migratedDir := storeDir + ".migrated"
	if err := os.Rename(storeDir, migratedDir); err != nil {
		fmt.Printf("Warning: could not rename legacy store: %v\n", err)
	}

	return nil
}

// legacyStoredIdentity mirrors the old store.StoredIdentity type.
type legacyStoredIdentity struct {
	DID   string                 `json:"did"`
	Log   []string               `json:"log"`
	State protocol.IdentityState `json:"state"`
	Local legacyLocalMeta        `json:"local"`
}

type legacyStoredContent struct {
	ContentID  string               `json:"contentId"`
	GenesisCID string               `json:"genesisCID"`
	Log        []string             `json:"log"`
	State      protocol.ContentState `json:"state"`
	Local      legacyLocalMeta      `json:"local"`
}

type legacyStoredBeacon struct {
	DID       string         `json:"did"`
	JWSToken  string         `json:"jwsToken"`
	BeaconCID string         `json:"beaconCID"`
	Payload   map[string]any `json:"payload"`
	Local     legacyLocalMeta `json:"local"`
}

type legacyLocalMeta struct {
	Name        string   `json:"name,omitempty"`
	Origin      string   `json:"origin"`
	PublishedTo []string `json:"publishedTo,omitempty"`
	BlobPath    string   `json:"blobPath,omitempty"`
}

// migrateIdentities, migrateContent, and migrateBeacons call IngestOperations
// directly (not Relay.Ingest) because the Relay instance isn't created yet
// during migration. This means migrated ops land in chain state tables but
// not in the global operation log. This is fine — the operation log is used
// for peer sync cursors, and migrated local data doesn't need log entries.
// A subsequent `dfos sync` will populate the log from peers if needed.

func migrateIdentities(store *relay.SQLiteStore, storeDir string) (int, error) {
	dir := filepath.Join(storeDir, "identities")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	count := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var legacy legacyStoredIdentity
		if err := json.Unmarshal(data, &legacy); err != nil {
			continue
		}

		// ingest the identity chain operations into the relay
		results := relay.IngestOperations(legacy.Log, store)
		ingested := false
		for _, r := range results {
			if r.Status == "new" || r.Status == "duplicate" {
				ingested = true
			}
		}
		if ingested {
			count++
		}
	}
	return count, nil
}

func migrateContent(store *relay.SQLiteStore, storeDir string) (int, error) {
	dir := filepath.Join(storeDir, "content")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	count := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var legacy legacyStoredContent
		if err := json.Unmarshal(data, &legacy); err != nil {
			continue
		}

		// ingest the content chain operations
		results := relay.IngestOperations(legacy.Log, store)
		ingested := false
		for _, r := range results {
			if r.Status == "new" || r.Status == "duplicate" {
				ingested = true
			}
		}
		if !ingested {
			continue
		}

		// migrate blob if present
		if legacy.State.CurrentDocumentCID != nil {
			blobKey := relay.BlobKey{
				CreatorDID:  legacy.State.CreatorDID,
				DocumentCID: *legacy.State.CurrentDocumentCID,
			}
			var blobData []byte
			if legacy.Local.BlobPath != "" {
				blobData, _ = os.ReadFile(legacy.Local.BlobPath)
			}
			if blobData == nil {
				// try legacy blob path convention: blobs/<contentId>.bin
				blobData, _ = os.ReadFile(filepath.Join(storeDir, "blobs", legacy.ContentID+".bin"))
			}
			if blobData != nil {
				if err := store.PutBlob(blobKey, blobData); err != nil {
					fmt.Printf("  Warning: failed to migrate blob for %s: %v\n", legacy.ContentID, err)
				}
			}
		}

		count++
	}
	return count, nil
}

func migrateBeacons(store *relay.SQLiteStore, storeDir string) (int, error) {
	dir := filepath.Join(storeDir, "beacons")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	count := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var legacy legacyStoredBeacon
		if err := json.Unmarshal(data, &legacy); err != nil {
			continue
		}

		// ingest beacon operation
		results := relay.IngestOperations([]string{legacy.JWSToken}, store)
		for _, r := range results {
			if r.Status == "new" || r.Status == "duplicate" {
				count++
				break
			}
		}
	}
	return count, nil
}
