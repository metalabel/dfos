package relay

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// ===================================================================
// an interrupted migration must not cost the operator the database
//
// upgradeOperationLogCIDIndex converts a non-unique idx_operation_log_cid into a
// unique one by dropping it, deleting the duplicates it let through, and
// recreating it. As three autocommits with the unique index also declared in the
// schema constant, a crash in the middle was terminal: the drop committed, the
// delete did not, and every subsequent boot re-declared the unique index during
// schema creation and failed on the very rows the repair further down existed to
// remove.
// ===================================================================

// openRawSQLite opens the store file directly, as a migration inspector would.
func openRawSQLite(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestAnInterruptedCIDIndexMigrationStillOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "interrupted.sqlite")
	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()

	// The crash window: the index is gone and the duplicates it would have
	// refused are still there.
	db := openRawSQLite(t, path)
	if _, err := db.Exec("DROP INDEX idx_operation_log_cid"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := db.Exec(
			`INSERT INTO operation_log (cid, jws_token, kind, chain_id, created_at, ingested_at)
			 VALUES ('bafy-duplicated-cid', 'token', 'identity-op', 'did:dfos:chain', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("an interrupted migration must leave the database openable: %v", err)
	}
	defer reopened.Close()

	var rows int
	if err := reopened.readDB.QueryRow(
		"SELECT COUNT(*) FROM operation_log WHERE cid = 'bafy-duplicated-cid'",
	).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("the reopen must dedupe the log, got %d rows for one CID", rows)
	}

	var ddl string
	if err := reopened.readDB.QueryRow(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_operation_log_cid'",
	).Scan(&ddl); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToUpper(ddl), "UNIQUE") {
		t.Fatalf("the reopen must restore the UNIQUE index, got %q", ddl)
	}
}

// TestAFreshStoreCarriesTheUniqueCIDIndex: the index left the schema constant,
// so the function that owns it has to create it on a database that never had one.
func TestAFreshStoreCarriesTheUniqueCIDIndex(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "fresh.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var ddl string
	if err := store.readDB.QueryRow(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_operation_log_cid'",
	).Scan(&ddl); err != nil {
		t.Fatalf("a fresh store must carry idx_operation_log_cid: %v", err)
	}
	if !strings.Contains(strings.ToUpper(ddl), "UNIQUE") {
		t.Fatalf("idx_operation_log_cid must be UNIQUE, got %q", ddl)
	}
}
