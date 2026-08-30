package relay

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The lookup GetPublicCredentials answers used to be a json_each scan of every
// stored credential. It is now an indexed probe of a derived resource table, so
// these tests pin the two things a derived table can get wrong: the answers it
// gives, and staying level with the column it derives from.

func addCred(t *testing.T, store *SQLiteStore, cid string, resources ...string) {
	t.Helper()
	att := make([]AttenuationPair, 0, len(resources))
	for _, resource := range resources {
		att = append(att, AttenuationPair{Resource: resource, Action: "read"})
	}
	if err := store.AddPublicCredential(StoredPublicCredential{
		CID:       cid,
		IssuerDID: "did:dfos:" + strings.Repeat("a", 23),
		Att:       att,
		Exp:       0,
		JWSToken:  "token-" + cid,
	}); err != nil {
		t.Fatalf("AddPublicCredential(%s): %v", cid, err)
	}
}

func credsFor(t *testing.T, store *SQLiteStore, resource string) []string {
	t.Helper()
	tokens, err := store.GetPublicCredentials(resource)
	if err != nil {
		t.Fatalf("GetPublicCredentials(%s): %v", resource, err)
	}
	sort.Strings(tokens)
	return tokens
}

func assertTokens(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %v, want %v", label, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: got %v, want %v", label, got, want)
		}
	}
}

// TestPublicCredentialResourceLookup covers the matching rules the att scan
// carried: exact resource match, chain:* as a wildcard over chain: resources
// only, and a non-chain resource that the wildcard must NOT reach.
func TestPublicCredentialResourceLookup(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "creds.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	addCred(t, store, "cid-one", "chain:content-a")
	addCred(t, store, "cid-two", "chain:content-b", "chain:content-a")
	addCred(t, store, "cid-star", "chain:*")
	addCred(t, store, "cid-other", "service:mailbox")

	assertTokens(t, "chain:content-a", credsFor(t, store, "chain:content-a"),
		[]string{"token-cid-one", "token-cid-star", "token-cid-two"})
	assertTokens(t, "chain:content-b", credsFor(t, store, "chain:content-b"),
		[]string{"token-cid-star", "token-cid-two"})
	// A chain the wildcard covers and nothing else names.
	assertTokens(t, "chain:unnamed", credsFor(t, store, "chain:unnamed"),
		[]string{"token-cid-star"})
	// chain:* is scoped to chain: resources — it must not answer for a service.
	assertTokens(t, "service:mailbox", credsFor(t, store, "service:mailbox"),
		[]string{"token-cid-other"})
	assertTokens(t, "service:absent", credsFor(t, store, "service:absent"), []string{})
}

// TestPublicCredentialRemoveClearsResources pins the half a derived table
// forgets: a removed credential must stop answering, not linger as an orphaned
// resource row pointing at a credential that is gone.
func TestPublicCredentialRemoveClearsResources(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "remove.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	addCred(t, store, "cid-one", "chain:content-a")
	addCred(t, store, "cid-two", "chain:content-a")
	if err := store.RemovePublicCredential("cid-one"); err != nil {
		t.Fatalf("RemovePublicCredential: %v", err)
	}

	assertTokens(t, "after remove", credsFor(t, store, "chain:content-a"),
		[]string{"token-cid-two"})

	var orphans int
	if err := store.readerDB().QueryRow(
		"SELECT COUNT(*) FROM public_credential_resources WHERE cid = ?", "cid-one",
	).Scan(&orphans); err != nil {
		t.Fatalf("count orphans: %v", err)
	}
	if orphans != 0 {
		t.Fatalf("removed credential left %d resource rows", orphans)
	}
}

// TestPublicCredentialResourcesWriteAllOrNothing pins what makes the boot
// repair's cid-granular NOT EXISTS sound: one credential's resources land in a
// single statement, so a credential is projected completely or not at all.
// A per-resource write loop autocommits outside a batch, and a credential left
// holding SOME rows reads as already-projected forever — its missing grants
// silently stop being returned. The proxy for "one statement" this can check
// cheaply is that a many-resource att is fully present and that the row count
// is exactly the non-empty resource count, with no host-parameter ceiling in
// the way.
func TestPublicCredentialResourcesWriteAllOrNothing(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "atomic.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Comfortably past SQLite's host-parameter ceiling had this bound one
	// parameter per resource.
	const wide = 20000
	resources := make([]string, 0, wide)
	for i := 0; i < wide; i++ {
		resources = append(resources, "chain:content-"+strconv.Itoa(i))
	}
	addCred(t, store, "cid-wide", resources...)

	var rows int
	if err := store.readerDB().QueryRow(
		"SELECT COUNT(*) FROM public_credential_resources WHERE cid = ?", "cid-wide",
	).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rows != wide {
		t.Fatalf("projected %d of %d resources", rows, wide)
	}
	assertTokens(t, "first resource", credsFor(t, store, resources[0]), []string{"token-cid-wide"})
	assertTokens(t, "last resource", credsFor(t, store, resources[wide-1]), []string{"token-cid-wide"})
}

// TestPublicCredentialEmptyResourceSkippedByBothPaths pins that the live write
// and the boot repair admit the same rows. An empty resource names nothing, so
// neither may store it — and in particular the repair must not resurrect a row
// the writer deliberately declined, which would leave the two paths disagreeing
// about the same att.
func TestPublicCredentialEmptyResourceSkippedByBothPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.db")
	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	addCred(t, store, "cid-mixed", "chain:content-a", "", "chain:content-b")

	countRows := func(t *testing.T, s *SQLiteStore, label string) int {
		t.Helper()
		var n int
		if err := s.readerDB().QueryRow(
			"SELECT COUNT(*) FROM public_credential_resources WHERE cid = ?", "cid-mixed",
		).Scan(&n); err != nil {
			t.Fatalf("%s: count: %v", label, err)
		}
		return n
	}
	if got := countRows(t, store, "live"); got != 2 {
		t.Fatalf("live path projected %d rows, want 2 (empty resource skipped)", got)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Clear the projection and let the boot repair rebuild it from att alone.
	reopened, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := reopened.writerDB().Exec("DELETE FROM public_credential_resources"); err != nil {
		t.Fatalf("clear projection: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	repaired, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("reopen for repair: %v", err)
	}
	defer repaired.Close()
	if got := countRows(t, repaired, "backfill"); got != 2 {
		t.Fatalf("backfill projected %d rows, want 2 (must match the live path)", got)
	}
}

// TestPublicCredentialResourcesBackfillOnOpen covers the in-place upgrade: a
// database written before the resource table existed holds att and nothing
// else, and reopening it must derive the rows rather than answer with an empty
// lookup — which would read as "this chain has no standing public grant" and
// silently flip live content to non-public in the index projection.
func TestPublicCredentialResourcesBackfillOnOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backfill.db")
	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	addCred(t, store, "cid-one", "chain:content-a", "chain:content-b")
	addCred(t, store, "cid-star", "chain:*")
	// Simulate the pre-upgrade shape: att intact, projection absent.
	if _, err := store.writerDB().Exec("DELETE FROM public_credential_resources"); err != nil {
		t.Fatalf("clear projection: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	assertTokens(t, "backfilled chain:content-a", credsFor(t, reopened, "chain:content-a"),
		[]string{"token-cid-one", "token-cid-star"})
	assertTokens(t, "backfilled chain:content-b", credsFor(t, reopened, "chain:content-b"),
		[]string{"token-cid-one", "token-cid-star"})
}
