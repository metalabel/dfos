package relay

import (
	"path/filepath"
	"sort"
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
