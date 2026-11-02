package relay

// Revocation is issuer-only (CREDENTIALS.md, "Relay Enforcement": the scoping
// "prevents a rogue DID from revoking credentials it did not issue"). The
// revocation SET has always been keyed by (issuerDID, credentialCID); these
// tests pin the other half — that evicting the standing public credential is
// keyed the same way, at the store and through ingest. Eviction reaches the
// store only inside a revocation's atomic commit
// (OperationCommit.RemovePublicCredential), so the store-level cases drive it
// the way ingestion does rather than through a standalone remove call.
//
// The stakes are why this is a red bar and not a nicety: eviction by CID alone
// is PERMANENT. Re-presenting the destroyed credential lands on the
// duplicate-by-CID branch in ingestPublicCredential before the credential's own
// commit can run, so the grant never comes back.
//
// The status route is the third half. Any DID can sign a revocation naming any
// CID, so the unscoped /revocations/v1/credential/{cid} answer is one
// revocation for the CID, not necessarily the issuer's, and a stranger whose
// DID sorts below the issuer's would mask the real one. `?issuer=` scopes the
// answer to the exact (issuerDID, credentialCID) row.
//
// Twin coverage lives in the TS relay (tests/revocation-issuer-scope.spec.ts).

import (
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// TestRemovePublicCredentialIsIssuerScoped_SQLite proves the store operation
// itself refuses a mismatched issuer — both the credential row and the derived
// resource rows it answers lookups from.
func TestRemovePublicCredentialIsIssuerScoped_SQLite(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "scope.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	stranger := "did:dfos:" + strings.Repeat("b", 23)
	addCred(t, store, "cid-owned", "chain:content-a")

	if err := seedRevocation(t, store, StoredRevocation{
		CID: "rev-stranger", IssuerDID: stranger, CredentialCID: "cid-owned",
		JWSToken: "token-rev-stranger", CreatedAt: "2026-01-01T00:00:00.000Z",
	}); err != nil {
		t.Fatalf("commit stranger revocation: %v", err)
	}
	assertTokens(t, "after stranger eviction", credsFor(t, store, "chain:content-a"),
		[]string{"token-cid-owned"})

	// the derived resource rows must survive too — a lookup that still answers
	// while the resource table has been emptied is a lookup one boot-repair away
	// from disagreeing with itself
	var resources int
	if err := store.readerDB().QueryRow(
		"SELECT COUNT(*) FROM public_credential_resources WHERE cid = ?", "cid-owned",
	).Scan(&resources); err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if resources != 1 {
		t.Fatalf("stranger eviction left %d resource rows, want 1", resources)
	}

	// the issuer's own eviction still lands
	if err := seedRevocation(t, store, StoredRevocation{
		CID: "rev-issuer", IssuerDID: testCredIssuer, CredentialCID: "cid-owned",
		JWSToken: "token-rev-issuer", CreatedAt: "2026-01-01T00:00:01.000Z",
	}); err != nil {
		t.Fatalf("commit issuer revocation: %v", err)
	}
	assertTokens(t, "after issuer eviction", credsFor(t, store, "chain:content-a"), nil)
}

// TestRemovePublicCredentialIsIssuerScoped_Memory is the same contract on the
// memory store, so the two implementations cannot drift.
func TestRemovePublicCredentialIsIssuerScoped_Memory(t *testing.T) {
	store := NewMemoryStore()
	issuer := "did:dfos:" + strings.Repeat("a", 23)
	stranger := "did:dfos:" + strings.Repeat("b", 23)

	commitOne(t, store, OperationCommit{
		Operation: StoredOperation{CID: "cid-owned", JWSToken: "token-cid-owned", ChainType: "credential", ChainID: issuer},
		PublicCredential: &StoredPublicCredential{
			CID:       "cid-owned",
			IssuerDID: issuer,
			Att:       []AttenuationPair{{Resource: "chain:content-a", Action: "read"}},
			JWSToken:  "token-cid-owned",
		},
	})

	if err := seedRevocation(t, store, StoredRevocation{
		CID: "rev-stranger", IssuerDID: stranger, CredentialCID: "cid-owned",
		JWSToken: "token-rev-stranger", CreatedAt: "2026-01-01T00:00:00.000Z",
	}); err != nil {
		t.Fatalf("commit stranger revocation: %v", err)
	}
	held, err := store.GetPublicCredentials("chain:content-a")
	if err != nil {
		t.Fatalf("GetPublicCredentials: %v", err)
	}
	assertTokens(t, "after stranger eviction", held, []string{"token-cid-owned"})

	if err := seedRevocation(t, store, StoredRevocation{
		CID: "rev-issuer", IssuerDID: issuer, CredentialCID: "cid-owned",
		JWSToken: "token-rev-issuer", CreatedAt: "2026-01-01T00:00:01.000Z",
	}); err != nil {
		t.Fatalf("commit issuer revocation: %v", err)
	}
	held, err = store.GetPublicCredentials("chain:content-a")
	if err != nil {
		t.Fatalf("GetPublicCredentials: %v", err)
	}
	assertTokens(t, "after issuer eviction", held, nil)
}

// TestForeignRevocationDoesNotEvictPublicCredential drives the whole ingest
// path: identity B mints a perfectly valid revocation naming a credential
// identity A issued. The revocation is stored (it is a well-formed artifact
// under B's own key) but reaches nothing of A's.
func TestForeignRevocationDoesNotEvictPublicCredential(t *testing.T) {
	r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}

	issuer := createTestIdentity(t)
	stranger := createTestIdentity(t)
	for _, id := range []testIdentity{issuer, stranger} {
		if res := r.Ingest([]string{id.token}); res[0].Status != "new" {
			t.Fatalf("identity ingest: %+v", res[0])
		}
	}

	issuerKid := issuer.did + "#" + issuer.auth.keyID
	cred, err := dfos.CreateCredential(issuer.did, "*", issuerKid, "chain:someContentId", "read", time.Hour, issuer.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	header, _, err := dfos.DecodeJWSUnsafe(cred)
	if err != nil {
		t.Fatal(err)
	}
	credentialCID := header.CID
	if res := r.Ingest([]string{cred}); res[0].Status != "new" {
		t.Fatalf("credential ingest: %+v", res[0])
	}

	held, err := r.readStore.GetPublicCredentials("chain:someContentId")
	if err != nil {
		t.Fatalf("GetPublicCredentials: %v", err)
	}
	if len(held) != 1 {
		t.Fatalf("seeded grant: got %d credentials, want 1", len(held))
	}

	// B revokes a CID it never issued
	strangerKid := stranger.did + "#" + stranger.auth.keyID
	foreignRev, _, err := dfos.SignRevocation(stranger.did, credentialCID, strangerKid, stranger.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	res := r.Ingest([]string{foreignRev})[0]
	if res.Status != "new" {
		t.Fatalf("foreign revocation ingest: %+v", res)
	}
	// the result must not report a grant it did not reach
	if res.RevokedGrant != nil {
		t.Fatalf("foreign revocation reported a revoked grant: %+v", res.RevokedGrant)
	}

	held, err = r.readStore.GetPublicCredentials("chain:someContentId")
	if err != nil {
		t.Fatalf("GetPublicCredentials: %v", err)
	}
	if len(held) != 1 || held[0] != cred {
		t.Fatalf("standing grant destroyed by a foreign revocation: %v", held)
	}
	// the revocation set stays issuer-scoped in both directions
	revoked, err := r.readStore.IsCredentialRevoked(issuer.did, credentialCID, 0)
	if err != nil {
		t.Fatalf("IsCredentialRevoked: %v", err)
	}
	if revoked {
		t.Fatal("foreign revocation marked the issuer's credential revoked")
	}

	// A's own revocation still evicts it
	ownRev, _, err := dfos.SignRevocation(issuer.did, credentialCID, issuerKid, issuer.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	res = r.Ingest([]string{ownRev})[0]
	if res.Status != "new" {
		t.Fatalf("own revocation ingest: %+v", res)
	}
	if res.RevokedGrant == nil || len(res.RevokedGrant.ContentIDs) != 1 || res.RevokedGrant.ContentIDs[0] != "someContentId" {
		t.Fatalf("own revocation grant = %+v, want contentIds [someContentId]", res.RevokedGrant)
	}
	held, err = r.readStore.GetPublicCredentials("chain:someContentId")
	if err != nil {
		t.Fatalf("GetPublicCredentials: %v", err)
	}
	if len(held) != 0 {
		t.Fatalf("issuer's own revocation left the grant standing: %v", held)
	}
}

// revocationCollision boots a relay on the given store, has the issuer and a
// stranger both revoke the same credential CID, and serves it over httptest.
type revocationCollision struct {
	srv                *httptest.Server
	issuer, stranger   testIdentity
	credentialCID      string
	issuerRevocation   string
	strangerRevocation string
	path               string
}

func seedRevocationCollision(t *testing.T, store RelayReadStore) revocationCollision {
	t.Helper()
	r, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(r.Handler())
	t.Cleanup(srv.Close)

	issuer := createTestIdentity(t)
	stranger := createTestIdentity(t)
	for _, id := range []testIdentity{issuer, stranger} {
		if res := r.Ingest([]string{id.token}); res[0].Status != "new" {
			t.Fatalf("identity ingest: %+v", res[0])
		}
	}

	issuerKid := issuer.did + "#" + issuer.auth.keyID
	cred, err := dfos.CreateCredential(issuer.did, "*", issuerKid, "chain:someContentId", "read", time.Hour, issuer.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	header, _, err := dfos.DecodeJWSUnsafe(cred)
	if err != nil {
		t.Fatal(err)
	}
	credentialCID := header.CID

	issuerRev, _, err := dfos.SignRevocation(issuer.did, credentialCID, issuerKid, issuer.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	strangerKid := stranger.did + "#" + stranger.auth.keyID
	strangerRev, _, err := dfos.SignRevocation(stranger.did, credentialCID, strangerKid, stranger.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	for i, res := range r.Ingest([]string{cred, issuerRev, strangerRev}) {
		if res.Status != "new" {
			t.Fatalf("ingest %d: %+v", i, res)
		}
	}

	return revocationCollision{
		srv:                srv,
		issuer:             issuer,
		stranger:           stranger,
		credentialCID:      credentialCID,
		issuerRevocation:   issuerRev,
		strangerRevocation: strangerRev,
		path:               srv.URL + "/revocations/v1/credential/" + credentialCID,
	}
}

func revocationCollisionStores(t *testing.T) map[string]func() RelayReadStore {
	return map[string]func() RelayReadStore{
		"memory": func() RelayReadStore { return NewMemoryStore() },
		"sqlite": func() RelayReadStore {
			store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "collision.db"))
			if err != nil {
				t.Fatalf("NewSQLiteStore: %v", err)
			}
			t.Cleanup(func() { store.Close() })
			return store
		},
	}
}

func assertRevocationStatus(t *testing.T, label string, body map[string]any, credentialCID string, revocation string) {
	t.Helper()
	if body["credentialCID"] != credentialCID {
		t.Fatalf("%s: credentialCID = %v, want %s", label, body["credentialCID"], credentialCID)
	}
	if revocation == "" {
		if body["revoked"] != false {
			t.Fatalf("%s: revoked = %v, want false", label, body["revoked"])
		}
		if _, ok := body["revocation"]; ok {
			t.Fatalf("%s: revocation key present on revoked:false: %v", label, body)
		}
		return
	}
	if body["revoked"] != true || body["revocation"] != revocation {
		t.Fatalf("%s: body = %v, want revoked:true with %s", label, body, revocation)
	}
}

// TestRevocationStatusIssuerScope pins the ?issuer= query on both stores: each
// issuer's own revocation when scoped, the smallest-issuerDID one unscoped,
// revoked:false for an issuer with none, and a 400 for any present issuer that
// is not a canonical did:dfos.
func TestRevocationStatusIssuerScope(t *testing.T) {
	for name, newStore := range revocationCollisionStores(t) {
		t.Run(name, func(t *testing.T) {
			c := seedRevocationCollision(t, newStore())

			t.Run("scoped answers each issuer's own revocation", func(t *testing.T) {
				for _, want := range []struct {
					did, revocation string
				}{
					{c.issuer.did, c.issuerRevocation},
					{c.stranger.did, c.strangerRevocation},
				} {
					status, body, _ := getJSONBody(t, c.path+"?issuer="+url.QueryEscape(want.did))
					if status != 200 {
						t.Fatalf("scoped %s: status = %d, want 200", want.did, status)
					}
					assertRevocationStatus(t, "scoped "+want.did, body, c.credentialCID, want.revocation)
				}
			})

			t.Run("unscoped answer unchanged: smallest issuerDID", func(t *testing.T) {
				smallest := c.strangerRevocation
				if c.issuer.did < c.stranger.did {
					smallest = c.issuerRevocation
				}
				status, body, _ := getJSONBody(t, c.path)
				if status != 200 {
					t.Fatalf("unscoped: status = %d, want 200", status)
				}
				assertRevocationStatus(t, "unscoped", body, c.credentialCID, smallest)
			})

			t.Run("scoped for an issuer with none is revoked:false", func(t *testing.T) {
				bystander := createTestIdentity(t)
				status, body, _ := getJSONBody(t, c.path+"?issuer="+url.QueryEscape(bystander.did))
				if status != 200 {
					t.Fatalf("bystander: status = %d, want 200", status)
				}
				assertRevocationStatus(t, "bystander", body, c.credentialCID, "")
			})

			t.Run("present non-canonical issuer is a 400", func(t *testing.T) {
				for _, issuer := range []string{"", "not-a-did", "did:dfos:tooshort", c.issuer.did + "x"} {
					status, body, _ := getJSONBody(t, c.path+"?issuer="+url.QueryEscape(issuer))
					if status != 400 {
						t.Fatalf("issuer %q: status = %d, want 400", issuer, status)
					}
					if body["error"] != "invalid DID" || len(body) != 1 {
						t.Fatalf("issuer %q: body = %v, want {error: invalid DID}", issuer, body)
					}
				}
			})
		})
	}
}
