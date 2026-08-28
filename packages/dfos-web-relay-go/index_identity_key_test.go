package relay

import (
	"net/url"
	"path/filepath"
	"sort"
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// identityDIDsMatching returns the DIDs a /index/v0/identities query pages back,
// sorted, so a multi-row assertion is order-independent.
func identityDIDsMatching(t *testing.T, r *Relay, query string) []string {
	t.Helper()
	status, body, raw := getIndexJSONBody(t, r.Handler(), "/index/v0/identities?"+query+"&limit=1000")
	if status != 200 {
		t.Fatalf("GET /index/v0/identities?%s = %d (%s)", query, status, raw)
	}
	rows, ok := body["identities"].([]any)
	if !ok {
		t.Fatalf("identities missing from %s", raw)
	}
	dids := make([]string, 0, len(rows))
	for _, row := range rows {
		dids = append(dids, row.(map[string]any)["did"].(string))
	}
	sort.Strings(dids)
	return dids
}

func keyQuery(publicKey string) string {
	return "key=" + url.QueryEscape(publicKey)
}

// createTestIdentityWithKeys mints an identity declaring the exact key set given,
// signed by the first controller key.
func createTestIdentityWithKeys(t *testing.T, controller testKeypair, auth, assert []dfos.MultikeyPublicKey) (token string, did string, opCID string) {
	t.Helper()
	token, did, opCID, err := dfos.SignIdentityCreate(
		[]dfos.MultikeyPublicKey{controller.mk},
		auth,
		assert,
		controller.keyID,
		controller.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	return token, did, opCID
}

// All three key classes land in the reverse index. There is no key-class column
// — which array carried the key is the chain's answer, not the index's — so a
// controller, auth, or assert key each matches its identity the same way.
func TestIndexIdentityKeyMatchesEveryKeyClass(t *testing.T) {
	r, _ := indexRelay(t)
	controller := newTestKeypair()
	auth := newTestKeypair()
	assert := newTestKeypair()
	token, did, _ := createTestIdentityWithKeys(t, controller,
		[]dfos.MultikeyPublicKey{auth.mk}, []dfos.MultikeyPublicKey{assert.mk})
	if res := r.Ingest([]string{token}); res[0].Status != "new" {
		t.Fatalf("ingest genesis: %+v", res[0])
	}

	for label, key := range map[string]dfos.MultikeyPublicKey{
		"controllerKeys": controller.mk,
		"authKeys":       auth.mk,
		"assertKeys":     assert.mk,
	} {
		got := identityDIDsMatching(t, r, keyQuery(key.PublicKeyMultibase))
		if len(got) != 1 || got[0] != did {
			t.Fatalf("key= on %s matched %v, want [%s]", label, got, did)
		}
	}
}

// The filter is has-ever-declared, not current-state: a key a later update
// rotated out still matches. This is the case the filter exists for — a holder
// recovering from a restored key holds exactly the keys that were rotated away.
func TestIndexIdentityKeyMatchesRotatedOutKey(t *testing.T) {
	r, _ := indexRelay(t)
	id := ingestIdentity(t, r)
	rotated, _ := rotateExistingTestIdentity(t, r, id)

	// sanity: the rotation really did replace the key array
	chain, err := r.readStore.GetIdentityChain(id.did)
	if err != nil || chain == nil {
		t.Fatalf("chain: %v", err)
	}
	if len(chain.State.AuthKeys) != 1 || chain.State.AuthKeys[0].PublicKeyMultibase != rotated.mk.PublicKeyMultibase {
		t.Fatalf("head auth keys = %+v, want only the rotated-in key", chain.State.AuthKeys)
	}

	for label, key := range map[string]string{
		"rotated-out genesis key": id.auth.mk.PublicKeyMultibase,
		"rotated-in current key":  rotated.mk.PublicKeyMultibase,
	} {
		got := identityDIDsMatching(t, r, keyQuery(key))
		if len(got) != 1 || got[0] != id.did {
			t.Fatalf("key= on the %s matched %v, want [%s]", label, got, id.did)
		}
	}
}

// One key may match many identities: the reverse index is (key → identities),
// so a key declared by two chains pages back both rows.
func TestIndexIdentityKeyMatchesManyIdentities(t *testing.T) {
	r, _ := indexRelay(t)
	shared := newTestKeypair()

	first, firstDID, _ := createTestIdentityWithKeys(t, newTestKeypair(), []dfos.MultikeyPublicKey{shared.mk}, nil)
	second, secondDID, _ := createTestIdentityWithKeys(t, newTestKeypair(), []dfos.MultikeyPublicKey{shared.mk}, nil)
	if firstDID == secondDID {
		t.Fatal("expected two distinct identities declaring the same key")
	}
	for _, token := range []string{first, second} {
		if res := r.Ingest([]string{token}); res[0].Status != "new" {
			t.Fatalf("ingest: %+v", res[0])
		}
	}

	want := []string{firstDID, secondDID}
	sort.Strings(want)
	got := identityDIDsMatching(t, r, keyQuery(shared.mk.PublicKeyMultibase))
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("key= matched %v, want %v", got, want)
	}
}

// A deleted identity still matches: deletion is terminal chain state, not a
// retraction of history. isDeleted stays in the row so the caller can see it.
func TestIndexIdentityKeyMatchesDeletedIdentity(t *testing.T) {
	r, _ := indexRelay(t)
	id := ingestIdentity(t, r)
	deleteToken, _, err := dfos.SignIdentityDelete(id.opCID, id.did+"#"+id.controller.keyID, id.controller.priv)
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Ingest([]string{deleteToken}); res[0].Status != "new" {
		t.Fatalf("ingest delete: %+v", res[0])
	}

	got := identityDIDsMatching(t, r, keyQuery(id.auth.mk.PublicKeyMultibase))
	if len(got) != 1 || got[0] != id.did {
		t.Fatalf("key= on a deleted identity matched %v, want [%s]", got, id.did)
	}
	row := indexIdentityRowByDID(t, r.Handler(), id.did)
	if row == nil || row["isDeleted"] != true {
		t.Fatalf("deleted identity row = %v, want isDeleted true", row)
	}
}

// Filters are ANDed: key= composes with the rest of the identity family rather
// than replacing it.
func TestIndexIdentityKeyComposesWithOtherFilters(t *testing.T) {
	r, _ := indexRelay(t)
	id := ingestIdentity(t, r)
	other := ingestIdentity(t, r)
	key := keyQuery(id.auth.mk.PublicKeyMultibase)

	if got := identityDIDsMatching(t, r, key+"&did="+url.QueryEscape(id.did)); len(got) != 1 || got[0] != id.did {
		t.Fatalf("key= AND did= matched %v, want [%s]", got, id.did)
	}
	// A contradictory conjunction is empty, not an error — the AND is real.
	if got := identityDIDsMatching(t, r, key+"&did="+url.QueryEscape(other.did)); len(got) != 0 {
		t.Fatalf("key= AND a different did= matched %v, want none", got)
	}
	// Neither identity anchors a public profile, so the predicate excludes both.
	if got := identityDIDsMatching(t, r, key+"&hasPublicProfile=true"); len(got) != 0 {
		t.Fatalf("key= AND hasPublicProfile=true matched %v, want none", got)
	}
	if got := identityDIDsMatching(t, r, key+"&hasPublicProfile=false"); len(got) != 1 || got[0] != id.did {
		t.Fatalf("key= AND hasPublicProfile=false matched %v, want [%s]", got, id.did)
	}
}

// The value is opaque bytes. A string no operation ever declared matches
// nothing — a 200 with an empty page, never a 400. There is no key format to
// validate against: the index does not know, or need to know, what a key looks
// like.
func TestIndexIdentityKeyGarbageMatchesNothing(t *testing.T) {
	r, _ := indexRelay(t)
	id := ingestIdentity(t, r)

	for _, garbage := range []string{
		"not-a-key",
		"z" + id.auth.mk.PublicKeyMultibase, // right shape, never declared
		id.auth.mk.PublicKeyMultibase + " ", // trailing space: byte-for-byte match
		id.did,                              // a DID is not a key
		"%%%",
	} {
		if got := identityDIDsMatching(t, r, keyQuery(garbage)); len(got) != 0 {
			t.Fatalf("key=%q matched %v, want none", garbage, got)
		}
	}
}

// The reverse index is history, so an upgraded relay can only backfill it by
// replaying the op log — which is what the versioned rebuild does. A key the
// head state no longer carries has to come back.
func TestIndexIdentityKeyRebuildsFromOpLog(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "identity-keys.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	r, err := NewRelay(RelayOptions{Store: store, Authority: testAuthority})
	if err != nil {
		t.Fatal(err)
	}
	id := ingestIdentity(t, r)
	rotated, _ := rotateExistingTestIdentity(t, r, id)
	rotatedOut := id.auth.mk.PublicKeyMultibase

	if got := identityDIDsMatching(t, r, keyQuery(rotatedOut)); len(got) != 1 {
		t.Fatalf("pre-rebuild key= matched %v, want [%s]", got, id.did)
	}

	// Simulate a store whose projection predates this schema version.
	if err := store.ClearIndexProjection(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIndexProjectionVersion(0); err != nil {
		t.Fatal(err)
	}
	if got := identityDIDsMatching(t, r, keyQuery(rotatedOut)); len(got) != 0 {
		t.Fatalf("expected an empty projection after clear, matched %v", got)
	}

	// Booting on the same store rebuilds synchronously before serving.
	r2, err := NewRelay(RelayOptions{
		Store:     store,
		Authority: testAuthority,
		Identity:  &RelayIdentity{DID: r.DID(), ProfileArtifactJWS: r.ProfileArtifactJWS()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := store.GetIndexProjectionVersion(); v != IndexProjectionVersion {
		t.Fatalf("projection_version = %d, want %d", v, IndexProjectionVersion)
	}
	for label, key := range map[string]string{
		"rotated-out genesis key": rotatedOut,
		"current key":             rotated.mk.PublicKeyMultibase,
		"controller key":          id.controller.mk.PublicKeyMultibase,
	} {
		got := identityDIDsMatching(t, r2, keyQuery(key))
		if len(got) != 1 || got[0] != id.did {
			t.Fatalf("post-rebuild key= on the %s matched %v, want [%s]", label, got, id.did)
		}
	}
}
