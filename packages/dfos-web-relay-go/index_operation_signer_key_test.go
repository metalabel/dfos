package relay

import (
	"net/url"
	"path/filepath"
	"sort"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// operationCIDsMatching returns the CIDs a /index/v0/operations query pages back,
// sorted, so a multi-row assertion is order-independent.
func operationCIDsMatching(t *testing.T, r *Relay, query string) []string {
	t.Helper()
	status, body, raw := getIndexJSONBody(t, r.Handler(), "/index/v0/operations?"+query+"&limit=1000")
	if status != 200 {
		t.Fatalf("GET /index/v0/operations?%s = %d (%s)", query, status, raw)
	}
	rows, ok := body["operations"].([]any)
	if !ok {
		t.Fatalf("operations missing from %s", raw)
	}
	cids := make([]string, 0, len(rows))
	for _, row := range rows {
		cids = append(cids, row.(map[string]any)["cid"].(string))
	}
	sort.Strings(cids)
	return cids
}

func signerKeyQuery(publicKey string) string {
	return "signerKey=" + url.QueryEscape(publicKey)
}

// signedCorpus is one operation of every indexable kind, so a per-kind assertion
// can name the CID it expects the filter to return.
type signedCorpus struct {
	author    testIdentity
	witness   testIdentity
	identity  string // the author's genesis op — signed by the CONTROLLER key
	content   string // content genesis — signed by the author's auth key
	artifact  string
	countersn string // signed by the WITNESS, not the author
	credentl  string
	revocatn  string
}

// ingestSignedCorpus mints one op of every kind. The author signs everything with
// its auth key EXCEPT its own genesis (controller key, self-declared in the same
// op), and the countersignature is the witness's signature over the author's
// content op — the two cases where "whose key is this row?" has a wrong answer
// available.
func ingestSignedCorpus(t *testing.T, r *Relay) signedCorpus {
	t.Helper()
	author := ingestIdentity(t, r)
	witness := ingestIdentity(t, r)
	authorKid := author.did + "#" + author.auth.keyID
	witnessKid := witness.did + "#" + witness.auth.keyID

	contentToken, _, contentCID := createTestContent(t, author)
	if res := r.Ingest([]string{contentToken})[0]; res.Status != "new" {
		t.Fatalf("ingest content: %+v", res)
	}

	artifactToken, artifactCID, err := dfos.SignArtifact(author.did,
		map[string]any{"$schema": "test/v1", "title": "signer key"}, authorKid, author.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Ingest([]string{artifactToken})[0]; res.Status != "new" {
		t.Fatalf("ingest artifact: %+v", res)
	}

	csToken, csCID, err := dfos.SignCountersign(witness.did, contentCID, witnessKid, witness.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Ingest([]string{csToken})[0]; res.Status != "new" {
		t.Fatalf("ingest countersign: %+v", res)
	}

	credentialToken, err := dfos.CreateCredential(author.did, "*", authorKid,
		"chain:*", "read", time.Hour, author.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	credentialResult := r.Ingest([]string{credentialToken})[0]
	if credentialResult.Status != "new" {
		t.Fatalf("ingest credential: %+v", credentialResult)
	}

	revocationToken, revocationCID, err := dfos.SignRevocation(author.did, credentialResult.CID,
		authorKid, author.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Ingest([]string{revocationToken})[0]; res.Status != "new" {
		t.Fatalf("ingest revocation: %+v", res)
	}

	return signedCorpus{
		author:    author,
		witness:   witness,
		identity:  author.opCID,
		content:   contentCID,
		artifact:  artifactCID,
		countersn: csCID,
		credentl:  credentialResult.CID,
		revocatn:  revocationCID,
	}
}

// Every row kind carries a signer key, and it is uniformly the key the row's own
// JWS header resolved to at ingest: the author's auth key for its content,
// artifact, credential and revocation; its CONTROLLER key for its own genesis
// (the only op the auth key did not sign); and the WITNESS's key for the
// countersignature over the author's content — never the countersigned op's
// author. No per-kind branch, because the header is uniform.
func TestIndexOperationSignerKeyCoversEveryRowKind(t *testing.T) {
	r, _ := indexRelay(t)
	corpus := ingestSignedCorpus(t, r)

	authorAuth := corpus.author.auth.mk.PublicKeyMultibase
	authorController := corpus.author.controller.mk.PublicKeyMultibase
	witnessAuth := corpus.witness.auth.mk.PublicKeyMultibase

	for _, test := range []struct {
		label string
		key   string
		want  []string
	}{
		{"author auth key", authorAuth,
			[]string{corpus.content, corpus.artifact, corpus.credentl, corpus.revocatn}},
		{"author controller key (its own genesis)", authorController,
			[]string{corpus.identity}},
		{"witness auth key (only the countersignature)", witnessAuth,
			[]string{corpus.countersn}},
		{"witness controller key (only its own genesis)",
			corpus.witness.controller.mk.PublicKeyMultibase,
			[]string{corpus.witness.opCID}},
	} {
		want := append([]string{}, test.want...)
		sort.Strings(want)
		got := operationCIDsMatching(t, r, signerKeyQuery(test.key))
		if len(got) != len(want) {
			t.Fatalf("signerKey= on the %s matched %v, want %v", test.label, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("signerKey= on the %s matched %v, want %v", test.label, got, want)
			}
		}
	}
}

// The countersignature indexes the WITNESS. Asserted on its own because it is
// the one row where the tempting wrong answer — the author of the operation
// being countersigned — is also a real key present in the same corpus.
func TestIndexOperationSignerKeyCountersignIndexesTheWitness(t *testing.T) {
	r, _ := indexRelay(t)
	corpus := ingestSignedCorpus(t, r)

	got := operationCIDsMatching(t, r,
		signerKeyQuery(corpus.witness.auth.mk.PublicKeyMultibase)+"&kind=countersign")
	if len(got) != 1 || got[0] != corpus.countersn {
		t.Fatalf("countersign under the witness key = %v, want [%s]", got, corpus.countersn)
	}
	got = operationCIDsMatching(t, r,
		signerKeyQuery(corpus.author.auth.mk.PublicKeyMultibase)+"&kind=countersign")
	if len(got) != 0 {
		t.Fatalf("countersign under the countersigned op's author = %v, want none", got)
	}
}

// The value is opaque bytes. A string no accepted operation was signed with
// matches nothing — a 200 with an empty page, never a 400. There is no key
// format to validate against: the index does not know what a key looks like.
func TestIndexOperationSignerKeyGarbageMatchesNothing(t *testing.T) {
	r, _ := indexRelay(t)
	corpus := ingestSignedCorpus(t, r)
	real := corpus.author.auth.mk.PublicKeyMultibase

	for _, garbage := range []string{
		"not-a-key",
		"z" + real,        // right shape, never signed with
		real + " ",        // trailing space: the match is byte-for-byte
		corpus.author.did, // a DID is not a key — this filter is key-addressed
		corpus.author.did + "#" + corpus.author.auth.keyID, // nor is a kid
		"%%%",
	} {
		if got := operationCIDsMatching(t, r, signerKeyQuery(garbage)); len(got) != 0 {
			t.Fatalf("signerKey=%q matched %v, want none", garbage, got)
		}
	}
}

// An empty signerKey= is NO filter, the identities key= posture the spec names —
// deliberately unlike this route's chainId=, which presence-detects and so
// filters for the empty chain id.
func TestIndexOperationSignerKeyEmptyValueIsNoFilter(t *testing.T) {
	r, _ := indexRelay(t)
	corpus := ingestSignedCorpus(t, r)

	unfiltered := operationCIDsMatching(t, r, "kind=artifact")
	empty := operationCIDsMatching(t, r, "signerKey=&kind=artifact")
	if len(empty) != len(unfiltered) || !containsString(empty, corpus.artifact) {
		t.Fatalf("signerKey= (empty) matched %v, want the unfiltered %v", empty, unfiltered)
	}
	for i := range unfiltered {
		if empty[i] != unfiltered[i] {
			t.Fatalf("signerKey= (empty) matched %v, want the unfiltered %v", empty, unfiltered)
		}
	}
	if got := operationCIDsMatching(t, r, "chainId=&kind=artifact"); len(got) != 0 {
		t.Fatalf("chainId= (empty) matched %v — the contrast this test documents is gone", got)
	}
}

// Filters are ANDed: signerKey= composes with kind and chainId rather than
// replacing them, and a contradictory conjunction is an empty page, not an error.
func TestIndexOperationSignerKeyComposesWithOtherFilters(t *testing.T) {
	r, _ := indexRelay(t)
	corpus := ingestSignedCorpus(t, r)
	key := signerKeyQuery(corpus.author.auth.mk.PublicKeyMultibase)

	if got := operationCIDsMatching(t, r, key+"&kind=artifact"); len(got) != 1 || got[0] != corpus.artifact {
		t.Fatalf("signerKey= AND kind=artifact matched %v, want [%s]", got, corpus.artifact)
	}
	if got := operationCIDsMatching(t, r, key+"&chainId="+url.QueryEscape(corpus.author.did)+"&kind=artifact"); len(got) != 1 {
		t.Fatalf("signerKey= AND chainId= AND kind= matched %v, want the artifact", got)
	}
	// The author never signed a countersignature, and the witness never signed
	// an artifact — both conjunctions are honestly empty.
	if got := operationCIDsMatching(t, r, key+"&kind=countersign"); len(got) != 0 {
		t.Fatalf("author key AND kind=countersign matched %v, want none", got)
	}
	witnessKey := signerKeyQuery(corpus.witness.auth.mk.PublicKeyMultibase)
	if got := operationCIDsMatching(t, r, witnessKey+"&kind=artifact"); len(got) != 0 {
		t.Fatalf("witness key AND kind=artifact matched %v, want none", got)
	}
	// A key that exists AND a chain it never touched.
	if got := operationCIDsMatching(t, r, witnessKey+"&chainId="+url.QueryEscape(corpus.author.did)); len(got) != 0 {
		t.Fatalf("witness key AND the author's chain matched %v, want none", got)
	}
}

// The filter pages through the shared ordered-cursor envelope like every other
// index route: the cursor stays inside the filtered set and walks it exactly once.
func TestIndexOperationSignerKeyPagination(t *testing.T) {
	r, _ := indexRelay(t)
	corpus := ingestSignedCorpus(t, r)
	key := signerKeyQuery(corpus.author.auth.mk.PublicKeyMultibase)

	all := operationCIDsMatching(t, r, key)
	if len(all) != 4 {
		t.Fatalf("author key matched %v, want 4 rows to page through", all)
	}

	for _, order := range []string{"ingestedAt.desc", "createdAt.desc"} {
		seen := []string{}
		after := ""
		for page := 0; page < len(all)+2; page++ {
			path := "/index/v0/operations?" + key + "&order=" + order + "&limit=1"
			if after != "" {
				path += "&after=" + url.QueryEscape(after)
			}
			status, body, raw := getIndexJSONBody(t, r.Handler(), path)
			if status != 200 {
				t.Fatalf("%s = %d (%s)", path, status, raw)
			}
			rows := body["operations"].([]any)
			for _, row := range rows {
				seen = append(seen, row.(map[string]any)["cid"].(string))
			}
			next, ok := body["next"].(string)
			if !ok || next == "" {
				break
			}
			after = next
		}
		sort.Strings(seen)
		if len(seen) != len(all) {
			t.Fatalf("%s paging saw %v, want %v", order, seen, all)
		}
		for i := range all {
			if seen[i] != all[i] {
				t.Fatalf("%s paging saw %v, want %v", order, seen, all)
			}
		}
	}
}

// The row retains the key its signature verified against AT INGEST — a fact
// about the past. A later rotation removes the key from head state without
// touching any row it already signed.
func TestIndexOperationSignerKeySurvivesRotation(t *testing.T) {
	r, _ := indexRelay(t)
	id := ingestIdentity(t, r)
	artifact, artifactCID, err := dfos.SignArtifact(id.did,
		map[string]any{"$schema": "test/v1", "title": "pre-rotation"},
		id.did+"#"+id.auth.keyID, id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Ingest([]string{artifact})[0]; res.Status != "new" {
		t.Fatalf("ingest artifact: %+v", res)
	}
	rotatedOut := id.auth.mk.PublicKeyMultibase
	rotateExistingTestIdentity(t, r, id)

	got := operationCIDsMatching(t, r, signerKeyQuery(rotatedOut)+"&kind=artifact")
	if len(got) != 1 || got[0] != artifactCID {
		t.Fatalf("rotated-out signer key matched %v, want [%s]", got, artifactCID)
	}
}

// A corpus ingested before the signer key was retained carries none, so the
// versioned projection rebuild re-resolves it from each row's stored JWS. Unlike
// every other projection pass this one fills a column in place — the operation
// log is authoritative and is never cleared — and it has to reach a rotated-out
// key through the identity chain's historical declarations.
func TestIndexOperationSignerKeyRebuildsPreExistingRows(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "operation-signer-keys.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	r, err := NewRelay(RelayOptions{Store: store, Authority: testAuthority})
	if err != nil {
		t.Fatal(err)
	}
	corpus := ingestSignedCorpus(t, r)
	rotatedOut := corpus.author.auth.mk.PublicKeyMultibase
	rotated, _ := rotateExistingTestIdentity(t, r, corpus.author)

	if got := operationCIDsMatching(t, r, signerKeyQuery(rotatedOut)); len(got) != 4 {
		t.Fatalf("pre-rebuild author key matched %v, want 4 rows", got)
	}

	// Simulate a store whose operation log predates the column: strip every
	// resolved key and unstamp the projection version.
	if _, err := store.writerDB().Exec("UPDATE operation_log SET signer_key = NULL"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIndexProjectionVersion(0); err != nil {
		t.Fatal(err)
	}
	if got := operationCIDsMatching(t, r, signerKeyQuery(rotatedOut)); len(got) != 0 {
		t.Fatalf("expected no signer keys after stripping them, matched %v", got)
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

	// The rotated-out key is only reachable from the chain's historical
	// declarations — head state no longer carries it.
	if got := operationCIDsMatching(t, r2, signerKeyQuery(rotatedOut)); len(got) != 4 {
		t.Fatalf("post-rebuild rotated-out author key matched %v, want the 4 rows it signed", got)
	}
	// The controller key is still current, so it resolves through the head-state
	// fast path — and it signed BOTH the genesis (a bare kid, self-declared in
	// its own payload) and the rotation, the two shapes the resolver splits on.
	controllerSigned := operationCIDsMatching(t, r2,
		signerKeyQuery(corpus.author.controller.mk.PublicKeyMultibase)+"&kind=identity-op")
	if len(controllerSigned) != 2 || !containsString(controllerSigned, corpus.identity) {
		t.Fatalf("post-rebuild author controller key matched %v, want its genesis %s and its rotation",
			controllerSigned, corpus.identity)
	}
	witnessSigned := operationCIDsMatching(t, r2,
		signerKeyQuery(corpus.witness.auth.mk.PublicKeyMultibase)+"&kind=countersign")
	if len(witnessSigned) != 1 || witnessSigned[0] != corpus.countersn {
		t.Fatalf("post-rebuild countersignature under its witness matched %v, want [%s]",
			witnessSigned, corpus.countersn)
	}
	// The newly rotated-in key has signed nothing, so it matches nothing — the
	// backfill records what signed each row, not what the chain now holds.
	if got := operationCIDsMatching(t, r2, signerKeyQuery(rotated.mk.PublicKeyMultibase)); len(got) != 0 {
		t.Fatalf("the newly rotated-in key signed nothing yet, matched %v", got)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// The signer key is a filter, never a field: adding it must not widen the
// metadata-only row the route serves.
func TestIndexOperationSignerKeyIsNotAResponseField(t *testing.T) {
	r, _ := indexRelay(t)
	corpus := ingestSignedCorpus(t, r)

	_, body, raw := getIndexJSONBody(t, r.Handler(),
		"/index/v0/operations?"+signerKeyQuery(corpus.author.auth.mk.PublicKeyMultibase))
	rows := body["operations"].([]any)
	if len(rows) == 0 {
		t.Fatalf("no rows to inspect (%s)", raw)
	}
	for _, row := range rows {
		row := row.(map[string]any)
		if len(row) != 5 {
			t.Fatalf("operation row grew beyond cid/kind/chainId/createdAt/ingestedAt: %v", row)
		}
		for _, forbidden := range []string{"signerKey", "signerDID", "jwsToken"} {
			if _, present := row[forbidden]; present {
				t.Fatalf("operation row leaked %s: %v", forbidden, row)
			}
		}
	}
}
