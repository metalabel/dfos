package conformance

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// ===========================================================================
// WP-7 — DUAL-RELAY PARITY HARNESS
//
// Boots BOTH relays (TS in-memory + Go sqlite, started by run-parity.sh from
// the SAME pinned identity fixture), replays a FIXED-SEED op set into each, and
// asserts the proof-plane GET routes return SEMANTICALLY-IDENTICAL bodies. The
// fixture pins one ed25519 key + pinned timestamps so the relay's own genesis +
// profile log entries are byte-identical too — the #1 parity flake is a random
// relay identity leaking into /log entry #1.
//
// Bodies are compared after CANONICALIZING JSON (recursive key sort): Go's
// writeJSON encodes map[string]any with keys sorted, while Hono's c.json keeps
// insertion order, so even {entries, next, cursor} differs at the raw-byte level while
// being semantically identical. Canonicalization is the correct equality.
//
// Run via packages/relay-conformance/scripts/run-parity.sh, which sets
// TS_RELAY_URL, GO_RELAY_URL, and PARITY_FIXTURE.
// ===========================================================================

type parityFixtureBlob struct {
	ContentID    string          `json:"contentId"`
	OperationCID string          `json:"operationCid"`
	Body         json.RawMessage `json:"body"`
}

type parityFixture struct {
	RelayDID                  string              `json:"relayDid"`
	RelayProfileJWS           string              `json:"relayProfileJws"`
	BootstrapOps              []string            `json:"bootstrapOps"`
	Ops                       []string            `json:"ops"`
	Blobs                     []parityFixtureBlob `json:"blobs"`
	QueryAuthKeyID            string              `json:"queryAuthKeyId"`
	QueryDID                  string              `json:"queryDid"`
	QueryContentID            string              `json:"queryContentId"`
	QueryDocumentCID          string              `json:"queryDocumentCid"`
	QueryServiceDID           string              `json:"queryServiceDid"`
	QueryDeletedDID           string              `json:"queryDeletedDid"`
	QueryProfileDID           string              `json:"queryProfileDid"`
	QueryProfileName          string              `json:"queryProfileName"`
	QueryRevokedCredentialCID string              `json:"queryRevokedCredentialCid"`
	QueryRevocationIssuerDID  string              `json:"queryRevocationIssuerDid"`
	QueryCountersignedCID     string              `json:"queryCountersignedCid"`

	// The two key-addressed filters — `signerKey=` on /index/v0/operations and
	// `key=` on /index/v0/identities — speak the SAME alphabet: these are the
	// multibase strings the fixture's chains declared, byte for byte, so a value
	// found through one filter pastes straight into the other.
	QueryAuthKeyMultibase      string `json:"queryAuthKeyMultibase"`
	QueryWitnessKeyMultibase   string `json:"queryWitnessKeyMultibase"`
	QueryAuthGenesisCID        string `json:"queryAuthGenesisCid"`
	QueryWitnessCountersignCID string `json:"queryWitnessCountersignCid"`
	// User E: one identity, two keys. E1 signs the genesis and the update that
	// rotates it out; E2 signs the artifact after it.
	QueryRotationDID            string `json:"queryRotationDid"`
	QueryRotatedOutKeyMultibase string `json:"queryRotatedOutKeyMultibase"`
	QueryRotationKeyMultibase   string `json:"queryRotationKeyMultibase"`
}

func loadParityEnv(t *testing.T) (tsURL, goURL string, fix parityFixture) {
	t.Helper()
	tsURL = os.Getenv("TS_RELAY_URL")
	goURL = os.Getenv("GO_RELAY_URL")
	fixPath := os.Getenv("PARITY_FIXTURE")
	if tsURL == "" || goURL == "" || fixPath == "" {
		t.Skip("TS_RELAY_URL / GO_RELAY_URL / PARITY_FIXTURE not set — skipping parity harness")
	}
	data, err := os.ReadFile(fixPath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixPath, err)
	}
	if err := json.Unmarshal(data, &fix); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return tsURL, goURL, fix
}

// canonicalize parses a JSON body and re-marshals it with all object keys sorted
// recursively, so two semantically-identical bodies with different key order
// compare equal.
func canonicalize(t *testing.T, body []byte) string {
	t.Helper()
	var v any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // preserve integer precision (no float coercion)
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("parse JSON for canonicalization: %v (body: %s)", err, string(body))
	}
	out, err := json.Marshal(sortKeys(v))
	if err != nil {
		t.Fatalf("re-marshal canonical JSON: %v", err)
	}
	return string(out)
}

// sortKeys recursively re-encodes maps with keys in sorted order, returning a
// json.RawMessage so the parent marshal preserves the ordering. Arrays keep
// their order (semantically significant); scalars pass through.
func sortKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var buf bytes.Buffer
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			vb, _ := json.Marshal(sortKeys(t[k]))
			buf.Write(vb)
		}
		buf.WriteByte('}')
		return json.RawMessage(buf.Bytes())
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = sortKeys(e)
		}
		return out
	default:
		return v
	}
}

func getBody(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func postOps(t *testing.T, base string, ops []string) []byte {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"operations": ops})
	resp, err := http.Post(base+"/proof/v1/operations", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST %s/proof/v1/operations: %v", base, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("POST %s/proof/v1/operations: status %d, body %s", base, resp.StatusCode, b)
	}
	return b
}

// canonicalizeNormalized canonicalizes after replacing the values of named
// relay-local volatile fields (e.g. ingestedAt — each relay stamps its own
// receipt clock, so byte-equality is impossible by construction) with a fixed
// placeholder. Structure and every convergent field still byte-compare.
func canonicalizeNormalized(t *testing.T, body []byte, volatile ...string) string {
	t.Helper()
	var parsed any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("canonicalizeNormalized: unmarshal: %v (body: %s)", err, body)
	}
	vol := map[string]bool{}
	for _, key := range volatile {
		vol[key] = true
	}
	normalized := normalizeVolatileFields(parsed, vol)
	out, err := json.Marshal(sortKeys(normalized))
	if err != nil {
		t.Fatalf("canonicalizeNormalized: marshal: %v", err)
	}
	return string(out)
}

func normalizeVolatileFields(v any, volatile map[string]bool) any {
	switch x := v.(type) {
	case map[string]any:
		for key, value := range x {
			if volatile[key] {
				if s, ok := value.(string); ok && s != "" {
					x[key] = "<relay-local>"
				}
				continue
			}
			x[key] = normalizeVolatileFields(value, volatile)
		}
		return x
	case []any:
		for i := range x {
			x[i] = normalizeVolatileFields(x[i], volatile)
		}
		return x
	default:
		return v
	}
}

// putParityBlobs uploads the fixture blobs to one relay. Each upload signs its
// OWN identity proof — bound to that relay's authority, that blob's path, and
// that blob's bytes — so the same fixture lands on both twins without anything
// reusable crossing between them.
func putParityBlobs(t *testing.T, base string, fix parityFixture, signer *proofSigner) {
	t.Helper()
	for _, blob := range fix.Blobs {
		u := fmt.Sprintf("%s/content/%s/blob/%s", base, blob.ContentID, blob.OperationCID)
		req, err := http.NewRequest(http.MethodPut, u, bytes.NewReader(blob.Body))
		if err != nil {
			t.Fatalf("build PUT %s: %v", u, err)
		}
		signRequest(t, base, req, signer, blob.Body, newJTI(t))
		req.Header.Set("content-type", "application/octet-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT %s: %v", u, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT %s: status %d, body: %s", u, resp.StatusCode, body)
		}
	}
}

// compareIndexCursorWalk follows an ordered content cursor to exhaustion on
// both relays and compares every page. Requiring two non-empty pages proves
// parity of cursor generation/resumption, not merely parity of the first page.
func compareIndexCursorWalk(t *testing.T, tsURL, goURL, routeBase string) {
	t.Helper()
	after := ""
	nonEmptyPages := 0
	finished := false
	for pageNumber := 1; pageNumber <= 20; pageNumber++ {
		route := routeBase
		if after != "" {
			route += "&after=" + url.QueryEscape(after)
		}
		tsStatus, tsBody := getBody(t, tsURL+route)
		goStatus, goBody := getBody(t, goURL+route)
		if tsStatus != http.StatusOK || goStatus != http.StatusOK {
			t.Fatalf("ordered cursor page %d on %s: TS=%d body=%s; Go=%d body=%s", pageNumber, route, tsStatus, tsBody, goStatus, goBody)
		}
		tsCanon := canonicalize(t, tsBody)
		goCanon := canonicalize(t, goBody)
		if tsCanon != goCanon {
			t.Fatalf("PARITY MISMATCH on ordered cursor page %d (%s)\n%s\n--- TS (canonical) ---\n%s\n--- Go (canonical) ---\n%s",
				pageNumber, route, prettyDiff(tsCanon, goCanon), tsCanon, goCanon)
		}

		var page struct {
			Content []json.RawMessage `json:"content"`
			Next    *string           `json:"next"`
		}
		if err := json.Unmarshal(tsBody, &page); err != nil {
			t.Fatalf("parse ordered cursor page %d: %v", pageNumber, err)
		}
		if len(page.Content) > 0 {
			nonEmptyPages++
		}
		if page.Next == nil {
			finished = true
			break
		}
		if *page.Next == "" {
			t.Fatalf("ordered cursor page %d returned an empty next token", pageNumber)
		}
		after = *page.Next
	}
	if !finished {
		t.Fatal("ordered cursor parity walk exceeded 20 pages")
	}
	if nonEmptyPages < 2 {
		t.Fatalf("ordered cursor parity walk had %d non-empty pages, want at least 2", nonEmptyPages)
	}
}

// logEntryCount polls GET /log and returns the number of entries. Used to wait
// for the Go relay's ticker-driven sequencer to drain before comparing.
func logEntryCount(t *testing.T, base string) int {
	t.Helper()
	_, body := getBody(t, base+"/proof/v1/log?limit=1000")
	var parsed struct {
		logPaginationFields
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return -1
	}
	assertLogPaginationFields(t, parsed.logPaginationFields)
	return len(parsed.Entries)
}

// drainUntilStable polls /log on a relay until the entry count is >= want AND
// stops changing across two consecutive polls. Sequence-then-read: never
// compare mid-drain.
func drainUntilStable(t *testing.T, base string, want int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	last := -1
	stableHits := 0
	for time.Now().Before(deadline) {
		n := logEntryCount(t, base)
		if n >= want && n == last {
			stableHits++
			if stableHits >= 2 {
				return
			}
		} else {
			stableHits = 0
		}
		last = n
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("relay %s did not drain to >= %d stable entries (last=%d)", base, want, last)
}

func TestDualRelayParity(t *testing.T) {
	tsURL, goURL, fix := loadParityEnv(t)

	// Replay the fixed op set into BOTH relays in the SAME fixed order:
	// bootstrap ops (relay genesis + profile) first, then the user op set.
	allOps := append(append([]string{}, fix.BootstrapOps...), fix.Ops...)
	tsPostBody := postOps(t, tsURL, allOps)
	goPostBody := postOps(t, goURL, allOps)

	// POST response parity: the ingestion verdict (per-op status / error /
	// dependencyMissing) is the relay's most semantically loaded output —
	// compare the bodies, not just the HTTP status.
	t.Run("POST /proof/v1/operations response body", func(t *testing.T) {
		tsCanon := canonicalize(t, tsPostBody)
		goCanon := canonicalize(t, goPostBody)
		if tsCanon != goCanon {
			t.Fatalf("PARITY MISMATCH on POST /proof/v1/operations response\n%s\n--- TS (canonical) ---\n%s\n--- Go (canonical) ---\n%s",
				prettyDiff(tsCanon, goCanon), tsCanon, goCanon)
		}
	})

	// Expected accepted entries = every op in the fixture: bootstrap (relay
	// genesis + profile) + the user op set (identities A/B/C/D, A's content
	// create+update, artifact, credential, D's delete). All sequence cleanly in
	// dependency order, so the drained log count equals len(allOps).
	wantEntries := len(allOps)

	// Drain both: TS sequences inline, Go runs on a ticker. Wait for both to
	// reach a stable entry count before reading — never read mid-drain.
	drainUntilStable(t, tsURL, wantEntries)
	drainUntilStable(t, goURL, wantEntries)

	// Hold the same fixture bytes on both relays. This makes the profile/name
	// index filters positive parity cases while keeping the operation fixture
	// byte-pinned.
	seed := bytes.Repeat([]byte{2}, ed25519.SeedSize)
	querySigner := &proofSigner{
		kid:  fix.QueryDID + "#" + fix.QueryAuthKeyID,
		priv: ed25519.NewKeyFromSeed(seed),
	}
	putParityBlobs(t, tsURL, fix, querySigner)
	putParityBlobs(t, goURL, fix, querySigner)

	orderedContentRoute := "/index/v0/content?order=genesisAt.desc&limit=1000"
	signerRoute := "/index/v0/content?signer=" + url.QueryEscape(fix.QueryDID) + "&limit=1000"
	nameRoute := "/index/v0/identities?nameContains=" + url.QueryEscape(fix.QueryProfileName) + "&limit=1000"
	publicProfileRoute := "/index/v0/identities?hasPublicProfile=true&limit=1000"
	publicReadRoute := "/index/v0/content?publicRead=true&limit=1000"
	creditsRoute := "/index/v0/credits?contentId=" + url.QueryEscape(fix.QueryContentID) + "&limit=1000"
	creditsDIDRoute := "/index/v0/credits?did=" + url.QueryEscape(fix.QueryRevocationIssuerDID) + "&limit=1000"
	// `key=` on identities is the sibling of `signerKey=` on operations — the
	// other key-addressed, byte-for-byte, opaque filter. The rotated-out variant
	// is the has-ever-declared property: the key is gone from head state and the
	// row must still come back, identically on both twins.
	identityKeyRoute := "/index/v0/identities?key=" + url.QueryEscape(fix.QueryAuthKeyMultibase) + "&limit=1000"
	identityRotatedKeyRoute := "/index/v0/identities?key=" + url.QueryEscape(fix.QueryRotatedOutKeyMultibase) + "&limit=1000"

	routes := []string{
		"/proof/v1/log?limit=1000",
		"/proof/v1/identities/" + fix.QueryDID + "/log?limit=1000",
		"/proof/v1/content/" + fix.QueryContentID + "/log?limit=1000",
		"/.well-known/dfos-relay",
		"/index/v0/identities?limit=1000",
		"/index/v0/content?limit=1000",
		orderedContentRoute,
		signerRoute,
		nameRoute,
		publicProfileRoute,
		publicReadRoute,
		creditsRoute,
		creditsDIDRoute,
		"/index/v0/content?documentCID=" + fix.QueryDocumentCID + "&limit=1000",
		"/index/v0/countersignatures?witness=" + fix.QueryRevocationIssuerDID + "&limit=1000",
		"/index/v0/credentials?resource=chain:*&limit=1000",
		identityKeyRoute,
		identityRotatedKeyRoute,
		// OPAQUE: a value no operation ever declared matches nothing on both
		// twins — 200 with an empty page, never a 400.
		"/index/v0/identities?key=" + url.QueryEscape("not-a-multibase-key !") + "&limit=1000",
	}
	// REGRESSION GUARD (index fan-out). The content-row expectations below pin a
	// real shared relay defect that this gate caught on its first run and that
	// was FIXED in the same commit that added the guard (215fa14). Kept as a
	// guard, not a bug report — the history is recorded here so a future failure
	// is recognized as this regression rather than re-debugged from scratch.
	//
	// The defect: the fixture posts its ops as ONE batch. That batch contains
	// user A's `chain:*` credential, which sets `allContent` on the batch dirty
	// set; the flush (flushIndexMaintenance in both twins) then took the
	// `allContent` branch and DISCARDED the per-id `contentIds` collected from
	// the content-ops in the same batch. The `allContent` sweep enumerates the
	// MATERIALIZED PROJECTION (queryIndexContent → index_content /
	// s.indexContentRows), not the authoritative chain table, so on a relay whose
	// content rows had never been written it enumerated nothing and wrote
	// nothing. Any batch carrying a `chain:*` grant alongside brand-new content
	// ops therefore left those content rows permanently absent from
	// /index/v0/content — nothing recovered them, including a later blob upload
	// (maintainIndexAfterBlob also reads the projection). The sibling
	// `allPublicContent` branch already unioned the per-id set; `allContent` did
	// not.
	//
	// The fix: both flushes now ALWAYS run the per-id `contentIds` set, unioned
	// with whichever sweep the batch selected.
	//
	// Repro of the original bug: post the fixture ops split into two batches
	// (content ops first, credentials second) and the rows appeared; post them as
	// one batch and they never did.
	//
	// Do NOT weaken these assertions to make the gate green — a failure here means
	// the fan-out union has regressed.
	expectedRows := map[string]string{
		orderedContentRoute: fix.QueryContentID,
		signerRoute:         fix.QueryContentID,
		nameRoute:           fix.QueryProfileDID,
		publicProfileRoute:  fix.QueryProfileDID,
		publicReadRoute:     fix.QueryContentID,
		creditsRoute:        fix.QueryRevocationIssuerDID,
		creditsDIDRoute:     fix.QueryContentID,
		// A's declared key resolves back to A; E's ROTATED-OUT key still resolves
		// to E, which is the has-ever-declared contract rather than head state.
		identityKeyRoute:        fix.QueryDID,
		identityRotatedKeyRoute: fix.QueryRotationDID,
	}

	for routeIndex, route := range routes {
		t.Run(route, func(t *testing.T) {
			tsStatus, tsBody := getBody(t, tsURL+route)
			goStatus, goBody := getBody(t, goURL+route)

			if tsStatus != goStatus {
				t.Fatalf("status mismatch on %s: TS=%d Go=%d", route, tsStatus, goStatus)
			}
			if tsStatus != 200 {
				t.Fatalf("expected 200 on %s, got %d (TS body: %s)", route, tsStatus, tsBody)
			}
			if expected, ok := expectedRows[route]; ok {
				if !bytes.Contains(tsBody, []byte(expected)) || !bytes.Contains(goBody, []byte(expected)) {
					t.Fatalf("positive parity fixture row %s absent on %s (TS body: %s; Go body: %s)", expected, route, tsBody, goBody)
				}
			}
			if routeIndex < 3 {
				var tsLog, goLog logPaginationFields
				if err := json.Unmarshal(tsBody, &tsLog); err != nil {
					t.Fatalf("parse TS log envelope: %v", err)
				}
				if err := json.Unmarshal(goBody, &goLog); err != nil {
					t.Fatalf("parse Go log envelope: %v", err)
				}
				assertLogPaginationFields(t, tsLog)
				assertLogPaginationFields(t, goLog)
			}

			tsCanon := canonicalize(t, tsBody)
			goCanon := canonicalize(t, goBody)
			if tsCanon != goCanon {
				t.Fatalf("PARITY MISMATCH on %s\n%s\n--- TS (canonical) ---\n%s\n--- Go (canonical) ---\n%s",
					route, prettyDiff(tsCanon, goCanon), tsCanon, goCanon)
			}
		})
	}

	// The two newest index families expose `ingestedAt` — a relay-local receipt
	// stamp that can never byte-match across two processes — so they compare
	// under canonicalizeNormalized with that one field neutralized. Everything
	// else (row sets, ordering, cursors, every other field) still byte-compares.
	// Ordering uses the author clock (createdAt), which the fixture pins.
	volatileRoutes := []string{
		"/index/v0/artifacts?limit=1000",
		"/index/v0/artifacts?order=createdAt.desc&limit=1000",
		"/index/v0/operations?order=createdAt.desc&limit=1000",
		"/index/v0/operations?kind=artifact&order=createdAt.desc&limit=1000",
	}
	for _, route := range volatileRoutes {
		t.Run(route, func(t *testing.T) {
			tsStatus, tsBody := getBody(t, tsURL+route)
			goStatus, goBody := getBody(t, goURL+route)
			if tsStatus != goStatus {
				t.Fatalf("status mismatch on %s: TS=%d Go=%d", route, tsStatus, goStatus)
			}
			if tsStatus != 200 {
				t.Fatalf("expected 200 on %s, got %d (TS body: %s)", route, tsStatus, tsBody)
			}
			tsCanon := canonicalizeNormalized(t, tsBody, "ingestedAt")
			goCanon := canonicalizeNormalized(t, goBody, "ingestedAt")
			if tsCanon != goCanon {
				t.Fatalf("PARITY MISMATCH on %s\n%s\n--- TS (canonical) ---\n%s\n--- Go (canonical) ---\n%s",
					route, prettyDiff(tsCanon, goCanon), tsCanon, goCanon)
			}
		})
	}

	// ---------------------------------------------------------------------
	// KEY-ADDRESSED FILTER PARITY — `signerKey=` (/index/v0/operations) and
	// `key=` (/index/v0/identities).
	//
	// These two filters are one class: both match a multibase public key
	// BYTE-FOR-BYTE against strings the chains DECLARED, both are opaque (no
	// format validation, no 400), and both must therefore answer identically on
	// the two reference relays or a client cannot paste a key from one into the
	// other. Every route here compares under ingestedAt normalization for
	// operations (a relay-local receipt stamp can never byte-match) and strictly
	// for identities.
	// ---------------------------------------------------------------------
	t.Run("key-addressed filters", func(t *testing.T) {
		authKey := fix.QueryAuthKeyMultibase
		witnessKey := fix.QueryWitnessKeyMultibase
		rotatedOutKey := fix.QueryRotatedOutKeyMultibase
		rotationKey := fix.QueryRotationKeyMultibase
		if authKey == "" || witnessKey == "" || rotatedOutKey == "" || rotationKey == "" {
			t.Fatal("fixture is missing the multibase key fields — regenerate it with parity/genfixture")
		}

		signerKeyRoute := func(key string, extra ...string) string {
			route := "/index/v0/operations?signerKey=" + url.QueryEscape(key) + "&order=createdAt.desc&limit=1000"
			for _, e := range extra {
				route += "&" + e
			}
			return route
		}

		// PER-ROW-KIND. A's key signs its own GENESIS — the shape whose kid is a
		// BARE key ID rather than a DID URL, which a resolver that only splits on
		// "#" silently drops (the Go twin's builder caught exactly that in its own
		// resolver). Asserting the genesis CID by name is what makes a twin that
		// drops it fail here rather than diverge quietly.
		t.Run("author key returns its genesis (bare-kid) row", func(t *testing.T) {
			rows := compareOperationsRoute(t, tsURL, goURL, signerKeyRoute(authKey))
			if !containsCID(rows, fix.QueryAuthGenesisCID) {
				t.Fatalf("signerKey=<author> did not return the genesis row %s (rows: %v)", fix.QueryAuthGenesisCID, operationCIDs(rows))
			}
			if containsCID(rows, fix.QueryWitnessCountersignCID) {
				t.Fatalf("signerKey=<author> leaked the witness's countersign row %s", fix.QueryWitnessCountersignCID)
			}
			genesisOnly := compareOperationsRoute(t, tsURL, goURL, signerKeyRoute(authKey, "kind=identity-op"))
			if got := operationCIDs(genesisOnly); len(got) != 1 || got[0] != fix.QueryAuthGenesisCID {
				t.Fatalf("signerKey=<author>&kind=identity-op = %v, want exactly [%s]", got, fix.QueryAuthGenesisCID)
			}
		})

		// COUNTERSIGN indexes the WITNESS's key, never the countersigned op's
		// author. B witnessed A's content-create; the row must answer to B.
		t.Run("countersign row indexes the witness key", func(t *testing.T) {
			rows := compareOperationsRoute(t, tsURL, goURL, signerKeyRoute(witnessKey))
			if !containsCID(rows, fix.QueryWitnessCountersignCID) {
				t.Fatalf("signerKey=<witness> did not return the countersign row %s (rows: %v)", fix.QueryWitnessCountersignCID, operationCIDs(rows))
			}
			only := compareOperationsRoute(t, tsURL, goURL, signerKeyRoute(witnessKey, "kind=countersign"))
			if got := operationCIDs(only); len(got) != 1 || got[0] != fix.QueryWitnessCountersignCID {
				t.Fatalf("signerKey=<witness>&kind=countersign = %v, want exactly [%s]", got, fix.QueryWitnessCountersignCID)
			}
		})

		// ROTATION SURVIVAL + the key-addressed partition. One identity, two keys:
		// rows signed by the key a later update rotated OUT still match it (the
		// value is frozen at ingest, never re-resolved against head state), and the
		// replacement key matches only what it actually signed. A DID-addressed
		// signer filter could not separate these two sets at all.
		t.Run("rotated-out key keeps its rows; the replacement key gets its own", func(t *testing.T) {
			before := compareOperationsRoute(t, tsURL, goURL, signerKeyRoute(rotatedOutKey))
			after := compareOperationsRoute(t, tsURL, goURL, signerKeyRoute(rotationKey))
			if len(before) != 2 {
				t.Fatalf("signerKey=<rotated-out> returned %d rows, want 2 (genesis + the update that rotated it out): %v", len(before), operationCIDs(before))
			}
			for _, row := range before {
				if row.Kind != "identity-op" || row.ChainID != fix.QueryRotationDID {
					t.Fatalf("signerKey=<rotated-out> row off-chain or wrong kind: %+v", row)
				}
			}
			if len(after) != 1 || after[0].Kind != "artifact" || after[0].ChainID != fix.QueryRotationDID {
				t.Fatalf("signerKey=<replacement> = %+v, want exactly the one artifact on %s", after, fix.QueryRotationDID)
			}
			for _, row := range before {
				if row.CID == after[0].CID {
					t.Fatalf("the two keys of one identity returned overlapping rows (%s)", row.CID)
				}
			}
		})

		// AND-COMPOSITION with the route's other filters, including an honestly
		// empty contradiction (A's key never signed anything on B's chain).
		t.Run("ANDs with kind= and chainId=", func(t *testing.T) {
			onChain := compareOperationsRoute(t, tsURL, goURL,
				signerKeyRoute(authKey, "chainId="+url.QueryEscape(fix.QueryContentID)))
			if len(onChain) == 0 {
				t.Fatalf("signerKey=<author>&chainId=<A's content> returned nothing")
			}
			for _, row := range onChain {
				if row.ChainID != fix.QueryContentID || row.Kind != "content-op" {
					t.Fatalf("composed filter leaked a row: %+v", row)
				}
			}
			contradiction := compareOperationsRoute(t, tsURL, goURL,
				signerKeyRoute(authKey, "chainId="+url.QueryEscape(fix.QueryRotationDID)))
			if len(contradiction) != 0 {
				t.Fatalf("signerKey=<author>&chainId=<E> returned %v, want an empty page", operationCIDs(contradiction))
			}
		})

		// OPAQUE: no format validation, so no 400 — including for the two values a
		// caller is most likely to paste by mistake, a valid kid and a valid DID.
		// Both are well-formed protocol strings and neither is a public key.
		t.Run("opaque garbage is an empty 200, never a 400", func(t *testing.T) {
			for _, garbage := range []string{
				"not-a-multibase-key !",
				fix.QueryDID + "#" + fix.QueryAuthKeyID, // a valid kid
				fix.QueryDID,                            // a valid DID
				"z" + strings.Repeat("0", 40),
			} {
				route := signerKeyRoute(garbage)
				rows := compareOperationsRoute(t, tsURL, goURL, route)
				if len(rows) != 0 {
					t.Fatalf("signerKey=%q returned %v, want an empty page", garbage, operationCIDs(rows))
				}
			}
		})

		// PRESENT-BUT-EMPTY IS NO FILTER, on BOTH key-addressed filters. Go reads
		// these params with `query.Get`, which cannot distinguish `?signerKey=`
		// from an absent param at all — so "unfiltered" is the only posture the
		// two twins can both hold, and it is the one they now both ship. (`key=`
		// on identities used to diverge here: the TS twin presence-detected and
		// answered an empty page. These two cases are what pin the class.)
		t.Run("an empty value is no filter at all", func(t *testing.T) {
			for _, pair := range [][2]string{
				{"/index/v0/operations?signerKey=&order=createdAt.desc&limit=1000",
					"/index/v0/operations?order=createdAt.desc&limit=1000"},
				{"/index/v0/identities?key=&limit=1000", "/index/v0/identities?limit=1000"},
			} {
				empty, unfiltered := pair[0], pair[1]
				for name, base := range map[string]string{"ts": tsURL, "go": goURL} {
					_, emptyBody := getBody(t, base+empty)
					_, unfilteredBody := getBody(t, base+unfiltered)
					if canonicalizeNormalized(t, emptyBody, "ingestedAt") != canonicalizeNormalized(t, unfilteredBody, "ingestedAt") {
						t.Fatalf("%s: %s did not answer as the unfiltered page %s\n--- empty ---\n%s\n--- unfiltered ---\n%s",
							name, empty, unfiltered, emptyBody, unfilteredBody)
					}
					if bytes.Contains(emptyBody, []byte(`"next"`)) && len(emptyBody) < 40 {
						t.Fatalf("%s: %s returned a suspiciously empty page: %s", name, empty, emptyBody)
					}
				}
				tsCanon := canonicalizeNormalized(t, mustBody(t, tsURL+empty), "ingestedAt")
				goCanon := canonicalizeNormalized(t, mustBody(t, goURL+empty), "ingestedAt")
				if tsCanon != goCanon {
					t.Fatalf("PARITY MISMATCH on %s\n%s\n--- TS ---\n%s\n--- Go ---\n%s", empty, prettyDiff(tsCanon, goCanon), tsCanon, goCanon)
				}
			}
		})

		// PAGINATION under BOTH orderings. createdAt.desc is the author clock the
		// fixture pins, so every page byte-compares across twins. ingestedAt.desc
		// is each relay's OWN receipt clock — the page BOUNDARIES are legitimately
		// relay-local there, so that ordering is walked per twin and compared as a
		// row SET against the unpaged answer: it still proves the cursor drains the
		// filtered feed exactly once, without asserting a cross-relay clock.
		t.Run("pages a filtered feed under both orderings", func(t *testing.T) {
			compareOperationsCursorWalk(t, tsURL, goURL,
				"/index/v0/operations?signerKey="+url.QueryEscape(authKey)+"&order=createdAt.desc&limit=1")
			want := operationCIDs(compareOperationsRoute(t, tsURL, goURL, signerKeyRoute(authKey)))
			for name, base := range map[string]string{"ts": tsURL, "go": goURL} {
				walked := walkOperationCIDs(t, base,
					"/index/v0/operations?signerKey="+url.QueryEscape(authKey)+"&order=ingestedAt.desc&limit=1")
				if strings.Join(walked, ",") != strings.Join(want, ",") {
					t.Fatalf("%s: ingestedAt.desc walk of signerKey=<author> visited %v, want the unpaged set %v", name, walked, want)
				}
			}
		})
	})

	// Cursor canonicality parity: non-canonical base64 variants of a
	// well-formed cursor MUST be rejected identically by both twins. This exact
	// divergence shipped (TS accepted padded/whitespace ordered cursors that Go
	// rejected; Go accepted a newline credits cursor that TS rejected), and the
	// emitted-cursor walks above can never catch it — they only replay cursors
	// the relays themselves produced.
	orderedCanonical := base64.RawURLEncoding.EncodeToString([]byte("2026-01-01T00:00:00Z~did:dfos:parity"))
	creditCanonical := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", 31) + "~0"))
	for _, suffix := range []string{"=", "==", "\n", " "} {
		malformedRoutes := []string{
			"/index/v0/content?order=genesisAt.desc&after=" + url.QueryEscape(orderedCanonical+suffix),
			"/index/v0/identities?order=genesisAt.desc&after=" + url.QueryEscape(orderedCanonical+suffix),
			"/index/v0/artifacts?order=createdAt.desc&after=" + url.QueryEscape(orderedCanonical+suffix),
			"/index/v0/countersignatures?witness=" + url.QueryEscape(fix.QueryRevocationIssuerDID) + "&order=createdAt.desc&after=" + url.QueryEscape(orderedCanonical+suffix),
			"/index/v0/operations?after=" + url.QueryEscape(orderedCanonical+suffix),
			"/index/v0/credits?after=" + url.QueryEscape(creditCanonical+suffix),
		}
		for _, route := range malformedRoutes {
			t.Run("malformed cursor "+route, func(t *testing.T) {
				tsStatus, tsBody := getBody(t, tsURL+route)
				goStatus, goBody := getBody(t, goURL+route)
				if tsStatus != goStatus {
					t.Fatalf("status mismatch on %s: TS=%d Go=%d (TS body: %s; Go body: %s)", route, tsStatus, goStatus, tsBody, goBody)
				}
				if tsStatus != http.StatusBadRequest {
					t.Fatalf("expected 400 on %s, got %d (TS body: %s)", route, tsStatus, tsBody)
				}
				tsCanon := canonicalize(t, tsBody)
				goCanon := canonicalize(t, goBody)
				if tsCanon != goCanon {
					t.Fatalf("PARITY MISMATCH on %s\n--- TS ---\n%s\n--- Go ---\n%s", route, tsCanon, goCanon)
				}
			})
		}
	}

	// REGRESSION GUARD (index fan-out): the walk requires >= 2 non-empty pages, so
	// it also failed under the defect described above — the missing content rows
	// made every page empty. Same root cause, same fix (215fa14).
	compareIndexCursorWalk(
		t,
		tsURL,
		goURL,
		"/index/v0/content?order=genesisAt.desc&signer="+url.QueryEscape(fix.QueryDID)+"&limit=1",
	)

	for name, base := range map[string]string{"ts": tsURL, "go": goURL} {
		t.Run(name+" global log unknown cursor", func(t *testing.T) {
			status, _ := getBody(t, base+"/proof/v1/log?after=bafyunknown")
			if status != http.StatusBadRequest {
				t.Fatalf("unknown global-log cursor: status %d, want 400", status)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// operations-index parity helpers
//
// /index/v0/operations rows carry `ingestedAt`, a relay-local receipt stamp that
// can never byte-match across two processes, so every comparison here runs under
// canonicalizeNormalized with that one field neutralized. Row sets, ordering,
// cursors, and every other field still byte-compare.
// ---------------------------------------------------------------------------

type parityOperationRow struct {
	CID     string `json:"cid"`
	Kind    string `json:"kind"`
	ChainID string `json:"chainId"`
}

func mustBody(t *testing.T, url string) []byte {
	t.Helper()
	status, body := getBody(t, url)
	if status != http.StatusOK {
		t.Fatalf("GET %s: status %d, body %s", url, status, body)
	}
	return body
}

func operationCIDs(rows []parityOperationRow) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.CID)
	}
	sort.Strings(out)
	return out
}

func containsCID(rows []parityOperationRow, cid string) bool {
	for _, row := range rows {
		if row.CID == cid {
			return true
		}
	}
	return false
}

// compareOperationsRoute asserts both twins answer route with the same body and
// returns the decoded rows, so a caller can additionally assert WHICH rows came
// back — two twins that agree on an empty page agree about nothing.
func compareOperationsRoute(t *testing.T, tsURL, goURL, route string) []parityOperationRow {
	t.Helper()
	tsBody := mustBody(t, tsURL+route)
	goBody := mustBody(t, goURL+route)
	tsCanon := canonicalizeNormalized(t, tsBody, "ingestedAt")
	goCanon := canonicalizeNormalized(t, goBody, "ingestedAt")
	if tsCanon != goCanon {
		t.Fatalf("PARITY MISMATCH on %s\n%s\n--- TS (canonical) ---\n%s\n--- Go (canonical) ---\n%s",
			route, prettyDiff(tsCanon, goCanon), tsCanon, goCanon)
	}
	var page struct {
		Operations []parityOperationRow `json:"operations"`
	}
	if err := json.Unmarshal(tsBody, &page); err != nil {
		t.Fatalf("parse %s: %v (body %s)", route, err, tsBody)
	}
	return page.Operations
}

// compareOperationsCursorWalk follows an operations cursor to exhaustion on both
// relays and compares every page. Requiring two non-empty pages proves parity of
// cursor generation AND resumption, not merely parity of the first page.
func compareOperationsCursorWalk(t *testing.T, tsURL, goURL, routeBase string) {
	t.Helper()
	after := ""
	nonEmptyPages := 0
	for pageNumber := 1; ; pageNumber++ {
		if pageNumber > 50 {
			t.Fatal("operations cursor parity walk exceeded 50 pages")
		}
		route := routeBase
		if after != "" {
			route += "&after=" + url.QueryEscape(after)
		}
		tsBody := mustBody(t, tsURL+route)
		goBody := mustBody(t, goURL+route)
		tsCanon := canonicalizeNormalized(t, tsBody, "ingestedAt")
		goCanon := canonicalizeNormalized(t, goBody, "ingestedAt")
		if tsCanon != goCanon {
			t.Fatalf("PARITY MISMATCH on operations cursor page %d (%s)\n%s\n--- TS ---\n%s\n--- Go ---\n%s",
				pageNumber, route, prettyDiff(tsCanon, goCanon), tsCanon, goCanon)
		}
		var page struct {
			Operations []json.RawMessage `json:"operations"`
			Next       *string           `json:"next"`
		}
		if err := json.Unmarshal(tsBody, &page); err != nil {
			t.Fatalf("parse operations cursor page %d: %v", pageNumber, err)
		}
		if len(page.Operations) > 0 {
			nonEmptyPages++
		}
		if page.Next == nil {
			break
		}
		if *page.Next == "" {
			t.Fatalf("operations cursor page %d returned an empty next token", pageNumber)
		}
		after = *page.Next
	}
	if nonEmptyPages < 2 {
		t.Fatalf("operations cursor parity walk had %d non-empty pages, want at least 2", nonEmptyPages)
	}
}

// walkOperationCIDs drains a paginated operations feed on ONE relay and returns
// the CIDs it visited, sorted. Used where the ordering key is a relay-local
// clock, so the page boundaries are legitimately not comparable across twins but
// the drained SET still must be.
func walkOperationCIDs(t *testing.T, base, routeBase string) []string {
	t.Helper()
	after := ""
	seen := map[string]bool{}
	out := []string{}
	for pageNumber := 1; ; pageNumber++ {
		if pageNumber > 50 {
			t.Fatalf("operations walk on %s exceeded 50 pages", base)
		}
		route := routeBase
		if after != "" {
			route += "&after=" + url.QueryEscape(after)
		}
		var page struct {
			Operations []parityOperationRow `json:"operations"`
			Next       *string              `json:"next"`
		}
		body := mustBody(t, base+route)
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatalf("parse %s: %v (body %s)", route, err, body)
		}
		for _, row := range page.Operations {
			if seen[row.CID] {
				t.Fatalf("operations walk on %s revisited %s", base, row.CID)
			}
			seen[row.CID] = true
			out = append(out, row.CID)
		}
		if page.Next == nil {
			break
		}
		after = *page.Next
	}
	sort.Strings(out)
	return out
}

// prettyDiff returns the two canonical bodies for the failure message, trimmed
// to the first divergence for readability.
func prettyDiff(a, b string) string {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	start := i - 40
	if start < 0 {
		start = 0
	}
	return fmt.Sprintf("first diff at offset %d:\nTS: ...%s\nGo: ...%s", i, snippet(a, start), snippet(b, start))
}

func snippet(s string, start int) string {
	end := start + 120
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}
