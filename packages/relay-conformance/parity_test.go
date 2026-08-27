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
