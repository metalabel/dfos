package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
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
// insertion order, so even {entries, cursor} differs at the raw-byte level while
// being semantically identical. Canonicalization is the correct equality.
//
// Run via packages/relay-conformance/scripts/run-parity.sh, which sets
// TS_RELAY_URL, GO_RELAY_URL, and PARITY_FIXTURE.
// ===========================================================================

type parityFixture struct {
	RelayDID                  string   `json:"relayDid"`
	RelayProfileJWS           string   `json:"relayProfileJws"`
	BootstrapOps              []string `json:"bootstrapOps"`
	Ops                       []string `json:"ops"`
	QueryDID                  string   `json:"queryDid"`
	QueryContentID            string   `json:"queryContentId"`
	QueryServiceDID           string   `json:"queryServiceDid"`
	QueryDeletedDID           string   `json:"queryDeletedDid"`
	QueryRevokedCredentialCID string   `json:"queryRevokedCredentialCid"`
	QueryRevocationIssuerDID  string   `json:"queryRevocationIssuerDid"`
	QueryCountersignedCID     string   `json:"queryCountersignedCid"`
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

func postOps(t *testing.T, base string, ops []string) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"operations": ops})
	resp, err := http.Post(base+"/proof/v1/operations", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST %s/proof/v1/operations: %v", base, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST %s/proof/v1/operations: status %d, body %s", base, resp.StatusCode, b)
	}
}

// logEntryCount polls GET /log and returns the number of entries. Used to wait
// for the Go relay's ticker-driven sequencer to drain before comparing.
func logEntryCount(t *testing.T, base string) int {
	t.Helper()
	_, body := getBody(t, base+"/proof/v1/log?limit=1000")
	var parsed struct {
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return -1
	}
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
	postOps(t, tsURL, allOps)
	postOps(t, goURL, allOps)

	// Expected accepted entries = every op in the fixture: bootstrap (relay
	// genesis + profile) + the user op set (identities A/B/C/D, A's content
	// create+update, artifact, credential, D's delete). All sequence cleanly in
	// dependency order, so the drained log count equals len(allOps).
	wantEntries := len(allOps)

	// Drain both: TS sequences inline, Go runs on a ticker. Wait for both to
	// reach a stable entry count before reading — never read mid-drain.
	drainUntilStable(t, tsURL, wantEntries)
	drainUntilStable(t, goURL, wantEntries)

	routes := []string{
		"/proof/v1/log?limit=1000",
		"/proof/v1/identities/" + fix.QueryDID + "/log?limit=1000",
		"/proof/v1/content/" + fix.QueryContentID + "/log?limit=1000",
		"/.well-known/dfos-relay",
	}

	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			tsStatus, tsBody := getBody(t, tsURL+route)
			goStatus, goBody := getBody(t, goURL+route)

			if tsStatus != goStatus {
				t.Fatalf("status mismatch on %s: TS=%d Go=%d", route, tsStatus, goStatus)
			}
			if tsStatus != 200 {
				t.Fatalf("expected 200 on %s, got %d (TS body: %s)", route, tsStatus, tsBody)
			}

			tsCanon := canonicalize(t, tsBody)
			goCanon := canonicalize(t, goBody)
			if tsCanon != goCanon {
				t.Fatalf("PARITY MISMATCH on %s\n%s\n--- TS (canonical) ---\n%s\n--- Go (canonical) ---\n%s",
					route, prettyDiff(tsCanon, goCanon), tsCanon, goCanon)
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
