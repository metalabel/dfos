// Well-known enrichment conformance (peers[] + stats block).
//
// The amendment enriches GET /.well-known/dfos-relay beyond the protocol
// contract (did/capabilities/profile) with two operational blocks:
//
//	peers: [{ endpoint }]   — MAY be empty [] but MUST NOT be JSON null.
//	stats: { pendingOps, …} — pendingOps ALWAYS present (raw_ops backlog).
//	                          When the store implements the OPTIONAL getStats
//	                          surface, stats also carries opCount, countsByKind
//	                          (exactly six kind buckets), oldestOpAt, and headCid.
//
// The reference relays (memory + sqlite) both implement getStats, so the
// enriched fields run in CI; against a relay that omits them the enriched
// assertions self-gate on presence (consistent with the suite's optional-
// capability handling) while peers[] and pendingOps are asserted unconditionally.
//
// Bodies are decoded through json.RawMessage / map[string]json.RawMessage so the
// two JSON-parity gotchas the amendment calls out are observable: empty peers
// serializing as [] (never null), and nullable oldestOpAt/headCid serializing as
// JSON null (never omitted).
package conformance

import (
	"encoding/json"
	"strings"
	"testing"
)

// kindBuckets is the exact, closed set of countsByKind keys the enriched stats
// block MUST carry — one per operation kind, no more, no fewer.
var kindBuckets = []string{"identity", "content", "artifact", "credential", "countersign", "revocation"}

func TestWellKnownEnrichment(t *testing.T) {
	base := relayURL(t)

	// Ingest a known identity + content so the relay's log is non-empty and the
	// enriched stats (opCount, kind buckets) have real ops to reflect. The relay
	// always carries at least its own genesis, but seeding concrete ops makes the
	// opCount == sum(countsByKind) invariant a live check rather than a bootstrap
	// tautology.
	id := createIdentity(t, base)
	createContent(t, base, id)

	var top map[string]json.RawMessage
	resp := getJSON(t, base+"/.well-known/dfos-relay", &top)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /.well-known/dfos-relay: status %d", resp.StatusCode)
	}

	// -----------------------------------------------------------------------
	// peers: a JSON array (never null); each element carries a non-empty endpoint
	// -----------------------------------------------------------------------
	peersRaw, ok := top["peers"]
	if !ok {
		t.Fatal("well-known missing peers field")
	}
	if strings.TrimSpace(string(peersRaw)) == "null" {
		t.Fatal("peers serialized as JSON null — an empty peer set MUST be [] not null")
	}
	var peers []struct {
		Endpoint string `json:"endpoint"`
	}
	if err := json.Unmarshal(peersRaw, &peers); err != nil {
		t.Fatalf("peers is not a JSON array of {endpoint} objects: %v (raw: %s)", err, peersRaw)
	}
	for i, p := range peers {
		if p.Endpoint == "" {
			t.Fatalf("peers[%d] has an empty endpoint", i)
		}
	}

	// -----------------------------------------------------------------------
	// stats: pendingOps ALWAYS present as an integer
	// -----------------------------------------------------------------------
	statsRaw, ok := top["stats"]
	if !ok {
		t.Fatal("well-known missing stats field")
	}
	var stats map[string]json.RawMessage
	if err := json.Unmarshal(statsRaw, &stats); err != nil {
		t.Fatalf("stats is not a JSON object: %v (raw: %s)", err, statsRaw)
	}
	pendingRaw, ok := stats["pendingOps"]
	if !ok {
		t.Fatal("stats.pendingOps is absent — it MUST be present even when zero")
	}
	var pendingOps int
	if err := json.Unmarshal(pendingRaw, &pendingOps); err != nil {
		t.Fatalf("stats.pendingOps is not an integer: %v (raw: %s)", err, pendingRaw)
	}

	// -----------------------------------------------------------------------
	// Enriched stats (optional getStats surface): gate on opCount presence.
	// Both reference relays populate these, so the block runs in CI.
	// -----------------------------------------------------------------------
	opCountRaw, enriched := stats["opCount"]
	if !enriched {
		t.Log("stats.opCount absent — relay does not implement the optional getStats surface; skipping enriched assertions")
		return
	}

	var opCount int
	if err := json.Unmarshal(opCountRaw, &opCount); err != nil {
		t.Fatalf("stats.opCount is not an integer: %v (raw: %s)", err, opCountRaw)
	}
	if opCount < 1 {
		t.Fatalf("stats.opCount = %d — a relay carrying its own genesis plus ingested ops MUST report >= 1", opCount)
	}

	// countsByKind: EXACTLY the six kind buckets, no more, no fewer.
	countsRaw, ok := stats["countsByKind"]
	if !ok {
		t.Fatal("enriched stats missing countsByKind")
	}
	var counts map[string]int
	if err := json.Unmarshal(countsRaw, &counts); err != nil {
		t.Fatalf("stats.countsByKind is not an object of integers: %v (raw: %s)", err, countsRaw)
	}
	if len(counts) != len(kindBuckets) {
		t.Fatalf("stats.countsByKind has %d keys, want exactly %d (%v); got %v", len(counts), len(kindBuckets), kindBuckets, counts)
	}
	sum := 0
	for _, kind := range kindBuckets {
		v, ok := counts[kind]
		if !ok {
			t.Fatalf("stats.countsByKind missing required key %q; got %v", kind, counts)
		}
		if v < 0 {
			t.Fatalf("stats.countsByKind[%q] = %d, must be non-negative", kind, v)
		}
		sum += v
	}
	// Every logged op falls into exactly one of the six buckets, so the buckets
	// partition the log: their sum MUST equal opCount. This is deployment- and
	// test-order-independent, so it holds against a shared store.
	if sum != opCount {
		t.Fatalf("sum(countsByKind) = %d != opCount = %d — every logged op must map to exactly one kind bucket", sum, opCount)
	}

	// oldestOpAt and headCid: keys MUST be present and each MUST be a JSON string
	// or JSON null (never absent) — the amendment's nullable-not-omitted contract.
	for _, key := range []string{"oldestOpAt", "headCid"} {
		raw, ok := stats[key]
		if !ok {
			t.Fatalf("enriched stats missing %q — nullable fields MUST be present as JSON null, not omitted", key)
		}
		trimmed := strings.TrimSpace(string(raw))
		if trimmed == "null" {
			continue // explicit null is valid
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatalf("stats.%s is neither a JSON string nor null: %v (raw: %s)", key, err, raw)
		}
		if s == "" {
			t.Fatalf("stats.%s is an empty string — expected a non-empty value or JSON null", key)
		}
	}
}
