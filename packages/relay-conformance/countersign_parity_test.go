package conformance

import (
	"strings"
	"testing"
)

// ===========================================================================
// WP-7 — COUNTERSIGNATURES PARITY
//
// Proves the Go countersignatures route (GET /proof/v1/countersignatures/{cid})
// is a byte/semantic twin of the TS route (relay.ts). Boots the SAME two relays
// as TestDualRelayParity (started by run-parity.sh from the pinned fixture) and
// compares canonicalized bodies across the cases the projection cares about:
//
//   1. present     — 200 { cid, countersignatures:[<JWS>], next } for the
//                     fixture's B-witnessed A-content-create CID. Pins the
//                     { cid, countersignatures, next } shape and the csCid sort.
//   2. paginated   — 200 with ?limit=1 over the same CID: pins the `next`
//                     cursor emission (full page) parity. (One countersig, so
//                     limit=1 is a full page → next present on both twins.)
//   3. notFound    — 404 envelope for a well-formed but never-seen CID: pins the
//                     "not-a-known-op AND no countersigs target it" 404 parity.
//
// compareResolver (resolver_parity_test.go) handles ANY status, so it catches
// divergence in the 404 envelope too. The test name contains the
// "TestDualRelayParity" substring so run-parity.sh's `-run 'TestDualRelayParity'`
// selects it with no script edit.
// ===========================================================================

func TestDualRelayParity_Countersignatures(t *testing.T) {
	tsURL, goURL, fix := loadParityEnv(t)

	// Re-post the full op set to both (idempotent — dups return "duplicate"), then
	// wait for both to drain so the countersignatures route reads terminal state.
	// Self-sufficient regardless of whether TestDualRelayParity ran first.
	allOps := append(append([]string{}, fix.BootstrapOps...), fix.Ops...)
	postOps(t, tsURL, allOps)
	postOps(t, goURL, allOps)
	drainUntilStable(t, tsURL, len(allOps))
	drainUntilStable(t, goURL, len(allOps))

	t.Run("present", func(t *testing.T) {
		compareResolver(t, tsURL, goURL, "/proof/v1/countersignatures/"+fix.QueryCountersignedCID, 200)
	})
	t.Run("paginated", func(t *testing.T) {
		// one countersig, so limit=1 is a FULL page → `next` present on both twins
		compareResolver(t, tsURL, goURL, "/proof/v1/countersignatures/"+fix.QueryCountersignedCID+"?limit=1", 200)
	})
	t.Run("notFound", func(t *testing.T) {
		// well-formed dag-cbor CID that is neither a known op nor a countersig target
		compareResolver(t, tsURL, goURL, "/proof/v1/countersignatures/bafyrei"+strings.Repeat("a", 52), 404)
	})
}
