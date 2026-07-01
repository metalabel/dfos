package conformance

import (
	"testing"
)

// ===========================================================================
// WP-7 — UNIVERSAL DID RESOLVER PARITY
//
// Proves the Go universal-resolver route (GET /1.0/identifiers/{did}) is a
// byte/semantic twin of the TS route (relay.ts). Boots the SAME two relays as
// TestDualRelayParity (started by run-parity.sh from the pinned fixture) and
// compares canonicalized bodies across the five cases the projection cares about:
//
//   1. live+services  — VM dedup, FULL per-role arrays, service[] with DfosRelay
//                        (serviceEndpoint) + ContentAnchor (serviceEndpoint+label)
//                        in state order.
//   2. live+noService — a live identity with NO services: pins the `service` key
//                        OMISSION (omitempty) parity end-to-end on the wire.
//   3. deactivated    — four-key doc, deactivated:true, empty verificationMethod,
//                        NO relationships / service.
//   4. invalidDid     — 400 invalidDid envelope (bad width/charset).
//   5. notFound       — 404 notFound envelope (well-formed but unseeded DID).
//
// Unlike the 200-only loop in TestDualRelayParity, compareResolver handles ANY
// status, so it catches divergence in the error envelopes too. The test name
// contains the "TestDualRelayParity" substring so run-parity.sh's
// `-run 'TestDualRelayParity'` selects it with no script edit.
// ===========================================================================

// compareResolver GETs the same resolver path on both relays, asserts the status
// matches wantStatus on each, and compares canonicalized bodies.
func compareResolver(t *testing.T, tsURL, goURL, path string, wantStatus int) {
	t.Helper()
	tsStatus, tsBody := getBody(t, tsURL+path)
	goStatus, goBody := getBody(t, goURL+path)

	if tsStatus != wantStatus || goStatus != wantStatus {
		t.Fatalf("status mismatch on %s: want %d, TS=%d Go=%d (TS body: %s | Go body: %s)",
			path, wantStatus, tsStatus, goStatus, tsBody, goBody)
	}

	tsCanon := canonicalize(t, tsBody)
	goCanon := canonicalize(t, goBody)
	if tsCanon != goCanon {
		t.Fatalf("RESOLVER PARITY MISMATCH on %s\n%s\n--- TS (canonical) ---\n%s\n--- Go (canonical) ---\n%s",
			path, prettyDiff(tsCanon, goCanon), tsCanon, goCanon)
	}
}

func TestDualRelayParity_Resolver(t *testing.T) {
	tsURL, goURL, fix := loadParityEnv(t)

	// Re-post the full op set to both (idempotent — dups return "duplicate"), then
	// wait for both to drain so the resolver reads terminal state. Self-sufficient
	// regardless of whether TestDualRelayParity ran first.
	allOps := append(append([]string{}, fix.BootstrapOps...), fix.Ops...)
	postOps(t, tsURL, allOps)
	postOps(t, goURL, allOps)
	drainUntilStable(t, tsURL, len(allOps))
	drainUntilStable(t, goURL, len(allOps))

	t.Run("live+services", func(t *testing.T) {
		compareResolver(t, tsURL, goURL, "/1.0/identifiers/"+fix.QueryServiceDID, 200)
	})
	t.Run("live+noService", func(t *testing.T) {
		// QueryDID (user A) is a live identity with no services set — the `service`
		// key MUST be omitted on both twins.
		compareResolver(t, tsURL, goURL, "/1.0/identifiers/"+fix.QueryDID, 200)
	})
	t.Run("deactivated", func(t *testing.T) {
		compareResolver(t, tsURL, goURL, "/1.0/identifiers/"+fix.QueryDeletedDID, 200)
	})
	t.Run("invalidDid", func(t *testing.T) {
		compareResolver(t, tsURL, goURL, "/1.0/identifiers/did:dfos:short", 400)
	})
	t.Run("notFound", func(t *testing.T) {
		// well-formed 31-char did:dfos over the protocol alphabet, never seeded
		compareResolver(t, tsURL, goURL, "/1.0/identifiers/did:dfos:2222222222222222222222222222222", 404)
	})
}
