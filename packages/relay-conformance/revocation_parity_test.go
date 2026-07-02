package conformance

import (
	"strings"
	"testing"
)

// ===========================================================================
// WP-7 — REVOCATION-STATUS PARITY
//
// Proves the Go revocation-status routes (/revocations/v1) are byte/semantic
// twins of the TS routes (relay.ts / revocations.ts). Boots the SAME two relays
// as TestDualRelayParity (started by run-parity.sh from the pinned fixture) and
// compares canonicalized bodies across the six cases the projection cares about:
//
//   1. revoked        — 200 { credentialCID, revoked:true, revocation:<JWS> }
//                        for the fixture's B-issued, B-revoked credential.
//   2. unknownCID     — 200 revoked:false for a well-formed but never-seen CID:
//                        pins the `revocation` key OMISSION (omitempty) parity.
//   3. malformedCID   — 400 invalid-credential-CID envelope.
//   4. issuerListing  — 200 { did, revocations:[...] } for issuer B.
//   5. issuerEmpty    — 200 empty `[]` (never null) for issuer A (revoked nothing).
//   6. malformedDID   — 400 invalid-DID envelope.
//
// compareResolver (resolver_parity_test.go) already handles ANY status, so it
// catches divergence in the 400 envelopes too. The test name contains the
// "TestDualRelayParity" substring so run-parity.sh's `-run 'TestDualRelayParity'`
// selects it with no script edit.
// ===========================================================================

func TestDualRelayParity_RevocationStatus(t *testing.T) {
	tsURL, goURL, fix := loadParityEnv(t)

	// Re-post the full op set to both (idempotent — dups return "duplicate"), then
	// wait for both to drain so the status routes read terminal state. Self-
	// sufficient regardless of whether TestDualRelayParity ran first.
	allOps := append(append([]string{}, fix.BootstrapOps...), fix.Ops...)
	postOps(t, tsURL, allOps)
	postOps(t, goURL, allOps)
	drainUntilStable(t, tsURL, len(allOps))
	drainUntilStable(t, goURL, len(allOps))

	t.Run("revoked", func(t *testing.T) {
		compareResolver(t, tsURL, goURL, "/revocations/v1/credential/"+fix.QueryRevokedCredentialCID, 200)
	})
	t.Run("unknownCID", func(t *testing.T) {
		// well-formed dag-cbor CID never seeded — both twins answer revoked:false
		// with the revocation key OMITTED
		compareResolver(t, tsURL, goURL, "/revocations/v1/credential/bafyrei"+strings.Repeat("a", 52), 200)
	})
	t.Run("malformedCID", func(t *testing.T) {
		compareResolver(t, tsURL, goURL, "/revocations/v1/credential/not-a-cid", 400)
	})
	t.Run("issuerListing", func(t *testing.T) {
		compareResolver(t, tsURL, goURL, "/revocations/v1/issuer/"+fix.QueryRevocationIssuerDID, 200)
	})
	t.Run("issuerEmpty", func(t *testing.T) {
		// QueryDID (user A) never revoked anything — empty `[]` on both twins
		compareResolver(t, tsURL, goURL, "/revocations/v1/issuer/"+fix.QueryDID, 200)
	})
	t.Run("malformedDID", func(t *testing.T) {
		compareResolver(t, tsURL, goURL, "/revocations/v1/issuer/did:dfos:short", 400)
	})
}
