package conformance

import (
	"os"
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// DID resolution conformance.
//
// A relay resolves an identity chain into a materialized state served at
// GET /proof/v1/identities/{did}. That resolution MUST be an honest, reproducible
// projection of the chain's operations — in particular the resolved state.did MUST
// equal the DID self-derived from the genesis operation, at the canonical width.
//
// These tests exist because a relay can pass the rest of the suite while running a
// stale derivation in its resolver: it serves correct 31-char chainIds in /log but
// truncates the resolved state.did to a pre-v1 width. The recompute-from-log check
// (verifyServedIdentity) catches that; here we run it on the WRITE-ENABLED path
// (the common deployment) rather than only on write-disabled lite nodes, and also
// against a relay's own pre-existing corpus.

// TestSeededIdentityResolvesCanonically creates an identity and verifies the relay
// resolves it back honestly: recompute-from-log matches the served state, and the
// served DID is a well-formed (canonical-width) did:dfos identifier. This promotes
// the strongest read-plane invariant out of the write-disabled-only path so every
// write-enabled relay is held to it.
func TestSeededIdentityResolvesCanonically(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	verifyServedIdentity(t, base, id.did)
}

// TestServedCorpusIdentityResolvesCanonically verifies an identity the relay
// ALREADY serves, discovered from its global operation log (or pinned via
// CONFORMANCE_VERIFY_DID). This is what catches a relay that resolves freshly
// created identities correctly but truncates its older corpus: pointing the suite
// at such a relay surfaces the non-conformance on real served data. Self-skips when
// the relay exposes no identity in its log, so the default reference run stays green.
func TestServedCorpusIdentityResolvesCanonically(t *testing.T) {
	base := relayURL(t)

	did := os.Getenv("CONFORMANCE_VERIFY_DID")
	if did == "" {
		did = firstServedIdentityDID(t, base)
	}
	if did == "" {
		t.Skip("no served identity found in the relay log — nothing to verify")
	}
	verifyServedIdentity(t, base, did)
}

// firstServedIdentityDID returns the chainId of the first identity-op in the
// relay's global proof-plane log, or "" if none is present.
func firstServedIdentityDID(t *testing.T, base string) string {
	t.Helper()
	var body struct {
		Entries []struct {
			Kind    string `json:"kind"`
			ChainID string `json:"chainId"`
		} `json:"entries"`
	}
	resp := getJSON(t, base+"/proof/v1/log", &body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /proof/v1/log: status %d", resp.StatusCode)
	}
	for _, e := range body.Entries {
		if e.Kind == "identity-op" && e.ChainID != "" {
			return e.ChainID
		}
	}
	return ""
}

// TestDeriveDIDIsCanonicalWidth is a pure-library guard: the DID derivation this
// suite relies on must itself produce canonical, well-formed DIDs. If this ever
// fails, every served-DID assertion above is comparing against a broken baseline.
func TestDeriveDIDIsCanonicalWidth(t *testing.T) {
	did := dfos.DeriveDID([]byte("conformance-probe"))
	if !dfos.IsValidDID(did) {
		t.Fatalf("DeriveDID produced a non-well-formed DID: %q", did)
	}
}
