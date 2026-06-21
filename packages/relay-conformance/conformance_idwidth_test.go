package conformance

import (
	"strings"
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// TestIdentifierWidthConformance asserts that every derived identifier the relay
// has persisted uses the canonical v1 width.
//
// A did:dfos identity DID and a bare content ID are both self-certifying
// identifiers derived from a genesis operation's CID (sha256 → modular encoding
// over a fixed alphabet) to a FIXED character width — see
// dfos-protocol-go/derivation.go. v1 uses 31 chars; the pre-v1 (0.9.x) width was
// 22. Because the encoding consumes a prefix of the same hash, a 22-char id is a
// strict prefix of the 31-char id for the same op: they are NOT the same
// identifier, and they do not interoperate.
//
// A relay can pass every behavioral test while still serving a pre-v1 corpus:
// its binary derives 31-char identifiers for freshly minted ops (so create /
// resolve / verify all succeed), yet its persisted /log still carries 22-char
// chainIds from a corpus that was ingested under the old width and never
// re-minted. Such a relay advertises a v1 version but will not resolve its own
// identities on a peering v1 relay (which re-derives them to 31 chars). This
// test closes that gap by auditing the width the relay actually persisted.
//
// The relay reports, per log entry, the identifier it indexed the op under
// (chainId): a DID for identity-ops, a bare content ID for content-ops. Other
// kinds key off those, so checking the two covers the corpus.
func TestIdentifierWidthConformance(t *testing.T) {
	base := relayURL(t)

	// Canonical id width, taken from the protocol package rather than hardcoded
	// so the test tracks the spec if the width ever changes. DeriveID always
	// returns exactly idLength characters regardless of input.
	canonical := len(dfos.DeriveID([]byte("conformance-id-width-probe")))

	// Seed one v1 identity-op and content-op so the audit is never vacuous on a
	// fresh relay and the positive (31-char) path is exercised.
	seed := createIdentity(t, base)
	createContent(t, base, seed)

	// Walk the global operation log. Mirrors the convergence-guarded pagination
	// used in the global-log test: advance by last CID, stop on the first short
	// page, and fail fast if a page-boundary cursor repeats (non-convergent
	// /log) rather than hang until the test timeout.
	checked := 0
	cursor := ""
	seen := map[string]bool{}
	const maxLogPages = 10000 // backstop: 1M entries at limit=100
	for pages := 0; ; pages++ {
		url := base + "/proof/v1/log?limit=100"
		if cursor != "" {
			url += "&after=" + cursor
		}
		var logResp struct {
			Entries []struct {
				CID     string `json:"cid"`
				Kind    string `json:"kind"`
				ChainID string `json:"chainId"`
			} `json:"entries"`
		}
		getJSON(t, url, &logResp)
		for _, e := range logResp.Entries {
			cursor = e.CID

			// Only identity-op and content-op carry a derived identifier as
			// their chainId. An identity DID is "did:dfos:<id>"; a content ID is
			// the bare "<id>".
			var idPart string
			switch e.Kind {
			case "identity-op":
				idPart = strings.TrimPrefix(e.ChainID, "did:dfos:")
			case "content-op":
				idPart = e.ChainID
			default:
				continue
			}
			if idPart == "" {
				continue
			}
			checked++
			if len(idPart) != canonical {
				t.Errorf("non-canonical identifier width in operation log: "+
					"chainId=%q (kind=%s) has a %d-char id, want %d — the relay "+
					"is serving a pre-v1 (%d-char) corpus under a v1 surface; its "+
					"identifiers must be re-minted to the v1 width to interoperate",
					e.ChainID, e.Kind, len(idPart), canonical, len(idPart))
			}
		}
		if len(logResp.Entries) < 100 {
			break // a short page is the only valid terminus
		}
		if seen[cursor] {
			t.Fatalf("global /log cursor did not converge: page-boundary CID %s "+
				"repeated after %d pages", cursor, pages+1)
		}
		seen[cursor] = true
		if pages+1 >= maxLogPages {
			t.Fatalf("global /log did not terminate after %d full pages", maxLogPages)
		}
	}

	if checked == 0 {
		t.Fatal("no identity-op or content-op entries found in /log to width-check " +
			"(expected at least the seeded ops)")
	}
	t.Logf("identifier-width conformance: %d derived identifiers checked, all %d-char", checked, canonical)
}
