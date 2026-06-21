package conformance

import (
	"strings"
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// Max operation size — the single aggregate validity bound on a proof-layer
// operation's dag-cbor-encoded payload (64 KiB), measured over the exact bytes
// the CID commits to. It replaces the former per-field string-length caps. An
// operation whose encoded payload exceeds the cap is rejected on ingest; one
// just under it is accepted. This bound is validity-determining and holds
// identically on both relays.
func TestOperationSizeCap(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	doc := map[string]any{"$schema": "https://schemas.dfos.com/post/v1", "format": "short-post", "body": "x"}
	docCID, _, err := dfos.DocumentCID(doc)
	if err != nil {
		t.Fatalf("DocumentCID: %v", err)
	}
	kid := id.did + "#" + id.auth.keyID

	// over-cap content op (~70 KB note) → rejected by the op-size cap.
	overToken, _, _, err := dfos.SignContentCreate(id.did, docCID, kid, strings.Repeat("x", 70000), id.auth.priv)
	if err != nil {
		t.Fatalf("SignContentCreate (over): %v", err)
	}
	if st, _ := postStatus(t, base, overToken); st != "rejected" {
		t.Fatalf("over-cap operation should be rejected, got status %q", st)
	}

	// under-cap content op (~60 KB note) → accepted.
	underToken, _, _, err := dfos.SignContentCreate(id.did, docCID, kid, strings.Repeat("x", 60000), id.auth.priv)
	if err != nil {
		t.Fatalf("SignContentCreate (under): %v", err)
	}
	if st, _ := postStatus(t, base, underToken); st != "new" {
		t.Fatalf("under-cap operation should be accepted, got status %q", st)
	}
}
