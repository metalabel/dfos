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
	kid := id.did + "#" + id.auth.keyID

	// The op-size cap is measured over the whole dag-cbor payload, independent of
	// any single field. We inflate the (string-validated) documentCID to push the
	// encoded operation over / under the 64 KiB bound.
	overToken, _, _, err := dfos.SignContentCreate(id.did, strings.Repeat("x", 70000), kid, id.auth.priv)
	if err != nil {
		t.Fatalf("SignContentCreate (over): %v", err)
	}
	if st, _ := postStatus(t, base, overToken); st != "rejected" {
		t.Fatalf("over-cap operation should be rejected, got status %q", st)
	}

	// under-cap content op → accepted.
	underToken, _, _, err := dfos.SignContentCreate(id.did, strings.Repeat("x", 60000), kid, id.auth.priv)
	if err != nil {
		t.Fatalf("SignContentCreate (under): %v", err)
	}
	if st, _ := postStatus(t, base, underToken); st != "new" {
		t.Fatalf("under-cap operation should be accepted, got status %q", st)
	}
}
