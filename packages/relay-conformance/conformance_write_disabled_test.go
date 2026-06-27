package conformance

import (
	"net/http"
	"os"
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// Write-disabled (lite / pull-only) relay conformance.
//
// A relay MAY advertise capabilities.write == false — a "lite" pull-only node
// that serves the proof plane read-only and rejects ingestion. WEB-RELAY.md and
// CONFORMANCE.md make writes OPTIONAL: POST /proof/v1/operations returns 501
// Not Implemented while every proof-plane READ route stays fully conformant.
//
// This poses a bootstrapping problem for a conformance suite that normally
// SEEDS its fixtures by POSTing ops (see helpers_test.go createIdentity): a
// write:false node 501s those POSTs, so the ingestion/lifecycle tests can't set
// up state. The resolution is that a read-only node does not need the suite to
// seed it. Every conformant relay — including a write:false one — bootstraps its
// OWN identity chain IN-PROCESS (not over the POST route), and that chain is
// served by the read routes. So the read tier is verified by RECOMPUTE-FROM-LOG:
// pull /proof/v1/identities/{did}/log, INDEPENDENTLY re-derive head + state with
// VerifyIdentityChain, and assert the relay's served state matches the
// recomputation. The served state must be reproducible from the served ops
// alone — that is the whole point of conformance, and it needs no write.
//
// Like the content-disabled suite, this is GATED on the well-known capability:
// it self-skips unless the relay advertises capabilities.write == false, so it
// is safe in the default `go test ./...` run. To exercise it, point RELAY_URL at
// a write-disabled relay (see scripts/run-write-disabled.sh, which boots both
// the TS and Go reference relays in write:false mode).

// writeDisabledBase returns the relay URL only if the relay advertises
// capabilities.write == false; otherwise it skips. Mirrors contentDisabledBase —
// the gate keeps these assertions scoped to the deployment they describe (a
// write-enabled relay, the common case, legitimately accepts POSTs).
func writeDisabledBase(t *testing.T) string {
	t.Helper()
	base := relayURL(t)

	var meta struct {
		Capabilities struct {
			Write bool `json:"write"`
		} `json:"capabilities"`
	}
	resp := getJSON(t, base+"/.well-known/dfos-relay", &meta)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /.well-known/dfos-relay: status %d", resp.StatusCode)
	}
	if meta.Capabilities.Write {
		t.Skip("relay advertises capabilities.write: true — skipping write-disabled conformance")
	}
	return base
}

// wdLogEntry is a single entry of a proof-plane /log response.
type wdLogEntry struct {
	CID      string `json:"cid"`
	JWSToken string `json:"jwsToken"`
}

// wdGetLog fetches a proof-plane log (global or per-chain) and returns its
// entries, asserting a 200.
func wdGetLog(t *testing.T, url string) []wdLogEntry {
	t.Helper()
	var body struct {
		Entries []wdLogEntry `json:"entries"`
	}
	resp := getJSON(t, url, &body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	return body.Entries
}

// verifyServedIdentity is the recompute-from-log core. It pulls the identity's
// log, re-derives head + state from the ops alone via VerifyIdentityChain (a
// pure function — no relay, no network), and asserts the relay's served
// /proof/v1/identities/{did} matches: head CID, DID, deletion flag. It also
// checks CID integrity + DID self-derivation on the genesis op, and that the
// recomputed head op is fetchable by CID. This proves the read plane is an
// honest projection of verifiable operations.
func verifyServedIdentity(t *testing.T, base, did string) {
	t.Helper()

	// 1. Pull the per-identity log (genesis → head order).
	entries := wdGetLog(t, base+"/proof/v1/identities/"+did+"/log")
	if len(entries) == 0 {
		t.Fatalf("identity %s: log is empty — nothing to verify", did)
	}
	tokens := make([]string, len(entries))
	for i, e := range entries {
		if e.JWSToken == "" {
			t.Fatalf("identity %s log[%d]: missing jwsToken", did, i)
		}
		tokens[i] = e.JWSToken
	}

	// 2. Independently re-derive head + state from the ops alone.
	result, err := dfos.VerifyIdentityChain(tokens)
	if err != nil {
		t.Fatalf("identity %s: recompute-from-log failed: %v", did, err)
	}

	// 3. Genesis CID integrity + DID self-derivation: the DID derives from the
	//    hash of the genesis operation, so re-encoding the served genesis op
	//    must reproduce both its own CID and the DID it is served under.
	header, payload, err := dfos.DecodeJWSUnsafe(tokens[0])
	if err != nil {
		t.Fatalf("identity %s: decode genesis JWS: %v", did, err)
	}
	_, genCIDBytes, computedGenCID, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("identity %s: DagCborCID of genesis payload: %v", did, err)
	}
	if computedGenCID != header.CID {
		t.Fatalf("identity %s: genesis CID mismatch: header.cid=%s, recomputed=%s", did, header.CID, computedGenCID)
	}
	if derived := dfos.DeriveDID(genCIDBytes); derived != did {
		t.Fatalf("identity %s: not self-certifying — DID derived from genesis CID is %s", did, derived)
	}
	if result.HeadCID != entries[len(entries)-1].CID {
		t.Fatalf("identity %s: recomputed head %s != last log entry CID %s", did, result.HeadCID, entries[len(entries)-1].CID)
	}

	// 4. The relay's served resolved state must match the recomputation.
	var served struct {
		State struct {
			DID       string `json:"did"`
			IsDeleted bool   `json:"isDeleted"`
		} `json:"state"`
		HeadCID string `json:"headCID"`
	}
	resp := getJSON(t, base+"/proof/v1/identities/"+did, &served)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /proof/v1/identities/%s: status %d", did, resp.StatusCode)
	}
	if served.HeadCID != result.HeadCID {
		t.Fatalf("identity %s: served headCID %s != recomputed headCID %s — read plane is not an honest projection", did, served.HeadCID, result.HeadCID)
	}
	if served.State.DID != result.State.DID {
		t.Fatalf("identity %s: served state.did %s != recomputed %s", did, served.State.DID, result.State.DID)
	}
	// The served DID MUST be a well-formed did:dfos identifier (canonical width
	// over the protocol alphabet). A relay running a stale derivation that
	// truncates the resolved DID to a pre-v1 width is non-conformant even if it
	// echoes that truncated DID consistently.
	if !dfos.IsValidDID(served.State.DID) {
		t.Fatalf("identity %s: served state.did %q is not a well-formed did:dfos identifier", did, served.State.DID)
	}
	if served.State.IsDeleted != result.State.IsDeleted {
		t.Fatalf("identity %s: served isDeleted=%v != recomputed %v", did, served.State.IsDeleted, result.State.IsDeleted)
	}

	// 5. The recomputed head op is addressable by CID on the read plane.
	var op struct {
		CID      string `json:"cid"`
		JWSToken string `json:"jwsToken"`
	}
	opResp := getJSON(t, base+"/proof/v1/operations/"+result.HeadCID, &op)
	if opResp.StatusCode != 200 {
		t.Fatalf("GET /proof/v1/operations/%s: status %d — recomputed head op not served by CID", result.HeadCID, opResp.StatusCode)
	}
	if op.CID != result.HeadCID {
		t.Fatalf("operation %s: served CID is %s", result.HeadCID, op.CID)
	}
}

// TestWriteDisabledPostRejected asserts a write-disabled relay returns 501 Not
// Implemented on POST /proof/v1/operations — not 404, 405, or 400. The write
// gate fires before body parsing, so an arbitrary body suffices.
func TestWriteDisabledPostRejected(t *testing.T) {
	base := writeDisabledBase(t)

	resp := postOperations(t, base, []string{"not.a.real.jws"})
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		t.Fatalf("POST /proof/v1/operations: returned 404 — a write-disabled relay MUST return 501 (writes not supported), not 404")
	}
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("POST /proof/v1/operations: expected 501 Not Implemented, got %d", resp.StatusCode)
	}
}

// TestWriteDisabledReadPlaneServes is the core read-only conformance check — and
// the answer to "how do you verify a node you cannot seed?": you don't seed it.
// Every conformant relay bootstraps its OWN identity chain in-process, so this
// recompute-verifies that always-present chain with no write of any kind.
func TestWriteDisabledReadPlaneServes(t *testing.T) {
	base := writeDisabledBase(t)
	did := getRelayDID(t, base)
	if did == "" {
		t.Fatal("relay DID is empty")
	}
	verifyServedIdentity(t, base, did)
}

// TestWriteDisabledSeededIdentity recompute-verifies an identity chain that was
// seeded OUT-OF-BAND (not via POST) into the relay — the real product scenario:
// a read-only node serving user identity chains it received through its own data
// path. Gated on WRITE_DISABLED_SEED_DID (set by run-write-disabled.sh); it
// self-skips otherwise, so the default run and a bare write:false node stay
// green.
func TestWriteDisabledSeededIdentity(t *testing.T) {
	base := writeDisabledBase(t)
	did := os.Getenv("WRITE_DISABLED_SEED_DID")
	if did == "" {
		t.Skip("WRITE_DISABLED_SEED_DID not set — skipping out-of-band-seeded chain recompute")
	}
	verifyServedIdentity(t, base, did)
}

// TestWriteDisabledReadRoutesNot501 is the negative control: write:false gates
// ONLY the POST ingestion route. Every proof-plane READ route MUST still serve
// (200 for the relay's own chain), never 501 — 501 here would mean the relay
// conflated "writes disabled" with "read plane disabled".
func TestWriteDisabledReadRoutesNot501(t *testing.T) {
	base := writeDisabledBase(t)
	did := getRelayDID(t, base)
	for _, path := range []string{
		"/.well-known/dfos-relay",
		"/proof/v1/identities/" + did,
		"/proof/v1/identities/" + did + "/log",
	} {
		resp := getJSON(t, base+path, nil)
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotImplemented {
			t.Fatalf("GET %s: returned 501 — write:false gates only POST; proof-plane read routes must serve", path)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s: expected 200 on a write-disabled relay, got %d", path, resp.StatusCode)
		}
	}
}
