package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// poisonOpToken builds a credential JWS whose header `cid` deliberately disagrees
// with DagCborCID(payload) — the storage key. It is rejected structurally ("kid
// must be a DID URL") BEFORE VerifyCredential's CID-integrity check, so ingest
// carries the bogus header CID on the rejection. PutRawOp keys the row under the
// recomputed CID, so draining by the header CID (the old behavior) misses the row.
// No valid signature is needed — rejection happens pre-verify.
func poisonOpToken(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	header := dfos.JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:credential",
		Kid: "no-did-url", // no '#' → rejected "kid must be a DID URL"
		CID: "bafyreibogusheadercidthatdoesnotmatchpayloaddigestxxxxxxxxxxx",
	}
	token, err := dfos.CreateJWS(header, map[string]any{"aud": "*"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// TestSequencerDrainsDivergentHeaderCID is the regression for the lark wedge: a
// raw op whose header-claimed CID differs from its storage CID must still drain
// from raw_ops, and the sequencer must terminate (not spin at 100% CPU holding
// ingestMu re-verifying an un-drainable row).
func TestSequencerDrainsDivergentHeaderCID(t *testing.T) {
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}

	token := poisonOpToken(t)
	storageCID := computeOpCID(token)
	if storageCID == "" {
		t.Fatal("expected a decodable storage CID")
	}
	// Stage the op exactly as Ingest/SyncFromPeers do: keyed by the recomputed CID.
	if err := store.PutRawOp(storageCID, token); err != nil {
		t.Fatal(err)
	}
	if n, _ := store.CountUnsequenced(); n != 1 {
		t.Fatalf("expected 1 pending raw op, got %d", n)
	}

	// Run the sequencer under a timeout. Before the fix this spins forever
	// (MarkOpRejected(headerCID) matches no row → progress=true → re-verify),
	// so a regression manifests as a hang → timeout failure here.
	done := make(chan struct{})
	go func() {
		relay.RunSequencer()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sequencer did not terminate — un-drainable raw op spin regression")
	}

	// The poison op must have drained (rejected → deleted), keyed by its storage CID.
	if n, err := store.CountUnsequenced(); err != nil || n != 0 {
		t.Fatalf("expected 0 pending raw ops after sequencing, got %d (err=%v)", n, err)
	}
}

// backstopStubStore forces the livelock scenario the backstop guards: every pass
// GetUnsequencedOps yields the same op (so the op classifies → progress=true) but
// MarkOps* are no-ops and CountUnsequenced never shrinks — i.e. progress is claimed
// without the pending set ever draining. All other Store behavior delegates to the
// embedded MemoryStore so IngestOperations can classify the op normally.
type backstopStubStore struct {
	*MemoryStore
	token string
}

func (s *backstopStubStore) GetUnsequencedOps(limit int) ([]string, error) {
	return []string{s.token}, nil
}
func (s *backstopStubStore) MarkOpsSequenced(cids []string) error    { return nil }
func (s *backstopStubStore) MarkOpRejected(cid, reason string) error { return nil }
func (s *backstopStubStore) CountUnsequenced() (int, error)          { return 1, nil }

// TestSequencerLivelockBackstop covers the defensive backstop directly: when a pass
// claims progress but the pending set does not shrink, the loop must break rather
// than spin forever. Without the backstop this hangs (→ timeout failure).
func TestSequencerLivelockBackstop(t *testing.T) {
	base := NewMemoryStore()
	store := &backstopStubStore{MemoryStore: base, token: createTestIdentity(t).token}
	relay, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		relay.RunSequencer()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sequencer did not terminate — livelock backstop did not fire")
	}
}
