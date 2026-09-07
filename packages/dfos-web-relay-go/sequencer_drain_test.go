package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
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
	if _, err := store.PutRawOp(storageCID, token); err != nil {
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

// emptyHeaderCIDCredToken builds a credential JWS with an EMPTY header `cid`. It is
// rejected ("kid must be a DID URL") before any CID-integrity check, returning
// res.CID=="" — yet computeOpCID(token) (the storage key) is non-empty because the
// payload decodes fine, so PutRawOp stored a real row. Gating the drain on res.CID
// would strand that row 'pending' forever; gating on the storage CID drains it.
func emptyHeaderCIDCredToken(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	header := dfos.JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:credential",
		Kid: "no-did-url", // no '#' → rejected before the cid-integrity check
		CID: "",           // empty header cid → ingest returns res.CID==""
	}
	token, err := dfos.CreateJWS(header, map[string]any{"aud": "*"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// TestSequencerDrainsEmptyHeaderCID is the regression for the #117 sibling: a raw op
// whose ingest result carries an EMPTY CID (but whose payload hashed to a real,
// stored storage CID) must still drain — not leak as permanently 'pending'. Before
// the drain-guard fix the loop `continue`d on res.CID=="" and stranded the row.
func TestSequencerDrainsEmptyHeaderCID(t *testing.T) {
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}

	token := emptyHeaderCIDCredToken(t)
	storageCID := computeOpCID(token)
	if storageCID == "" {
		t.Fatal("expected a decodable, non-empty storage CID")
	}
	if _, err := store.PutRawOp(storageCID, token); err != nil {
		t.Fatal(err)
	}
	if n, _ := store.CountUnsequenced(); n != 1 {
		t.Fatalf("expected 1 pending raw op, got %d", n)
	}

	relay.RunSequencer()

	// The malformed credential must have drained (permanent reject → deleted),
	// keyed by its storage CID — not leaked as permanently 'pending'.
	if n, err := store.CountUnsequenced(); err != nil || n != 0 {
		t.Fatalf("expected 0 pending raw ops after sequencing, got %d (err=%v)", n, err)
	}
}

// TestStuckOpsDoNotStarveTheTail is the regression for the head-window
// starvation.
//
// A dependency-missing op is cheap to mint and never drains: nothing rejects it,
// nothing ages it out, it just stays pending. The sequencer used to fetch the
// OLDEST N pending rows every pass, so once N of those accumulated it fetched
// the same N forever — and every row behind them, including a freshly
// pull-synced op whose dependency had since landed, was never selected. Direct
// POST ingest kept working (it ingests inline), so peer ingestion stopped
// converging silently.
//
// The window is lowered rather than the fixture raised: what is under test is a
// window that fills entirely with rows that cannot advance, and ten thousand of
// them prove nothing four do not.
func TestStuckOpsDoNotStarveTheTail(t *testing.T) {
	store := NewMemoryStore()
	relay, err := NewRelay(RelayOptions{Store: store, Authority: testAuthority})
	if err != nil {
		t.Fatal(err)
	}
	relay.sequencerWindowOps = 4

	// Four ops whose signer identity this relay will never hold.
	for i := 0; i < 4; i++ {
		stranger := createTestIdentity(t)
		token, _, err := dfos.SignRevocation(
			stranger.did,
			"bafyreiggnbfr4a6xz3xoi4qlbaawyzimxecwltvj5fqxbmc7pfrzwe22ta",
			stranger.did+"#"+stranger.auth.keyID,
			stranger.auth.priv,
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.PutRawOp(computeOpCID(token), token); err != nil {
			t.Fatal(err)
		}
	}

	// And behind them, one perfectly ingestible op.
	good := createTestIdentity(t)
	if _, err := store.PutRawOp(computeOpCID(good.token), good.token); err != nil {
		t.Fatal(err)
	}

	if n, _ := store.CountUnsequenced(); n != 5 {
		t.Fatalf("fixture: expected 5 pending raw ops, got %d", n)
	}

	done := make(chan SequenceResult, 1)
	go func() {
		_, result := relay.RunSequencer()
		done <- result
	}()
	var result SequenceResult
	select {
	case result = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the sequencer did not terminate")
	}

	if result.Sequenced != 1 {
		t.Fatalf("the op behind the stuck window must still sequence, sequenced=%d", result.Sequenced)
	}
	if chain, _ := store.GetIdentityChain(good.did); chain == nil {
		t.Fatal("the op behind the stuck window never landed — the tail is starved")
	}
	// The stuck rows are untouched, which is the point: they are walked over, not
	// evicted. Eviction is a separate policy question.
	if n, _ := store.CountUnsequenced(); n != 4 {
		t.Fatalf("expected the 4 stuck rows to remain pending, got %d", n)
	}
}

// TestPendingOpsPageByKeysetOnBothStores pins the cursor contract itself on both
// reference stores. The SQLite half is the one worth writing down: it walks a
// ROW-VALUE comparison over (created_at, cid), and created_at has one-second
// resolution, so a burst of ops shares a timestamp and the CID tiebreak is what
// stops the walk from either repeating or skipping a row.
func TestPendingOpsPageByKeysetOnBothStores(t *testing.T) {
	tokens := make([]string, 5)
	for i := range tokens {
		tokens[i] = createTestIdentity(t).token
	}

	sqlite, err := NewSQLiteStore(filepath.Join(t.TempDir(), "keyset.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer sqlite.Close()

	for name, store := range map[string]RelayWriterState{"memory": NewMemoryStore(), "sqlite": sqlite} {
		t.Run(name, func(t *testing.T) {
			for _, token := range tokens {
				if _, err := store.PutRawOp(computeOpCID(token), token); err != nil {
					t.Fatal(err)
				}
			}

			seen := make([]string, 0, len(tokens))
			after := ""
			for range len(tokens) + 1 {
				page, err := store.GetUnsequencedOps(after, 2)
				if err != nil {
					t.Fatal(err)
				}
				if len(page) == 0 {
					break
				}
				if len(page) > 2 {
					t.Fatalf("a page of %d exceeded the limit of 2", len(page))
				}
				for _, op := range page {
					seen = append(seen, op.JWSToken)
				}
				after = page[len(page)-1].Cursor
			}

			if len(seen) != len(tokens) {
				t.Fatalf("the keyset walk saw %d ops, want %d", len(seen), len(tokens))
			}
			unique := map[string]struct{}{}
			for _, token := range seen {
				if _, dup := unique[token]; dup {
					t.Fatal("the keyset walk returned the same op twice")
				}
				unique[token] = struct{}{}
			}
		})
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

// The stub ignores the cursor and always answers with the same row under the
// same cursor, which is precisely the shape the backstop exists for: the keyset
// walk cannot advance past a store that will not advance.
func (s *backstopStubStore) GetUnsequencedOps(after string, limit int) ([]PendingOp, error) {
	return []PendingOp{{JWSToken: s.token, Origin: OpOriginDirect, Cursor: "stuck"}}, nil
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
