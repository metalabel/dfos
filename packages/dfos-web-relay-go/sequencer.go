package relay

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// SequenceResult reports the outcome of a sequencer run.
type SequenceResult struct {
	Sequenced int `json:"sequenced"`
	Rejected  int `json:"rejected"`
	Pending   int `json:"pending"`
}

// RunSequencer acquires the ingest mutex and runs the sequencer loop.
// Called by the background ticker and SyncFromPeers.
func (r *Relay) RunSequencer() ([]string, SequenceResult) {
	r.ingestMu.Lock()
	defer r.ingestMu.Unlock()
	return r.runSequencerLocked()
}

// sequencerBatchOps bounds how many pending ops share one write batch.
//
// A single pass can drain up to GetUnsequencedOps' limit (10k). Committing that
// as one transaction would hold a write transaction open across the verify+apply
// of every one of those ops, and would make a single failed commit discard the
// whole pass. One batch per chunk keeps the atomic unit small enough that a
// failure costs one chunk of re-ingest work, while still being large enough that
// the per-transaction overhead is amortized away.
const sequencerBatchOps = 1000

// runSequencerLocked is the sequencer inner loop. Caller must hold ingestMu.
func (r *Relay) runSequencerLocked() ([]string, SequenceResult) {
	var newOps []string
	var result SequenceResult

	var opts []IngestOption
	if !r.logEnabled {
		opts = append(opts, WithLogDisabled())
	}

	prevPending := -1
	for {
		pendingOps, err := r.store.GetUnsequencedOps(10000)
		if err != nil || len(pendingOps) == 0 {
			break
		}

		progress := false
		aborted := false

		for _, origin := range []OpOrigin{OpOriginDirect, OpOriginPeer} {
			var tokens []string
			for _, op := range pendingOps {
				if op.Origin == origin {
					tokens = append(tokens, op.JWSToken)
				}
			}
			if len(tokens) == 0 {
				continue
			}
			partitionOpts := append([]IngestOption{}, opts...)
			if origin == OpOriginPeer {
				partitionOpts = append(partitionOpts, WithHistoricalAdmission())
			}
			for start := 0; start < len(tokens) && !aborted; start += sequencerBatchOps {
				chunk := tokens[start:min(start+sequencerBatchOps, len(tokens))]
				chunkOps, chunkResult, chunkProgress, ok := r.sequenceChunkLocked(chunk, partitionOpts)
				newOps = append(newOps, chunkOps...)
				result.Sequenced += chunkResult.Sequenced
				result.Rejected += chunkResult.Rejected
				result.Pending += chunkResult.Pending
				progress = progress || chunkProgress
				aborted = !ok
			}
			if aborted {
				break
			}
		}

		// A chunk that could not be persisted has already been rolled back and
		// contributed nothing above, so backing off here is only about the ops
		// still pending: retrying them in this same call would hit the same
		// unhealthy store, and leaving the loop running would spin at ~100% CPU
		// holding ingestMu. The next sequencer tick retries. Chunks that DID
		// commit before the failure are held durably, so their ops stay in newOps
		// and are still gossiped — they are landed, and suppressing them would
		// only strand them (they are already marked sequenced and will never be
		// re-ingested).
		if aborted {
			return newOps, result
		}

		if !progress {
			break
		}

		// Livelock backstop: a pass that claims progress MUST shrink the pending
		// set. If it didn't, no forward progress is possible — the same pending
		// ops re-verify identically next pass — so break instead of spinning at
		// ~100% CPU holding ingestMu. With the drain keyed on the storage CID
		// above, progress now implies a real drain, so a flat (or growing) count
		// is a genuine dead-end, not a transient. The next sequencer tick retries.
		pending, cerr := r.store.CountUnsequenced()
		if cerr == nil {
			if prevPending >= 0 && pending >= prevPending {
				r.logger.Error("sequencer: progress claimed but pending set did not shrink — backing off",
					"pending", pending,
				)
				break
			}
			prevPending = pending
		}
	}

	return newOps, result
}

// sequenceChunkLocked ingests one chunk of pending raw ops and drains their
// raw_ops rows inside a SINGLE write batch. Caller must hold ingestMu.
//
// The batch is what makes an accepted op atomic. Admitting one op writes its
// chain state, its operation row, and its /proof/v1/log append as separate
// statements. Outside a transaction each of those commits on its own, so a
// failure after the operation row but before the log append leaves an operation
// that every per-chain route serves but that the proof log has never heard of —
// and leaves it that way permanently, because the idempotency check at the top
// of each ingest path finds the stored operation and returns "duplicate" before
// the missing append is ever retried. Re-ingesting the op cannot repair it and
// nothing reports it: the log is simply short one entry, and opCount is derived
// from the log itself. Inside one batch the three writes land together or not
// at all, so the window does not exist.
//
// Extends the contract Ingest already holds for its own batch: a batch that is
// not fully held is rolled back and must neither be gossiped nor reported as
// landed. Returns the tokens to gossip, this chunk's counts, whether the chunk
// drained any raw op, and ok=false when the chunk was discarded — in which case
// the first three returns are all empty, because the relay holds none of it.
// The discarded chunk's raw ops stay 'pending' (their drain was part of the same
// batch), so the next pass re-ingests them cleanly.
//
// Stores that do not implement BatchableStore keep the previous per-statement
// behavior; there is no transaction to roll back and nothing to wrap.
func (r *Relay) sequenceChunkLocked(tokens []string, opts []IngestOption) ([]string, SequenceResult, bool, bool) {
	var newOps []string
	var result SequenceResult
	progress := false

	batchable, hasBatch := r.store.(BatchableStore)
	if hasBatch {
		if err := batchable.BeginWriteBatch(); err != nil {
			r.logger.Error("sequencer: failed to begin write batch — falling back to unbatched writes", "error", err)
			hasBatch = false
		}
	}

	results := IngestOperations(tokens, r.store, opts...)

	// A half-applied op poisons its own retry: the writes that DID land make
	// every later attempt short-circuit as a "duplicate", so the writes that
	// failed — the log append, last of the three — are never made up. Discarding
	// the batch is what keeps the op whole and re-ingestable.
	if hasBatch && batchPersistFailed(results) {
		r.logger.Error("sequencer: a write failed mid-batch — chunk rolled back, not gossiped",
			"ops", len(tokens),
		)
		_ = batchable.RollbackWriteBatch()
		return nil, SequenceResult{}, false, false
	}

	var sequencedCIDs []string
	for i, res := range results {
		// Drain the raw_ops row by the SAME CID it was stored under
		// (computeOpCID(token) == PutRawOp's key), NOT res.CID — and GATE on
		// this storage CID too, not res.CID. Ingest carries the JWS-header-
		// claimed CID on some results, which can DIVERGE from the storage CID:
		//   - non-empty but wrong (e.g. a forged header cid): keying drain on
		//     res.CID would update zero rows → row stays 'pending' → re-verifies
		//     as duplicate/rejected → 100% CPU spin holding ingestMu.
		//   - EMPTY while the payload decoded fine (e.g. a credential with a
		//     missing/empty header cid, rejected at ingest.go): gating on
		//     res.CID=="" would `continue` past a row that PutRawOp DID store
		//     under the non-empty recomputed CID → stranded 'pending' forever
		//     (a permanent leak + unbounded-growth vector, since each distinct
		//     payload mints a fresh row).
		// rawCID=="" means the token was undecodable, so PutRawOp was skipped
		// and there is genuinely nothing to drain — skip it.
		rawCID := computeOpCID(tokens[i])
		if rawCID == "" {
			continue
		}
		switch {
		case res.Status == "new":
			sequencedCIDs = append(sequencedCIDs, rawCID)
			newOps = append(newOps, tokens[i])
			result.Sequenced++
			progress = true
			r.markContentFollowDirty(res, tokens[i])
		case res.Status == "duplicate":
			sequencedCIDs = append(sequencedCIDs, rawCID)
			progress = true
		case res.Status == "rejected" && isPermanentRejection(res):
			// The one durable trace of the drop: MarkOpRejected DELETES the row,
			// and the reason was previously passed only to be discarded. Log
			// before the delete so a relay refusing everything it is handed can
			// be diagnosed. Observability only — deletion semantics unchanged.
			//
			// The event string and both field names match the TS twin's structured
			// line (sequencer.ts logOpRejected) so one query shape works across
			// implementations.
			//
			// One line per rejected op on an unauthenticated ingest endpoint is a
			// considered tradeoff: a flood of junk ops does amplify into logs, but
			// each such op already cost signature verification and store reads, so
			// the marginal write is small next to the work it reports — and a
			// silent drop is the failure mode that actually goes undiagnosed.
			r.logger.Warn("relay.op.rejected", "cid", rawCID, "reason", res.Error)
			r.store.MarkOpRejected(rawCID, res.Error)
			result.Rejected++
			progress = true
		default:
			result.Pending++
		}
	}

	if len(sequencedCIDs) > 0 {
		if err := r.store.MarkOpsSequenced(sequencedCIDs); err != nil {
			// The sequenced status was never persisted. Do NOT gossip these ops
			// (local state is inconsistent with what we'd advertise) and abandon
			// the chunk — leaving the rows pending while continuing would spin
			// here forever (re-verify → "duplicate" → progress) at 100% CPU
			// holding ingestMu. The next sequencer tick retries.
			r.logger.Error("sequencer: failed to mark ops sequenced — rolling back and backing off",
				"count", len(sequencedCIDs),
				"error", err,
			)
			if hasBatch {
				// Roll back rather than commit a batch whose bookkeeping half is
				// missing — and never leave the transaction open, or every later
				// write on this store would join a batch nobody commits.
				_ = batchable.RollbackWriteBatch()
			}
			return nil, SequenceResult{}, false, false
		}
	}

	if hasBatch {
		if err := batchable.CommitWriteBatch(); err != nil {
			// The chunk's writes are GONE. Nothing it claimed to land is held, so
			// none of it may be gossiped or counted. The raw ops were staged
			// before the batch opened and their drain was inside it, so they are
			// still 'pending' and the next pass re-ingests them from scratch.
			r.logger.Error("sequencer: failed to commit write batch — chunk rolled back, not gossiped",
				"error", err,
				"ops", len(tokens),
			)
			_ = batchable.RollbackWriteBatch()
			return nil, SequenceResult{}, false, false
		}
	}

	return newOps, result, progress, true
}

// RunSequencerAndGossip runs the sequencer and gossips newly sequenced ops.
func (r *Relay) RunSequencerAndGossip() SequenceResult {
	start := time.Now()
	newOps, result := r.RunSequencer()
	elapsed := time.Since(start)
	if result.Sequenced > 0 {
		r.logger.Info("sequencer processed ops",
			"sequenced", result.Sequenced,
			"rejected", result.Rejected,
			"pending", result.Pending,
			"elapsed", elapsed.Round(time.Millisecond).String(),
		)
	}
	r.gossipOps(newOps)
	return result
}

// maxGossipBatch is the max ops per gossip POST. The receiver's /operations
// endpoint rejects any batch with more than 100 items, so larger gossip runs
// must be chunked or they are silently dropped.
const maxGossipBatch = 100

// gossipOps pushes JWS tokens to all gossip-enabled peers, chunked into batches
// of at most maxGossipBatch so the receiver never 400s the whole push.
func (r *Relay) gossipOps(tokens []string) {
	if r.peerClient == nil || len(tokens) == 0 {
		return
	}
	for _, peer := range r.peers {
		if peer.Gossip != nil && !*peer.Gossip {
			continue
		}
		// Skip peers known to be pull-only (write-disabled): they rejected an
		// earlier push with 501, so re-trying every cycle is pure log spam and
		// wasted goroutines. Suppression lasts the process lifetime; a peer that
		// gains write support is re-probed on the next relay restart.
		if _, disabled := r.gossipDisabled.Load(peer.URL); disabled {
			continue
		}
		for start := 0; start < len(tokens); start += maxGossipBatch {
			end := start + maxGossipBatch
			if end > len(tokens) {
				end = len(tokens)
			}
			chunk := tokens[start:end]
			peerURL := peer.URL
			peerCfg := peer
			go func() {
				// The pin check runs INSIDE the goroutine on purpose. gossipOps is
				// called on the ingest path, right after a write commits, and a cold
				// verdict costs a well-known round-trip — checking synchronously
				// would stall the submission that triggered it behind every
				// configured peer in turn. Skipping here still means nothing leaves
				// this relay for a peer whose identity moved, which is the property
				// that matters: gossip is the direction that PUBLISHES.
				if r.peerPinned(peerCfg) != nil {
					return
				}
				err := r.submitGossip(peerURL, chunk)
				if err == nil {
					return
				}
				if errors.Is(err, ErrPeerWriteDisabled) {
					// First push that learns the peer is pull-only: suppress all
					// further gossip to it. LoadOrStore dedupes the log line
					// across the concurrent per-batch goroutines.
					if _, loaded := r.gossipDisabled.LoadOrStore(peerURL, struct{}{}); !loaded {
						r.logger.Info("peer is write-disabled; suppressing further gossip", "peer", peerURL)
					}
					return
				}
				r.logger.Warn("gossip submit failed", "peer", peerURL, "ops", len(chunk), "error", err)
			}()
		}
	}
}

// submitGossip pushes one chunk, carrying an identity proof of the relay's OWN
// DID when the relay holds a signing key and the transport can take one.
//
// A PeerClient that does not implement SigningPeerClient gossips anonymously —
// which every in-process test mock does, unchanged. A default-open peer admits
// an anonymous push anyway; the proof is what lets a peer whose policy is
// proof-required or allowlist-based admit this relay at all.
func (r *Relay) submitGossip(peerURL string, chunk []string) error {
	signer, ok := r.peerClient.(SigningPeerClient)
	if !ok || !r.gossipProofSigned {
		return r.peerClient.SubmitOperations(peerURL, chunk)
	}
	return signer.SubmitOperationsSigned(peerURL, chunk, r.signGossipProof)
}

// signGossipProof mints an identity proof over the exact gossip request.
//
// POST /operations is WRITE-SHAPED, so the proof MUST carry jti. A fresh random
// value per push: the receiver's replay cache is keyed (jti, presenter), so a
// re-gossip of the same ops is a new request, not a replay.
func (r *Relay) signGossipProof(method, host, path string, body []byte) (string, error) {
	if r.privateKey == nil || r.keyID == "" {
		return "", nil
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	return dfos.BuildIdentityProof(method, host, path, r.did+"#"+r.keyID, r.privateKey,
		dfos.IdentityProofOptions{
			Body:         body,
			ExtraMembers: dfos.ProofExtraMembers{"jti": hex.EncodeToString(jti)},
		})
}

// computeOpCID derives the operation CID from a JWS token.
func computeOpCID(jwsToken string) string {
	_, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err != nil {
		return ""
	}
	_, _, cid, err := dfos.DagCborCID(payload)
	if err != nil {
		return ""
	}
	return cid
}

// persistErrorPrefix marks a rejection caused by a transient storage write
// failure (not a protocol-level rejection). Ops that fail to persist must stay
// pending so the raw-op + sequencer retry can recover once the store is healthy
// — they must never be marked sequenced or gossiped, since local state was
// never written.
const persistErrorPrefix = "persistence failed: "

// ForkPointStateErrorPrefix is the human-readable prefix for a fork-point
// state-computation failure. Declared as ONE shared constant so the producer
// (the ingest rejection sites) and any string classifier reference the same
// literal — eliminating the #56 colon-mismatch drift. Mirrors the TS twin's
// FORK_POINT_STATE_ERROR_PREFIX in ingest.ts.
//
// Classification no longer depends on this string — the sequencer branches on
// the structured IngestionResult.DependencyMissing flag — but the constant
// keeps the two twins byte-identical for the human-readable error.
const ForkPointStateErrorPrefix = "failed to compute state at fork point: "

// persistError wraps a store write error in a retryable rejection result. The
// caller's CID is preserved so the op can be located in the raw store, and the
// structured DependencyMissing flag is set so the sequencer keeps it pending
// (the transient-store-retry path is Go-only — TS's in-memory store has no
// analogue — and is flag-gated, NOT a string pattern the TS classifier must
// mirror). Returns nil if err is nil (no persistence failure).
func persistError(cid string, err error) *IngestionResult {
	if err == nil {
		return nil
	}
	return &IngestionResult{
		CID:               cid,
		Status:            "rejected",
		Error:             persistErrorPrefix + err.Error(),
		DependencyMissing: true,
		PersistFailed:     true,
	}
}

// errPartialWriteRolledBack is the error a batch's surviving results are
// rewritten with when the batch is discarded because one of its ops could not
// be fully written. The op that failed already carries its own store error;
// this one explains to every OTHER op in the batch why a result it had earned
// is being taken back.
var errPartialWriteRolledBack = errors.New("a write in this batch failed and the batch was rolled back")

// batchPersistFailed reports whether any op in the batch left a half-applied
// write behind. Branches on the structured PersistFailed flag, never on the
// human-readable error string.
func batchPersistFailed(results []IngestionResult) bool {
	for _, res := range results {
		if res.PersistFailed {
			return true
		}
	}
	return false
}

// storeReadErrorPrefix marks a rejection caused by a store READ failing at an
// authorization gate (revocation lookup, deleted-identity lookup). Distinct from
// persistErrorPrefix so the two transient-store failure modes are separable in
// logs, but the semantics are the same: a gate that cannot be evaluated FAILS
// CLOSED — the op is not admitted — and stays pending for retry rather than
// being durably rejected.
const storeReadErrorPrefix = "storage read failed: "

// storeReadError wraps a store read error at an authorization gate in a
// retryable rejection. The alternative — treating a failed lookup as
// "not revoked" / "not deleted" — fails OPEN and admits an operation the relay
// has no evidence is authorized. Returns nil if err is nil.
func storeReadError(cid string, err error) *IngestionResult {
	if err == nil {
		return nil
	}
	return &IngestionResult{
		CID:               cid,
		Status:            "rejected",
		Error:             storeReadErrorPrefix + err.Error(),
		DependencyMissing: true,
	}
}

// isDependencyFailure returns true if a rejection is retryable — a missing
// dependency that may arrive later via sync or gossip, OR a transient storage
// write failure. Branches on the STRUCTURED DependencyMissing flag set by the
// ingest producer, not on substring matching of the Error string. Mirrors the
// TS twin's structured discriminator.
func isDependencyFailure(res IngestionResult) bool {
	return res.DependencyMissing
}

// isPermanentRejection returns true if a rejection is permanent and should not
// be retried. The inverse of isDependencyFailure.
func isPermanentRejection(res IngestionResult) bool {
	return !res.DependencyMissing
}
