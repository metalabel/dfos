package relay

import (
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
		tokens, err := r.store.GetUnsequencedOps(10000)
		if err != nil || len(tokens) == 0 {
			break
		}

		results := IngestOperations(tokens, r.store, opts...)

		progress := false
		var sequencedCIDs []string

		for i, res := range results {
			if res.CID == "" {
				continue
			}
			// Drain the raw_ops row by the SAME CID it was stored under
			// (computeOpCID(token) == PutRawOp's key), NOT res.CID. Ingest carries
			// the JWS-header-claimed CID on some results (e.g. credential
			// rejections, ingest.go); when that disagrees with the recomputed
			// storage CID, MarkOps{Sequenced,Rejected}(res.CID) would update zero
			// rows, the op would stay 'pending', re-verify as duplicate/rejected
			// next pass (progress=true), and this loop would spin at ~100% CPU
			// holding ingestMu. Keying on the storage CID guarantees the row drains.
			rawCID := computeOpCID(tokens[i])
			switch {
			case res.Status == "new":
				sequencedCIDs = append(sequencedCIDs, rawCID)
				newOps = append(newOps, tokens[i])
				result.Sequenced++
				progress = true
			case res.Status == "duplicate":
				sequencedCIDs = append(sequencedCIDs, rawCID)
				progress = true
			case res.Status == "rejected" && isPermanentRejection(res):
				r.store.MarkOpRejected(rawCID, res.Error)
				result.Rejected++
				progress = true
			default:
				result.Pending++
			}
		}

		if len(sequencedCIDs) > 0 {
			if err := r.store.MarkOpsSequenced(sequencedCIDs); err != nil {
				// The sequenced status was never persisted. Do NOT gossip these
				// ops (local state is inconsistent with what we'd advertise) and
				// stop the loop — leaving the rows pending would otherwise spin
				// here forever (re-verify → "duplicate" → progress) at 100% CPU
				// holding ingestMu. The next sequencer tick retries.
				r.logger.Error("sequencer: failed to mark ops sequenced — skipping gossip and backing off",
					"count", len(sequencedCIDs),
					"error", err,
				)
				return nil, result
			}
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
			go func() {
				err := r.peerClient.SubmitOperations(peerURL, chunk)
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
