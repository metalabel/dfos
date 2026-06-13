package relay

import (
	"strings"
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
			switch {
			case res.Status == "new":
				sequencedCIDs = append(sequencedCIDs, res.CID)
				newOps = append(newOps, tokens[i])
				result.Sequenced++
				progress = true
			case res.Status == "duplicate":
				sequencedCIDs = append(sequencedCIDs, res.CID)
				progress = true
			case res.Status == "rejected" && isPermanentRejection(res.Error):
				r.store.MarkOpRejected(res.CID, res.Error)
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
		for start := 0; start < len(tokens); start += maxGossipBatch {
			end := start + maxGossipBatch
			if end > len(tokens) {
				end = len(tokens)
			}
			chunk := tokens[start:end]
			peerURL := peer.URL
			go func() {
				if err := r.peerClient.SubmitOperations(peerURL, chunk); err != nil {
					r.logger.Warn("gossip submit failed", "peer", peerURL, "ops", len(chunk), "error", err)
				}
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

// persistError wraps a store write error in a retryable rejection result. The
// caller's CID is preserved so the op can be located in the raw store. Returns
// nil if err is nil (no persistence failure).
func persistError(cid string, err error) *IngestionResult {
	if err == nil {
		return nil
	}
	return &IngestionResult{CID: cid, Status: "rejected", Error: persistErrorPrefix + err.Error()}
}

// isDependencyFailure returns true if the rejection is due to a missing
// dependency that may arrive later via sync or gossip, OR a transient storage
// write failure. These are retryable — everything else is treated as permanent.
func isDependencyFailure(errMsg string) bool {
	dependencyPatterns := []string{
		"unknown previous operation",             // previousCID not in store or not in chain log
		"unknown identity:",                      // identity chain not synced yet (key resolution)
		"content chain not found:",               // content chain genesis not synced yet
		"failed to compute state at fork point:", // fork state replay failed (dep missing)
		persistErrorPrefix,                       // transient store write failure — retry
	}
	for _, p := range dependencyPatterns {
		if strings.Contains(errMsg, p) {
			return true
		}
	}
	return false
}

// isPermanentRejection returns true if the rejection is permanent and should
// not be retried. This is the inverse of isDependencyFailure.
func isPermanentRejection(errMsg string) bool {
	return !isDependencyFailure(errMsg)
}
