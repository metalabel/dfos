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
//
// THE PROJECTION IS KICKED HERE, NOT INSIDE THE LOOP. The sequencer is the ONLY
// path by which a peer-pulled operation reaches the log: SyncFromPeers stages
// raw ops and drains them through here, and a pull-only node (--no-write, or a
// relay nobody POSTs to) never enters Relay.Ingest at all. Kicking only from
// the accepting path would freeze such a relay's index at whatever the boot
// drain reached while /.well-known still advertised index: true. It runs after
// ingestMu is released, for the same reason the ingest kick does — the whole
// point of the projection is that it is not inside the write lock.
func (r *Relay) RunSequencer() ([]string, SequenceResult) {
	// A relay whose store keeps no writer state has no pending set to drain and
	// nothing to write it back to.
	if r.writerState == nil || r.writeStore == nil {
		return nil, SequenceResult{}
	}
	newOps, result := r.runSequencerUnderLock()
	r.kickIndexProjection()
	return newOps, result
}

// runSequencerUnderLock is RunSequencer's locked half, split out so the
// projection kick above happens with ingestMu released.
func (r *Relay) runSequencerUnderLock() ([]string, SequenceResult) {
	r.ingestMu.Lock()
	defer r.ingestMu.Unlock()
	return r.runSequencerLocked()
}

// sequencerBatchOps bounds how many pending ops one pass hands to
// IngestOperations at a time.
//
// A single window can drain up to sequencerWindowOps (10k) rows, and that whole
// set is classified, dependency-sorted, and held in memory together. Chunking
// bounds that working set and the latency of one turn; it is NOT a transaction
// boundary — the atomic unit is one operation, owned by the store (see
// RelayWriteStore.Commit).
const sequencerBatchOps = 1000

// sequencerWindowOps is how many pending rows one keyset window fetches. The
// window is a WINDOW now rather than a head: a pass walks the whole pending set
// window by window, so this bounds a single fetch and the working set it feeds,
// not how far into the queue the sequencer can see.
const sequencerWindowOps = 10000

// runSequencerLocked is the sequencer inner loop. Caller must hold ingestMu.
func (r *Relay) runSequencerLocked() ([]string, SequenceResult) {
	var newOps []string
	var result SequenceResult

	var opts []IngestOption
	if !r.logEnabled {
		opts = append(opts, WithLogDisabled())
	}

	// after is the keyset position of the last pending row this call has looked
	// at; sweepProgress records whether the sweep from the head has drained
	// anything. A window that drains nothing no longer ends the pass — it just
	// moves the cursor on — so ten thousand permanently dependency-missing rows
	// can no longer hide every row behind them. The pass still restarts from the
	// head after a sweep that moved something, because an op admitted late in a
	// sweep can unblock one the sweep already walked past.
	prevPending := -1
	after := ""
	sweepProgress := false
	for {
		pendingOps, err := r.writerState.GetUnsequencedOps(after, r.sequencerWindowOps)
		if err != nil {
			break
		}
		if len(pendingOps) == 0 {
			if after == "" || !sweepProgress {
				break
			}
			after, sweepProgress = "", false
			continue
		}
		after = pendingOps[len(pendingOps)-1].Cursor

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
			// This window drained nothing. The cursor has already moved past it,
			// so the next iteration reads the NEXT window rather than re-reading
			// this one — which is the whole point: a stuck block is walked over,
			// not stalled on. Termination is the cursor, which strictly advances
			// across a finite set.
			continue
		}
		sweepProgress = true

		// Livelock backstop: a window that claims progress MUST shrink the pending
		// set. If it didn't, no forward progress is possible — the same pending
		// ops re-verify identically next pass — so break instead of spinning at
		// ~100% CPU holding ingestMu. With the drain keyed on the storage CID
		// above, progress now implies a real drain, so a flat (or growing) count
		// is a genuine dead-end, not a transient. The next sequencer tick retries.
		pending, cerr := r.writerState.CountUnsequenced()
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
// raw_ops rows. Caller must hold ingestMu.
//
// THE ATOMIC UNIT IS ONE OPERATION, AND THE STORE OWNS IT. Admitting one
// operation writes its chain state, its operation row, and its /proof/v1/log
// append, and RelayWriteStore.Commit persists all three or none. The relay used
// to orchestrate that itself — open a transaction around a chunk, watch for a
// half-applied op, roll back — which meant the relay had to detect a partial
// write from the outside and the ops in the chunk shared each other's fate. Now
// a failed op is just a store fault on that op: it stays pending, the rest of the
// chunk is unaffected, and nothing is half-held.
//
// Returns the tokens to gossip, this chunk's counts, whether the chunk drained
// any raw op, and ok=false when the pass must back off.
func (r *Relay) sequenceChunkLocked(tokens []string, opts []IngestOption) ([]string, SequenceResult, bool, bool) {
	var newOps []string
	var result SequenceResult
	progress := false

	results := IngestOperations(tokens, r.writeStore, opts...)

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
			r.writerState.MarkOpRejected(rawCID, res.Error)
			result.Rejected++
			progress = true
		default:
			// Retryable: a missing dependency, or a store fault. Either way the raw
			// op stays pending and a later pass re-ingests it.
			result.Pending++
		}
	}

	if len(sequencedCIDs) > 0 {
		if err := r.writerState.MarkOpsSequenced(sequencedCIDs); err != nil {
			// The ops themselves ARE held — each one committed atomically — so
			// they are still reported and gossiped. What failed is the bookkeeping
			// that stops them being re-ingested, and re-ingesting them would
			// re-verify to "duplicate", claim progress, and spin here at 100% CPU
			// holding ingestMu. Back off; the next sequencer tick retries the drain
			// against a healthy store.
			r.logger.Error("sequencer: failed to mark ops sequenced — backing off",
				"count", len(sequencedCIDs),
				"error", err,
			)
			return newOps, result, progress, false
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

// storeReadErrorPrefix marks a rejection caused by a store READ failing at an
// authorization gate (revocation lookup, deleted-identity lookup). Distinct from
// persistErrorPrefix so the two transient-store failure modes are separable in
// logs, but the semantics are the same: a gate that cannot be evaluated FAILS
// CLOSED — the op is not admitted — and stays pending for retry rather than
// being durably rejected.
const storeReadErrorPrefix = "storage read failed: "

// isRetryableRejection reports whether a rejection may be answered differently
// later — a dependency that sync or gossip may deliver, or a store fault that
// decided nothing at all. Branches on the STRUCTURED flags the ingest producer
// sets, never on substring matching of the Error string. Mirrors the TS twin's
// discriminator.
func isRetryableRejection(res IngestionResult) bool {
	return res.DependencyMissing || res.StoreFault
}

// isPermanentRejection is the inverse: a verdict re-asking cannot change, which
// DELETES the raw op. Everything that is not provably retryable would be
// permanent under this rule, which is why a store fault carries its own flag.
func isPermanentRejection(res IngestionResult) bool {
	return !isRetryableRejection(res)
}
