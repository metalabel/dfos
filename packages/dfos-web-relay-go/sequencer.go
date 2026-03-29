package relay

import (
	"strings"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// SequenceResult reports the outcome of a sequencer run.
type SequenceResult struct {
	Sequenced int `json:"sequenced"`
	Rejected  int `json:"rejected"`
	Pending   int `json:"pending"`
}

// RunSequencer processes unsequenced raw ops in a fixed-point loop until no
// more progress is made. Returns the JWS tokens of newly sequenced ops (for
// gossip) and aggregate stats.
func (r *Relay) RunSequencer() ([]string, SequenceResult) {
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
			r.store.MarkOpsSequenced(sequencedCIDs)
		}

		if !progress {
			break
		}
	}

	return newOps, result
}

// RunSequencerAndGossip runs the sequencer and gossips newly sequenced ops.
func (r *Relay) RunSequencerAndGossip() SequenceResult {
	newOps, result := r.RunSequencer()
	r.gossipOps(newOps)
	return result
}

// gossipOps pushes JWS tokens to all gossip-enabled peers.
func (r *Relay) gossipOps(tokens []string) {
	if r.peerClient == nil || len(tokens) == 0 {
		return
	}
	for _, peer := range r.peers {
		if peer.Gossip != nil && !*peer.Gossip {
			continue
		}
		go r.peerClient.SubmitOperations(peer.URL, tokens) //nolint:errcheck
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

// isDependencyFailure returns true if the rejection is due to a missing
// dependency that may arrive later via sync or gossip. Only these specific
// patterns are retryable — everything else is treated as permanent.
func isDependencyFailure(errMsg string) bool {
	dependencyPatterns := []string{
		"unknown previous operation",   // previousCID not in store or not in chain log
		"unknown identity:",            // identity chain not synced yet (key resolution)
		"content chain not found:",     // content chain genesis not synced yet
		"failed to compute state at fork point:", // fork state replay failed (dep missing)
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
