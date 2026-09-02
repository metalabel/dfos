package relay

// The peer identity pin.
//
// Every other piece of peer state in this library is keyed by URL — the sync
// cursor, the gossip-disabled set, the blob circuit breaker — because a URL is
// how you reach a peer. It is not who the peer IS. A relay that re-keyed and a
// stranger answering at that address produce the same bytes on the wire, and
// this relay would sync from it, gossip its whole sequenced output to it, serve
// its answers as read-through results, and materialize its blobs, all without a
// single check that the relay it is talking to is the relay it was configured
// against.
//
// PeerConfig.DID closes that: a peer carrying a pin is checked, before each
// touch, against the DID it actually serves, and a mismatch skips the peer for
// that touch in every direction.
//
// Three things this gate deliberately does NOT do:
//
//   - It does not fail on an unanswered question. Unreachable, non-200, and
//     undecodable are all "no evidence", never "a different identity" — the same
//     rule the CLI's verifyPeerPin follows. An offline peer is a reachability
//     problem, and the operation the caller was running reports it in its own
//     words.
//   - It does not check what it cannot check. A PeerClient that does not
//     implement IdentifyingPeerClient (every in-process test mock) has no way to
//     ask, and a pin nothing can verify is not a pin that failed.
//   - It does not write configuration. Trust-on-first-use — pinning an unpinned
//     peer to whoever answered — belongs where the config lives, which is the
//     CLI. This library reads a pin it was handed and enforces it; it never
//     mints one.

import (
	"fmt"
	"time"
)

// peerPinRecheck is how long a pin verdict stands before the peer is asked
// again. It is deliberately of the same order as the default sync interval
// (30s): the point of a recheck cadence at all is that a pin is checked "before
// and during", so an identity that moves under a long-running `serve` is caught
// within a cycle or two rather than at the next restart. Long enough that a
// read-through storm on a 404 costs one well-known fetch rather than one per
// request; short enough that a moved pin stops the traffic promptly.
const peerPinRecheck = 60 * time.Second

// peerPinVerdict is one peer's cached answer. mismatch nil means the peer is
// cleared for traffic — either it served the pinned DID, or the question could
// not be answered and absence of contact is not evidence.
type peerPinVerdict struct {
	checkedAt time.Time
	mismatch  error
}

// peerPinned reports whether traffic to this peer is allowed right now. A nil
// return clears the touch; a non-nil error is the refusal, naming the URL, the
// pinned DID, and the one the peer served.
//
// Callers skip the peer for that touch and say nothing — the logging lives here,
// keyed off the verdict cache, so a mismatch is announced once when it is
// established rather than once per sync tick, per gossip chunk, and per
// read-through request.
func (r *Relay) peerPinned(peer PeerConfig) error {
	if peer.DID == "" {
		return nil // unpinned: this entry makes no claim about identity
	}
	identifier, ok := r.peerClient.(IdentifyingPeerClient)
	if !ok {
		return nil // this transport cannot ask; an unverifiable pin is not a violated one
	}

	r.peerPinMu.Lock()
	verdict, cached := r.peerPins[peer.URL]
	r.peerPinMu.Unlock()
	if cached && time.Since(verdict.checkedAt) < peerPinRecheck {
		return verdict.mismatch
	}

	// The fetch happens WITHOUT the lock held. This gate is hit from the sync
	// goroutine, from every per-chunk gossip goroutine, and from request
	// handlers; holding a mutex across a peer round-trip would serialize all of
	// them behind one slow peer. Two callers racing a cold verdict both fetch and
	// both write the same answer, which costs one redundant request and is the
	// right trade against a global stall.
	served, err := identifier.GetPeerDID(peer.URL)

	var mismatch error
	switch {
	case err != nil || served == "":
		// No answer. Not evidence of a changed identity — cache the clearance so
		// an unreachable peer costs one well-known attempt per recheck window
		// rather than one per touch.
	case served != peer.DID:
		mismatch = fmt.Errorf("peer %s is not the relay it is pinned to: pinned %s, serves %s",
			peer.URL, peer.DID, served)
	}

	r.peerPinMu.Lock()
	previous, hadPrevious := r.peerPins[peer.URL]
	r.peerPins[peer.URL] = peerPinVerdict{checkedAt: time.Now(), mismatch: mismatch}
	r.peerPinMu.Unlock()

	// Announce the EDGES only. A standing mismatch re-confirmed every recheck
	// window is the same fact, and repeating it every cycle buries the moment it
	// started under identical lines.
	changed := !hadPrevious || (previous.mismatch == nil) != (mismatch == nil)
	switch {
	case mismatch != nil && changed:
		r.logger.Warn("peer pin mismatch — suppressing all traffic to this peer",
			"peer", peer.URL, "pinned", peer.DID, "serves", served)
	case mismatch == nil && changed && hadPrevious:
		r.logger.Info("peer pin now matches — resuming traffic", "peer", peer.URL, "did", peer.DID)
	}
	return mismatch
}

// recordPeerPin folds a pin verdict into the peer's sync status, so a peer the
// sync loop skipped over a moved pin says so at stats.peerSync rather than
// looking like a peer that had nothing to send.
func (r *Relay) recordPeerPin(peerURL string, mismatch error) {
	r.peerSyncMu.Lock()
	defer r.peerSyncMu.Unlock()
	st := r.peerStatusLocked(peerURL)
	if mismatch == nil {
		st.PinMismatch = nil
		return
	}
	msg := mismatch.Error()
	st.PinMismatch = &msg
}
