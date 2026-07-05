package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// contentFollowEager is the only ContentFollow mode that does work today. Any
// other value ("", "none", or an unknown string) leaves the relay byte-identical
// to a non-following node. "lazy" (read-through on a blob 404) is reserved.
const contentFollowEager = "eager"

// materializeConcurrency bounds how many chains a single sweep pulls in parallel.
// Network fetches overlap; PutBlob still serializes on ingestMu. Modest by design
// — a follower shouldn't fan a thundering herd at its origin.
const materializeConcurrency = 8

// blobSourceCooldownWindow is how long a peer stays in the blob circuit breaker
// after a transport/5xx failure, so a dead origin isn't re-hit once per granted
// chain every sweep. A 404 never trips the breaker (the peer is reachable).
const blobSourceCooldownWindow = 30 * time.Second

// verifyBlobBytes returns nil iff bytes canonically (dag-cbor) hash to
// wantDocumentCID. This is the content-addressed integrity check at the heart of
// the content plane: a blob's meaning IS its CID, and the CID is already signed
// in the proof plane, so any source — trusted or not — is safe to pull bytes from
// as long as they re-hash to the documentCID the chain committed. Shared by
// handlePutBlob (an author's upload) and the follower materializer (a peer pull):
// both doors reduce to the same content-addressing check.
func verifyBlobBytes(bytes []byte, wantDocumentCID string) error {
	var parsed any
	if err := json.Unmarshal(bytes, &parsed); err != nil {
		return fmt.Errorf("blob bytes are not valid JSON: %w", err)
	}
	_, _, computedCID, err := dfos.DagCborCID(parsed)
	if err != nil {
		return fmt.Errorf("compute documentCID: %w", err)
	}
	if computedCID != wantDocumentCID {
		return fmt.Errorf("blob bytes hash to %s, want %s", computedCID, wantDocumentCID)
	}
	return nil
}

// markContentFollowDirty records, for one newly-sequenced op, what content-follow
// work it makes relevant. Called under ingestMu in the sequencer loop, so it only
// touches the in-memory dirty queues — never any I/O. A no-op unless following.
//
//   - content-op (create/update/delete): the chain's own bytes may need pulling, so
//     mark that contentID for a targeted materialize. A delete leaves stale blobs,
//     but GC is correctness-free and revocation/delete are rare, so reclamation
//     rides the periodic GC backstop rather than decoding every content-op here.
//   - credential: a new public grant's blast radius is unbounded (a broad grant can
//     authorize many chains), so request a full materialize scan rather than guess
//     the resource — credentials are rare relative to content-ops.
//   - revocation: may orphan materialized blobs — request a GC pass.
func (r *Relay) markContentFollowDirty(res IngestionResult) {
	if r.contentFollow != contentFollowEager {
		return
	}
	switch res.Kind {
	case "content-op":
		r.materializeDirty.markID(res.ChainID) // ChainID is the contentID for content-ops
	case "credential":
		r.materializeDirty.markFull()
	case "revocation":
		r.gcDirty.markFull()
	}
}

// MaterializeFollowedContent drains the materialize work queue: for each contentID
// the sequencer flagged (or, on a full-scan request, every granted chain), ensure
// the chain's committed document blobs are present locally, pulling any missing
// ones from peers (content-address-verified). Idempotent and safe to call
// repeatedly — already-present blobs are skipped and transient failures are left
// for the next pass (the sweep IS the retry). A no-op unless ContentFollow ==
// "eager", a no-op if another sweep is already in flight (TryLock coalesces the
// trigger-kicked and timer sweeps), and — crucially — a near-instant no-op when the
// queue is empty, so a steady-state follower sits idle instead of re-scanning every
// chain and re-verifying every grant on every tick.
//
// This is the correctness backbone of content following. The full-scan path
// converges a follower to "all granted public blobs materialized" regardless of
// op-ingest ordering: in a sync batch a credential op (sequencer priority 1) is
// replayed BEFORE the content op it grants (priority 2), so a purely trigger-driven
// materializer would race the chain into existence — the scan cannot, because it
// only ever acts on chains already present in local state. The boot catch-up and
// the periodic backstop both request a full scan, so the event-driven fast path
// never weakens the convergence guarantee. The materialize gate is the SAME
// predicate as the per-read serve gate (hasPublicStandingAuth), which is what makes
// revoke correctness-free: a revoked chain stops being swept and its cached bytes
// become unreachable to readers (GCRevokedContent reclaims the storage).
func (r *Relay) MaterializeFollowedContent() {
	if r.contentFollow != contentFollowEager {
		return
	}
	if r.peerClient == nil || len(r.peers) == 0 {
		return
	}
	// Coalesce: if a sweep is already running, this caller is redundant.
	if !r.materializeMu.TryLock() {
		return
	}
	defer r.materializeMu.Unlock()

	// Drain until empty so a burst of ops sequenced during a pass still materializes
	// this tick. A full-scan request supersedes any pending ids (it covers the whole
	// corpus), so we run it and return rather than looping.
	for {
		ids, full := r.materializeDirty.take()
		if full {
			r.materializeAllGrantedChains()
			return
		}
		if len(ids) == 0 {
			return
		}
		for _, contentID := range ids {
			r.materializeOneChain(contentID)
		}
	}
}

// materializeAllGrantedChains is the convergent whole-corpus pass: pull missing
// blobs for every content chain a standing public-read grant authorizes. O(corpus)
// — reserved for boot catch-up and the periodic backstop, NOT the per-tick path.
func (r *Relay) materializeAllGrantedChains() {
	chains, err := r.readStore.ListContentChains()
	if err != nil {
		r.logger.Warn("materialize: list content chains failed", "error", err)
		return
	}

	sem := make(chan struct{}, materializeConcurrency)
	var wg sync.WaitGroup
	for _, chain := range chains {
		// Never materialize a sealed/deleted chain — its tombstone is the point.
		if chain.State.IsDeleted {
			continue
		}
		// The gate is the gate: only follow chains a standing public-read grant
		// authorizes anonymous read of. Revoked → falls out here automatically.
		if !hasPublicStandingAuth(chain.ContentID, "read", r.readStore) {
			continue
		}
		chain := chain
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r.materializeChainBlobs(chain)
		}()
	}
	wg.Wait()
}

// materializeOneChain is the targeted fast path: load a single chain by contentID,
// gate it, and pull its missing blobs. O(1) chains — driven by the sequencer's
// dirty marks so a freshly created/granted chain materializes within a tick without
// a whole-corpus scan.
func (r *Relay) materializeOneChain(contentID string) {
	chain, err := r.readStore.GetContentChain(contentID)
	if err != nil || chain == nil {
		return
	}
	if chain.State.IsDeleted {
		return
	}
	if !hasPublicStandingAuth(chain.ContentID, "read", r.readStore) {
		return
	}
	r.materializeChainBlobs(*chain)
}

// ReconcileFollowedContent forces a convergent full pass over both planes:
// materialize every granted chain's missing blobs and GC every now-unreadable
// chain's stale blobs. This is the boot catch-up and the periodic backstop behind
// the event-driven fast path — it guarantees eventual consistency regardless of
// which dirty marks were or weren't recorded. A no-op unless ContentFollow ==
// "eager".
func (r *Relay) ReconcileFollowedContent() {
	if r.contentFollow != contentFollowEager {
		return
	}
	r.materializeDirty.markFull()
	r.MaterializeFollowedContent()
	r.gcDirty.markFull()
	r.GCRevokedContent()
}

// materializeChainBlobs ensures every document blob committed by a chain's ops is
// present in the local store, pulling any missing one from peers and verifying it
// against the documentCID committed in the LOCAL op log (never the source's
// claim). Whole-chain (head + history): profile chains are short and sub-KB, so
// simplicity wins; selective head-only fetch is a posts-tier knob.
func (r *Relay) materializeChainBlobs(chain StoredContentChain) {
	creatorDID := chain.State.CreatorDID
	for _, jws := range chain.Log {
		header, payload, err := dfos.DecodeJWSUnsafe(jws)
		if err != nil || header == nil {
			continue
		}
		docCID, ok := payload["documentCID"].(string)
		if !ok || docCID == "" {
			continue // e.g. a delete op commits no document
		}
		key := BlobKey{CreatorDID: creatorDID, DocumentCID: docCID}
		if existing, err := r.readStore.GetBlob(key); err == nil && existing != nil {
			continue // already materialized
		}
		r.pullAndStoreBlob(chain.ContentID, header.CID, key)
	}
}

// pullAndStoreBlob fetches one document blob (by operationCID) from the first
// healthy peer that can serve it, content-address-verifies the bytes against the
// committed documentCID, and persists it under ingestMu. Best-effort: any failure
// leaves the blob for the next sweep — there is no hard-fail or spin. Peers in the
// circuit-breaker cooldown are skipped; a transport/5xx failure trips the breaker,
// a 404 ("ask elsewhere") does not, and a good response clears it.
func (r *Relay) pullAndStoreBlob(contentID, operationCID string, key BlobKey) {
	for _, peer := range r.peers {
		if r.blobSourceCoolingDown(peer.URL) {
			continue // breaker open for this source — skip without a network hit
		}
		bytes, err := r.peerClient.GetBlob(peer.URL, contentID, operationCID)
		if err != nil {
			if errors.Is(err, ErrBlobNotFound) {
				continue // peer reachable, just doesn't hold it — try the next
			}
			r.tripBlobSource(peer.URL, err) // transport/5xx — open the breaker
			continue
		}
		r.clearBlobSource(peer.URL) // a good response closes the breaker
		if err := verifyBlobBytes(bytes, key.DocumentCID); err != nil {
			// A peer served bytes that don't hash to the committed CID. Reject and
			// try another source; never store unverified bytes. (Bad bytes are not
			// a liveness failure, so they don't trip the breaker.)
			r.logger.Warn("materialize: blob failed content-address verification",
				"contentId", contentID, "documentCID", key.DocumentCID, "peer", peer.URL, "error", err)
			continue
		}
		r.ingestMu.Lock()
		err = r.store.PutBlob(key, bytes)
		if err == nil {
			// The followed blob landed — recompute content rows that project this
			// documentCID (docSchema/name/profile) + their anchored identities.
			maintainIndexAfterBlob(key.DocumentCID, r.store)
		}
		r.ingestMu.Unlock()
		if err != nil {
			r.logger.Warn("materialize: persist blob failed", "documentCID", key.DocumentCID, "error", err)
			return
		}
		r.logger.Info("materialize: stored blob", "contentId", contentID, "documentCID", key.DocumentCID)
		return
	}
}

// blobSourceCoolingDown reports whether peerURL is currently inside its circuit-
// breaker cooldown. An elapsed deadline self-clears so the next sweep retries.
func (r *Relay) blobSourceCoolingDown(peerURL string) bool {
	v, ok := r.blobSourceCooldown.Load(peerURL)
	if !ok {
		return false
	}
	if time.Now().UnixNano() >= v.(int64) {
		r.blobSourceCooldown.Delete(peerURL)
		return false
	}
	return true
}

// tripBlobSource opens the circuit breaker for peerURL for blobSourceCooldownWindow.
func (r *Relay) tripBlobSource(peerURL string, cause error) {
	deadline := time.Now().Add(blobSourceCooldownWindow).UnixNano()
	if _, existed := r.blobSourceCooldown.Swap(peerURL, deadline); !existed {
		r.logger.Warn("materialize: blob source failing — cooling down",
			"peer", peerURL, "cooldown", blobSourceCooldownWindow.String(), "error", cause)
	}
}

// clearBlobSource closes the circuit breaker for peerURL after a healthy response.
func (r *Relay) clearBlobSource(peerURL string) {
	r.blobSourceCooldown.Delete(peerURL)
}

// GCRevokedContent runs one convergent reclamation pass: for every content chain
// that is NO LONGER publicly readable (its standing grant was revoked, or the
// chain was deleted/sealed), delete any document blobs the follower had
// materialized for it. Idempotent and coalesced (gcMu); a no-op unless
// ContentFollow == "eager".
//
// This is the GC complement to MaterializeFollowedContent — same convergent shape,
// opposite direction, same gate. Correctness never depends on it (a revoked
// chain's bytes are already unreachable via the per-read serve gate); it only
// reclaims storage. Run on a slower cadence than the materialize sweep so a
// revoke-then-regrant flip just re-fetches rather than thrashing.
func (r *Relay) GCRevokedContent() {
	if r.contentFollow != contentFollowEager {
		return
	}
	if !r.gcMu.TryLock() {
		return
	}
	defer r.gcMu.Unlock()

	// GC only ever has whole-corpus work (a revocation or delete can orphan blobs
	// anywhere), and revocation/delete are rare — so the queue is a single "a scan
	// is warranted" flag. Nothing flagged since the last pass → skip the corpus
	// scan entirely (the common case). Reclamation is correctness-free, so even if a
	// mark is missed the periodic backstop catches it.
	if _, full := r.gcDirty.take(); !full {
		return
	}

	chains, err := r.readStore.ListContentChains()
	if err != nil {
		r.logger.Warn("gc: list content chains failed", "error", err)
		return
	}
	for _, chain := range chains {
		publiclyReadable := !chain.State.IsDeleted && hasPublicStandingAuth(chain.ContentID, "read", r.readStore)
		if publiclyReadable {
			continue
		}
		r.gcChainBlobs(chain)
	}
}

// gcChainBlobs deletes any materialized document blobs for a chain that is no
// longer publicly readable. Sequential — revocations are rare. The GetBlob guard
// means a chain that was never materialized (e.g. a private chain whose op log we
// hold but never followed) costs only a cheap read.
func (r *Relay) gcChainBlobs(chain StoredContentChain) {
	creatorDID := chain.State.CreatorDID
	for _, jws := range chain.Log {
		header, payload, err := dfos.DecodeJWSUnsafe(jws)
		if err != nil || header == nil {
			continue
		}
		docCID, ok := payload["documentCID"].(string)
		if !ok || docCID == "" {
			continue
		}
		key := BlobKey{CreatorDID: creatorDID, DocumentCID: docCID}
		if existing, err := r.readStore.GetBlob(key); err != nil || existing == nil {
			continue // nothing materialized for this op
		}
		r.ingestMu.Lock()
		err = r.store.DeleteBlob(key)
		r.ingestMu.Unlock()
		if err != nil {
			r.logger.Warn("gc: delete blob failed", "documentCID", docCID, "error", err)
			continue
		}
		r.logger.Info("gc: reclaimed revoked/deleted blob", "contentId", chain.ContentID, "documentCID", docCID)
	}
}
