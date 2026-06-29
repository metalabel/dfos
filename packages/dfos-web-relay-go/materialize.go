package relay

import (
	"encoding/json"
	"fmt"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// contentFollowEager is the only ContentFollow mode that does work today. Any
// other value ("", "none", or an unknown string) leaves the relay byte-identical
// to a non-following node. "lazy" (read-through on a blob 404) is reserved.
const contentFollowEager = "eager"

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

// MaterializeFollowedContent runs one convergent materialization pass: for every
// content chain this relay holds a standing public-read grant for, ensure its
// committed document blobs are present locally, pulling any missing ones from
// peers. Idempotent and safe to call repeatedly — already-present blobs are
// skipped and transient failures are simply left for the next pass (the sweep IS
// the retry). A no-op unless ContentFollow == "eager".
//
// This is the correctness backbone of content following. It converges a follower
// to "all granted public blobs materialized" regardless of op-ingest ordering: in
// a sync batch a credential op (sequencer priority 1) is replayed BEFORE the
// content op it grants (priority 2), so a purely trigger-driven materializer would
// race the chain into existence — the sweep cannot, because it only ever acts on
// chains already present in local state. The materialize gate is the SAME
// predicate as the per-read serve gate (hasPublicStandingAuth), which is what
// makes revoke correctness-free: a revoked chain simply stops being swept and its
// cached bytes become unreachable to readers; reclaiming the storage is a separate,
// optional concern (no GC here).
func (r *Relay) MaterializeFollowedContent() {
	if r.contentFollow != contentFollowEager {
		return
	}
	if r.peerClient == nil || len(r.peers) == 0 {
		return
	}

	chains, err := r.readStore.ListContentChains()
	if err != nil {
		r.logger.Warn("materialize: list content chains failed", "error", err)
		return
	}
	for _, chain := range chains {
		// Never materialize a sealed/deleted chain — its tombstone is the point.
		if chain.State.IsDeleted {
			continue
		}
		// The gate is the gate: only follow chains a standing public-read grant
		// authorizes anonymous read of. Revoked → falls out here automatically.
		if !r.hasPublicStandingAuth(chain.ContentID, "read") {
			continue
		}
		r.materializeChainBlobs(chain)
	}
}

// materializeChainBlobs ensures every document blob committed by a chain's ops is
// present in the local store, pulling any missing one from peers and verifying it
// against the documentCID committed in the LOCAL op log (never the source's
// claim). Sequential and whole-chain (head + history): profile chains are short
// and sub-KB, so simplicity wins; selective head-only fetch is a posts-tier knob.
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

// pullAndStoreBlob fetches one document blob (by operationCID) from the first peer
// that can serve it, content-address-verifies the bytes against the committed
// documentCID, and persists it under ingestMu (the write store aliases the active
// batch tx, exactly as handlePutBlob does). Best-effort: any failure logs and
// returns, leaving the blob for the next sweep — there is no hard-fail or spin.
func (r *Relay) pullAndStoreBlob(contentID, operationCID string, key BlobKey) {
	for _, peer := range r.peers {
		bytes, err := r.peerClient.GetBlob(peer.URL, contentID, operationCID)
		if err != nil {
			continue // peer can't serve it (404/down) — try the next
		}
		if err := verifyBlobBytes(bytes, key.DocumentCID); err != nil {
			// A peer served bytes that don't hash to the committed CID. Reject and
			// try another source; never store unverified bytes.
			r.logger.Warn("materialize: blob failed content-address verification",
				"contentId", contentID, "documentCID", key.DocumentCID, "peer", peer.URL, "error", err)
			continue
		}
		r.ingestMu.Lock()
		err = r.store.PutBlob(key, bytes)
		r.ingestMu.Unlock()
		if err != nil {
			r.logger.Warn("materialize: persist blob failed", "documentCID", key.DocumentCID, "error", err)
			return
		}
		r.logger.Info("materialize: stored blob", "contentId", contentID, "documentCID", key.DocumentCID)
		return
	}
}
