package relay

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// BatchableStore is optionally implemented by stores that support wrapping
// writes in a single transaction.
type BatchableStore interface {
	BeginWriteBatch() error
	CommitWriteBatch() error
	RollbackWriteBatch() error
}

// Relay is a DFOS web relay — the core verification and storage engine.
type Relay struct {
	store              Store // ingestion store — sees write transactions for within-batch reads
	readStore          Store // HTTP read store — always uses WAL read pool, never races on tx
	did                string
	profileArtifactJWS string
	contentEnabled     bool
	logEnabled         bool
	writeEnabled       bool   // false = LITE pull-only node (POST /operations rejected)
	contentFollow      string // "eager" = materialize granted public content blobs; else off
	logger             *slog.Logger
	peers              []PeerConfig
	peerClient         PeerClient
	maxAuthTokenTTL    time.Duration // ceiling on self-signed auth-token lifetime (exp-iat)
	ingestMu           sync.Mutex    // serializes all chain-state mutations (ingest + sequencer)
	// gossipDisabled holds peer URLs that rejected a gossip push as pull-only
	// (HTTP 501, write-disabled). Pushing to them is guaranteed to 501, so once
	// a peer rejects we suppress all further gossip to it for the process
	// lifetime. Keyed by peer URL (values struct{}); a sync.Map because gossipOps
	// records hits from concurrent per-batch goroutines.
	gossipDisabled sync.Map
	// reconcileCycle counts sync cycles per peer URL to pace the bounded
	// anti-entropy scrubber (see reconcilePeer). In-memory only — the scrubber's
	// trailing position is persisted in peer_cursors; the cadence counter just
	// resets to 0 on restart. SyncFromPeers is the sole caller and runs on one
	// ticker goroutine, but reconcileMu guards it so a future concurrent caller
	// stays correct.
	reconcileMu    sync.Mutex
	reconcileCycle map[string]int
}

// NewRelay creates a new Relay instance. If no identity is provided, a JIT
// identity and profile artifact are generated.
func NewRelay(opts RelayOptions) (*Relay, error) {
	if opts.Store == nil {
		return nil, fmt.Errorf("store is required")
	}

	contentEnabled := opts.Content == nil || *opts.Content
	logEnabled := opts.Log == nil || *opts.Log
	writeEnabled := opts.Write == nil || *opts.Write

	identity := opts.Identity
	if identity == nil {
		var err error
		identity, err = BootstrapRelayIdentity(opts.Store)
		if err != nil {
			return nil, fmt.Errorf("bootstrap relay identity: %w", err)
		}
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// If the store supports it, create a read-only view for HTTP handlers
	// that never races on the write transaction. Falls back to the main store
	// for non-SQLite backends (e.g. in-memory test store).
	readStore := opts.Store
	if sqlStore, ok := opts.Store.(*SQLiteStore); ok {
		readStore = sqlStore.ReadStore()
	}

	maxAuthTokenTTL := opts.MaxAuthTokenTTL
	if maxAuthTokenTTL == 0 {
		maxAuthTokenTTL = DefaultMaxAuthTokenTTL
	}

	return &Relay{
		store:              opts.Store,
		readStore:          readStore,
		did:                identity.DID,
		profileArtifactJWS: identity.ProfileArtifactJWS,
		contentEnabled:     contentEnabled,
		logEnabled:         logEnabled,
		writeEnabled:       writeEnabled,
		contentFollow:      opts.ContentFollow,
		logger:             logger,
		peers:              opts.Peers,
		peerClient:         opts.PeerClient,
		maxAuthTokenTTL:    maxAuthTokenTTL,
		reconcileCycle:     make(map[string]int),
	}, nil
}

// DID returns the relay's DID.
func (r *Relay) DID() string { return r.did }

// ProfileArtifactJWS returns the relay's profile artifact JWS token.
func (r *Relay) ProfileArtifactJWS() string { return r.profileArtifactJWS }

// Ingest stores raw ops, processes a batch for immediate results, and gossips.
func (r *Relay) Ingest(tokens []string) []IngestionResult {
	start := time.Now()

	// process immediately — mutex serializes all chain-state mutations.
	// Raw-op writes go through writerDB(), which aliases the active batch
	// transaction, so they must also be serialized under ingestMu — otherwise
	// a concurrent sequencer batch races on s.tx.
	r.ingestMu.Lock()

	// store all raw ops first — they can never be lost. Capture each row's
	// storage CID (computeOpCID) so the drain loop below reuses the exact same
	// key it was stored under, rather than recomputing it (or trusting res.CID,
	// which can diverge — see the sequencer loop).
	rawCIDs := make([]string, len(tokens))
	for i, token := range tokens {
		rawCIDs[i] = computeOpCID(token)
		if rawCIDs[i] != "" {
			r.store.PutRawOp(rawCIDs[i], token)
		}
	}

	// wrap in a transaction if the store supports it
	batchable, hasBatch := r.store.(BatchableStore)
	if hasBatch {
		if err := batchable.BeginWriteBatch(); err != nil {
			r.logger.Error("failed to begin write batch", "error", err)
			hasBatch = false
		}
	}

	var opts []IngestOption
	if !r.logEnabled {
		opts = append(opts, WithLogDisabled())
	}
	results := IngestOperations(tokens, r.store, opts...)

	// mark results in raw store
	var newOps []string
	var newCount, dupCount, rejCount int
	for i, res := range results {
		// Drain raw_ops by the storage CID (PutRawOp's key, captured above) and
		// GATE on it too, not res.CID — see runSequencerLocked for why res.CID (the
		// JWS-header-claimed CID) can diverge: it may be empty for a decodable-but-
		// malformed credential whose payload still hashed to a real, stored rawCID,
		// so gating on res.CID=="" would strand that row 'pending' forever.
		// rawCID=="" ⇒ undecodable token ⇒ PutRawOp was skipped ⇒ nothing to drain.
		rawCID := rawCIDs[i]
		if rawCID == "" {
			continue
		}
		switch {
		case res.Status == "new":
			// Only gossip if the sequenced status was actually persisted —
			// otherwise local state and what we'd advertise diverge. On failure
			// the op stays pending and the sequencer retries it.
			if err := r.store.MarkOpsSequenced([]string{rawCID}); err != nil {
				r.logger.Error("ingest: failed to mark op sequenced — skipping gossip", "cid", rawCID, "error", err)
			} else {
				newOps = append(newOps, tokens[i])
				newCount++
			}
		case res.Status == "duplicate":
			if err := r.store.MarkOpsSequenced([]string{rawCID}); err != nil {
				r.logger.Error("ingest: failed to mark duplicate op sequenced", "cid", rawCID, "error", err)
			}
			dupCount++
		case res.Status == "rejected" && isPermanentRejection(res):
			r.store.MarkOpRejected(rawCID, res.Error)
			rejCount++
		}
	}

	if hasBatch {
		if err := batchable.CommitWriteBatch(); err != nil {
			r.logger.Error("failed to commit write batch", "error", err)
			batchable.RollbackWriteBatch()
		}
	}

	// run sequencer after commit — reads must see the committed status updates
	seqNewOps, _ := r.runSequencerLocked()

	r.ingestMu.Unlock()

	r.logger.Info("ingest complete",
		"batch", len(tokens),
		"new", newCount,
		"duplicate", dupCount,
		"rejected", rejCount,
		"duration", time.Since(start),
	)

	// gossip outside the lock
	r.gossipOps(newOps)
	r.gossipOps(seqNewOps)

	return results
}

// maxOpsPerSyncCycle caps how many ops are fetched from a single peer in one
// sync cycle. This prevents a large backlog from blocking the relay for
// minutes — catch-up happens incrementally over multiple cycles.
const maxOpsPerSyncCycle = 5000

// Bounded anti-entropy ("reconcile scrubber") — defense-in-depth for the
// forward pull. The forward pull tracks a single high-water cursor and can only
// move forward; if that cursor ever becomes stale or unusable against a peer,
// the pull silently fetches nothing and the relay stops converging. That happens
// in practice: a relay that persisted a cursor a peer no longer accepts (e.g. a
// bare CID fabricated by the pre-fix pullPeerOps, which the production relay's
// timestamp|cid pagination returns empty for), or any peer whose log ordering
// can place an op behind an already-advanced cursor. The scrubber is a slow
// SECOND cursor that re-walks the peer's log in bounded windows so the relay
// self-heals regardless of how the high-water cursor got wedged. Each sweep
// re-fetches at most reconcileWindow ops (dedup makes the re-fetch cheap) and
// advances a persisted trailing cursor; when it reaches the head it laps back to
// the start, re-walking the whole log over time WITHOUT ever re-streaming the
// corpus in a single tick. A deliberate, immediate full re-sync remains a
// separate on-purpose operation (ResetPeerCursors / RESYNC), not this routine
// background scrub.
const (
	// reconcileEveryCycles is the number of sync cycles between scrub sweeps.
	// Wall-clock cadence is this times SYNC_INTERVAL.
	reconcileEveryCycles = 12
	// reconcileWindow caps ops re-fetched per sweep — the "sensible number of
	// ops back" we re-examine, never the full corpus at once.
	reconcileWindow = 2000
	// reconcileCursorSuffix mangles the peer URL into a second peer_cursors key
	// so the scrubber's trailing position persists alongside (but distinct from)
	// the high-water cursor. ResetPeerCursors clears both.
	reconcileCursorSuffix = "#reconcile"
)

// SyncFromPeers pulls raw ops from all configured sync peers into the raw
// store, then runs the sequencer to process everything. Fetch volume is
// bounded by maxOpsPerSyncCycle per peer per cycle — if more ops are available
// the next cycle picks up where the cursor left off. Each cycle also advances a
// bounded anti-entropy scrubber per peer (see reconcilePeer).
func (r *Relay) SyncFromPeers() error {
	if r.peerClient == nil {
		return nil
	}
	for _, peer := range r.peers {
		if peer.Sync != nil && !*peer.Sync {
			continue
		}
		// readStore for the cursor read — never races on the ingestion tx.
		cursor, _ := r.readStore.GetPeerCursor(peer.URL)
		fetched, reached := r.pullPeerOps(peer.URL, cursor, maxOpsPerSyncCycle, true)
		if fetched > 0 {
			r.logger.Info("peer sync fetched ops",
				"peer", peer.URL,
				"ops", fetched,
				"caughtUp", fetched < maxOpsPerSyncCycle,
			)
		}
		// Bounded anti-entropy: self-heal a wedged/stale forward cursor.
		r.reconcilePeer(peer.URL, reached)
	}

	// sequence all stored ops — fixed-point loop until no more progress
	r.RunSequencerAndGossip()
	return nil
}

// pullPeerOps fetches up to maxOps ops from peerURL starting at startCursor,
// storing each op deduped by its locally-computed storage CID. It returns the
// number of ops stored and the cursor reached. When persist is true the peer's
// high-water cursor is advanced as each page commits (the normal forward pull);
// when false the stored high-water cursor is left untouched and the caller owns
// the cursor bookkeeping (the bounded scrub sweep). On a transient store failure
// it stops without advancing, so the same page is re-fetched next cycle.
func (r *Relay) pullPeerOps(peerURL, startCursor string, maxOps int, persist bool) (int, string) {
	cursor := startCursor
	fetched := 0
	for fetched < maxOps {
		page, err := r.peerClient.GetOperationLog(peerURL, cursor, 1000)
		if err != nil {
			r.logger.Error("peer sync failed", "peer", peerURL, "error", err)
			break
		}
		if page == nil || len(page.Entries) == 0 {
			break
		}
		// Raw-op + cursor writes go through the ingestion store's writerDB(),
		// which aliases the active batch transaction. Hold ingestMu so these
		// writes don't race on s.tx with a concurrent ingest/sequencer batch.
		r.ingestMu.Lock()
		pageStoreFailed := false
		for _, e := range page.Entries {
			// Compute the CID LOCALLY from the token — never trust the
			// peer-claimed CID. A mismatched cid would key the raw_ops row
			// by a bogus CID; the sequencer's MarkOpsSequenced(realCID)
			// would then match no row and loop forever holding ingestMu.
			// Undecodable tokens are skipped (computeOpCID returns "")
			// rather than stored under an empty key.
			cid := computeOpCID(e.JWSToken)
			if cid == "" {
				r.logger.Warn("peer sync: skipping undecodable op",
					"peer", peerURL,
					"claimedCID", e.CID,
				)
				continue
			}
			if err := r.store.PutRawOp(cid, e.JWSToken); err != nil {
				// Durability discipline (mirrors Ingest's "never advance past
				// unpersisted work"): on a transient store failure, do NOT
				// advance the cursor — otherwise the next cycle resumes AFTER
				// the dropped op and it is permanently lost. Stop the page and
				// re-fetch this same page next cycle.
				r.logger.Error("peer sync: failed to store raw op — not advancing cursor",
					"peer", peerURL,
					"cid", cid,
					"error", err,
				)
				pageStoreFailed = true
				break
			}
		}
		if pageStoreFailed {
			r.ingestMu.Unlock()
			break
		}
		fetched += len(page.Entries)
		if page.Cursor == nil {
			// The peer signals no further pages from this cursor. Do NOT
			// fabricate a resume cursor from the last entry's CID: a peer whose
			// cursor format is not a bare CID — notably the production relay,
			// which pages a timestamp|cid cursor and returns null on the final
			// page — serves an EMPTY page for an unrecognized bare CID, which
			// permanently stalls the forward pull at this point (the bug this
			// fixes). Retain the last peer-supplied cursor (already persisted)
			// so the next cycle resumes with a token the peer understands; it
			// re-fetches the final partial page, which dedups cheaply. A relay
			// that already persisted a fabricated bare CID (pre-fix) self-heals
			// via the bounded reconcile scrubber, which re-walks from the start.
			r.ingestMu.Unlock()
			break
		}
		cursor = *page.Cursor
		if persist {
			// Check the SetPeerCursor return — a silent failure here would let
			// the high-water mark drift. On failure, stop without persisting
			// further progress; the same page is re-fetched next cycle.
			if err := r.store.SetPeerCursor(peerURL, cursor); err != nil {
				r.logger.Error("peer sync: failed to persist peer cursor — backing off",
					"peer", peerURL,
					"cursor", cursor,
					"error", err,
				)
				r.ingestMu.Unlock()
				break
			}
		}
		r.ingestMu.Unlock()
	}
	return fetched, cursor
}

// reconcilePeer advances the bounded anti-entropy scrubber for one peer. Every
// reconcileEveryCycles cycles it re-scans up to reconcileWindow ops forward from
// a persisted trailing cursor, recovering any op the forward pull's high-water
// cursor misses — including the case where that cursor is wedged or stale and
// the forward pull is fetching nothing. The trailing cursor laps back to the
// start once it reaches the head, so over time the scrub re-walks the whole log
// in bounded steps. highWater is the cursor the normal forward pull reached this
// cycle, used only to detect when the scrubber has caught up to the head.
func (r *Relay) reconcilePeer(peerURL, highWater string) {
	r.reconcileMu.Lock()
	n := r.reconcileCycle[peerURL] + 1
	if n < reconcileEveryCycles {
		r.reconcileCycle[peerURL] = n
		r.reconcileMu.Unlock()
		return
	}
	r.reconcileCycle[peerURL] = 0
	r.reconcileMu.Unlock()

	rcKey := peerURL + reconcileCursorSuffix
	anchor, _ := r.readStore.GetPeerCursor(rcKey)
	fetched, reached := r.pullPeerOps(peerURL, anchor, reconcileWindow, false)

	// Advance the trailing cursor; lap back to the start once the scrub reaches
	// the head (short page, or caught up to the forward high-water mark), so the
	// next pass re-walks from the oldest op and no back-dated op is missed for
	// more than one lap.
	next := reached
	if fetched < reconcileWindow || reached == "" || reached == highWater {
		next = ""
	}
	if err := r.store.SetPeerCursor(rcKey, next); err != nil {
		r.logger.Error("peer reconcile: failed to persist scrub cursor",
			"peer", peerURL,
			"error", err,
		)
	}
	if fetched > 0 {
		r.logger.Info("peer reconcile swept ops",
			"peer", peerURL,
			"ops", fetched,
		)
	}
}

// ResetPeerCursors clears all sync cursors, forcing a full re-sync on next cycle.
func (r *Relay) ResetPeerCursors() error {
	return r.store.ResetPeerCursors()
}

// GetIdentity returns a stored identity chain by DID, or nil.
func (r *Relay) GetIdentity(did string) (*StoredIdentityChain, error) {
	return r.store.GetIdentityChain(did)
}

// GetContent returns a stored content chain by content ID, or nil.
func (r *Relay) GetContent(contentID string) (*StoredContentChain, error) {
	return r.store.GetContentChain(contentID)
}

// GetOperation returns a stored operation by CID, or nil.
func (r *Relay) GetOperation(cid string) (*StoredOperation, error) {
	return r.store.GetOperation(cid)
}

// Handler returns an http.Handler implementing the DFOS web relay HTTP API.
// CORS is outermost so OPTIONS preflight is answered before routing and CORS
// headers are present on every response, including errors.
func (r *Relay) Handler() http.Handler {
	return withCORS(r.withRequestLogging(newRouter(r)))
}

func (r *Relay) withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, req)
		duration := time.Since(start)

		level := slog.LevelInfo
		if rw.status == 200 && req.Method == http.MethodGet {
			level = slog.LevelDebug
		}
		r.logger.Log(req.Context(), level, "http request",
			"method", req.Method,
			"path", req.URL.Path,
			"status", rw.status,
			"duration", duration,
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}
