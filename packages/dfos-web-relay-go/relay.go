package relay

import (
	"crypto/ed25519"
	"errors"
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
	revocationsEnabled bool
	indexEnabled       bool
	writeEnabled       bool // false = LITE pull-only node (POST /operations rejected)
	signingEnabled     bool
	contentFollow      string // "eager" = materialize granted public content blobs; else off
	logger             *slog.Logger
	peers              []PeerConfig
	peerClient         PeerClient
	// authority is THE RELAY'S OWN CONFIGURED AUTHORITY — the host binding for
	// every identity proof. Never read from a request; see RelayOptions.Authority.
	// Empty makes every authenticated route answer 503.
	authority          string
	proofWindowSeconds int64
	proofSkewSeconds   int64
	// jtiCache is the replay cache for write-shaped proofs (ingestion, blob
	// upload). Defaults to the in-memory per-process implementation; a
	// multi-process deployment injects its own (RelayOptions.JtiCache).
	jtiCache JtiCache
	// ingestionMode is the advertised admission mode; admissionPolicy is step 3
	// of the ingestion ladder.
	ingestionMode   IngestionMode
	admissionPolicy AdmissionPolicy
	// privateKey / keyID are the relay's OWN signing material, retained for the
	// single purpose of minting an identity proof on gossip-out. Nil = gossip
	// anonymously.
	privateKey        ed25519.PrivateKey
	keyID             string
	gossipProofSigned bool
	ingestMu          sync.Mutex // serializes all chain-state mutations (ingest + sequencer)
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
	// peerSync holds the per-peer sync-loop status served at stats.peerSync in
	// the well-known. In-memory only, like reconcileCycle — it describes THIS
	// process's loop, not durable state, and a restart honestly resets it.
	// Seeded at construction with one entry per sync-eligible peer so a peer
	// that has never been reached still appears (null timestamps) instead of
	// being silently absent.
	peerSyncMu sync.Mutex
	peerSync   map[string]*PeerSyncStatus
	// maxOpsPerSyncCycle is this relay's per-peer per-cycle fetch cap, defaulted
	// from the package constant of the same name. A field rather than a bare
	// const read so tests can lower it and exercise the backlog boundary (a
	// backlog that ends on an exact multiple of the cap is the case the
	// caught-up logging has to get right) without minting thousands of ops.
	maxOpsPerSyncCycle int
	// materializeMu coalesces content-follow sweeps: both the timer sweep and the
	// trigger-kicked sweep (fired when the sequencer makes progress) call
	// MaterializeFollowedContent, and a TryLock here makes a concurrent caller a
	// no-op rather than a redundant second pass. gcMu does the same for the GC sweep.
	materializeMu sync.Mutex
	gcMu          sync.Mutex
	// materializeDirty / gcDirty are the event-driven work queues for content
	// following. The sequencer records the contentIDs (or a full-scan request) that
	// new ops make relevant; the sweeps drain them. This is what keeps a steady-
	// state follower idle instead of re-scanning every chain and re-verifying every
	// grant on each sync tick. nil unless ContentFollow == "eager".
	materializeDirty *dirtyQueue
	gcDirty          *dirtyQueue
	// blobSourceCooldown is the per-peer circuit breaker for blob pulls: a peer
	// that fails a fetch with a transport/5xx error (NOT a 404 — that's "ask
	// elsewhere," not "down") is suppressed until the stored unix-nanos deadline,
	// so a dead origin isn't hammered once per granted chain every sweep. Keyed by
	// peer URL → int64 deadline; a sync.Map because sweeps fetch concurrently.
	blobSourceCooldown sync.Map
}

// NewRelay creates a new Relay instance. If no identity is provided, a JIT
// identity and profile artifact are generated.
func NewRelay(opts RelayOptions) (*Relay, error) {
	if opts.Store == nil {
		return nil, fmt.Errorf("store is required")
	}

	contentEnabled := opts.Content == nil || *opts.Content
	logEnabled := opts.Log == nil || *opts.Log
	revocationsEnabled := opts.Revocations == nil || *opts.Revocations
	indexEnabled := opts.Index == nil || *opts.Index
	writeEnabled := opts.Write == nil || *opts.Write
	signingEnabled := opts.Signing != nil && *opts.Signing
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
	if signingEnabled {
		if _, ok := opts.Store.(SigningStore); !ok {
			return nil, fmt.Errorf("signing capability requires an ingestion store implementing SigningStore")
		}
		if _, ok := readStore.(SigningStore); !ok {
			return nil, fmt.Errorf("signing capability requires a read store implementing SigningStore")
		}
	}
	// Retention is independent of the capability flag: sweep courier state at
	// construction whenever the backing store supports signing.
	if signingStore, ok := opts.Store.(SigningStore); ok {
		if err := signingStore.PruneExpiredSignRequests(time.Now()); err != nil {
			return nil, fmt.Errorf("prune expired sign requests: %w", err)
		}
	}

	proofWindow := opts.ProofWindowSeconds
	if proofWindow == 0 {
		proofWindow = DefaultProofWindowSeconds
	}
	proofSkew := opts.ProofSkewSeconds
	if proofSkew == 0 {
		proofSkew = DefaultProofSkewSeconds
	}

	// Ingestion admission. Explicit wins; absent derives from the write capability
	// (WEB-RELAY.md, well-known `ingestion`). A relay with writes off is closed
	// whatever it asked for — the capability gate fires first and answers 501.
	//
	// An unrecognized spelling is refused HERE rather than serving as its silent
	// fallback: the routes special-case only "closed" and "proof-required", so a
	// typo would run OPEN while the well-known advertised the typo.
	ingestionMode := opts.Ingestion
	switch ingestionMode {
	case "", IngestionOpen, IngestionProofRequired, IngestionClosed:
	default:
		return nil, fmt.Errorf("unknown ingestion mode: %q (expected %s, %s, %s)",
			ingestionMode, IngestionOpen, IngestionProofRequired, IngestionClosed)
	}
	if ingestionMode == "" {
		ingestionMode = IngestionOpen
	}
	if !writeEnabled {
		ingestionMode = IngestionClosed
	}
	// Default policy: ADMIT EVERYTHING — today's behavior, stated as a policy
	// rather than as the absence of one.
	admissionPolicy := opts.AdmissionPolicy
	if admissionPolicy == nil {
		admissionPolicy = func(string) (bool, error) { return true, nil }
	}

	// Gossip-out can announce this relay as a NAMED peer by signing an identity
	// proof of its own DID — OPT-IN, because a presented proof is not optional to
	// the receiver: a peer that has never ingested this relay's identity chain
	// answers 503, so signing unilaterally would refuse pushes that were being
	// accepted. See RelayOptions.GossipIdentityProof.
	gossipProofSigned := opts.GossipIdentityProof != nil && *opts.GossipIdentityProof &&
		identity.PrivateKey != nil && identity.KeyID != ""

	// Index projection startup rebuild: when index is enabled and a durable store
	// carries a stale (or unstamped) projection_version, rebuild all projection
	// rows from the authoritative chain/countersign tables synchronously, before
	// serving. Migrates a pre-existing corpus on redeploy with zero manual steps.
	if indexEnabled {
		if err := rebuildIndexProjection(opts.Store, logger); err != nil {
			return nil, fmt.Errorf("rebuild index projection: %w", err)
		}
	}

	// One status row per peer the sync loop will actually poll — an explicitly
	// sync:false peer is configured for gossip only and has no sync state to report.
	// Injected when the deployment needs a replay cache wider than this process;
	// see RelayOptions.JtiCache.
	jtiCache := opts.JtiCache
	if jtiCache == nil {
		jtiCache = NewJtiReplayCache()
	}

	peerSync := make(map[string]*PeerSyncStatus, len(opts.Peers))
	for _, p := range opts.Peers {
		if p.Sync != nil && !*p.Sync {
			continue
		}
		peerSync[p.URL] = &PeerSyncStatus{}
	}

	return &Relay{
		store:              opts.Store,
		readStore:          readStore,
		did:                identity.DID,
		profileArtifactJWS: identity.ProfileArtifactJWS,
		contentEnabled:     contentEnabled,
		logEnabled:         logEnabled,
		revocationsEnabled: revocationsEnabled,
		indexEnabled:       indexEnabled,
		writeEnabled:       writeEnabled,
		signingEnabled:     signingEnabled,
		contentFollow:      opts.ContentFollow,
		logger:             logger,
		peers:              opts.Peers,
		peerClient:         opts.PeerClient,
		authority:          opts.Authority,
		proofWindowSeconds: proofWindow,
		proofSkewSeconds:   proofSkew,
		jtiCache:           jtiCache,
		ingestionMode:      ingestionMode,
		admissionPolicy:    admissionPolicy,
		privateKey:         identity.PrivateKey,
		keyID:              identity.KeyID,
		gossipProofSigned:  gossipProofSigned,
		reconcileCycle:     make(map[string]int),
		peerSync:           peerSync,
		maxOpsPerSyncCycle: maxOpsPerSyncCycle,
		materializeDirty:   newDirtyQueue(),
		gcDirty:            newDirtyQueue(),
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
			r.store.PutRawOp(rawCIDs[i], token, OpOriginDirect)
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
				// Mark content-follow work here too: ops arriving via gossip-push or a
				// direct client write are sequenced in THIS immediate batch (not the
				// runSequencerLocked pass below, which then sees them as duplicates), so
				// without this an eager follower would only materialize them on the slow
				// reconcile backstop. Mirrors the sequencer-loop marking.
				r.markContentFollowDirty(res, tokens[i])
			}
		case res.Status == "duplicate":
			if err := r.store.MarkOpsSequenced([]string{rawCID}); err != nil {
				r.logger.Error("ingest: failed to mark duplicate op sequenced", "cid", rawCID, "error", err)
			}
			dupCount++
		case res.Status == "rejected" && isPermanentRejection(res):
			// see the sequencer twin: log before the row is dropped, since
			// MarkOpRejected deletes it and the reason is otherwise discarded.
			// Same event string and fields as the TS twin and the sequencer site.
			r.logger.Warn("relay.op.rejected", "cid", rawCID, "reason", res.Error)
			r.store.MarkOpRejected(rawCID, res.Error)
			rejCount++
		}
	}

	if hasBatch {
		// Two ways to end up holding nothing, with one outcome. Either a write
		// inside the batch failed — leaving that op half-applied, which poisons
		// its own retry, since the writes that DID land make every later attempt
		// short-circuit as a "duplicate" and the ones that failed are never made
		// up — or the commit itself failed. Both mean the batch must be
		// discarded rather than half-kept.
		err := errPartialWriteRolledBack
		discard := batchPersistFailed(results)
		if !discard {
			err = batchable.CommitWriteBatch()
			discard = err != nil
		}
		if discard {
			// The batch's chain-state writes are GONE. Nothing this batch
			// claimed to land is actually held, so the batch must neither be
			// gossiped nor reported as landed — the same rule the per-op
			// MarkOpsSequenced guard above enforces, applied to the whole batch.
			// The raw ops were stored BEFORE the batch opened, so every op here
			// stays pending and the sequencer retries it once the store is
			// healthy; the results are rewritten to the retryable
			// persistence-failure shape (persistError) to say exactly that.
			// Permanent rejections are left alone: that verdict is a function of
			// the op against the pre-batch state, which is the state a retry
			// sees, so it remains true and claims nothing about what we hold.
			r.logger.Error("write batch rolled back, not gossiped", "error", err, "ops", len(tokens))
			batchable.RollbackWriteBatch()
			newOps = nil
			newCount, dupCount = 0, 0
			for i, res := range results {
				if res.Status == "new" || res.Status == "duplicate" {
					results[i] = *persistError(res.CID, err)
				}
			}
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
// minutes — catch-up happens incrementally over multiple cycles. Each relay
// copies this into its own maxOpsPerSyncCycle field at construction; the sync
// loop reads the field.
const maxOpsPerSyncCycle = 5000

// Bounded anti-entropy ("reconcile scrubber") — defense-in-depth for the
// forward pull. The forward pull tracks a single high-water cursor and can only
// move forward; if that cursor ever becomes stale or unusable against a peer,
// the pull silently fetches nothing and the relay stops converging. That happens
// in practice: a relay that persisted a cursor a peer no longer accepts or no
// longer recognizes (e.g. a bare CID fabricated by the pre-fix pullPeerOps — see
// the cursor-fabrication note in pullPeerOps for what real peers do with one),
// or any peer whose log ordering can place an op behind an already-advanced
// cursor. The scrubber is a slow SECOND
// cursor that re-walks the peer's log in bounded windows so the relay
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
		attemptAt := time.Now()
		// readStore for the cursor read — never races on the ingestion tx.
		cursor, _ := r.readStore.GetPeerCursor(peer.URL)
		res := r.pullPeerOps(peer.URL, cursor, r.maxOpsPerSyncCycle, true)
		// Caught up means the cycle ran to the end of the peer's log, which only
		// a cycle that actually COMPLETED can claim: a failed pass and an
		// unresolved cursor reset both receive nothing too, and reading a bare
		// zero as "caught up" would paint a wedged peer green.
		caughtUp := !res.failed && !res.resetUnresolved && res.received < r.maxOpsPerSyncCycle
		wasCaughtUp := r.recordPeerSync(peer.URL, attemptAt, res, caughtUp)
		// Log the work, and log the EDGE into caught-up. Logging every quiet
		// cycle would bury the mesh in noise; logging only cycles that received
		// something makes a caught-up relay indistinguishable from a dead sync
		// goroutine, and never announces catch-up at all when the backlog ends on
		// an exact multiple of the cap (that cycle receives a full cap's worth
		// and reports caughtUp:false; the next receives nothing). The edge is
		// what covers both.
		if res.received > 0 || caughtUp != wasCaughtUp {
			r.logger.Info("peer sync cycle",
				"peer", peer.URL,
				"received", res.received,
				"inserted", res.inserted,
				"caughtUp", caughtUp,
			)
		}
		// Bounded anti-entropy: self-heal a wedged/stale forward cursor.
		if !res.resetUnresolved {
			r.reconcilePeer(peer.URL, res.cursor)
		}
	}

	// sequence all stored ops — fixed-point loop until no more progress
	r.RunSequencerAndGossip()
	return nil
}

// pullResult reports one pass of pullPeerOps over a peer's log.
type pullResult struct {
	// received counts entries the peer served, duplicates included; inserted
	// counts the rows that were genuinely new to the raw store. Every pass
	// re-reads at least the final partial page, and the scrub sweep re-walks the
	// log on purpose, so the two diverge routinely — reporting only received
	// overstates the work done and hides a peer that is serving but adding nothing.
	received int
	inserted int
	cursor   string // the cursor this pass reached
	// resetUnresolved reports that a cursor reset was attempted this pass and
	// never landed a page to persist it against.
	resetUnresolved bool
	// failed reports that a transport or store error ended the pass early, so
	// received==0 does NOT mean "nothing left to fetch".
	failed bool
}

// pullPeerOps fetches up to maxOps ops from peerURL starting at startCursor,
// storing each op deduped by its locally-computed storage CID. When persist is
// true the peer's high-water cursor is advanced as each page commits (the normal
// forward pull); when false the stored high-water cursor is left untouched and
// the caller owns the cursor bookkeeping (the bounded scrub sweep). On a
// transient store failure it stops without advancing, so the same page is
// re-fetched next cycle.
func (r *Relay) pullPeerOps(peerURL, startCursor string, maxOps int, persist bool) pullResult {
	cursor := startCursor
	fetched := 0
	inserted := 0
	failed := false
	resetAttempted := false
	resetPending := false
	for fetched < maxOps {
		page, err := r.peerClient.GetOperationLog(peerURL, cursor, 1000)
		if errors.Is(err, ErrPeerInvalidCursor) {
			if resetAttempted {
				r.logger.Warn("peer sync: peer rejected cursor again after reset — aborting cycle", "peer", peerURL)
				failed = true
				break
			}
			// The peer no longer recognizes our persisted cursor (wiped/rebuilt
			// log, or a pre-fix fabricated cursor). Reset only in memory and
			// persist it only after a from-scratch page succeeds.
			r.logger.Warn("peer sync: peer rejected cursor — resetting", "peer", peerURL)
			resetAttempted = true
			resetPending = true
			cursor = ""
			continue
		}
		if err != nil {
			r.logger.Error("peer sync failed", "peer", peerURL, "error", err)
			failed = true
			break
		}
		if page == nil {
			// A peer that answers with neither a page nor an error told us
			// nothing. Count it as a failed pass rather than an empty log —
			// otherwise a peer stuck in this state reads as permanently caught up.
			failed = true
			break
		}
		if len(page.Entries) == 0 {
			if resetPending {
				if persist {
					resume := ""
					if page.Resume() != nil {
						resume = *page.Resume()
					}
					if err := r.store.SetPeerCursor(peerURL, resume); err != nil {
						r.logger.Error("peer sync: failed to persist peer cursor reset", "peer", peerURL, "error", err)
					} else {
						resetPending = false
					}
				} else {
					resetPending = false
				}
			}
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
			isNew, err := r.store.PutRawOp(cid, e.JWSToken, OpOriginPeer)
			if err != nil {
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
			if isNew {
				inserted++
			}
		}
		if pageStoreFailed {
			failed = true
			r.ingestMu.Unlock()
			break
		}
		fetched += len(page.Entries)
		if page.Resume() == nil {
			// The peer signals no further pages from this cursor. Do NOT
			// fabricate a resume cursor from the last entry's CID — a cursor is
			// the peer's to mint, and what a peer does with one we invented is
			// not something we get to assume.
			//
			// Measured against relay.dfos.com on 2026-08-26: its log cursor is
			// base64 of a plain decimal sequence integer, and an `after` value it
			// does not recognize is answered with 200 and a full FROM-SCRATCH
			// first page — not an empty page, and not the 400 this spec
			// prescribes. So a fabricated bare CID does not wedge against that
			// relay; it silently restarts the walk at the head of the log, which
			// is self-correcting but re-streams the corpus on every cycle. A peer
			// that answers an unrecognized cursor with an EMPTY page instead
			// stalls the forward pull here permanently (the bug this fixes).
			//
			// One rule avoids both outcomes: never fabricate. Retain the last
			// peer-supplied cursor (already persisted) so the next cycle resumes
			// with a token the peer minted; it re-fetches the final partial page,
			// which dedups cheaply. Only a spec-compliant 400 counts as the reset
			// signal (ErrPeerInvalidCursor) — a 200 is progress, however odd its
			// contents, and must never be read as "reset your cursor". A relay
			// that already persisted a fabricated bare CID (pre-fix) self-heals
			// via the bounded reconcile scrubber, which re-walks from the start.
			if resetPending {
				if persist {
					if err := r.store.SetPeerCursor(peerURL, ""); err != nil {
						r.logger.Error("peer sync: failed to persist peer cursor reset", "peer", peerURL, "error", err)
					} else {
						resetPending = false
					}
				} else {
					resetPending = false
				}
			}
			r.ingestMu.Unlock()
			break
		}
		cursor = *page.Resume()
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
			resetPending = false
		} else {
			resetPending = false
		}
		r.ingestMu.Unlock()
	}
	return pullResult{
		received:        fetched,
		inserted:        inserted,
		cursor:          cursor,
		resetUnresolved: resetPending,
		failed:          failed,
	}
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

	sweptAt := time.Now()
	rcKey := peerURL + reconcileCursorSuffix
	anchor, _ := r.readStore.GetPeerCursor(rcKey)
	res := r.pullPeerOps(peerURL, anchor, reconcileWindow, false)

	// Advance the trailing cursor; lap back to the start once the scrub reaches
	// the head (short page, or caught up to the forward high-water mark), so the
	// next pass re-walks from the oldest op and no back-dated op is missed for
	// more than one lap.
	lapped := res.received < reconcileWindow || res.cursor == "" || res.cursor == highWater
	next := res.cursor
	if lapped {
		next = ""
	}
	if err := r.store.SetPeerCursor(rcKey, next); err != nil {
		r.logger.Error("peer reconcile: failed to persist scrub cursor",
			"peer", peerURL,
			"error", err,
		)
	}
	r.recordPeerReconcile(peerURL, sweptAt, res)
	// One line per SWEEP, not per sweep that found something. The scrub already
	// paces itself at one run per reconcileEveryCycles, so this is a
	// low-frequency heartbeat rather than noise — and a sweep that finds nothing
	// is exactly the case that has to be visible, because it is otherwise
	// identical from the outside to a scrubber that has stopped running.
	// received almost always exceeds inserted here: re-walking is the point.
	r.logger.Info("peer reconcile sweep",
		"peer", peerURL,
		"received", res.received,
		"inserted", res.inserted,
		"lapped", lapped,
		"failed", res.failed,
	)
}

// recordPeerSync folds one forward-pull pass into the peer's status and returns
// the caughtUp value it replaced, so the caller can log the edge into caught-up
// rather than a line every quiet cycle.
func (r *Relay) recordPeerSync(peerURL string, attemptAt time.Time, res pullResult, caughtUp bool) (wasCaughtUp bool) {
	r.peerSyncMu.Lock()
	defer r.peerSyncMu.Unlock()
	st := r.peerStatusLocked(peerURL)
	wasCaughtUp = st.CaughtUp
	st.LastAttemptAt = telemetryTime(attemptAt)
	st.LastReceived = res.received
	st.LastInserted = res.inserted
	st.CaughtUp = caughtUp
	if res.failed {
		st.ConsecutiveFailures++
	} else {
		st.ConsecutiveFailures = 0
		st.LastSuccessAt = telemetryTime(attemptAt)
	}
	return wasCaughtUp
}

// recordPeerReconcile folds one anti-entropy sweep into the peer's status.
func (r *Relay) recordPeerReconcile(peerURL string, sweptAt time.Time, res pullResult) {
	r.peerSyncMu.Lock()
	defer r.peerSyncMu.Unlock()
	st := r.peerStatusLocked(peerURL)
	st.LastReconcileAt = telemetryTime(sweptAt)
	st.LastReconcileReceived = res.received
	st.LastReconcileInserted = res.inserted
}

// peerStatusLocked returns the peer's status row, creating it if the peer was
// not seeded at construction. Caller holds peerSyncMu.
func (r *Relay) peerStatusLocked(peerURL string) *PeerSyncStatus {
	st := r.peerSync[peerURL]
	if st == nil {
		st = &PeerSyncStatus{}
		r.peerSync[peerURL] = st
	}
	return st
}

// PeerSyncStatuses returns a snapshot of per-peer sync status keyed by peer URL,
// empty when no sync-eligible peer is configured. The values are copies; the
// timestamp pointers they carry are shared with the live rows, which is safe
// because the record* helpers always assign a FRESH pointer and never write
// through an existing one.
func (r *Relay) PeerSyncStatuses() map[string]PeerSyncStatus {
	r.peerSyncMu.Lock()
	defer r.peerSyncMu.Unlock()
	out := make(map[string]PeerSyncStatus, len(r.peerSync))
	for url, st := range r.peerSync {
		out[url] = *st
	}
	return out
}

// telemetryTime formats t in the same timestamp grammar the well-known's
// oldestOpAt uses, and returns a fresh pointer.
func telemetryTime(t time.Time) *string {
	s := t.UTC().Format("2006-01-02T15:04:05.000Z")
	return &s
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
