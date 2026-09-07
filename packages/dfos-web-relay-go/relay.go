package relay

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"
)

// Relay is a DFOS web relay — the core verification and storage engine.
//
// WHAT A STORE CAN DO IS A FACT ABOUT ITS TYPE. NewRelay type-asserts each
// further contract ONCE and holds the narrowed reference; the advertised
// capabilities are derived from those assertions plus config. No route probes a
// member, and no member is satisfied by throwing.
type Relay struct {
	// readStore is the base contract every route reads through.
	readStore RelayReadStore
	// writeStore is nil when the store cannot accept operations. A nil here is
	// what makes capabilities.write false and POST /proof/v1/operations answer
	// 501 — not a config flag alone.
	writeStore RelayWriteStore
	// indexRead is nil when the store answers no /index/v0 query.
	indexRead IndexReadStore
	// projection is the store shape the index projection worker needs, nil when
	// this relay does not maintain the projection (either the store keeps its
	// index current some other way, or it has no index at all).
	projection IndexProjectionStore
	// signStore is nil unless the store implements the signing mailbox.
	signStore SigningStore
	// writerState is nil when the store keeps no writer-internal bookkeeping, in
	// which case this relay cannot sequence raw ops or track peer cursors.
	writerState        RelayWriterState
	did                string
	profileArtifactJWS string
	contentEnabled     bool
	logEnabled         bool
	revocationsEnabled bool
	indexEnabled       bool
	writeEnabled       bool // false = LITE pull-only node (POST /operations rejected)
	signingEnabled     bool
	logger             *slog.Logger
	peers              []PeerConfig
	peerClient         PeerClient
	// authority is THE RELAY'S OWN CONFIGURED AUTHORITY — the host binding for
	// every identity proof. Never read from a request; see RelayOptions.Authority.
	// Empty makes every authenticated route answer 503.
	authority          string
	proofWindowSeconds int64
	proofSkewSeconds   int64
	// openapi* cache the served OpenAPI document. Per-relay rather than
	// package-level because the document self-describes: its `servers` names this
	// relay's authority, so two relays in one process serve two documents.
	openapiOnce sync.Once
	openapiJSON []byte
	openapiErr  error
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
	// projectionMode selects who drives the index projection worker;
	// projectionBudget caps one run's work. The worker NEVER runs under ingestMu:
	// that is the structural fix for the fan-out sweeps that used to sit inside
	// the accepting path.
	projectionMode   IndexProjectionMode
	projectionBudget int
	// projectionMu coalesces projection drains. Both the post-ingest kick and an
	// operator's timer call ProjectIndex, and a TryLock here makes a concurrent
	// caller a no-op rather than a redundant second pass over the same cursor.
	projectionMu sync.Mutex
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
	// peerPins caches the per-URL peer-identity pin verdict (see peerpin.go).
	// In-memory and process-local like the two above: it records what a peer
	// served recently, never durable state, and a restart honestly re-asks. It
	// carries its own mutex because the gate is hit from the sync goroutine, the
	// per-chunk gossip goroutines, and request handlers concurrently.
	peerPinMu sync.Mutex
	peerPins  map[string]peerPinVerdict
	// maxOpsPerSyncCycle is this relay's per-peer per-cycle fetch cap, defaulted
	// from the package constant of the same name. A field rather than a bare
	// const read so tests can lower it and exercise the backlog boundary (a
	// backlog that ends on an exact multiple of the cap is the case the
	// caught-up logging has to get right) without minting thousands of ops.
	maxOpsPerSyncCycle int
	// sequencerWindowOps is how many pending rows one keyset window fetches,
	// defaulted from the package constant of the same name. A field for the same
	// reason as maxOpsPerSyncCycle above: the behavior worth testing is what
	// happens when a window fills entirely with rows that cannot advance, and
	// proving that at the production window size costs ten thousand signature
	// verifications per pass to say something a window of four says exactly.
	sequencerWindowOps int
}

// NewRelay creates a new Relay instance. If no identity is provided, a JIT
// identity and profile artifact are generated.
func NewRelay(opts RelayOptions) (*Relay, error) {
	if opts.Store == nil {
		return nil, fmt.Errorf("store is required")
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// ONE NARROWING, AT CONSTRUCTION. Everything below reads a field, never a
	// type assertion, and the capability block the well-known serves is derived
	// from what these assertions found plus what config asked for.
	store := opts.Store
	writeStore, _ := store.(RelayWriteStore)
	indexRead, _ := store.(IndexReadStore)
	signStore, _ := store.(SigningStore)
	writerState, _ := store.(RelayWriterState)

	contentEnabled := opts.Content == nil || *opts.Content
	logEnabled := opts.Log == nil || *opts.Log
	revocationsEnabled := opts.Revocations == nil || *opts.Revocations
	// A capability is what the store can do AND what the operator asked for. A
	// store that cannot write makes this a pull-only proof node whatever the flag
	// says, and a store with no index queries serves no /index/v0 whatever the
	// flag says — advertising otherwise would be a promise the routes cannot keep.
	//
	// Two of these derive from more than the one obvious assertion:
	//
	//   - INDEX NEEDS THE LOG. The projection's only input is ReadLog, and a relay
	//     that publishes no log appends nothing for it to read, so the rows would
	//     stay empty forever. index: true beside log: false is a capability block
	//     that lies.
	//   - WRITE NEEDS THE WRITER STATE. Ingest also needs raw-op and sequencer
	//     bookkeeping (RelayWriterState); a store with Commit but without it
	//     rejects every submitted operation, so advertising write: true would
	//     promise an endpoint that is 100% refusal.
	indexEnabled := (opts.Index == nil || *opts.Index) && indexRead != nil && logEnabled
	writeEnabled := (opts.Write == nil || *opts.Write) && writeStore != nil && writerState != nil
	signingEnabled := opts.Signing != nil && *opts.Signing

	if signingEnabled && signStore == nil {
		return nil, fmt.Errorf("signing capability requires a store implementing SigningStore")
	}
	// An EXPLICIT ask that cannot hold is an error, the same way an explicit
	// signing ask on a store without SigningStore is. Deriving it away silently is
	// right when the flag was defaulted (index defaults on, so every operator who
	// turns the log off would otherwise be refused boot); it is wrong when the
	// operator wrote both flags down and they contradict each other.
	if opts.Index != nil && *opts.Index && !logEnabled {
		return nil, fmt.Errorf("index capability requires the operation log: the projection reads the log and has no other input")
	}
	// Retention is independent of the capability flag: sweep courier state at
	// construction whenever the backing store supports signing.
	if signStore != nil {
		if err := signStore.PruneExpiredSignRequests(time.Now()); err != nil {
			return nil, fmt.Errorf("prune expired sign requests: %w", err)
		}
	}

	// The projection worker needs all three contracts at once, asserted on the
	// store ITSELF rather than assembled from the three narrowed references: a
	// wrapper struct would satisfy the union while hiding the concrete type, and
	// the boot-time rebuild still has to be able to ask whether this store is a
	// RebuildableIndexStore. A store with the queries but not the writes serves an
	// index some other process maintains, which is a supported shape — this relay
	// simply does no projection work for it.
	var projection IndexProjectionStore
	if indexEnabled {
		if p, ok := store.(IndexProjectionStore); ok {
			projection = p
		}
	}

	identity := opts.Identity
	if identity == nil {
		if writeStore == nil {
			return nil, fmt.Errorf("a relay on a read-only store must be given an Identity: bootstrap writes its own chain")
		}
		var err error
		identity, err = BootstrapRelayIdentity(writeStore)
		if err != nil {
			return nil, fmt.Errorf("bootstrap relay identity: %w", err)
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
	// (RELAY.md, The well-known document). A relay with writes off is closed
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

	projectionMode := opts.IndexProjection
	switch projectionMode {
	case "", IndexProjectionInline, IndexProjectionExternal:
	default:
		return nil, fmt.Errorf("unknown index projection mode: %q (expected %s, %s)",
			projectionMode, IndexProjectionInline, IndexProjectionExternal)
	}
	if projectionMode == "" {
		projectionMode = IndexProjectionInline
	}
	projectionBudget := opts.IndexProjectionBudget
	if projectionBudget <= 0 {
		projectionBudget = DefaultIndexProjectionBudget
	}

	// Gossip-out can announce this relay as a NAMED peer by signing an identity
	// proof of its own DID — OPT-IN, because a presented proof is not optional to
	// the receiver: a peer that has never ingested this relay's identity chain
	// answers 503, so signing unilaterally would refuse pushes that were being
	// accepted. See RelayOptions.GossipIdentityProof.
	gossipProofSigned := opts.GossipIdentityProof != nil && *opts.GossipIdentityProof &&
		identity.PrivateKey != nil && identity.KeyID != ""

	// Identity state startup backfill: a row persisted before dfos.IdentityState
	// carried ProvedKeys unmarshals with an absent has-ever-proved union, and
	// every has-ever-proved reader then falls back to the narrower effective
	// arrays — a proved-then-rotated-out key silently stops resolving. Re-walk
	// those rows before serving. Runs UNCONDITIONALLY (the historical key
	// resolver needs it whether or not the index is on) and BEFORE the projection
	// reset below, so a rebuild triggered by the same upgrade materializes the
	// `key=` index from repaired state rather than from the fallback.
	if migratable, ok := store.(MigratableStore); ok {
		rewrote, err := backfillProvedKeyState(migratable, logger)
		if err != nil {
			return nil, fmt.Errorf("backfill identity proved keys: %w", err)
		}
		// A backfill that rewrote rows changed the very state the `key=` index is
		// folded FROM, and the rebuild below reads only the stamped
		// projection_version to decide whether to re-walk. A corpus that first
		// materialized that index under the CURRENT version — from the narrow
		// fallback, before this repair existed — is therefore stamped as already
		// correct, and takes the early-return branch. Invalidating the stamp here
		// is what makes the two migrations one upgrade instead of two that pass in
		// the night; the rebuild is a log re-walk, so the cost is bounded work and
		// the outcome is the same rows a fresh sync would produce.
		if rewrote {
			if rebuildable, ok := store.(RebuildableIndexStore); ok {
				logger.Info("index projection: invalidating the version stamp after an identity-state backfill")
				if err := rebuildable.SetIndexProjectionVersion(0); err != nil {
					return nil, fmt.Errorf("invalidate index projection version: %w", err)
				}
			}
		}
	}

	// Index projection startup rebuild: when a durable store carries a stale (or
	// unstamped) projection_version, clear the rows and reset the cursor. Migrates
	// a pre-existing corpus on redeploy with zero manual steps.
	//
	// The re-walk that follows is the ORDINARY projection worker, not a separate
	// corpus enumeration — the operation log is the authoritative record every row
	// derives from, so a rebuild and an incremental run are the same code. Under
	// the default inline mode it is drained here so the first /index/v0 request
	// sees a complete projection; under "external" the operator's schedule owns
	// it, and a partially drained index is honestly incomplete rather than wrong.
	// On a caught-up relay this is one empty log read.
	if projection != nil {
		if err := rebuildIndexProjection(projection, logger); err != nil {
			return nil, fmt.Errorf("rebuild index projection: %w", err)
		}
		if projectionMode == IndexProjectionInline {
			drainIndexProjection(projection, projectionBudget, 0, logger)
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
		readStore:          store,
		writeStore:         writeStore,
		indexRead:          indexRead,
		projection:         projection,
		signStore:          signStore,
		writerState:        writerState,
		did:                identity.DID,
		profileArtifactJWS: identity.ProfileArtifactJWS,
		contentEnabled:     contentEnabled,
		logEnabled:         logEnabled,
		revocationsEnabled: revocationsEnabled,
		indexEnabled:       indexEnabled,
		writeEnabled:       writeEnabled,
		signingEnabled:     signingEnabled,
		logger:             logger,
		peers:              opts.Peers,
		peerClient:         opts.PeerClient,
		authority:          opts.Authority,
		proofWindowSeconds: proofWindow,
		proofSkewSeconds:   proofSkew,
		jtiCache:           jtiCache,
		ingestionMode:      ingestionMode,
		admissionPolicy:    admissionPolicy,
		projectionMode:     projectionMode,
		projectionBudget:   projectionBudget,
		privateKey:         identity.PrivateKey,
		keyID:              identity.KeyID,
		gossipProofSigned:  gossipProofSigned,
		reconcileCycle:     make(map[string]int),
		peerSync:           peerSync,
		peerPins:           make(map[string]peerPinVerdict),
		maxOpsPerSyncCycle: maxOpsPerSyncCycle,
		sequencerWindowOps: sequencerWindowOps,
	}, nil
}

// DID returns the relay's DID.
func (r *Relay) DID() string { return r.did }

// ProfileArtifactJWS returns the relay's profile artifact JWS token.
func (r *Relay) ProfileArtifactJWS() string { return r.profileArtifactJWS }

// ProjectIndex advances the index projection until it is caught up or its budget
// runs out, and reports what it did.
//
// EXPORTED BECAUSE THE SCHEDULE IS THE OPERATOR'S. Under the default inline mode
// the relay kicks this itself after an ingest batch and after every sequencer
// pass — synchronously, with ingestMu released. Inline means inline: the caller
// pays the projection, and a read that follows an accepted write sees the rows
// it implied. A deployment that would rather not pay that latency beside the
// accepting path sets IndexProjection: "external" and calls this from a timer or
// another process. Either way the work is the same budgeted, cursor-resumable
// walk of the operation log, and a relay whose store maintains its index some
// other way has nothing to do here.
func (r *Relay) ProjectIndex() IndexProjectionRun {
	if r.projection == nil {
		return IndexProjectionRun{}
	}
	// Coalesce: a second caller arriving mid-drain would re-read the same cursor
	// and redo the same work.
	if !r.projectionMu.TryLock() {
		return IndexProjectionRun{}
	}
	defer r.projectionMu.Unlock()
	return drainIndexProjection(r.projection, r.projectionBudget, indexProjectionMaxRuns, r.logger)
}

// kickIndexProjection drains the projection after an accepted batch, unless the
// operator drives it. Never called with ingestMu held, and never in a goroutine:
// see ProjectIndex for why inline mode is synchronous.
func (r *Relay) kickIndexProjection() {
	if r.projection == nil || r.projectionMode != IndexProjectionInline {
		return
	}
	r.ProjectIndex()
}

// projectIndexForBlob recomputes the rows a landed blob changes, under the SAME
// mutex ProjectIndex holds.
//
// A blob upload is the one projection trigger the operation log does not carry,
// which is exactly what makes the race permanent: an in-flight projection run
// that read this content row BEFORE the blob landed applies its older snapshot
// afterwards, and because no log entry names the upload, no later run repairs it
// — the row keeps docSchema/title unknown until some unrelated operation touches
// that chain. One lock removes the interleaving.
func (r *Relay) projectIndexForBlob(documentCID string) {
	if r.projection == nil {
		return
	}
	r.projectionMu.Lock()
	defer r.projectionMu.Unlock()
	projectIndexAfterBlob(documentCID, r.projection, r.logger)
}

// Ingest stores raw ops, processes a batch for immediate results, and gossips.
func (r *Relay) Ingest(tokens []string) []IngestionResult {
	start := time.Now()

	if r.writeStore == nil || r.writerState == nil {
		results := make([]IngestionResult, len(tokens))
		for i, token := range tokens {
			results[i] = IngestionResult{CID: computeOpCID(token), Status: "rejected", Error: "this relay does not accept operations"}
		}
		return results
	}

	// process immediately — mutex serializes all chain-state mutations.
	r.ingestMu.Lock()

	// store all raw ops first — they can never be lost. Capture each row's
	// storage CID (computeOpCID) so the drain loop below reuses the exact same
	// key it was stored under, rather than recomputing it (or trusting res.CID,
	// which can diverge — see the sequencer loop).
	rawCIDs := make([]string, len(tokens))
	for i, token := range tokens {
		rawCIDs[i] = computeOpCID(token)
		if rawCIDs[i] != "" {
			r.writerState.PutRawOp(rawCIDs[i], token, OpOriginDirect)
		}
	}

	var opts []IngestOption
	if !r.logEnabled {
		opts = append(opts, WithLogDisabled())
	}
	results := IngestOperations(tokens, r.writeStore, opts...)

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
			if err := r.writerState.MarkOpsSequenced([]string{rawCID}); err != nil {
				r.logger.Error("ingest: failed to mark op sequenced — skipping gossip", "cid", rawCID, "error", err)
			} else {
				newOps = append(newOps, tokens[i])
				newCount++
			}
		case res.Status == "duplicate":
			if err := r.writerState.MarkOpsSequenced([]string{rawCID}); err != nil {
				r.logger.Error("ingest: failed to mark duplicate op sequenced", "cid", rawCID, "error", err)
			}
			dupCount++
		case res.Status == "rejected" && isPermanentRejection(res):
			// see the sequencer twin: log before the row is dropped, since
			// MarkOpRejected deletes it and the reason is otherwise discarded.
			// Same event string and fields as the TS twin and the sequencer site.
			r.logger.Warn("relay.op.rejected", "cid", rawCID, "reason", res.Error)
			r.writerState.MarkOpRejected(rawCID, res.Error)
			rejCount++
		}
	}

	// run sequencer after the batch — reads must see the committed status updates
	seqNewOps, _ := r.runSequencerLocked()

	r.ingestMu.Unlock()

	r.logger.Info("ingest complete",
		"batch", len(tokens),
		"new", newCount,
		"duplicate", dupCount,
		"rejected", rejCount,
		"duration", time.Since(start),
	)

	// gossip and project outside the lock
	r.gossipOps(newOps)
	r.gossipOps(seqNewOps)
	r.kickIndexProjection()

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
	// Pull sync stages raw ops and advances peer cursors, both of which are
	// writer-internal state. A store that keeps none has nothing to sync into.
	if r.peerClient == nil || r.writerState == nil || r.writeStore == nil {
		return nil
	}
	for _, peer := range r.peers {
		if peer.Sync != nil && !*peer.Sync {
			continue
		}
		// A pinned peer that has started answering as someone else is not synced
		// from. Bulk sync is the unbounded direction — every chain the peer holds
		// lands in the local store — so it is the one where "whoever answers at
		// this URL" is least acceptable. The verdict is recorded on the status row
		// because a skipped cycle otherwise looks exactly like a quiet one.
		if mismatch := r.peerPinned(peer); mismatch != nil {
			r.recordPeerPin(peer.URL, mismatch)
			continue
		}
		r.recordPeerPin(peer.URL, nil)
		attemptAt := time.Now()
		cursor, _ := r.writerState.GetPeerCursor(peer.URL)
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

// peerSyncStartupGraceCycles is how many CONSECUTIVE not-yet-listening failures
// a peer is granted before the failure is logged at ERROR. Three cycles: a cold
// mesh heals in one tick, so this is generous about startup and still escalates
// a real outage well inside any alerting window.
const peerSyncStartupGraceCycles = 3

// notYetListening reports whether err is the failure a peer that has not opened
// its socket yet produces: a refused connection, or a name that does not resolve
// yet (a container the DNS has not published). Deliberately narrow — a timeout
// is NOT here, because a peer that accepts and then hangs is a real condition,
// not a boot artifact.
func notYetListening(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// peerFailureStreak reads a peer's current consecutive-failure count without
// creating a status row. Read BEFORE recordPeerSync folds this cycle in, so it
// is the count of PRIOR consecutive failures.
func (r *Relay) peerFailureStreak(peerURL string) int {
	r.peerSyncMu.Lock()
	defer r.peerSyncMu.Unlock()
	if st := r.peerSync[peerURL]; st != nil {
		return st.ConsecutiveFailures
	}
	return 0
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
			// A PEER THAT IS NOT LISTENING YET IS NOT AN OUTAGE YET.
			//
			// Every node in a multi-node topology starts its sync loop before its
			// siblings have opened their sockets, so a cold boot reliably emits
			// connection-refused on the first tick or two and then heals itself.
			// Logging that at ERROR trains operators to ignore ERROR — it fires on
			// every clean start of every mesh, with nothing wrong.
			//
			// THE RULE: a not-yet-listening failure (refused connection, or a name
			// that does not resolve yet) is a WARN while this peer's consecutive
			// failure streak is under the grace, and an ERROR at or past it. Every
			// other failure — a peer answering 500, a malformed page — is an ERROR
			// on the first occurrence, because none of them is a startup artifact.
			// A genuine persistent outage still reaches ERROR, one grace period
			// late, and the peer's consecutiveFailures in the well-known counts it
			// from the first tick either way.
			if notYetListening(err) && r.peerFailureStreak(peerURL) < peerSyncStartupGraceCycles {
				r.logger.Warn("peer sync: peer not reachable yet",
					"peer", peerURL, "error", err, "graceCycles", peerSyncStartupGraceCycles)
			} else {
				r.logger.Error("peer sync failed", "peer", peerURL, "error", err)
			}
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
					if err := r.writerState.SetPeerCursor(peerURL, resume); err != nil {
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
		// Hold ingestMu across the page so raw ops cannot land between the
		// sequencer's GetUnsequencedOps and its MarkOpsSequenced. Correctness no
		// longer depends on it — every write here is a single statement and no
		// transaction is shared with ingestion — but a page landing mid-drain
		// would be sequenced on the next pass rather than this one, for no gain.
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
			isNew, err := r.writerState.PutRawOp(cid, e.JWSToken, OpOriginPeer)
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
					if err := r.writerState.SetPeerCursor(peerURL, ""); err != nil {
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
			if err := r.writerState.SetPeerCursor(peerURL, cursor); err != nil {
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
	anchor, _ := r.writerState.GetPeerCursor(rcKey)
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
	if err := r.writerState.SetPeerCursor(rcKey, next); err != nil {
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
	if r.writerState == nil {
		return nil
	}
	return r.writerState.ResetPeerCursors()
}

// GetIdentity returns a stored identity chain by DID, or nil.
func (r *Relay) GetIdentity(did string) (*StoredIdentityChain, error) {
	return r.readStore.GetIdentityChain(did)
}

// GetContent returns a stored content chain by content ID, or nil.
func (r *Relay) GetContent(contentID string) (*StoredContentChain, error) {
	return r.readStore.GetContentChain(contentID)
}

// GetOperation returns a stored operation by CID, or nil.
func (r *Relay) GetOperation(cid string) (*StoredOperation, error) {
	return r.readStore.GetOperation(cid)
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
