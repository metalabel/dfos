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
	store              Store
	did                string
	profileArtifactJWS string
	contentEnabled     bool
	logEnabled         bool
	logger     *slog.Logger
	peers      []PeerConfig
	peerClient PeerClient
	ingestMu   sync.Mutex // serializes all chain-state mutations (ingest + sequencer)
}

// NewRelay creates a new Relay instance. If no identity is provided, a JIT
// identity and profile artifact are generated.
func NewRelay(opts RelayOptions) (*Relay, error) {
	if opts.Store == nil {
		return nil, fmt.Errorf("store is required")
	}

	contentEnabled := opts.Content == nil || *opts.Content
	logEnabled := opts.Log == nil || *opts.Log

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

	return &Relay{
		store:              opts.Store,
		did:                identity.DID,
		profileArtifactJWS: identity.ProfileArtifactJWS,
		contentEnabled:     contentEnabled,
		logEnabled:         logEnabled,
		logger:     logger,
		peers:      opts.Peers,
		peerClient: opts.PeerClient,
	}, nil
}

// DID returns the relay's DID.
func (r *Relay) DID() string { return r.did }

// ProfileArtifactJWS returns the relay's profile artifact JWS token.
func (r *Relay) ProfileArtifactJWS() string { return r.profileArtifactJWS }

// Ingest stores raw ops, processes a batch for immediate results, and gossips.
func (r *Relay) Ingest(tokens []string) []IngestionResult {
	start := time.Now()

	// store all raw ops first — they can never be lost
	for _, token := range tokens {
		cid := computeOpCID(token)
		if cid != "" {
			r.store.PutRawOp(cid, token)
		}
	}

	// process immediately — mutex serializes all chain-state mutations
	r.ingestMu.Lock()

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
		if res.CID == "" {
			continue
		}
		switch {
		case res.Status == "new":
			r.store.MarkOpsSequenced([]string{res.CID})
			newOps = append(newOps, tokens[i])
			newCount++
		case res.Status == "duplicate":
			r.store.MarkOpsSequenced([]string{res.CID})
			dupCount++
		case res.Status == "rejected" && isPermanentRejection(res.Error):
			r.store.MarkOpRejected(res.CID, res.Error)
			rejCount++
		}
	}

	// run sequencer while still holding mutex — resolves pending ops whose deps just arrived
	seqNewOps, _ := r.runSequencerLocked()

	if hasBatch {
		if err := batchable.CommitWriteBatch(); err != nil {
			r.logger.Error("failed to commit write batch", "error", err)
			batchable.RollbackWriteBatch()
		}
	}

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

// SyncFromPeers pulls raw ops from all configured sync peers into the raw
// store, then runs the sequencer to process everything.
func (r *Relay) SyncFromPeers() error {
	if r.peerClient == nil {
		return nil
	}
	for _, peer := range r.peers {
		if peer.Sync != nil && !*peer.Sync {
			continue
		}
		cursor, _ := r.store.GetPeerCursor(peer.URL)
		fetched := 0
		for {
			page, err := r.peerClient.GetOperationLog(peer.URL, cursor, 1000)
			if err != nil {
				r.logger.Error("peer sync failed", "peer", peer.URL, "error", err)
				break
			}
			if page == nil || len(page.Entries) == 0 {
				break
			}
			for _, e := range page.Entries {
				r.store.PutRawOp(e.CID, e.JWSToken)
			}
			fetched += len(page.Entries)
			if page.Cursor != nil {
				cursor = *page.Cursor
			} else {
				cursor = page.Entries[len(page.Entries)-1].CID
			}
			r.store.SetPeerCursor(peer.URL, cursor)
			if page.Cursor == nil {
				break
			}
		}
		if fetched > 0 {
			r.logger.Info("peer sync fetched ops", "peer", peer.URL, "ops", fetched)
		}
	}

	// sequence all stored ops — fixed-point loop until no more progress
	r.RunSequencerAndGossip()
	return nil
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

// GetBeacon returns the latest beacon for a DID, or nil.
func (r *Relay) GetBeacon(did string) (*StoredBeacon, error) {
	return r.store.GetBeacon(did)
}

// Handler returns an http.Handler implementing the DFOS web relay HTTP API.
func (r *Relay) Handler() http.Handler {
	return r.withRequestLogging(newRouter(r))
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
