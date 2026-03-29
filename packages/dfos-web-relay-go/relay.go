package relay

import (
	"fmt"
	"net/http"
)

// Relay is a DFOS web relay — the core verification and storage engine.
type Relay struct {
	store              Store
	did                string
	profileArtifactJWS string
	contentEnabled     bool
	logEnabled         bool
	peers              []PeerConfig
	peerClient         PeerClient
	adminEnabled       bool
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

	return &Relay{
		store:              opts.Store,
		did:                identity.DID,
		profileArtifactJWS: identity.ProfileArtifactJWS,
		contentEnabled:     contentEnabled,
		logEnabled:         logEnabled,
		peers:              opts.Peers,
		peerClient:         opts.PeerClient,
		adminEnabled:       opts.AdminEnabled,
	}, nil
}

// DID returns the relay's DID.
func (r *Relay) DID() string { return r.did }

// ProfileArtifactJWS returns the relay's profile artifact JWS token.
func (r *Relay) ProfileArtifactJWS() string { return r.profileArtifactJWS }

// Ingest stores raw ops, processes a batch for immediate results, and gossips.
func (r *Relay) Ingest(tokens []string) []IngestionResult {
	// store all raw ops first — they can never be lost
	for _, token := range tokens {
		cid := computeOpCID(token)
		if cid != "" {
			r.store.PutRawOp(cid, token)
		}
	}

	// process immediately for synchronous response
	var opts []IngestOption
	if !r.logEnabled {
		opts = append(opts, WithLogDisabled())
	}
	results := IngestOperations(tokens, r.store, opts...)

	// mark results in raw store
	var newOps []string
	for i, res := range results {
		if res.CID == "" {
			continue
		}
		switch {
		case res.Status == "new":
			r.store.MarkOpsSequenced([]string{res.CID})
			newOps = append(newOps, tokens[i])
		case res.Status == "duplicate":
			r.store.MarkOpsSequenced([]string{res.CID})
		case res.Status == "rejected" && isPermanentRejection(res.Error):
			r.store.MarkOpRejected(res.CID, res.Error)
		}
		// transient failures stay as 'pending' in raw_ops
	}

	// gossip new ops to peers
	r.gossipOps(newOps)

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
		for {
			page, err := r.peerClient.GetOperationLog(peer.URL, cursor, 1000)
			if err != nil || page == nil || len(page.Entries) == 0 {
				break
			}
			// store raw — no verification during sync
			for _, e := range page.Entries {
				r.store.PutRawOp(e.CID, e.JWSToken)
			}
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
	return newRouter(r)
}
