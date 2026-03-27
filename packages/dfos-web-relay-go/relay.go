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
	}, nil
}

// DID returns the relay's DID.
func (r *Relay) DID() string { return r.did }

// ProfileArtifactJWS returns the relay's profile artifact JWS token.
func (r *Relay) ProfileArtifactJWS() string { return r.profileArtifactJWS }

// Ingest processes a batch of JWS operation tokens, then gossips new ops to peers.
func (r *Relay) Ingest(tokens []string) []IngestionResult {
	var opts []IngestOption
	if !r.logEnabled {
		opts = append(opts, WithLogDisabled())
	}
	results := IngestOperations(tokens, r.store, opts...)

	// gossip new ops to peers
	if r.peerClient != nil {
		var newOps []string
		for i, result := range results {
			if result.Status == "new" {
				newOps = append(newOps, tokens[i])
			}
		}
		if len(newOps) > 0 {
			for _, peer := range r.peers {
				if peer.Gossip != nil && !*peer.Gossip {
					continue
				}
				go r.peerClient.SubmitOperations(peer.URL, newOps) //nolint:errcheck
			}
		}
	}

	return results
}

// SyncFromPeers pulls operations from all configured sync peers.
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
			tokens := make([]string, len(page.Entries))
			for i, e := range page.Entries {
				tokens[i] = e.JWSToken
			}
			r.Ingest(tokens)
			if page.Cursor != nil {
				cursor = *page.Cursor
				r.store.SetPeerCursor(peer.URL, cursor)
			} else {
				break
			}
		}
	}
	return nil
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
