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
}

// NewRelay creates a new Relay instance. If no identity is provided, a JIT
// identity and profile artifact are generated.
func NewRelay(opts RelayOptions) (*Relay, error) {
	if opts.Store == nil {
		return nil, fmt.Errorf("store is required")
	}

	contentEnabled := opts.Content == nil || *opts.Content

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
	}, nil
}

// DID returns the relay's DID.
func (r *Relay) DID() string { return r.did }

// ProfileArtifactJWS returns the relay's profile artifact JWS token.
func (r *Relay) ProfileArtifactJWS() string { return r.profileArtifactJWS }

// Ingest processes a batch of JWS operation tokens.
func (r *Relay) Ingest(tokens []string) []IngestionResult {
	return IngestOperations(tokens, r.store)
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
