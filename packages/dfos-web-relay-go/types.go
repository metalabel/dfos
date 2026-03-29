package relay

import (
	"crypto/ed25519"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// Version is the release version of the dfos-web-relay-go package.
const Version = "0.6.1"

// RelayIdentity holds the relay's DID, profile artifact, and key material.
type RelayIdentity struct {
	DID                string
	ProfileArtifactJWS string
	PrivateKey         ed25519.PrivateKey // only set during bootstrap, not stored on Relay
	KeyID              string             // only set during bootstrap
}

// RelayOptions configures a new Relay instance.
type RelayOptions struct {
	Store      Store
	Identity   *RelayIdentity
	Content    *bool  // nil or true = enabled (default), false = disabled
	Log        *bool  // nil or true = enabled (default), false = disabled
	Peers      []PeerConfig
	PeerClient   PeerClient // injected peer transport (nil = no peering)
	ResyncOnBoot bool       // if true, reset peer cursors + sequencer on startup
}

// PeerConfig configures a single peer relay.
type PeerConfig struct {
	URL         string
	Gossip      *bool // nil or true = push new ops (default), false = disabled
	ReadThrough *bool // nil or true = fetch on local 404 (default), false = disabled
	Sync        *bool // nil or true = poll /log (default), false = disabled
}

// PeerLogEntry is a single entry returned by a peer's log endpoint.
type PeerLogEntry struct {
	CID      string `json:"cid"`
	JWSToken string `json:"jwsToken"`
}

// PeerClient is the injected peer transport — the relay expresses intent,
// the caller decides transport.
type PeerClient interface {
	GetIdentityLog(peerURL, did string, after string, limit int) (*PeerLogPage, error)
	GetContentLog(peerURL, contentID string, after string, limit int) (*PeerLogPage, error)
	GetOperationLog(peerURL string, after string, limit int) (*PeerLogPage, error)
	SubmitOperations(peerURL string, operations []string) error
}

// PeerLogPage is a paginated log response from a peer.
type PeerLogPage struct {
	Entries []PeerLogEntry `json:"entries"`
	Cursor  *string        `json:"cursor"`
}

// IdentityStateAtCID holds the materialized identity state at a specific
// operation CID. Used by fork verification.
type IdentityStateAtCID struct {
	State         dfos.IdentityState
	LastCreatedAt string
}

// ContentStateAtCID holds the materialized content state at a specific
// operation CID. Used by fork verification.
type ContentStateAtCID struct {
	State         dfos.ContentState
	LastCreatedAt string
}

// StoredIdentityChain is the relay's representation of an identity chain.
type StoredIdentityChain struct {
	DID           string             `json:"did"`
	Log           []string           `json:"log"`
	HeadCID       string             `json:"headCID"`
	LastCreatedAt string             `json:"lastCreatedAt"`
	State         dfos.IdentityState `json:"state"`
}

// StoredContentChain is the relay's representation of a content chain.
type StoredContentChain struct {
	ContentID     string            `json:"contentId"`
	GenesisCID    string            `json:"genesisCID"`
	Log           []string          `json:"log"`
	LastCreatedAt string            `json:"lastCreatedAt"`
	State         dfos.ContentState `json:"state"`
}

// BeaconPayload is the decoded beacon payload for JSON serialization.
type BeaconPayload struct {
	Version    int    `json:"version"`
	Type       string `json:"type"`
	DID        string `json:"did"`
	MerkleRoot string `json:"merkleRoot"`
	CreatedAt  string `json:"createdAt"`
}

// StoredBeacon is the relay's representation of a beacon.
type StoredBeacon struct {
	DID       string        `json:"did"`
	JWSToken  string        `json:"jwsToken"`
	BeaconCID string        `json:"beaconCID"`
	Payload   BeaconPayload `json:"payload"`
}

// StoredOperation is a single stored operation with its chain metadata.
type StoredOperation struct {
	CID       string `json:"cid"`
	JWSToken  string `json:"jwsToken"`
	ChainType string `json:"chainType"`
	ChainID   string `json:"chainId"`
}

// BlobKey uniquely identifies a blob by creator and document CID.
type BlobKey struct {
	CreatorDID  string
	DocumentCID string
}

// LogEntry is a single entry in the global append-only operation log.
type LogEntry struct {
	CID      string `json:"cid"`
	JWSToken string `json:"jwsToken"`
	Kind     string `json:"kind"`
	ChainID  string `json:"chainId"`
}

// IngestionResult reports the outcome of ingesting a single operation.
type IngestionResult struct {
	CID     string `json:"cid"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
	Kind    string `json:"kind,omitempty"`
	ChainID string `json:"chainId,omitempty"`
}

// Store is the storage backend for a DFOS web relay.
type Store interface {
	// operations
	GetOperation(cid string) (*StoredOperation, error)
	PutOperation(op StoredOperation) error

	// identity chains
	GetIdentityChain(did string) (*StoredIdentityChain, error)
	PutIdentityChain(chain StoredIdentityChain) error

	// content chains
	GetContentChain(contentID string) (*StoredContentChain, error)
	PutContentChain(chain StoredContentChain) error

	// beacons
	GetBeacon(did string) (*StoredBeacon, error)
	PutBeacon(beacon StoredBeacon) error

	// blobs (content plane)
	GetBlob(key BlobKey) ([]byte, error)
	PutBlob(key BlobKey, data []byte) error

	// countersignatures — implementations MUST dedup by witness DID per target CID
	GetCountersignatures(operationCID string) ([]string, error)
	AddCountersignature(operationCID string, jwsToken string) error

	// operation log — global append-only, CID-based cursor pagination
	AppendToLog(entry LogEntry) error
	ReadLog(after string, limit int) (entries []LogEntry, cursor string, err error)

	// chain state at arbitrary CID (snapshot-backed)
	GetIdentityStateAtCID(did, cid string) (*IdentityStateAtCID, error)
	GetContentStateAtCID(contentID, cid string) (*ContentStateAtCID, error)

	// peer sync state
	GetPeerCursor(peerURL string) (string, error)
	SetPeerCursor(peerURL string, cursor string) error

	// raw ops — content-addressed store for all received operations
	PutRawOp(cid string, jwsToken string) error
	GetUnsequencedOps(limit int) ([]string, error) // returns JWS tokens where status = 'pending'
	MarkOpsSequenced(cids []string) error
	MarkOpRejected(cid string, reason string) error
	CountUnsequenced() (int, error)

	// admin
	ResetPeerCursors() error
	ResetSequencer() error
}
