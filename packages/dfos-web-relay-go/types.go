package relay

import dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"

// RelayIdentity holds the relay's DID and profile artifact.
type RelayIdentity struct {
	DID                string
	ProfileArtifactJWS string
}

// RelayOptions configures a new Relay instance.
type RelayOptions struct {
	Store    Store
	Identity *RelayIdentity
	Content  *bool // nil or true = enabled (default), false = disabled
}

// StoredIdentityChain is the relay's representation of an identity chain.
type StoredIdentityChain struct {
	DID           string          `json:"did"`
	Log           []string        `json:"log"`
	HeadCID       string          `json:"headCID"`
	LastCreatedAt string          `json:"lastCreatedAt"`
	State         dfos.IdentityState `json:"state"`
}

// StoredContentChain is the relay's representation of a content chain.
type StoredContentChain struct {
	ContentID     string          `json:"contentId"`
	GenesisCID    string          `json:"genesisCID"`
	Log           []string        `json:"log"`
	LastCreatedAt string          `json:"lastCreatedAt"`
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
}
