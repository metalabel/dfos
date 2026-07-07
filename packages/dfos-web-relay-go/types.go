package relay

import (
	"crypto/ed25519"
	"log/slog"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// Version is the release version, set via ldflags at build time.
var Version = "dev"

// RelayIdentity holds the relay's DID, profile artifact, and key material.
type RelayIdentity struct {
	DID                string
	ProfileArtifactJWS string
	PrivateKey         ed25519.PrivateKey // only set during bootstrap, not stored on Relay
	KeyID              string             // only set during bootstrap
}

// RelayOptions configures a new Relay instance.
type RelayOptions struct {
	Store    Store
	Identity *RelayIdentity
	Content  *bool // nil or true = enabled (default), false = disabled
	Log      *bool // nil or true = enabled (default), false = disabled
	Index    *bool // nil or true = enabled (default), false = disabled
	// Write, when false, makes this a LITE pull-only proof node: POST
	// /proof/v1/operations is rejected (501), so neither client writes nor peer
	// gossip-in are accepted. The node still ingests by PULLING from peers
	// (SyncFromPeers polls their /log). nil or true = accept writes (default).
	Write        *bool
	Logger       *slog.Logger // nil = slog.Default()
	Peers        []PeerConfig
	PeerClient   PeerClient // injected peer transport (nil = no peering)
	ResyncOnBoot bool       // if true, reset peer cursors + sequencer on startup
	// MaxAuthTokenTTL caps the lifetime (exp-iat) honored on a self-signed auth
	// token. Zero = default (24h); a negative value disables the ceiling. Applies
	// only to auth tokens, never to DFOS credentials.
	MaxAuthTokenTTL time.Duration
	// ContentFollow controls whether this relay eagerly materializes the document
	// BYTES of content chains it holds a standing public-read grant for. The op
	// log federates the authz plane (grants are pushed + gossiped); the bytes are
	// NOT gossiped — a follower pulls them, content-addressed, behind the grant.
	// "" or "none" = off (default; byte-identical to today). "eager" = a periodic
	// convergent sweep pulls any missing granted blobs from peers. An origin (an
	// authoritative store) already holds its bytes and never follows; a follower
	// (a cache store, e.g. an edge SQLite node) opts in. See MaterializeFollowedContent.
	ContentFollow string
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
	// GetBlob fetches the raw document bytes a content chain committed at a given
	// ref ("head" or an operationCID) from a peer's content plane (the document
	// gateway, root-mounted — not under /proof/v1). Returns the verbatim
	// octet-stream body; the caller content-address-verifies it before storing.
	GetBlob(peerURL, contentID, ref string) ([]byte, error)
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

// StoredOperation is a single stored operation with its chain metadata.
type StoredOperation struct {
	CID       string `json:"cid"`
	JWSToken  string `json:"jwsToken"`
	ChainType string `json:"chainType"`
	ChainID   string `json:"chainId"`
}

// StoredRevocation represents a revocation in the store.
type StoredRevocation struct {
	CID           string `json:"cid"`
	IssuerDID     string `json:"issuerDID"`
	CredentialCID string `json:"credentialCID"`
	JWSToken      string `json:"jwsToken"`
}

// StoredCountersignature represents a countersignature indexed by target and witness.
type StoredCountersignature struct {
	CID        string  `json:"cid"`
	TargetCID  string  `json:"targetCID"`
	WitnessDID string  `json:"witnessDID"`
	Relation   *string `json:"relation"`
	JWSToken   string  `json:"jwsToken"`
}

// StoredPublicCredential represents a public credential (standing authorization).
type StoredPublicCredential struct {
	CID       string            `json:"cid"`
	IssuerDID string            `json:"issuerDID"`
	Att       []AttenuationPair `json:"att"`
	Exp       int64             `json:"exp"`
	JWSToken  string            `json:"jwsToken"`
}

// AttenuationPair is a resource + action pair.
type AttenuationPair struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

// RelayPeerInfo is a configured peer surfaced in the well-known for mesh discovery.
type RelayPeerInfo struct {
	Endpoint string `json:"endpoint"`
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

// RelayStats is optional operational telemetry a store MAY compute for the well-known.
// Byte twin of the TS RelayStats. oldestOpAt/headCid are pointers WITHOUT omitempty so
// an empty log serializes them as JSON null (parity with the TS `string | null`).
type RelayStats struct {
	OpCount      int            `json:"opCount"`
	CountsByKind map[string]int `json:"countsByKind"`
	OldestOpAt   *string        `json:"oldestOpAt"`
	HeadCID      *string        `json:"headCid"`
}

// StatsProvider is an OPTIONAL store capability (type-asserted like BatchableStore).
// A store implementing it lets the well-known report opCount/countsByKind/oldestOpAt/headCid.
type StatsProvider interface {
	RelayStats() (*RelayStats, error)
}

// newKindCounts returns a countsByKind map pre-seeded with all six buckets at 0, so the
// well-known always emits every key (parity with the TS object literal).
func newKindCounts() map[string]int {
	return map[string]int{"identity": 0, "content": 0, "artifact": 0, "credential": 0, "countersign": 0, "revocation": 0}
}

// kindBucket maps a global-log kind to its countsByKind bucket ("" = ignore).
func kindBucket(kind string) string {
	switch kind {
	case "identity-op":
		return "identity"
	case "content-op":
		return "content"
	case "artifact", "credential", "countersign", "revocation":
		return kind
	default:
		return ""
	}
}

// IngestionResult reports the outcome of ingesting a single operation.
type IngestionResult struct {
	CID     string `json:"cid"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
	Kind    string `json:"kind,omitempty"`
	ChainID string `json:"chainId,omitempty"`

	// DependencyMissing is the structured dependency-failure signal. When true,
	// the rejection is due to a missing dependency that may arrive later via
	// sync or gossip, so the sequencer keeps the op pending (retryable) rather
	// than durably reject it. The sequencer branches on this flag — NOT on
	// substring matching of the human-readable Error string. Mirrors the TS
	// twin's IngestionResult.dependencyMissing.
	DependencyMissing bool `json:"dependencyMissing,omitempty"`
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

	// blobs (content plane)
	GetBlob(key BlobKey) ([]byte, error)
	PutBlob(key BlobKey, data []byte) error
	// DeleteBlob removes a stored document blob. A missing key is a no-op (nil
	// error) — deletion is idempotent. Used by the follower GC sweep to reclaim
	// bytes whose chain is no longer publicly readable (revoked or deleted).
	DeleteBlob(key BlobKey) error

	// countersignatures — implementations MUST dedup by witness DID per target CID
	GetCountersignatures(operationCID string) ([]string, error)
	AddCountersignature(operationCID string, jwsToken string) error
	// ListCountersignatures enumerates every stored countersignature (all
	// witnesses). Used ONLY by the index-projection rebuild path — the serving
	// hot path reads the materialized index_countersign projection instead.
	ListCountersignatures() ([]StoredCountersignature, error)

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

	// revocations
	GetRevocations(issuerDID string) ([]string, error)
	AddRevocation(revocation StoredRevocation) error
	IsCredentialRevoked(issuerDID string, credentialCID string) (bool, error)
	// GetRevocationForCredential returns the stored revocation for a credential
	// CID, any issuer (nil when unknown). Serves the revocation-status route. If
	// more than one issuer has revoked the same CID, implementations MUST return
	// the one with the lexicographically smallest issuerDID (deterministic
	// across stores and twins).
	GetRevocationForCredential(credentialCID string) (*StoredRevocation, error)
	// GetRevocationsByIssuer returns all stored revocations issued by a DID,
	// sorted by revocation createdAt ascending with credentialCID as tiebreak
	// (deterministic across stores and twins — the frozen v1 feed order).
	GetRevocationsByIssuer(issuerDID string) ([]StoredRevocation, error)

	// public credentials (standing authorization)
	GetPublicCredentials(resource string) ([]string, error) // returns JWS tokens
	AddPublicCredential(credential StoredPublicCredential) error
	RemovePublicCredential(credentialCID string) error

	// listing — enumerate all chains in the store
	ListIdentityChains() ([]StoredIdentityChain, error)
	ListContentChains() ([]StoredContentChain, error)

	// --- index (v0) materialized projection ---
	//
	// The /index/v0 query family is served from materialized projection rows that
	// the ingestion pipeline maintains incrementally (see index_maintenance.go).
	// Queries push their filters and keyset cursor into the store so a page costs
	// O(page), never O(corpus): rows come back ascending by natural key, strictly
	// greater than After (bytewise), and capped at Limit. The route layer computes
	// next = len(rows) == limit ? key(last) : null. Row VALUES are a pure function
	// of chain state + held blobs + standing credentials, so a recompute always
	// converges to the same row regardless of when it runs — that is what makes
	// incremental maintenance and a full rebuild interchangeable.

	// QueryIndexIdentities pages identity projection rows ascending by DID,
	// did > After, length <= Limit. HasPublicProfile (≡ profile != nil &&
	// profile.publicRead) filters to identities exposing a public profile.
	QueryIndexIdentities(q IndexIdentityQuery) ([]indexIdentityRow, error)
	// QueryIndexContent pages content projection rows ascending by contentId,
	// contentId > After, length <= Limit, filtered by any provided
	// Creator / DocSchema / PublicRead.
	QueryIndexContent(q IndexContentQuery) ([]indexContentRow, error)
	// QueryIndexCountersignatures pages countersignature projection rows for one
	// witness ascending by cid, cid > After, length <= Limit. Reflects the
	// store's ACCEPTED countersign set (deduped one-per-witness-per-target).
	QueryIndexCountersignatures(q IndexCountersignatureQuery) ([]indexCountersignatureRow, error)
	// QueryIndexCredentials pages held public credentials ascending by cid,
	// cid > After, length <= Limit, filtered by issuer and/or resource exact
	// match. For chain resources, the chain:* bucket is unioned.
	QueryIndexCredentials(q IndexCredentialQuery) ([]indexCredentialRow, error)

	// PutIndexIdentityRow upserts an identity projection row by DID.
	PutIndexIdentityRow(row indexIdentityRow) error
	// PutIndexContentRow upserts a content projection row by contentId.
	PutIndexContentRow(row indexContentRow) error
	// PutIndexContentSigner adds one accepted content-operation signer to a
	// chain's signer set. The set is branch-inclusive and includes genesis.
	PutIndexContentSigner(contentID string, did string) error
	// PutIndexCountersignatureRow upserts a countersignature projection row by
	// cid. The WitnessDID column is stored (never echoed in the wire row) so
	// witness-scoped queries stay O(page).
	PutIndexCountersignatureRow(row storedIndexCountersignature) error

	// GetIndexIdentityDIDsByProfileAnchor is the reverse lookup for the "content
	// changed → recompute the identities anchored on it" cascade: DIDs of
	// identity projection rows whose profile.anchor equals contentID.
	GetIndexIdentityDIDsByProfileAnchor(contentID string) ([]string, error)
	// GetIndexContentIDsByDocumentCID is the reverse lookup for the "blob landed
	// → recompute the content rows that project that document" cascade: contentIds
	// of content projection rows whose currentDocumentCID equals documentCID.
	GetIndexContentIDsByDocumentCID(documentCID string) ([]string, error)

	// admin
	ResetPeerCursors() error
	ResetSequencer() error
}

// IndexIdentityQuery is the keyset-paged filter for identity projection rows.
type IndexIdentityQuery struct {
	HasPublicProfile *bool  // nil = no filter
	NameContains     string // "" = no filter
	After            string
	OrderedAfter     *indexOrderedCursor
	Order            string
	Limit            int
}

// IndexContentQuery is the keyset-paged filter for content projection rows.
type IndexContentQuery struct {
	Creator      string  // "" = no filter
	Signer       string  // "" = no filter
	DocSchema    *string // nil = no filter
	DocumentCID  *string // nil = no filter
	PublicRead   *bool   // nil = no filter
	After        string
	OrderedAfter *indexOrderedCursor
	Order        string
	Limit        int
}

// IndexCountersignatureQuery is the keyset-paged filter for countersignature
// projection rows scoped to a single witness.
type IndexCountersignatureQuery struct {
	Witness string
	After   string
	Limit   int
}

// IndexCredentialQuery is the keyset-paged filter for held public credentials.
type IndexCredentialQuery struct {
	Issuer   string
	Resource *string // nil = no filter
	After    string
	Limit    int
}

// storedIndexCountersignature is a countersignature projection row plus the
// witness_did column that scopes witness queries. WitnessDID is never part of the
// wire row (the witness is echoed at the response top level).
type storedIndexCountersignature struct {
	CID        string
	TargetCID  string
	Relation   *string
	JWSToken   string
	WitnessDID string
}

// RebuildableIndexStore is an OPTIONAL store capability (type-asserted like
// BatchableStore). A durable store implements it so the relay can detect a
// projection-schema version bump on boot and rebuild all projection rows from the
// authoritative chain/countersign tables before serving.
type RebuildableIndexStore interface {
	// GetIndexProjectionVersion returns the projection_version stamped in the
	// store's index_meta, or 0 when never stamped (a fresh or pre-projection DB).
	GetIndexProjectionVersion() (int, error)
	// SetIndexProjectionVersion stamps the projection_version after a rebuild.
	SetIndexProjectionVersion(v int) error
	// ClearIndexProjection truncates all projection rows so a rebuild starts from
	// a clean slate (a schema change may have altered row shape).
	ClearIndexProjection() error
}
