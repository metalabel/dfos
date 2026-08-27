package relay

import (
	"crypto/ed25519"
	"errors"
	"log/slog"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// ErrUnknownLogCursor is returned by Store.ReadLog when `after` names a cursor
// this relay's log never issued. Log cursors are relay-local (per-relay
// ingestion order); the route maps this to 400, never a silently empty page.
var ErrUnknownLogCursor = errors.New("unknown log cursor")

// ErrInvalidSigningCursor is returned when a signing mailbox cursor is either
// malformed or belongs to a different subject mailbox.
var ErrInvalidSigningCursor = errors.New("invalid signing cursor")

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
	Store       Store
	Identity    *RelayIdentity
	Content     *bool // nil or true = enabled (default), false = disabled
	Log         *bool // nil or true = enabled (default), false = disabled
	Revocations *bool // nil or true = enabled (default), false = disabled
	Index       *bool // nil or true = enabled (default), false = disabled
	// Write, when false, makes this a LITE pull-only proof node: POST
	// /proof/v1/operations is rejected (501), so neither client writes nor peer
	// gossip-in are accepted. The node still ingests by PULLING from peers
	// (SyncFromPeers polls their /log). nil or true = accept writes (default).
	Write *bool
	// Signing enables the optional SIGNING 0.1 mailbox. nil = disabled.
	Signing      *bool
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

// PeerLogPage is a paginated log response from a peer. `next` is the shared
// list envelope's resume field; `cursor` is the deprecated pre-rename alias
// still emitted by older relays — Resume() prefers `next` and falls back.
type PeerLogPage struct {
	Entries []PeerLogEntry `json:"entries"`
	Next    *string        `json:"next"`
	Cursor  *string        `json:"cursor"`
}

// Resume returns the page's resume cursor: `next` when present, else the
// deprecated `cursor` alias (older peers), else nil (caught up).
func (p *PeerLogPage) Resume() *string {
	if p.Next != nil {
		return p.Next
	}
	return p.Cursor
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
	CID        string `json:"cid"`
	JWSToken   string `json:"jwsToken"`
	ChainType  string `json:"chainType"`
	ChainID    string `json:"chainId"`
	IngestedAt string `json:"ingestedAt"`
}

// StoredRevocation represents a revocation in the store.
//
// CreatedAt is the revocation's own signed createdAt (ISO 8601), taken from the
// VERIFIED payload at ingest — never re-decoded unverified. Persisting it is what
// makes as-of revocation answerable: it is the boundary that separates operations
// a revocation reaches (signed before it) from operations it does not.
type StoredRevocation struct {
	CID           string `json:"cid"`
	IssuerDID     string `json:"issuerDID"`
	CredentialCID string `json:"credentialCID"`
	JWSToken      string `json:"jwsToken"`
	CreatedAt     string `json:"createdAt"`
}

// StoredCountersignature represents a countersignature indexed by target and witness.
type StoredCountersignature struct {
	CID        string  `json:"cid"`
	TargetCID  string  `json:"targetCID"`
	WitnessDID string  `json:"witnessDID"`
	Relation   *string `json:"relation"`
	JWSToken   string  `json:"jwsToken"`
	CreatedAt  string  `json:"-"`
	IngestedAt string  `json:"-"`
}

// StoredPublicCredential represents a public credential (standing authorization).
type StoredPublicCredential struct {
	CID       string            `json:"cid"`
	IssuerDID string            `json:"issuerDID"`
	Att       []AttenuationPair `json:"att"`
	Exp       int64             `json:"exp"`
	JWSToken  string            `json:"jwsToken"`
}

// StoredSignRequest is ephemeral signing-mailbox courier state.
type StoredSignRequest struct {
	CID          string `json:"cid"`
	Request      string `json:"request"`
	RequesterDID string `json:"requesterDID"`
	SubjectDID   string `json:"subjectDID"`
	PayloadTyp   string `json:"payloadTyp"`
	PayloadBytes []byte `json:"-"`
	ExpiresAt    string `json:"expiresAt"`
	DepositedAt  string `json:"depositedAt"`
	Declined     bool   `json:"declined"`
	Response     string `json:"response,omitempty"`
}

const signingTimeFormat = "2006-01-02T15:04:05.000Z"

type SigningPutResult string

const (
	SigningCreated    SigningPutResult = "created"
	SigningIdentical  SigningPutResult = "identical"
	SigningConflict   SigningPutResult = "conflict"
	SigningNotFound   SigningPutResult = "not-found"
	SigningAtCapacity SigningPutResult = "at-capacity"
)

// MaxPendingSignRequestsPerMailbox is the reference relay's per-subject flood
// fence. Idempotent re-deposits do not consume another slot.
const MaxPendingSignRequestsPerMailbox = 1024

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

// RevokedGrant is the revoked public grant scope. A nil result field means the
// credential was not held.
type RevokedGrant struct {
	Wildcard   bool     `json:"wildcard"`
	ContentIDs []string `json:"contentIds"`
}

// IngestionResult reports the outcome of ingesting a single operation.
type IngestionResult struct {
	CID          string        `json:"cid"`
	Status       string        `json:"status"`
	Error        string        `json:"error,omitempty"`
	Kind         string        `json:"kind,omitempty"`
	ChainID      string        `json:"chainId,omitempty"`
	RevokedGrant *RevokedGrant `json:"revokedGrant,omitempty"`

	// DependencyMissing is the structured dependency-failure signal. When true,
	// the rejection is due to a missing dependency that may arrive later via
	// sync or gossip, so the sequencer keeps the op pending (retryable) rather
	// than durably reject it. The sequencer branches on this flag — NOT on
	// substring matching of the human-readable Error string. Mirrors the TS
	// twin's IngestionResult.dependencyMissing.
	DependencyMissing bool `json:"dependencyMissing,omitempty"`

	// PersistFailed narrows DependencyMissing to its one destructive case: a
	// store WRITE that failed partway through applying an op, leaving that op's
	// writes half-landed. Set only by persistError, its single producer.
	//
	// It needs its own flag because the recovery differs. Every other retryable
	// rejection (an unknown parent, an authorization gate whose read failed)
	// wrote nothing, so retrying it later is free. A half-applied op is not:
	// whatever DID land makes the idempotency check at the top of each ingest
	// path answer "duplicate" on every retry, so the writes that failed are
	// never completed and the op stays permanently inconsistent. The batch owner
	// therefore rolls the whole batch back rather than committing the half — see
	// sequenceChunkLocked. Relay-internal, so it stays off the wire; the Go-only
	// transient-store-retry path has no TS twin to mirror.
	PersistFailed bool `json:"-"`
}

// OpOrigin records whether a raw operation first arrived directly or through
// committed peer-log ingestion. It is durable admission provenance.
type OpOrigin string

const (
	OpOriginDirect OpOrigin = "direct"
	OpOriginPeer   OpOrigin = "peer"
)

// PendingOp is one unsequenced raw operation with its durable provenance.
type PendingOp struct {
	JWSToken string
	Origin   OpOrigin
}

// SigningStore is the optional ephemeral signing-mailbox courier store.
type SigningStore interface {
	PruneExpiredSignRequests(now time.Time) error
	GetSignRequest(cid string, now time.Time) (*StoredSignRequest, error)
	PutSignRequest(request StoredSignRequest, now time.Time) (SigningPutResult, error)
	ListPendingSignRequests(subjectDID, after string, limit int, now time.Time) ([]StoredSignRequest, string, error)
	PutSignResponse(cid, response string, now time.Time) (SigningPutResult, error)
	DeclineSignRequest(cid string, now time.Time) (SigningPutResult, error)
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
	PutRawOp(cid string, jwsToken string, origin ...OpOrigin) error
	GetUnsequencedOps(limit int) ([]PendingOp, error) // returns JWS tokens + origins where status = 'pending'
	MarkOpsSequenced(cids []string) error
	MarkOpRejected(cid string, reason string) error
	CountUnsequenced() (int, error)

	// revocations

	GetRevocations(issuerDID string) ([]string, error)
	// AddRevocation stores a revocation for a (issuerDID, credentialCID) pair.
	// When the pair already has one, implementations MUST keep whichever has the
	// EARLIEST as-of boundary — an absent/unparseable boundary being the earliest
	// of all — with the artifact CID as tiebreak. Otherwise the validity boundary
	// for all of history would depend on gossip arrival order, and a later
	// re-revocation of the same credential could retroactively RE-VALIDATE
	// operations an earlier revocation had already invalidated. See
	// revocationSupersedes.
	AddRevocation(revocation StoredRevocation) error
	// IsCredentialRevoked reports whether a credential CID has been revoked by a
	// specific issuer.
	//
	// asOfUnix <= 0 is the FRESHNESS answer — "revoked as far as this relay knows
	// right now" — which is what acceptance gates (ingest, live read-path
	// authorization) ask. asOfUnix > 0 is the VALIDITY answer: true only if the
	// revocation's own signed createdAt is at or before asOfUnix, which is what
	// verifying already-committed history asks. See CREDENTIALS.md "Revocation
	// Scope".
	//
	// 0 is the in-band timeless sentinel, so "as of epoch 0" is not expressible;
	// the whole non-positive range is timeless in the TS twin too, so an operation
	// dated at or before 1970 gets the stricter answer in both languages.
	IsCredentialRevoked(issuerDID string, credentialCID string, asOfUnix int64) (bool, error)
	// GetRevocationForCredential returns the stored revocation for a credential
	// CID, any issuer (nil when unknown). Serves the revocation-status route. If
	// more than one issuer has revoked the same CID, implementations MUST return
	// the one with the lexicographically smallest issuerDID (deterministic
	// across stores and twins).
	GetRevocationForCredential(credentialCID string) (*StoredRevocation, error)
	// GetRevocationsByIssuer returns all stored revocations issued by a DID,
	// sorted by credentialCID ascending (the issuer route's transparent keyset
	// order, deterministic across stores and twins).
	GetRevocationsByIssuer(issuerDID string) ([]StoredRevocation, error)

	// public credentials (standing authorization)
	GetPublicCredentials(resource string) ([]string, error) // returns JWS tokens
	GetPublicCredentialByCID(cid string) (*StoredPublicCredential, error)
	AddPublicCredential(credential StoredPublicCredential) error
	RemovePublicCredential(credentialCID string) error

	// listing — enumerate all chains in the store
	ListIdentityChains() ([]StoredIdentityChain, error)
	ListContentChains() ([]StoredContentChain, error)
	ListArtifactOperations() ([]StoredOperation, error)

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
	// profile.publicRead) filters to identities exposing a public profile; DID is
	// an exact point lookup.
	QueryIndexIdentities(q IndexIdentityQuery) ([]indexIdentityRow, error)
	// QueryIndexContent pages content projection rows ascending by contentId,
	// contentId > After, length <= Limit, filtered by any provided
	// point ID / actor / document / visibility / deletion predicates.
	QueryIndexContent(q IndexContentQuery) ([]indexContentRow, error)
	// QueryIndexCredits pages public-head credit rows by their composite key.
	QueryIndexCredits(q IndexCreditQuery) ([]indexCreditRow, error)
	QueryIndexArtifacts(q IndexArtifactQuery) ([]indexArtifactRow, error)
	// QueryIndexCountersignatures pages countersignature projection rows for one
	// witness ascending by cid, cid > After, length <= Limit. Reflects the
	// store's ACCEPTED countersign set (deduped one-per-witness-per-target).
	QueryIndexCountersignatures(q IndexCountersignatureQuery) ([]indexCountersignatureRow, error)
	// QueryIndexCredentials pages held public credentials ascending by cid,
	// cid > After, length <= Limit, filtered by issuer, resource, and/or action
	// exact match. For chain resources, the chain:* bucket is unioned.
	QueryIndexCredentials(q IndexCredentialQuery) ([]indexCredentialRow, error)
	// QueryIndexOperations pages the accepted operation log by relay or author recency.
	QueryIndexOperations(q IndexOperationQuery) ([]indexOperationRow, error)

	// PutIndexIdentityRow upserts an identity projection row by DID.
	PutIndexIdentityRow(row indexIdentityRow) error
	// PutIndexContentRow upserts a content projection row by contentId.
	PutIndexContentRow(row indexContentRow) error
	// PutIndexCreditRows replaces one chain's complete public-head credit set.
	PutIndexCreditRows(contentID string, rows []indexCreditRow) error
	PutIndexArtifactRow(row indexArtifactRow) error
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
	DID              string // "" = no filter
	HasPublicProfile *bool  // nil = no filter
	NameContains     string // "" = no filter
	After            string
	OrderedAfter     *indexOrderedCursor
	Order            string
	Limit            int
}

// IndexContentQuery is the keyset-paged filter for content projection rows.
type IndexContentQuery struct {
	ContentID     *string // nil = no filter
	Creator       string  // "" = no filter
	Signer        string  // "" = no filter
	DocSchema     *string // nil = no filter
	DocumentCID   *string // nil = no filter
	PublicRead    *bool   // nil = no filter
	IsDeleted     *bool   // nil = no filter
	TitleContains string  // "" = no filter
	After         string
	OrderedAfter  *indexOrderedCursor
	Order         string
	Limit         int
}

type IndexCreditQuery struct {
	DID       *string
	ContentID *string
	Role      *string
	After     *indexCreditCursor
	Limit     int
}

type IndexArtifactQuery struct {
	CID          *string
	Signer       string
	DocSchema    *string
	After        string
	OrderedAfter *indexOrderedCursor
	Order        string
	Limit        int
}

// IndexCountersignatureQuery is the keyset-paged filter for countersignature
// projection rows scoped to a single witness.
type IndexCountersignatureQuery struct {
	Witness      string
	Relation     *string
	After        string
	OrderedAfter *indexOrderedCursor
	Order        string
	Limit        int
}

// IndexCredentialQuery is the keyset-paged filter for held public credentials.
type IndexCredentialQuery struct {
	Issuer   string
	Resource *string // nil = no filter
	Action   *string // nil = no filter
	After    string
	Limit    int
}

// IndexOperationQuery is the always-time-ordered filter over accepted operations.
type IndexOperationQuery struct {
	Kind         string
	ChainID      *string
	OrderedAfter *indexOrderedCursor
	Order        string
	Limit        int
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
	CreatedAt  string
	IngestedAt string
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
