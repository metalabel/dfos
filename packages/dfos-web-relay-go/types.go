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
//
// PrivateKey and KeyID are produced by bootstrap and RETAINED on the Relay, for
// exactly one purpose: signing an IDENTITY PROOF of the relay's own DID so
// gossip-out announces itself as a named peer rather than anonymously
// (WEB-RELAY.md, Relay Identity). A relay constructed from a DID and a profile
// alone still runs; it simply gossips anonymously.
type RelayIdentity struct {
	DID                string
	ProfileArtifactJWS string
	PrivateKey         ed25519.PrivateKey
	KeyID              string
}

// IngestionMode is the advertised ingestion admission mode (WEB-RELAY.md,
// Ingestion Admission).
//
//   - "open"           anonymous submissions admitted, subject to policy
//   - "proof-required" anonymous refused at the policy step (403)
//   - "closed"         no external ingestion; POST /proof/v1/operations answers
//     501, exactly as under capabilities.write: false
//
// Advertisement is a HINT; the policy decision is the authority.
type IngestionMode = string

const (
	IngestionOpen          IngestionMode = "open"
	IngestionProofRequired IngestionMode = "proof-required"
	IngestionClosed        IngestionMode = "closed"
)

// AdmissionPolicy is the relay-local admission policy — step 3 of the ingestion
// ladder.
//
// Called with the identity-proven principal DID, or "" for an anonymous
// submission. Returning false is a request-level refusal (403): nothing in the
// batch is examined further and no per-item results are produced. Returning an
// ERROR is a policy that could not be evaluated, which FAILS CLOSED (503 — the
// server's condition, not a judgment on the caller).
//
// Policy CONTENT is operator-defined and out of the spec: one relay admits only
// DIDs its operator recognizes, another is open-anonymous under quotas, another
// is allowlist-only. "My peers" is one possible policy set, not a separate
// authentication scheme.
type AdmissionPolicy func(principal string) (bool, error)

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
	// Authority is THE RELAY'S OWN CONFIGURED AUTHORITY — the host an identity
	// proof must bind to ("relay.example.com", or "host:port" on a non-default
	// port).
	//
	// IT IS NEVER READ FROM A REQUEST. Host, X-Forwarded-Host, and the request
	// URL's authority are all attacker-supplied; a relay that compared a proof's
	// host against a request header would have no host binding at all.
	//
	// MULTI-AUTHORITY DEPLOYMENTS. A relay serving several hostnames "selects the
	// expected one from its own configuration" (WEB-RELAY.md, Authentication).
	// This field is that selection, made at construction: run one relay instance
	// per authority, or have the front door route each authority to the instance
	// configured for it. There is deliberately no accept-any-of-these list —
	// accepting a proof bound to authority A on a request served as authority B is
	// exactly the cross-origin replay the binding exists to stop.
	//
	// WHEN EMPTY, every authenticated route answers 503: the relay cannot
	// authenticate anything, and says so rather than blaming the caller (401) or
	// inventing a binding from the request.
	Authority string
	// ProofWindowSeconds is the acceptance window W for identity proofs (zero =
	// 60). The freshness window is the relay's to own; W + S MUST NOT exceed 300.
	ProofWindowSeconds int64
	// ProofSkewSeconds is the clock-skew allowance S (zero = 60).
	ProofSkewSeconds int64
	// Ingestion is the advertised admission mode. Empty derives from Write: true
	// reads as "open", false as "closed".
	Ingestion IngestionMode
	// AdmissionPolicy is evaluated at step 3 of the ingestion ladder. nil admits
	// everything (today's behavior, stated as a policy rather than the absence of
	// one).
	AdmissionPolicy AdmissionPolicy
	// JtiCache is the replay cache backing write-shaped identity proofs.
	//
	// nil = NewJtiReplayCache(), which is PER-PROCESS — it refuses a replay only
	// against the process that saw the original. A multi-process deployment
	// (several workers behind one authority) injects an implementation whose
	// InsertIfAbsent is atomic across the fleet — a shared store's
	// insert-if-absent, SET NX PX, a conditional put — so the replay window is
	// the deployment's, not one worker's.
	JtiCache JtiCache
	// GossipIdentityProof controls whether gossip-out attaches an identity proof
	// signed by the relay's OWN DID (WEB-RELAY.md, Relay Identity: "a gossiping
	// peer authenticates like any client: anonymously, or with an identity proof
	// signed by its own DID").
	//
	// nil = OFF, deliberately — and this is the one place the obvious default is
	// the wrong one. Signing looks free because a default-open peer admits
	// anonymous submissions anyway, so a proof "can only help". It cannot: a
	// presented proof is no longer optional to the receiver. A peer that has never
	// ingested this relay's identity chain answers 503 (unresolvable presenter),
	// and a peer with no configured authority answers 503 as well — so turning
	// this on unilaterally converts pushes that were being ACCEPTED into pushes
	// that are refused, against exactly the peers least likely to know us.
	// Anonymous is the interoperable default; a named peer is a deliberate
	// pairing between operators who have already made each other resolvable.
	//
	// Requires the relay to hold its signing key, which the JIT bootstrap
	// produces; without one the flag is inert and gossip stays anonymous.
	// Sync-in and read-through are READS and stay public — nothing to sign.
	GossipIdentityProof *bool
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
	URL string
	// DID is the identity this URL is pinned to — the DID it must keep serving
	// for this entry to keep meaning the relay it was configured against. Peer
	// state everywhere else in this library is keyed purely by URL, and a URL is
	// an address, not an identity: without a pin, a relay that re-keyed and a
	// different relay answering at that address are indistinguishable, and every
	// direction of peer traffic (sync pull, gossip push, read-through, blob
	// materialization) runs against whoever answered.
	//
	// "" means UNCHECKED, and that is the compatible default on purpose: a peer
	// named by URL alone — a `--peers` URL, the TS twin's peer config, every
	// existing caller — carries no claim about identity, and inventing one would
	// turn a working mesh into a boot failure. The pin is opt-in, supplied by a
	// caller that recorded an identity to hold the peer to (the CLI's config.toml
	// `did`, the object form of `--peers`).
	DID         string
	Gossip      *bool // nil or true = push new ops (default), false = disabled
	ReadThrough *bool // nil or true = fetch on local 404 (default), false = disabled
	Sync        *bool // nil or true = poll /log (default), false = disabled
}

// PeerLogEntry is a single entry returned by a peer's log endpoint.
type PeerLogEntry struct {
	CID      string `json:"cid"`
	JWSToken string `json:"jwsToken"`
}

// GossipProofSigner signs an identity proof over the exact request a gossip push
// is about to make. It returns the compact JWS, or "" when the relay holds no
// signing key.
type GossipProofSigner func(method, host, path string, body []byte) (string, error)

// SigningPeerClient is the OPTIONAL half of PeerClient that can carry an
// identity proof on a gossip push.
//
// It is a separate interface, and the signer is a CALLBACK rather than a header,
// for one reason: the proof binds bodyHash, so only the transport knows the exact
// octets it is about to send, and only the transport can ask for a proof over
// them. A PeerClient that does not implement this gossips anonymously — which is
// what every mock in the test suite does, unchanged.
type SigningPeerClient interface {
	SubmitOperationsSigned(peerURL string, operations []string, sign GossipProofSigner) error
}

// IdentifyingPeerClient is the OPTIONAL half of PeerClient that can ask a peer
// which DID it serves — the one question PeerConfig.DID has to be checked
// against.
//
// It is a separate interface for the same reason SigningPeerClient is: the
// relay expresses the intent and the caller owns the transport, so a PeerClient
// that cannot (or will not) fetch a peer's well-known simply does not implement
// this, and every mock in the test suite keeps compiling and keeps working.
// A pin against such a transport is UNCHECKABLE, not violated — see peerPinned,
// which treats "cannot ask" the same way it treats "asked and got no answer".
type IdentifyingPeerClient interface {
	// GetPeerDID returns the DID the peer at peerURL currently serves. An error
	// means the question was not answered (unreachable, non-200, undecodable) —
	// it never means the peer answered with a different identity.
	GetPeerDID(peerURL string) (string, error)
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
	CID        string            `json:"cid"`
	IssuerDID  string            `json:"issuerDID"`
	Att        []AttenuationPair `json:"att"`
	Exp        int64             `json:"exp"`
	JWSToken   string            `json:"jwsToken"`
	CreatedAt  string            `json:"createdAt"`
	IngestedAt string            `json:"ingestedAt"`
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
	// SignerKey is the multibase public key this operation's signature verified
	// against, resolved at ingest by appendOperationToLog and persisted on the
	// operation-log row as the substrate for /index/v0/operations?signerKey=.
	//
	// json:"-" ON PURPOSE: the proof-plane /proof/v1/log entry shape is a wire
	// contract both reference relays serve byte-identically, and the signer key
	// is index metadata, not proof — the JWS in the same entry already carries
	// the kid a reader can resolve itself. A peer's log page therefore decodes
	// with SignerKey empty, and the receiving relay re-resolves it against its
	// own store when it ingests, which is the correct behavior anyway: the value
	// is what THIS relay's verification computed.
	SignerKey string `json:"-"`
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

// PeerSyncStatus is one peer's view of this process's sync loop — OPTIONAL
// additive telemetry surfaced at stats.peerSync in the well-known. The other
// stats say what this relay holds; none of them answer the two questions an
// operator actually has when replication looks wrong: is the loop still running
// at all, and is THIS peer converging. A caught-up relay is silent in the logs
// by design, which makes a healthy steady state and a dead sync goroutine
// indistinguishable from the outside without this.
//
// Timestamps are pointers WITHOUT omitempty so a peer that has never been
// attempted serializes them as JSON null rather than dropping the key.
type PeerSyncStatus struct {
	LastAttemptAt *string `json:"lastAttemptAt"`
	// LastSuccessAt is the last attempt that completed without a transport or
	// store failure; it stays put while ConsecutiveFailures climbs.
	LastSuccessAt *string `json:"lastSuccessAt"`
	// LastReceived counts entries the peer served on the last cycle, duplicates
	// included; LastInserted counts the ones genuinely new to the raw store.
	// They diverge on every re-walk, so LastReceived alone is not a work signal.
	LastReceived int `json:"lastReceived"`
	LastInserted int `json:"lastInserted"`
	// CaughtUp is false while a backlog remains (the cycle hit its op cap) and
	// while a cycle fails outright — a failed cycle also receives nothing, and
	// reading that as "caught up" would paint a wedged peer green.
	CaughtUp            bool `json:"caughtUp"`
	ConsecutiveFailures int  `json:"consecutiveFailures"`
	// The trailing anti-entropy scrub (see reconcilePeer), which runs on its own
	// slow cadence and is otherwise invisible.
	LastReconcileAt       *string `json:"lastReconcileAt"`
	LastReconcileReceived int     `json:"lastReconcileReceived"`
	LastReconcileInserted int     `json:"lastReconcileInserted"`
	// PinMismatch names the peer-pin refusal currently suppressing traffic to
	// this peer, or null when the peer is unpinned, unpinnable, or serving the
	// DID it is pinned to. A skipped peer is otherwise indistinguishable from a
	// peer with nothing to send — the cycle attempts, receives nothing, fails
	// nothing — which is exactly the silence a moved pin must not be able to hide
	// in. See peerPinned.
	PinMismatch *string `json:"pinMismatch"`
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

	// raw ops — content-addressed store for all received operations.
	// PutRawOp is put-if-absent. It reports whether the row was NEWLY inserted;
	// false means the CID was already stored, which is not an error. Peer sync
	// re-reads the same ops constantly (a partial final page is re-fetched every
	// cycle, and the anti-entropy scrub re-walks the log by design), so a caller
	// that counts received entries instead of inserted rows overstates the work
	// it did by an unbounded margin.
	PutRawOp(cid string, jwsToken string, origin ...OpOrigin) (inserted bool, err error)
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
	// an exact point lookup; Key keeps identities that have EVER PROVED that
	// public key (see PutIndexIdentityKey).
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
	// QueryIndexCredentials pages held public credentials by lexical cid or the
	// selected recency composite, filtered by issuer, resource, and/or action exact
	// match. For chain resources, the chain:* bucket is unioned.
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
	// PutIndexIdentityKey adds one public key a POSSESSION PROOF admitted into an
	// identity chain to that identity's has-ever-proved key set — the reverse
	// index behind `key=`, and the one-key-one-DID oracle a holder consults before
	// signing a key proof. Rows are (publicKey, did, keyID) and are never removed:
	// an update replaces the chain's key arrays, so has-ever-proved has to be
	// captured per op rather than diffed from head state. A key a chain merely
	// DECLARED never lands here — see putIndexIdentityProvedKeys for why indexing
	// declarations would let a stranger burn a key they do not hold. publicKey is
	// the multibase string verbatim, matched as opaque bytes.
	PutIndexIdentityKey(did string, keyID string, publicKey string) error
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
	Key              string // "" = no filter; opaque multibase public key, has-ever-proved
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
	Issuer       string
	Resource     *string // nil = no filter
	Action       *string // nil = no filter
	After        string
	OrderedAfter *indexOrderedCursor
	Order        string
	Limit        int
}

// IndexOperationQuery is the always-time-ordered filter over accepted operations.
type IndexOperationQuery struct {
	Kind    string
	ChainID *string
	// SignerKey is "" for no filter; otherwise an opaque multibase public key
	// matched byte-for-byte against the key the row's signature verified against
	// at ingest. Same posture as IndexIdentityQuery.Key: no format validation, so
	// a string no accepted operation was signed with is an empty page, not a 400.
	// A row with no resolved signer key matches no value.
	SignerKey    string
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
	// ListOperationLogEntriesMissingSignerKey returns the operation-log rows that
	// carry no resolved signer key, as (CID, JWSToken) pairs — the backfill input
	// for /index/v0/operations?signerKey= on a corpus ingested before the column
	// existed. NOT part of ClearIndexProjection: the operation log is the
	// authoritative record a rebuild reads FROM, never a projection table it
	// truncates, so the signer key is filled in place on rows that lack it.
	ListOperationLogEntriesMissingSignerKey() ([]LogEntry, error)
	// SetOperationLogSignerKey stamps one operation-log row's resolved signer key.
	SetOperationLogSignerKey(cid string, signerKey string) error
}
