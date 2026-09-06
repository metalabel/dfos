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
// (RELAY.md, Relay identity and profile). A relay constructed from a DID and a profile
// alone still runs; it simply gossips anonymously.
type RelayIdentity struct {
	DID                string
	ProfileArtifactJWS string
	PrivateKey         ed25519.PrivateKey
	KeyID              string
}

// IngestionMode is the advertised ingestion admission mode (RELAY.md, Admission).
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

// IndexProjectionMode selects who drives the index projection worker.
//
//   - "inline"   the relay drains the projection after an ingest batch, on its
//     own goroutine and OUTSIDE the ingest mutex (default)
//   - "external" the relay never runs the worker; the operator calls
//     Relay.ProjectIndex from a timer or another process
type IndexProjectionMode = string

const (
	IndexProjectionInline   IndexProjectionMode = "inline"
	IndexProjectionExternal IndexProjectionMode = "external"
)

// RelayOptions configures a new Relay instance.
type RelayOptions struct {
	// Store is at minimum a RelayReadStore. NewRelay type-asserts the further
	// contracts (RelayWriteStore, IndexReadStore, IndexWriteStore, SigningStore,
	// RelayWriterState) ONCE at construction and derives the advertised
	// capabilities from what it finds; nothing in this package probes a member
	// per call.
	Store       RelayReadStore
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
	// expected one from its own configuration" (RELAY.md, Authentication).
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
	// signed by the relay's OWN DID (RELAY.md, Relay identity and profile: "a gossiping
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
	// IndexProjection selects who drives the index projection worker. Empty =
	// "inline". Either way the worker runs OUTSIDE the ingest mutex, on a
	// persisted log cursor, with a per-run budget.
	IndexProjection IndexProjectionMode
	// IndexProjectionBudget caps log entries projected and content rows swept per
	// projection run. Zero = DefaultIndexProjectionBudget.
	IndexProjectionBudget int
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
	// IngestedAt is the relay's receipt stamp for this operation, in the
	// well-known's timestamp grammar.
	//
	// json:"-" ON PURPOSE: the proof-plane /proof/v1/log entry shape is a wire
	// contract both reference relays serve byte-identically, and the receipt time
	// is store state, not proof. It is carried here because the index projection
	// reads the log and needs it — an artifact row and a countersignature row both
	// report when the relay accepted the operation, and re-reading the wall clock
	// at projection time would date them by when the worker ran.
	IngestedAt string `json:"-"`
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

	// StoreFault is the structured store-fault signal. When true, the rejection
	// is not a verdict about the operation at all: a store call failed, so
	// nothing was decided and — because Commit is atomic — nothing was
	// persisted. Retryable for the same reason as a missing dependency and with
	// more urgency, since a permanent rejection DELETES the raw op and a
	// momentary store fault must never be able to destroy a valid operation.
	//
	// Relay-internal, so it stays off the wire. Mirrors the TS twin's
	// IngestionResult.storeFault.
	StoreFault bool `json:"-"`
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

// -----------------------------------------------------------------------------
// relay store contracts
// -----------------------------------------------------------------------------

/*

  SIX CONTRACTS, NOT ONE, AND NO OPTIONAL MEMBERS.

  RelayReadStore is every read a route performs. RelayWriteStore adds ONE method
  — Commit — and is what a relay that accepts operations needs. IndexReadStore /
  IndexWriteStore are the optional index profile: the query side and the
  projection side, split because a store can serve one without the other (a
  store whose index is maintained by an external worker implements the queries
  and not the writes). SigningStore is the optional mailbox. RelayWriterState is
  bookkeeping this package keeps for itself.

  The split exists because the single 53-member interface was not implementable.
  Its only production consumer serves the reads for real, answers the nine index
  queries for real, and satisfies ~22 write members by throwing — which is not
  an implementation, it is a runtime promise that those members are never
  called. A contract you satisfy by throwing tells you nothing at construction
  time.

  With the split, what a store can do is a fact about its TYPE. NewRelay type-
  asserts each further contract ONCE and holds the narrowed reference; the
  advertised capabilities are derived from those assertions plus config. No
  route probes a member.

*/

// RelayReadStore is EVERY READ A ROUTE PERFORMS. The base contract: implement
// this and the relay serves the whole proof plane, the content plane, the log,
// and the revocation routes — read-only.
//
// FAIL CLOSED. A read that cannot be answered returns an ERROR. It never
// returns a nil result to mean "the store is unwell": absence and failure are
// different answers, and ingestion classifies them differently — absence is a
// verdict, an error is retryable (see storeReadError in ingest.go).
//
// Concurrency contract: a durable implementation enforces optimistic
// concurrency (compare-and-swap on the chain head CID) or pessimistic locking
// so two concurrent extensions of one chain cannot overwrite each other.
type RelayReadStore interface {
	// --- operations ---

	GetOperation(cid string) (*StoredOperation, error)

	// --- chains ---

	GetIdentityChain(did string) (*StoredIdentityChain, error)
	GetContentChain(contentID string) (*StoredContentChain, error)

	// GetIdentityStateAtCID returns materialized identity state at a specific
	// operation CID, or nil when the CID is not in this chain's log. Fork
	// verification needs state at the fork point to check signer authority and
	// createdAt ordering. Implementations decide how: replay from genesis, or
	// replay from the nearest snapshot.
	GetIdentityStateAtCID(did, cid string) (*IdentityStateAtCID, error)
	// GetContentStateAtCID is the same for content chains.
	GetContentStateAtCID(contentID, cid string) (*ContentStateAtCID, error)

	// --- blobs (content plane) ---

	GetBlob(key BlobKey) ([]byte, error)

	// --- countersignatures ---

	// GetCountersignatures returns the accepted countersignatures over one
	// operation, deduped one per witness.
	GetCountersignatures(operationCID string) ([]string, error)

	// --- operation log ---

	// ReadLog pages the global append-only log by relay-local cursor. Cursors
	// are the relay's own ingestion order, so a cursor this log never issued
	// returns ErrUnknownLogCursor — the route maps that to 400, never a silently
	// empty page.
	ReadLog(after string, limit int) (entries []LogEntry, cursor string, err error)

	// RelayStats reports operational statistics over the global log, for the
	// well-known response.
	RelayStats() (*RelayStats, error)

	// --- revocations ---

	// IsCredentialRevoked reports whether a credential CID has been revoked by a
	// specific issuer.
	//
	// asOfUnix <= 0 is the FRESHNESS answer — "revoked as far as this relay knows
	// right now" — which is what acceptance gates (ingest, live read-path
	// authorization) ask. asOfUnix > 0 is the VALIDITY answer: true only if the
	// revocation's own signed createdAt is at or before asOfUnix, which is what
	// verifying already-committed history asks.
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

	// --- public credentials (standing authorization) ---

	// GetPublicCredentials returns the held public credentials covering a
	// resource, as JWS tokens. A chain:* grant covers every chain: resource and
	// is returned for any of them.
	GetPublicCredentials(resource string) ([]string, error)
	// GetPublicCredentialByCID returns one held public credential by CID.
	GetPublicCredentialByCID(cid string) (*StoredPublicCredential, error)
}

// CountersignatureCommit adds one countersignature to a target's set (one per
// witness per target).
type CountersignatureCommit struct {
	TargetCID string
	JWSToken  string
}

// PublicCredentialRemoval drops a held standing grant, ISSUER-SCOPED: the store
// removes the credential only when the held row's issuerDID equals IssuerDID.
//
// Scoping is the whole point. Revocation is only meaningful from a credential's
// own issuer (IsCredentialRevoked is keyed on the pair), but the removal used to
// be keyed on the credential CID alone — so any identity could sign a revocation
// naming someone else's credential CID and the relay would drop the held grant,
// un-publishing public content it had no authority over. The store enforces the
// pairing.
type PublicCredentialRemoval struct {
	IssuerDID     string
	CredentialCID string
}

// OperationCommit is ONE ACCEPTED OPERATION, AND EVERYTHING IT IMPLIES.
//
// The write contract used to be 14 put/add/remove members that ingestion called
// in sequence, so "an operation was accepted" was a shape a store had to infer
// from a run of unrelated calls it could not see the end of — and a fault
// halfway through left the store holding half an operation with no way to know
// it. This describes the whole effect up front so a store persists it in one
// transaction or not at all.
//
// Exactly one operation per commit. The members present are a function of the
// operation's kind:
//
//   - identity op   → Operation, IdentityChain, LogEntry
//   - content op    → Operation, ContentChain, LogEntry
//   - artifact      → Operation, LogEntry
//   - countersign   → Operation, Countersignature, LogEntry
//   - credential    → Operation, PublicCredential, LogEntry
//   - revocation    → Operation, Revocation, RemovePublicCredential, LogEntry
//
// LogEntry is nil when the relay runs with the global log disabled.
type OperationCommit struct {
	// Operation is the operation row. Its CID is the commit's idempotency key.
	Operation StoredOperation
	// LogEntry is the global-log append. Nil when the relay's log is disabled.
	LogEntry *LogEntry
	// IdentityChain is the identity chain's new head, log and state, whole.
	IdentityChain *StoredIdentityChain
	// ContentChain is the content chain's new head, log and state, whole.
	ContentChain *StoredContentChain
	// Countersignature adds this countersignature to the target's set.
	Countersignature *CountersignatureCommit
	// Revocation adds this revocation to the revocation set (earliest boundary
	// wins — see revocationSupersedes).
	Revocation *StoredRevocation
	// PublicCredential adds this credential as standing public authorization.
	PublicCredential *StoredPublicCredential
	// RemovePublicCredential drops a held standing grant, issuer-scoped.
	RemovePublicCredential *PublicCredentialRemoval
}

// BlobCommit is a document blob landing on the content plane, out of band from
// its operation.
type BlobCommit struct {
	Key   BlobKey
	Bytes []byte
}

// CommitBatch is one atomic unit of relay write. Exactly one member is set: the
// content plane accepts bytes that no single operation carries, because a
// document blob arrives on its own route, often after the operation that
// referenced it.
type CommitBatch struct {
	Operation *OperationCommit
	Blob      *BlobCommit
}

// CommitResult is "new" when the batch was persisted, "duplicate" when this
// operation CID was already held and NOTHING was written.
//
// The duplicate answer is the race backstop, not the primary check: ingestion
// still reads for an existing operation before it verifies, because it must
// distinguish "same op" from "same CID, different signature". A store that
// cannot detect the race may always answer "new", and idempotent writes make
// that correct — but a store that CAN detect it makes concurrent submission of
// one operation safe without a relay-wide lock. A blob commit always answers
// "new": blob bytes are content-addressed, so a rewrite is a no-op.
type CommitResult string

const (
	CommitNew       CommitResult = "new"
	CommitDuplicate CommitResult = "duplicate"
)

// RelayWriteStore is a store that accepts writes. ONE method: the relay
// describes an accepted operation, the store persists all of it or none of it.
//
// ATOMICITY IS THE CONTRACT, and it is what makes the relay fail closed. A
// partial commit is a corrupt relay: an operation in the operations table but
// not in the log is invisible to every puller forever, and a chain head advanced
// without its operation row breaks fork verification. Worse, the half that DID
// land makes the idempotency check at the top of each ingest path answer
// "duplicate" on every retry, so the half that failed is never made up.
//
// If Commit returns an error, the store MUST have persisted nothing. The relay
// classifies the error as a retryable store fault, leaves the raw operation
// pending, and re-ingests it on a later pass.
//
// This subsumes the transaction envelope the relay used to open around a chunk
// of operations (BeginWriteBatch / CommitWriteBatch / RollbackWriteBatch): the
// atomic unit is one operation, owned by the store, rather than a batch whose
// rollback the relay had to orchestrate from the outside.
type RelayWriteStore interface {
	RelayReadStore
	Commit(batch CommitBatch) (CommitResult, error)
}

// -----------------------------------------------------------------------------
// index profile (optional)
// -----------------------------------------------------------------------------

// IndexReadStore is THE QUERY SIDE of the index profile: the nine reads behind
// /index/v0.
//
// Queries push their filters and keyset cursor into the store so a page costs
// O(page), never O(corpus): rows come back ascending by natural key, strictly
// greater than After (bytewise), and capped at Limit. The route layer computes
// next = len(rows) == limit ? key(last) : null. Row VALUES are a pure function
// of chain state + held blobs + standing credentials, so a recompute always
// converges to the same row regardless of when it runs — that is what makes
// incremental projection and a full rebuild interchangeable.
//
// A store implementing this and NOT IndexWriteStore serves the index from rows
// some other process maintains. That is a supported shape, and the relay does no
// projection work for it.
//
// EVERY TYPE IN THESE SIGNATURES IS EXPORTED, which is what makes "optional
// profile" true rather than aspirational: a Postgres or Elasticsearch store in
// another package can implement the whole thing. The row structs used to be
// package-private, so an outside store could satisfy the method set only by
// being inside this package.
type IndexReadStore interface {
	// QueryIndexIdentities pages identity projection rows ascending by DID,
	// did > After, length <= Limit. HasPublicProfile (≡ profile != nil &&
	// profile.publicRead) filters to identities exposing a public profile; DID is
	// an exact point lookup; Key keeps identities that have EVER PROVED that
	// public key.
	QueryIndexIdentities(q IndexIdentityQuery) ([]IndexIdentityRow, error)
	// QueryIndexContent pages content projection rows ascending by contentId,
	// contentId > After, length <= Limit, filtered by any provided
	// point ID / actor / document / visibility / deletion predicates.
	QueryIndexContent(q IndexContentQuery) ([]IndexContentRow, error)
	// QueryIndexCredits pages public-head credit rows by their composite key.
	QueryIndexCredits(q IndexCreditQuery) ([]IndexCreditRow, error)
	QueryIndexArtifacts(q IndexArtifactQuery) ([]IndexArtifactRow, error)
	// QueryIndexCountersignatures pages countersignature projection rows for one
	// witness ascending by cid, cid > After, length <= Limit. Reflects the
	// store's ACCEPTED countersign set (deduped one-per-witness-per-target).
	QueryIndexCountersignatures(q IndexCountersignatureQuery) ([]IndexCountersignatureRow, error)
	// QueryIndexCredentials pages held public credentials by lexical cid or the
	// selected recency composite, filtered by issuer, resource, and/or action exact
	// match. For chain resources, the chain:* bucket is unioned.
	QueryIndexCredentials(q IndexCredentialQuery) ([]IndexCredentialRow, error)
	// QueryIndexOperations pages the accepted operation log by relay or author recency.
	QueryIndexOperations(q IndexOperationQuery) ([]IndexOperationRow, error)
	// GetIndexIdentityDIDsByProfileAnchor is the reverse lookup for the "content
	// changed → recompute the identities anchored on it" cascade: DIDs of
	// identity projection rows whose profile.anchor equals contentID.
	GetIndexIdentityDIDsByProfileAnchor(contentID string) ([]string, error)
	// GetIndexContentIDsByDocumentCID is the reverse lookup for the "blob landed
	// → recompute the content rows that project that document" cascade: contentIds
	// of content projection rows whose currentDocumentCID equals documentCID.
	GetIndexContentIDsByDocumentCID(documentCID string) ([]string, error)
}

// IndexCreditRowSet is one chain's COMPLETE public-head credit set. Applying it
// REPLACES that chain's credit rows.
type IndexCreditRowSet struct {
	ContentID string
	Rows      []IndexCreditRow
}

// IndexIdentityKeyRow is one has-ever-proved reverse row: the multibase public
// key an accepted identity operation left PROVED, with the DID and key id it was
// proved into.
//
// UPSERTED, NEVER DELETED. A rotation removes nothing and a deleted identity
// keeps its rows. Append-only plus a monotonic ProvedKeys is what makes the
// accumulated table equal head state's ProvedKeys, so incremental projection and
// a full rebuild agree. A key an operation merely DECLARED is never recorded: no
// possession proof admitted it, so recording it would let a stranger burn a key
// they do not hold.
type IndexIdentityKeyRow struct {
	DID       string
	KeyID     string
	PublicKey string
}

// IndexContentSignerRow is one accepted content-operation signer, added to a
// chain's branch-inclusive signer set.
type IndexContentSignerRow struct {
	ContentID string
	DID       string
}

// IndexOperationSignerKey is the multibase public key one accepted operation's
// signature verified against, stamped onto its operation-log row as the
// substrate for /index/v0/operations?signerKey=.
//
// The operation log is the authoritative record, never a projection table, so
// this column is filled IN PLACE and survives ClearIndexProjection. A key that
// does not resolve is never stamped: the row stays NULL, an equality predicate
// never matches NULL, and the filter's honest answer for a key no chain proved
// is an empty page.
type IndexOperationSignerKey struct {
	CID       string
	PublicKey string
}

// IndexRowBatch is one projection run's recomputed rows, applied together.
type IndexRowBatch struct {
	Identities          []IndexIdentityRow
	Content             []IndexContentRow
	Credits             []IndexCreditRowSet
	Artifacts           []IndexArtifactRow
	Countersignatures   []StoredIndexCountersignature
	IdentityKeys        []IndexIdentityKeyRow
	ContentSigners      []IndexContentSignerRow
	OperationSignerKeys []IndexOperationSignerKey
}

// IndexSweepScope names which content rows an outstanding sweep enumerates.
type IndexSweepScope string

const (
	// IndexSweepAll enumerates every content row: what a chain:* grant or an
	// identity restore reaches (a suspended row is not in the public subset, so
	// nothing narrower would find it).
	IndexSweepAll IndexSweepScope = "all"
	// IndexSweepPublic enumerates only currently-public-read rows: the affected
	// superset for a visibility revocation or an identity delete.
	IndexSweepPublic IndexSweepScope = "public"
)

// IndexSweepState is a resumable full-corpus sweep. After is the last contentId
// recomputed, "" at the start.
type IndexSweepState struct {
	Scope IndexSweepScope `json:"scope"`
	After string          `json:"after"`
}

// IndexCursor is where the projection worker got to. Persisted, so a run resumes
// rather than restarts.
//
// LogCursor is the CID of the last operation-log entry projected, "" before the
// first run. Sweep is a full-corpus recompute in progress: some operations (a
// chain:* grant, an identity delete or restore) change the visibility of rows
// they never name, and draining that in one pass is the unbounded stall this
// cursor exists to break up.
type IndexCursor struct {
	LogCursor string           `json:"logCursor"`
	Sweep     *IndexSweepState `json:"sweep"`
}

// IndexWriteStore is THE PROJECTION SIDE of the index profile. A store
// implementing it lets this package run the projection worker (see
// projectIndex); a store that omits it keeps its index current some other way.
//
// ApplyIndexRows applies one run's rows; implementations that can SHOULD apply
// them in a single transaction, so a failed run leaves the cursor and the rows
// consistent with each other.
type IndexWriteStore interface {
	ApplyIndexRows(rows IndexRowBatch) error
	GetIndexCursor() (IndexCursor, error)
	SetIndexCursor(cursor IndexCursor) error
}

// -----------------------------------------------------------------------------
// signing profile (optional)
// -----------------------------------------------------------------------------

// SigningStore is the optional ephemeral signing-mailbox courier store.
type SigningStore interface {
	PruneExpiredSignRequests(now time.Time) error
	GetSignRequest(cid string, now time.Time) (*StoredSignRequest, error)
	PutSignRequest(request StoredSignRequest, now time.Time) (SigningPutResult, error)
	ListPendingSignRequests(subjectDID, after string, limit int, now time.Time) ([]StoredSignRequest, string, error)
	PutSignResponse(cid, response string, now time.Time) (SigningPutResult, error)
	DeclineSignRequest(cid string, now time.Time) (SigningPutResult, error)
}

// -----------------------------------------------------------------------------
// writer-internal state
// -----------------------------------------------------------------------------

// RelayWriterState is INTERNAL TO A RELAY THAT WRITES. It is not part of the
// contract a store implementor reads: raw-op durability, the sequencer's pending
// set, and peer sync cursors are bookkeeping this package keeps for itself, and
// a store that never accepts writes and configures no peers has nothing to keep.
//
// Both reference stores implement it because the reference relay both writes and
// peers. It is exported so an embedder building a durable writing relay can
// implement it deliberately, not because a store needs it to be useful.
type RelayWriterState interface {
	// PutRawOp is put-if-absent. It reports whether the row was NEWLY inserted;
	// false means the CID was already stored, which is not an error. Peer sync
	// re-reads the same ops constantly (a partial final page is re-fetched every
	// cycle, and the anti-entropy scrub re-walks the log by design), so a caller
	// that counts received entries instead of inserted rows overstates the work
	// it did by an unbounded margin.
	PutRawOp(cid string, jwsToken string, origin ...OpOrigin) (inserted bool, err error)
	// GetUnsequencedOps returns JWS tokens + origins where status = 'pending'.
	GetUnsequencedOps(limit int) ([]PendingOp, error)
	MarkOpsSequenced(cids []string) error
	MarkOpRejected(cid string, reason string) error
	CountUnsequenced() (int, error)
	// ResetSequencer resets all non-rejected raw ops to pending.
	ResetSequencer() error
	GetPeerCursor(peerURL string) (string, error)
	SetPeerCursor(peerURL string, cursor string) error
	ResetPeerCursors() error
}

// -----------------------------------------------------------------------------
// durable-store maintenance (optional)
// -----------------------------------------------------------------------------

// MigratableStore is an OPTIONAL durable-store maintenance profile: the two
// members the boot-time identity-state repair needs, and nothing else.
//
// It is NOT a general write contract. RewriteIdentityChainState replaces a row's
// materialized state with a fresh walk of the same log it already holds — it
// admits nothing, changes no chain's history, and is only ever called by
// backfillProvedKeyState. An ephemeral store has nothing persisted by an older
// binary, and a read-only store has nothing to migrate; both simply omit it and
// the repair is a no-op.
type MigratableStore interface {
	ListIdentityChains() ([]StoredIdentityChain, error)
	RewriteIdentityChainState(chain StoredIdentityChain) error
}

// RebuildableIndexStore is an OPTIONAL durable-store maintenance profile for the
// index projection: the version stamp that says which projection schema the rows
// on disk were built under, and the truncate that lets a rebuild start clean.
//
// A rebuild is just "clear the rows, reset the cursor, and let the projection
// worker re-walk the log" — the log is the authoritative record every row is
// derived from, so there is no separate corpus enumeration to keep in sync with
// the incremental path.
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

// IndexIdentityQuery is the keyset-paged filter for identity projection rows.
type IndexIdentityQuery struct {
	DID              string // "" = no filter
	Key              string // "" = no filter; opaque multibase public key, has-ever-proved
	HasPublicProfile *bool  // nil = no filter
	NameContains     string // "" = no filter
	After            string
	OrderedAfter     *IndexOrderedCursor
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
	OrderedAfter  *IndexOrderedCursor
	Order         string
	Limit         int
}

type IndexCreditQuery struct {
	DID       *string
	ContentID *string
	Role      *string
	After     *IndexCreditCursor
	Limit     int
}

type IndexArtifactQuery struct {
	CID          *string
	Signer       string
	DocSchema    *string
	After        string
	OrderedAfter *IndexOrderedCursor
	Order        string
	Limit        int
}

// IndexCountersignatureQuery is the keyset-paged filter for countersignature
// projection rows scoped to a single witness.
type IndexCountersignatureQuery struct {
	Witness      string
	Relation     *string
	After        string
	OrderedAfter *IndexOrderedCursor
	Order        string
	Limit        int
}

// IndexCredentialQuery is the keyset-paged filter for held public credentials.
type IndexCredentialQuery struct {
	Issuer       string
	Resource     *string // nil = no filter
	Action       *string // nil = no filter
	After        string
	OrderedAfter *IndexOrderedCursor
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
	OrderedAfter *IndexOrderedCursor
	Order        string
	Limit        int
}

// StoredIndexCountersignature is a countersignature projection row plus the
// witness_did column that scopes witness queries. WitnessDID is never part of the
// wire row (the witness is echoed at the response top level).
type StoredIndexCountersignature struct {
	CID        string
	TargetCID  string
	Relation   *string
	JWSToken   string
	WitnessDID string
	CreatedAt  string
	IngestedAt string
}
