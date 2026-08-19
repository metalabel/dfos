/*

  TYPES

  Core types for the DFOS web relay

*/

import type { VerifiedContentChain, VerifiedIdentity } from '@metalabel/dfos-protocol/chain';
import type { Attenuation } from '@metalabel/dfos-protocol/credentials';
import { base64urlDecode, base64urlEncode } from '@metalabel/dfos-protocol/crypto';
import type {
  IndexContentRow,
  IndexCountersignatureQueryRow,
  IndexCredentialRow,
  IndexIdentityRow,
  IndexOperationRow,
  IndexOrder,
  IndexOrderedCursor,
  IndexRecencyOrder,
} from './index-routes';

/**
 * Namespaces every frozen proof-plane route under one prefix so the two version
 * clocks (proof v1 / document 0.x) are legible in the URL and each plane
 * mounts/proxies by prefix. Frozen with protocol v1; MUST stay in byte-sync
 * with the Go relay (proofBasePath in routes.go) and the clients. Document gateway
 * routes (/content/{id}/blob*) and .well-known stay at root on their own clock.
 */
export const PROOF_BASE_PATH = '/proof/v1';

// -----------------------------------------------------------------------------
// relay options
// -----------------------------------------------------------------------------

export interface RelayIdentity {
  /** The relay's DID */
  did: string;
  /** Profile artifact JWS token (signed by the relay DID) */
  profileArtifactJws: string;
}

export interface RelayOptions {
  /** Storage backend */
  store: RelayStore;
  /** Pre-created relay identity — if omitted, a JIT identity and profile are generated */
  identity?: RelayIdentity;
  /** Whether content plane routes are enabled (default: true) */
  content?: boolean;
  /** Whether the global operation log is enabled (default: true) */
  log?: boolean;
  /** Whether the revocation status route family is enabled (default: true) */
  revocations?: boolean;
  /** Whether the index query family is enabled (default: true) */
  index?: boolean;
  /**
   * Whether this relay accepts writes (default: true). When false, it is a LITE
   * pull-only proof node: POST /proof/v1/operations is rejected (501), so neither
   * client writes nor peer gossip-in are accepted. The node still ingests by
   * PULLING from peers (syncFromPeers polls their /log).
   */
  write?: boolean;
  /** Whether the ephemeral signing mailbox is enabled (default: false) */
  signing?: boolean;
  /** Peer relay configurations */
  peers?: PeerConfig[];
  /** Injected peer client — if omitted, a default HTTP implementation is used */
  peerClient?: PeerClient;
  /**
   * Max lifetime (exp-iat, seconds) honored on a self-signed auth token.
   * Default 86400 (24h); a value <= 0 disables the ceiling. Applies only to auth
   * tokens, never to DFOS credentials.
   */
  maxAuthTokenTTLSeconds?: number;
}

// -----------------------------------------------------------------------------
// peering
// -----------------------------------------------------------------------------

export interface PeerConfig {
  url: string;
  /** Push new ops to this peer (default: true) */
  gossip?: boolean;
  /** Fetch from this peer on local 404 (default: true) */
  readThrough?: boolean;
  /** Poll this peer's /log for background sync (default: true) */
  sync?: boolean;
}

/** A log entry returned by a peer — CID and JWS token */
export interface PeerLogEntry {
  cid: string;
  jwsToken: string;
  /**
   * Relay-asserted operation kind. Global /log entries carry it; chain logs
   * omit it. A ROUTING HINT for indexers/browsers, never a verification
   * input — folds re-derive everything from the JWS itself.
   */
  kind?: string;
  /**
   * Relay-asserted chain identifier — DID for identity/artifact ops, contentId
   * for content ops, targetCID for countersigns, issuer DID for credentials.
   * Same hint-only status as `kind`.
   */
  chainId?: string;
}

/** Injected peer transport — the relay expresses intent, the caller decides transport */
export interface PeerClient {
  /** Fetch identity chain log from a peer */
  getIdentityLog(
    peerUrl: string,
    did: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; next: string | null } | 'invalid-cursor' | null>;

  /** Fetch content chain log from a peer */
  getContentLog(
    peerUrl: string,
    contentId: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; next: string | null } | 'invalid-cursor' | null>;

  /**
   * Fetch global operation log from a peer. Returns the page, `null` on any
   * transport/peer failure, or `'invalid-cursor'` when the peer explicitly
   * rejected the `after` cursor (400) — cursors are relay-local, so a peer that
   * wiped or rebuilt its log invalidates ours; the sync loop resets and
   * re-syncs from the start (ingestion is idempotent).
   */
  getOperationLog(
    peerUrl: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; next: string | null } | 'invalid-cursor' | null>;

  /** Push operations to a peer (fire-and-forget) */
  submitOperations(peerUrl: string, operations: string[]): Promise<void>;
}

// -----------------------------------------------------------------------------
// stored artifacts
// -----------------------------------------------------------------------------

export interface StoredIdentityChain {
  did: string;
  /** Ordered JWS tokens from genesis to head */
  log: string[];
  /** CID of the most recent operation */
  headCID: string;
  /** createdAt timestamp of the most recent operation */
  lastCreatedAt: string;
  state: VerifiedIdentity;
}

export interface StoredContentChain {
  contentId: string;
  genesisCID: string;
  /** Ordered JWS tokens from genesis to head */
  log: string[];
  /** createdAt timestamp of the most recent operation */
  lastCreatedAt: string;
  state: VerifiedContentChain;
}

export interface StoredOperation {
  cid: string;
  jwsToken: string;
  /** Which chain type this operation belongs to */
  chainType: 'identity' | 'content' | 'artifact' | 'countersign' | 'revocation' | 'credential';
  /** The chain identifier — DID for identity/artifact, contentId for content, targetCID for countersign */
  chainId: string;
}

/** Key for blob storage — deduplicates across chains sharing the same document */
export interface BlobKey {
  creatorDID: string;
  documentCID: string;
}

// -----------------------------------------------------------------------------
// operation log
// -----------------------------------------------------------------------------

/** A single entry in the global append-only operation log */
export interface LogEntry {
  cid: string;
  jwsToken: string;
  kind: OperationKind;
  chainId: string;
}

/** A peer this relay is configured to talk to, surfaced in the well-known for mesh discovery. */
export interface RelayPeerInfo {
  /** The peer relay's base URL. */
  endpoint: string;
}

/** Optional operational statistics a store MAY compute for the well-known response. */
export interface RelayStats {
  /** Total operations in the global log. */
  opCount: number;
  /** Operation counts bucketed by primitive kind (all six keys always present). */
  countsByKind: {
    identity: number;
    content: number;
    artifact: number;
    credential: number;
    countersign: number;
    revocation: number;
  };
  /** createdAt of the oldest operation in the log (log position), or null when empty. */
  oldestOpAt: string | null;
  /** CID of the newest operation in the log (the tip), or null when empty. */
  headCid: string | null;
}

/** All operation kinds in the protocol */
export type OperationKind =
  | 'identity-op'
  | 'content-op'
  | 'artifact'
  | 'countersign'
  | 'revocation'
  | 'credential';

// -----------------------------------------------------------------------------
// revocations + public credentials
// -----------------------------------------------------------------------------

export interface StoredRevocation {
  cid: string;
  issuerDID: string;
  credentialCID: string;
  jwsToken: string;
  /**
   * The revocation's own signed `createdAt` (ISO 8601), taken from the VERIFIED
   * payload at ingest — never re-decoded unverified. Persisting it is what makes
   * as-of revocation answerable: it is the boundary that separates operations a
   * revocation reaches (signed before it) from operations it does not.
   */
  createdAt: string;
}

export interface StoredPublicCredential {
  cid: string;
  issuerDID: string;
  att: Attenuation[];
  exp: number;
  jwsToken: string;
}

export interface StoredCountersignature {
  cid: string;
  targetCID: string;
  witnessDID: string;
  relation: string | null;
  jwsToken: string;
}

/** Ephemeral courier state for one sign request. */
export interface StoredSignRequest {
  cid: string;
  request: string;
  requesterDID: string;
  subjectDID: string;
  payloadTyp: string;
  payloadBytes: Uint8Array;
  expiresAt: string;
  depositedAt: string;
  declined: boolean;
  response?: string;
}

export type SigningPutResult = 'created' | 'identical' | 'conflict' | 'not-found' | 'capacity';
export type SigningDeclineResult = 'declined' | 'responded' | 'not-found';

export interface SigningCursor {
  subjectDID: string;
  depositedAt: string;
  cid: string;
}

const signingCursorEncoder = new TextEncoder();
const signingCursorDecoder = new TextDecoder('utf-8', { fatal: true });

/** Unpadded base64url of `<subjectDID>|<depositedAt-ISO-millis>|<cid>`. */
export const encodeSigningCursor = (cursor: SigningCursor): string =>
  base64urlEncode(
    signingCursorEncoder.encode(`${cursor.subjectDID}|${cursor.depositedAt}|${cursor.cid}`),
  );

export const decodeSigningCursor = (raw: string): SigningCursor | undefined => {
  try {
    const bytes = base64urlDecode(raw);
    if (base64urlEncode(bytes) !== raw) return undefined;
    const decoded = signingCursorDecoder.decode(bytes);
    const firstSeparator = decoded.indexOf('|');
    const secondSeparator = decoded.indexOf('|', firstSeparator + 1);
    if (
      firstSeparator <= 0 ||
      secondSeparator <= firstSeparator + 1 ||
      secondSeparator !== decoded.lastIndexOf('|') ||
      secondSeparator === decoded.length - 1
    ) {
      return undefined;
    }
    const subjectDID = decoded.slice(0, firstSeparator);
    const depositedAt = decoded.slice(firstSeparator + 1, secondSeparator);
    const cid = decoded.slice(secondSeparator + 1);
    if (new Date(depositedAt).toISOString() !== depositedAt) return undefined;
    return { subjectDID, depositedAt, cid };
  } catch {
    return undefined;
  }
};

// -----------------------------------------------------------------------------
// relay store interface
// -----------------------------------------------------------------------------

/**
 * Storage backend for a DFOS web relay
 *
 * Implementations handle persistence (memory, SQLite, Postgres, S3, etc.).
 * The relay core handles verification — the store just reads and writes.
 *
 * Concurrency contract: the in-memory store is safe under single-threaded JS.
 * Durable implementations must enforce optimistic concurrency (compare-and-swap
 * on chain head CID) or pessimistic locking to prevent concurrent extensions
 * from silently overwriting each other.
 */
export interface RelayStore {
  // --- signing mailbox (ephemeral courier state) ---

  getSignRequest?(cid: string, now: number): Promise<StoredSignRequest | undefined>;
  pruneExpiredSignRequests?(now: number): Promise<void>;
  putSignRequest?(request: StoredSignRequest, now: number): Promise<SigningPutResult>;
  listPendingSignRequests?(params: {
    subjectDID: string;
    after?: string;
    limit: number;
    now: number;
  }): Promise<{ requests: StoredSignRequest[]; next: string | null } | null>;
  putSignResponse?(cid: string, response: string, now: number): Promise<SigningPutResult>;
  declineSignRequest?(cid: string, now: number): Promise<SigningDeclineResult>;

  // --- operations ---

  getOperation(cid: string): Promise<StoredOperation | undefined>;
  putOperation(op: StoredOperation): Promise<void>;

  // --- identity chains ---

  getIdentityChain(did: string): Promise<StoredIdentityChain | undefined>;
  putIdentityChain(chain: StoredIdentityChain): Promise<void>;

  // --- content chains ---

  getContentChain(contentId: string): Promise<StoredContentChain | undefined>;
  putContentChain(chain: StoredContentChain): Promise<void>;

  // --- blobs (content plane) ---

  getBlob(key: BlobKey): Promise<Uint8Array | undefined>;
  putBlob(key: BlobKey, data: Uint8Array): Promise<void>;

  // --- countersignatures ---
  // Implementations MUST deduplicate by witness DID per target CID.

  getCountersignatures(operationCID: string): Promise<string[]>;
  addCountersignature(operationCID: string, jwsToken: string): Promise<void>;

  // --- operation log ---
  // Global append-only log of all accepted operations. CID-based cursor pagination.
  // Cursors are relay-local (per-relay ingestion order): readLog resolves `after`
  // positionally and returns null for a cursor this log does not contain — the
  // route maps that to 400, never a silently empty page.

  appendToLog(entry: LogEntry): Promise<void>;
  readLog(params: {
    after?: string;
    limit: number;
  }): Promise<{ entries: LogEntry[]; next: string | null } | null>;
  /**
   * Optional: compute operational statistics over the global log for the well-known
   * response. A store that omits this leaves opCount/countsByKind/oldestOpAt/headCid
   * out of the well-known (pendingOps still reports). Reference stores implement it.
   */
  getStats?(): Promise<RelayStats>;

  // --- chain state at arbitrary CID (snapshot-backed) ---

  /**
   * Get the materialized identity state at a specific operation CID.
   *
   * Used by fork verification — the ingestion pipeline needs state at the fork
   * point to verify signer authority and createdAt ordering.
   *
   * Implementations decide how to compute this:
   * - MemoryStore: replay from genesis (chains are short in tests)
   * - SQLiteStore: check snapshot table, replay from nearest snapshot
   *
   * Returns null if the CID is not in this chain's log.
   */
  getIdentityStateAtCID(
    did: string,
    cid: string,
  ): Promise<{ state: VerifiedIdentity; lastCreatedAt: string } | null>;

  /** Same for content chains */
  getContentStateAtCID(
    contentId: string,
    cid: string,
  ): Promise<{ state: VerifiedContentChain; lastCreatedAt: string } | null>;

  // --- revocations ---

  /** Get all revoked credential CIDs for an issuer */
  getRevocations(issuerDID: string): Promise<string[]>;
  /** Add a revocation to the revocation set */
  addRevocation(revocation: StoredRevocation): Promise<void>;
  /**
   * Check if a specific credential CID has been revoked by a specific issuer.
   *
   * With `asOfUnix` omitted **or `<= 0`** this is the FRESHNESS answer — "revoked
   * as far as this relay knows right now" — which is what acceptance gates
   * (ingest, live read-path authorization) ask. With a positive `asOfUnix` it is
   * the VALIDITY answer: true only if the revocation's own signed `createdAt` is at
   * or before `asOfUnix`, which is what verifying already-committed history asks.
   * See CREDENTIALS.md "Revocation Scope".
   *
   * `<= 0` is timeless because the Go twin uses `0` as its in-band sentinel and
   * cannot express "as of epoch 0"; treating a non-positive instant as timeless in
   * both keeps the twins from answering that degenerate input oppositely. The
   * practical effect is that an operation dated at or before 1970 gets the
   * stricter (timeless) answer everywhere.
   *
   * **Implementors: accept and honor the third parameter.** JS/TS arity is
   * permissive, so a two-parameter implementation still satisfies this type — and
   * silently degrades every as-of query to the timeless answer. That direction is
   * safe (it over-rejects rather than over-admits) but it reintroduces exactly the
   * retroactive-invalidation behavior the parameter exists to fix: history that was
   * valid when it was signed starts failing verification as soon as any credential
   * in it is revoked. A store that genuinely cannot answer the as-of question
   * should document that rather than quietly ignore the argument.
   */
  isCredentialRevoked(
    issuerDID: string,
    credentialCID: string,
    asOfUnix?: number,
  ): Promise<boolean>;
  /**
   * Get the stored revocation for a credential CID, any issuer. Serves the
   * `/revocations/v1/credential/:credentialCID` status route. If more than one
   * issuer has revoked the same CID (possible — the set is keyed by
   * (issuerDID, credentialCID) and issuer-only enforcement happens at
   * credential verification, not ingest), implementations MUST return the one
   * with the lexicographically smallest issuerDID so the answer is
   * deterministic across stores and twins.
   */
  getRevocationForCredential(credentialCID: string): Promise<StoredRevocation | undefined>;
  /**
   * Get all stored revocations issued by a DID, sorted by credentialCID
   * ascending (deterministic across stores and twins — the frozen v1 keyset
   * order). Serves the
   * `/revocations/v1/issuer/:did` listing route.
   */
  getRevocationsByIssuer(issuerDID: string): Promise<StoredRevocation[]>;

  // --- index (v0) materialized projection ---
  //
  // The /index/v0 query family is served from materialized projection rows that
  // the ingestion pipeline maintains incrementally (see index-maintenance.ts).
  // Queries push their filters and keyset cursor into the store so a page costs
  // O(page), never O(corpus): rows come back ascending by natural key, strictly
  // greater than `after` (bytewise), and capped at `limit`. The route layer
  // computes `next = rows.length === limit ? key(last) : null`. Row VALUES are a
  // pure function of chain state + held blobs + standing credentials, so a
  // recompute always converges to the same row regardless of when it runs — that
  // is what makes incremental maintenance and a full rebuild interchangeable.

  /**
   * Page identity projection rows ascending by DID, `did > after`, length <=
   * limit. `hasPublicProfile` (≡ profile != null && profile.publicRead) filters
   * to identities that expose a public profile; `did` is an exact point lookup;
   * `nameContains` filters by case-insensitive substring over projected
   * `profile.name`.
   */
  queryIndexIdentities(q: {
    did?: string;
    hasPublicProfile?: boolean;
    nameContains?: string;
    after?: string;
    orderedAfter?: IndexOrderedCursor;
    order?: IndexOrder;
    limit: number;
  }): Promise<IndexIdentityRow[]>;
  /**
   * Page content projection rows ascending by contentId, `contentId > after`,
   * length <= limit, filtered by any provided point ID, actor, document,
   * visibility, or deletion predicate.
   */
  queryIndexContent(q: {
    contentId?: string;
    creator?: string;
    signer?: string;
    docSchema?: string;
    documentCID?: string;
    publicRead?: boolean;
    isDeleted?: boolean;
    after?: string;
    orderedAfter?: IndexOrderedCursor;
    order?: IndexOrder;
    limit: number;
  }): Promise<IndexContentRow[]>;
  /**
   * Page countersignature projection rows for one witness ascending by cid,
   * `cid > after`, length <= limit. Reflects the store's ACCEPTED countersign
   * set (deduped one-per-witness-per-target), never raw ops.
   */
  queryIndexCountersignatures(q: {
    witness: string;
    relation?: string;
    after?: string;
    orderedAfter?: IndexOrderedCursor;
    order?: IndexRecencyOrder;
    limit: number;
  }): Promise<IndexCountersignatureQueryRow[]>;
  /**
   * Page held public credentials ascending by cid, `cid > after`, length <=
   * limit, filtered by issuer, resource, and/or action exact match. For chain
   * resources, the `chain:*` bucket is unioned as an amber discovery hint.
   */
  queryIndexCredentials(q: {
    issuer?: string;
    resource?: string;
    action?: string;
    after?: string;
    limit: number;
  }): Promise<IndexCredentialRow[]>;

  /** Page relay-held operations in non-authoritative recency order. */
  queryIndexOperations(q: {
    kind?: OperationKind;
    chainId?: string;
    orderedAfter?: IndexOrderedCursor;
    order: IndexRecencyOrder;
    limit: number;
  }): Promise<IndexOperationRow[]>;

  /** Upsert an identity projection row by DID. */
  putIndexIdentityRow(row: IndexIdentityRow): Promise<void>;
  /** Upsert a content projection row by contentId. */
  putIndexContentRow(row: IndexContentRow): Promise<void>;
  /** Add one accepted content-operation signer to a chain's signer set. */
  putIndexContentSigner(contentId: string, did: string): Promise<void>;
  /**
   * Upsert a countersignature projection row by cid. The `witnessDID` column is
   * stored (never echoed in the row body) so witness-scoped queries stay O(page).
   */
  putIndexCountersignatureRow(
    row: IndexCountersignatureQueryRow & { witnessDID: string },
  ): Promise<void>;

  /**
   * Reverse lookup: DIDs of identity projection rows whose `profile.anchor`
   * equals the given contentId. Powers the "content changed → recompute the
   * identities anchored on it" cascade.
   */
  getIndexIdentityDIDsByProfileAnchor(contentId: string): Promise<string[]>;
  /**
   * Reverse lookup: contentIds of content projection rows whose
   * `currentDocumentCID` equals the given documentCID. Powers the "blob landed
   * → recompute the content rows that project that document" cascade.
   */
  getIndexContentIdsByDocumentCID(documentCID: string): Promise<string[]>;

  // --- public credentials (standing authorization) ---

  /** Get public credentials covering a specific resource */
  getPublicCredentials(resource: string): Promise<string[]>;
  /** Get a stored public credential by CID */
  getPublicCredentialByCID(cid: string): Promise<StoredPublicCredential | undefined>;
  /** Add a public credential as standing authorization */
  addPublicCredential(credential: StoredPublicCredential): Promise<void>;
  /** Remove a public credential (e.g., after revocation) */
  removePublicCredential(credentialCID: string): Promise<void>;

  // --- peer sync state ---

  /** Get last-synced log cursor for a peer relay */
  getPeerCursor(peerUrl: string): Promise<string | undefined>;
  /** Update last-synced log cursor for a peer relay */
  setPeerCursor(peerUrl: string, cursor: string): Promise<void>;

  // --- raw ops (content-addressed store for all received operations) ---

  /** Store a raw JWS token by CID — idempotent, ignores duplicates */
  putRawOp(cid: string, jwsToken: string): Promise<void>;
  /** Return JWS tokens for unsequenced (pending) ops */
  getUnsequencedOps(limit: number): Promise<string[]>;
  /** Mark ops as successfully sequenced */
  markOpsSequenced(cids: string[]): Promise<void>;
  /** Mark an op as permanently rejected */
  markOpRejected(cid: string, reason: string): Promise<void>;
  /** Count of pending (unsequenced) raw ops */
  countUnsequenced(): Promise<number>;
  /** Reset all non-rejected raw ops to pending (re-sequence) */
  resetSequencer(): Promise<void>;
}

export type SigningStore = RelayStore &
  Required<
    Pick<
      RelayStore,
      | 'getSignRequest'
      | 'pruneExpiredSignRequests'
      | 'putSignRequest'
      | 'listPendingSignRequests'
      | 'putSignResponse'
      | 'declineSignRequest'
    >
  >;

// -----------------------------------------------------------------------------
// ingestion result
// -----------------------------------------------------------------------------

/** Result of a sequencer run */
export interface SequenceResult {
  sequenced: number;
  rejected: number;
  pending: number;
}

export interface IngestionResult {
  cid: string;
  status: 'new' | 'duplicate' | 'rejected';
  error?: string;
  /** What was ingested */
  kind?: OperationKind;
  /** Chain identifier if applicable */
  chainId?: string;
  /** Revoked public grant scope; undefined when the credential was not held */
  revokedGrant?: { wildcard: boolean; contentIds: string[] };
  /**
   * Structured dependency-failure signal. When true, the rejection is due to a
   * missing dependency that may arrive later via sync or gossip, so the
   * sequencer must keep the op pending (retryable) rather than durably reject
   * it. This is the discriminator the sequencer branches on — NOT substring
   * matching of the human-readable `error` string.
   */
  dependencyMissing?: boolean;
}
