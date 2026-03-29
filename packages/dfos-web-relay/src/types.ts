/*

  TYPES

  Core types for the DFOS web relay

*/

import type {
  VerifiedBeacon,
  VerifiedContentChain,
  VerifiedIdentity,
} from '@metalabel/dfos-protocol/chain';

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
  /** Peer relay configurations */
  peers?: PeerConfig[];
  /** Injected peer client — if omitted, a default HTTP implementation is used */
  peerClient?: PeerClient;
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
}

/** Injected peer transport — the relay expresses intent, the caller decides transport */
export interface PeerClient {
  /** Fetch identity chain log from a peer */
  getIdentityLog(
    peerUrl: string,
    did: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; cursor: string | null } | null>;

  /** Fetch content chain log from a peer */
  getContentLog(
    peerUrl: string,
    contentId: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; cursor: string | null } | null>;

  /** Fetch global operation log from a peer */
  getOperationLog(
    peerUrl: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; cursor: string | null } | null>;

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

export interface StoredBeacon {
  did: string;
  jwsToken: string;
  beaconCID: string;
  state: VerifiedBeacon;
}

export interface StoredOperation {
  cid: string;
  jwsToken: string;
  /** Which chain type this operation belongs to */
  chainType: 'identity' | 'content' | 'artifact' | 'beacon' | 'countersign';
  /** The chain identifier — DID for identity/beacon/artifact, contentId for content, targetCID for countersign */
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

/** All operation kinds in the protocol */
export type OperationKind = 'identity-op' | 'content-op' | 'beacon' | 'artifact' | 'countersign';

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
  // --- operations ---

  getOperation(cid: string): Promise<StoredOperation | undefined>;
  putOperation(op: StoredOperation): Promise<void>;

  // --- identity chains ---

  getIdentityChain(did: string): Promise<StoredIdentityChain | undefined>;
  putIdentityChain(chain: StoredIdentityChain): Promise<void>;

  // --- content chains ---

  getContentChain(contentId: string): Promise<StoredContentChain | undefined>;
  putContentChain(chain: StoredContentChain): Promise<void>;

  // --- beacons ---

  getBeacon(did: string): Promise<StoredBeacon | undefined>;
  putBeacon(beacon: StoredBeacon): Promise<void>;

  // --- blobs (content plane) ---

  getBlob(key: BlobKey): Promise<Uint8Array | undefined>;
  putBlob(key: BlobKey, data: Uint8Array): Promise<void>;

  // --- countersignatures ---
  // Implementations MUST deduplicate by witness DID per target CID.

  getCountersignatures(operationCID: string): Promise<string[]>;
  addCountersignature(operationCID: string, jwsToken: string): Promise<void>;

  // --- operation log ---
  // Global append-only log of all accepted operations. CID-based cursor pagination.

  appendToLog(entry: LogEntry): Promise<void>;
  readLog(params: {
    after?: string;
    limit: number;
  }): Promise<{ entries: LogEntry[]; cursor: string | null }>;

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
}
