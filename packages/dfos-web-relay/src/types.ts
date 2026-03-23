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

export interface RelayOptions {
  /** The relay's DID — used as auth token audience and published in well-known */
  relayDID: string;
  /** Storage backend */
  store: RelayStore;
}

// -----------------------------------------------------------------------------
// stored artifacts
// -----------------------------------------------------------------------------

export interface StoredIdentityChain {
  did: string;
  /** Ordered JWS tokens from genesis to head */
  log: string[];
  state: VerifiedIdentity;
}

export interface StoredContentChain {
  contentId: string;
  genesisCID: string;
  /** Ordered JWS tokens from genesis to head */
  log: string[];
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
  chainType: 'identity' | 'content';
  /** The chain identifier — DID for identity, contentId for content */
  chainId: string;
}

/** Key for blob storage — deduplicates across chains sharing the same document */
export interface BlobKey {
  creatorDID: string;
  documentCID: string;
}

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
}

// -----------------------------------------------------------------------------
// ingestion result
// -----------------------------------------------------------------------------

export interface IngestionResult {
  cid: string;
  status: 'accepted' | 'rejected';
  error?: string;
  /** What was ingested */
  kind?: 'identity-op' | 'content-op' | 'beacon' | 'countersig' | 'beacon-countersig';
  /** Chain identifier if applicable */
  chainId?: string;
}
