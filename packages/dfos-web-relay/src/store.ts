/*

  MEMORY RELAY STORE

  In-memory implementation of RelayStore for development and testing

*/

import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import type {
  BlobKey,
  LogEntry,
  RelayStore,
  StoredBeacon,
  StoredContentChain,
  StoredIdentityChain,
  StoredOperation,
} from './types';

/** Serialize a BlobKey to a string for map indexing */
const blobKeyString = (key: BlobKey): string => `${key.creatorDID}::${key.documentCID}`;

/**
 * In-memory relay store — all data lives in Maps, lost on restart
 *
 * Suitable for development, testing, and short-lived relay instances.
 */
export class MemoryRelayStore implements RelayStore {
  private operations = new Map<string, StoredOperation>();
  private identityChains = new Map<string, StoredIdentityChain>();
  private contentChains = new Map<string, StoredContentChain>();
  private beacons = new Map<string, StoredBeacon>();
  private blobs = new Map<string, Uint8Array>();
  private countersignatures = new Map<string, string[]>();
  private operationLog: LogEntry[] = [];

  async getOperation(cid: string): Promise<StoredOperation | undefined> {
    return this.operations.get(cid);
  }

  async putOperation(op: StoredOperation): Promise<void> {
    this.operations.set(op.cid, op);
  }

  async getIdentityChain(did: string): Promise<StoredIdentityChain | undefined> {
    return this.identityChains.get(did);
  }

  async putIdentityChain(chain: StoredIdentityChain): Promise<void> {
    this.identityChains.set(chain.did, chain);
  }

  async getContentChain(contentId: string): Promise<StoredContentChain | undefined> {
    return this.contentChains.get(contentId);
  }

  async putContentChain(chain: StoredContentChain): Promise<void> {
    this.contentChains.set(chain.contentId, chain);
  }

  async getBeacon(did: string): Promise<StoredBeacon | undefined> {
    return this.beacons.get(did);
  }

  async putBeacon(beacon: StoredBeacon): Promise<void> {
    this.beacons.set(beacon.did, beacon);
  }

  async getBlob(key: BlobKey): Promise<Uint8Array | undefined> {
    return this.blobs.get(blobKeyString(key));
  }

  async putBlob(key: BlobKey, data: Uint8Array): Promise<void> {
    this.blobs.set(blobKeyString(key), data);
  }

  async getCountersignatures(operationCID: string): Promise<string[]> {
    return this.countersignatures.get(operationCID) ?? [];
  }

  async addCountersignature(operationCID: string, jwsToken: string): Promise<void> {
    const existing = this.countersignatures.get(operationCID) ?? [];

    // dedup by witness DID (kid DID prefix), not just exact token match
    const decoded = decodeJwsUnsafe(jwsToken);
    if (decoded) {
      const kid = decoded.header.kid as string;
      const witnessDID = kid.includes('#') ? kid.split('#')[0] : kid;
      for (const cs of existing) {
        const d = decodeJwsUnsafe(cs);
        if (!d) continue;
        const existingKid = d.header.kid as string;
        const existingDID = existingKid.includes('#') ? existingKid.split('#')[0] : existingKid;
        if (existingDID === witnessDID) return; // same witness, dedup
      }
    }

    existing.push(jwsToken);
    this.countersignatures.set(operationCID, existing);
  }

  async appendToLog(entry: LogEntry): Promise<void> {
    this.operationLog.push(entry);
  }

  async readLog(params: {
    after?: string;
    limit: number;
  }): Promise<{ entries: LogEntry[]; cursor: string | null }> {
    let startIdx = 0;
    if (params.after) {
      const idx = this.operationLog.findIndex((e) => e.cid === params.after);
      if (idx >= 0) startIdx = idx + 1;
      else startIdx = this.operationLog.length; // cursor not found → empty
    }

    const entries = this.operationLog.slice(startIdx, startIdx + params.limit);
    const cursor = entries.length === params.limit ? entries[entries.length - 1]!.cid : null;
    return { entries, cursor };
  }
}
