/*

  MEMORY RELAY STORE

  In-memory implementation of RelayStore for development and testing

*/

import type { VerifiedContentChain, VerifiedIdentity } from '@metalabel/dfos-protocol/chain';
import { verifyContentChain, verifyIdentityChain } from '@metalabel/dfos-protocol/chain';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { createKeyResolver } from './ingest';
import type {
  BlobKey,
  LogEntry,
  RelayStore,
  StoredBeacon,
  StoredContentChain,
  StoredDocument,
  StoredIdentityChain,
  StoredOperation,
  StoredPublicCredential,
  StoredRevocation,
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
  private peerCursors = new Map<string, string>();
  /** Keyed by `issuerDID::credentialCID` for issuer-scoped revocation */
  private revocations = new Map<string, StoredRevocation>();
  /** Keyed by credential CID */
  private publicCredentials = new Map<string, StoredPublicCredential>();

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

  // --- revocations ---

  async getRevocations(issuerDID: string): Promise<string[]> {
    const cids: string[] = [];
    for (const rev of this.revocations.values()) {
      if (rev.issuerDID === issuerDID) cids.push(rev.credentialCID);
    }
    return cids;
  }

  async addRevocation(revocation: StoredRevocation): Promise<void> {
    const key = `${revocation.issuerDID}::${revocation.credentialCID}`;
    this.revocations.set(key, revocation);
  }

  async isCredentialRevoked(issuerDID: string, credentialCID: string): Promise<boolean> {
    return this.revocations.has(`${issuerDID}::${credentialCID}`);
  }

  // --- public credentials ---

  async getPublicCredentials(resource: string): Promise<string[]> {
    const tokens: string[] = [];
    for (const cred of this.publicCredentials.values()) {
      for (const att of cred.att) {
        if (att.resource === resource) {
          tokens.push(cred.jwsToken);
          break;
        }
      }
    }
    return tokens;
  }

  async addPublicCredential(credential: StoredPublicCredential): Promise<void> {
    this.publicCredentials.set(credential.cid, credential);
  }

  async removePublicCredential(credentialCID: string): Promise<void> {
    this.publicCredentials.delete(credentialCID);
  }

  // --- documents ---

  async getDocuments(
    contentId: string,
    params: { after?: string; limit: number },
  ): Promise<{ documents: StoredDocument[]; cursor: string | null }> {
    const chain = this.contentChains.get(contentId);
    if (!chain) return { documents: [], cursor: null };

    // build ordered entries with metadata
    const entries: {
      cid: string;
      documentCID: string | null;
      signerDID: string;
      createdAt: string;
    }[] = [];
    for (const jws of chain.log) {
      const decoded = decodeJwsUnsafe(jws);
      if (!decoded) continue;
      const payload = decoded.payload as Record<string, unknown>;
      const cid = typeof decoded.header.cid === 'string' ? decoded.header.cid : '';
      const documentCID =
        typeof payload['documentCID'] === 'string' ? payload['documentCID'] : null;
      const signerDID = typeof payload['did'] === 'string' ? payload['did'] : '';
      const createdAt = typeof payload['createdAt'] === 'string' ? payload['createdAt'] : '';
      entries.push({ cid, documentCID, signerDID, createdAt });
    }

    // find start position
    let startIdx = 0;
    if (params.after) {
      const idx = entries.findIndex((e) => e.cid === params.after);
      startIdx = idx >= 0 ? idx + 1 : entries.length;
    }

    const page = entries.slice(startIdx, startIdx + params.limit);

    // resolve documents from blobs
    const documents: StoredDocument[] = [];
    for (const entry of page) {
      let document: unknown | null = null;
      if (entry.documentCID) {
        const blob = await this.getBlob({
          creatorDID: chain.state.creatorDID,
          documentCID: entry.documentCID,
        });
        if (blob) {
          try {
            document = JSON.parse(new TextDecoder().decode(blob));
          } catch {
            document = null;
          }
        }
      }
      documents.push({
        operationCID: entry.cid,
        documentCID: entry.documentCID,
        document,
        signerDID: entry.signerDID,
        createdAt: entry.createdAt,
      });
    }

    const cursor = page.length === params.limit ? page[page.length - 1]!.cid : null;
    return { documents, cursor };
  }

  // --- operation log ---

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

  async getIdentityStateAtCID(
    did: string,
    cid: string,
  ): Promise<{ state: VerifiedIdentity; lastCreatedAt: string } | null> {
    const chain = this.identityChains.get(did);
    if (!chain) return null;

    // build CID → { jws, previousCID } map
    const opsByCID = new Map<string, { jws: string; previousCID: string | null }>();
    for (const jws of chain.log) {
      const decoded = decodeJwsUnsafe(jws);
      if (!decoded) continue;
      const payload = decoded.payload as Record<string, unknown>;
      const opCID = typeof decoded.header.cid === 'string' ? decoded.header.cid : '';
      const prevCID =
        typeof payload['previousOperationCID'] === 'string'
          ? payload['previousOperationCID']
          : null;
      opsByCID.set(opCID, { jws, previousCID: prevCID });
    }

    if (!opsByCID.has(cid)) return null;

    // walk backward from target CID to genesis
    const path: string[] = [];
    let currentCID: string | null = cid;
    while (currentCID) {
      const op = opsByCID.get(currentCID);
      if (!op) return null;
      path.unshift(op.jws);
      currentCID = op.previousCID;
    }

    const identity = await verifyIdentityChain({ didPrefix: 'did:dfos', log: path });

    // extract createdAt of the target CID operation
    const targetDecoded = decodeJwsUnsafe(opsByCID.get(cid)!.jws);
    const lastCreatedAt =
      typeof (targetDecoded?.payload as Record<string, unknown>)?.['createdAt'] === 'string'
        ? ((targetDecoded?.payload as Record<string, unknown>)['createdAt'] as string)
        : '';

    return { state: identity, lastCreatedAt };
  }

  async getContentStateAtCID(
    contentId: string,
    cid: string,
  ): Promise<{ state: VerifiedContentChain; lastCreatedAt: string } | null> {
    const chain = this.contentChains.get(contentId);
    if (!chain) return null;

    // build CID → { jws, previousCID } map
    const opsByCID = new Map<string, { jws: string; previousCID: string | null }>();
    for (const jws of chain.log) {
      const decoded = decodeJwsUnsafe(jws);
      if (!decoded) continue;
      const payload = decoded.payload as Record<string, unknown>;
      const opCID = typeof decoded.header.cid === 'string' ? decoded.header.cid : '';
      const prevCID =
        typeof payload['previousOperationCID'] === 'string'
          ? payload['previousOperationCID']
          : null;
      opsByCID.set(opCID, { jws, previousCID: prevCID });
    }

    if (!opsByCID.has(cid)) return null;

    // walk backward from target CID to genesis
    const path: string[] = [];
    let currentCID: string | null = cid;
    while (currentCID) {
      const op = opsByCID.get(currentCID);
      if (!op) return null;
      path.unshift(op.jws);
      currentCID = op.previousCID;
    }

    const resolveKey = createKeyResolver(this);
    const resolveIdentity = async (did: string) => {
      const chain2 = await this.getIdentityChain(did);
      return chain2?.state;
    };
    const content = await verifyContentChain({
      log: path,
      resolveKey,
      enforceAuthorization: true,
      resolveIdentity,
    });

    const targetDecoded = decodeJwsUnsafe(opsByCID.get(cid)!.jws);
    const lastCreatedAt =
      typeof (targetDecoded?.payload as Record<string, unknown>)?.['createdAt'] === 'string'
        ? ((targetDecoded?.payload as Record<string, unknown>)['createdAt'] as string)
        : '';

    return { state: content, lastCreatedAt };
  }

  async getPeerCursor(peerUrl: string): Promise<string | undefined> {
    return this.peerCursors.get(peerUrl);
  }

  async setPeerCursor(peerUrl: string, cursor: string): Promise<void> {
    this.peerCursors.set(peerUrl, cursor);
  }

  // --- raw ops ---

  private rawOps = new Map<
    string,
    { jwsToken: string; status: 'pending' | 'sequenced' | 'rejected' }
  >();

  async putRawOp(cid: string, jwsToken: string): Promise<void> {
    if (!this.rawOps.has(cid)) {
      this.rawOps.set(cid, { jwsToken, status: 'pending' });
    }
  }

  async getUnsequencedOps(limit: number): Promise<string[]> {
    const out: string[] = [];
    for (const entry of this.rawOps.values()) {
      if (entry.status === 'pending') {
        out.push(entry.jwsToken);
        if (out.length >= limit) break;
      }
    }
    return out;
  }

  async markOpsSequenced(cids: string[]): Promise<void> {
    for (const cid of cids) {
      const entry = this.rawOps.get(cid);
      if (entry) entry.status = 'sequenced';
    }
  }

  async markOpRejected(cid: string, _reason: string): Promise<void> {
    const entry = this.rawOps.get(cid);
    if (entry) entry.status = 'rejected';
  }

  async countUnsequenced(): Promise<number> {
    let count = 0;
    for (const entry of this.rawOps.values()) {
      if (entry.status === 'pending') count++;
    }
    return count;
  }

  async resetSequencer(): Promise<void> {
    for (const entry of this.rawOps.values()) {
      if (entry.status !== 'rejected') entry.status = 'pending';
    }
  }
}
