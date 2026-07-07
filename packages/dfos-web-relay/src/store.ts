/*

  MEMORY RELAY STORE

  In-memory implementation of RelayStore for development and testing

*/

import type { VerifiedContentChain, VerifiedIdentity } from '@metalabel/dfos-protocol/chain';
import { verifyContentChain, verifyIdentityChain } from '@metalabel/dfos-protocol/chain';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import type {
  IndexContentRow,
  IndexCountersignatureRow,
  IndexCredentialRow,
  IndexIdentityRow,
} from './index-routes';
import { createKeyResolver } from './ingest';
import type {
  BlobKey,
  LogEntry,
  RelayStats,
  RelayStore,
  StoredContentChain,
  StoredIdentityChain,
  StoredOperation,
  StoredPublicCredential,
  StoredRevocation,
} from './types';

/** Ascending bytewise comparator — JS UTF-16 order over ASCII DIDs/CIDs. */
const ascending = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Page a projection: rows ascending by `keyOf`, strictly greater than `after`
 * (keyset semantics — deterministic and resumable even when the cursor row was
 * mutated or filtered out between pages), capped at `limit`.
 */
const pageRows = <T>(
  rows: T[],
  keyOf: (row: T) => string,
  after: string | undefined,
  limit: number,
): T[] => {
  const sorted = [...rows].sort((a, b) => ascending(keyOf(a), keyOf(b)));
  const gated = after === undefined ? sorted : sorted.filter((row) => keyOf(row) > after);
  return gated.slice(0, limit);
};

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
  private blobs = new Map<string, Uint8Array>();
  private countersignatures = new Map<string, string[]>();
  private operationLog: LogEntry[] = [];
  private peerCursors = new Map<string, string>();
  /** Keyed by `issuerDID::credentialCID` for issuer-scoped revocation */
  private revocations = new Map<string, StoredRevocation>();
  /** Keyed by credential CID */
  private publicCredentials = new Map<string, StoredPublicCredential>();
  // --- index (v0) materialized projection rows ---
  /** Identity projection rows keyed by DID. */
  private indexIdentityRows = new Map<string, IndexIdentityRow>();
  /** Content projection rows keyed by contentId. */
  private indexContentRows = new Map<string, IndexContentRow>();
  /** Countersignature projection rows keyed by cid (carry witnessDID column). */
  private indexCountersignatureRows = new Map<
    string,
    IndexCountersignatureRow & { witnessDID: string }
  >();

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

  async getRevocationForCredential(credentialCID: string): Promise<StoredRevocation | undefined> {
    // deterministic across stores/twins: smallest issuerDID wins on a
    // (theoretical) multi-issuer collision
    let found: StoredRevocation | undefined;
    for (const rev of this.revocations.values()) {
      if (rev.credentialCID !== credentialCID) continue;
      if (!found || rev.issuerDID < found.issuerDID) found = rev;
    }
    return found;
  }

  async getRevocationsByIssuer(issuerDID: string): Promise<StoredRevocation[]> {
    const revs: { revocation: StoredRevocation; createdAt: string }[] = [];
    for (const rev of this.revocations.values()) {
      if (rev.issuerDID !== issuerDID) continue;
      const createdAt = decodeJwsUnsafe(rev.jwsToken)?.payload?.createdAt;
      revs.push({
        revocation: rev,
        createdAt: typeof createdAt === 'string' ? createdAt : '',
      });
    }
    revs.sort((a, b) => {
      if (a.createdAt !== b.createdAt) return a.createdAt < b.createdAt ? -1 : 1;
      if (a.revocation.credentialCID === b.revocation.credentialCID) return 0;
      return a.revocation.credentialCID < b.revocation.credentialCID ? -1 : 1;
    });
    return revs.map((entry) => entry.revocation);
  }

  // --- index (v0) materialized projection ---

  async queryIndexIdentities(q: {
    hasPublicProfile?: boolean;
    nameContains?: string;
    after?: string;
    limit: number;
  }): Promise<IndexIdentityRow[]> {
    const rows = [...this.indexIdentityRows.values()].filter((row) => {
      if (q.hasPublicProfile !== undefined) {
        const isPublic = row.profile !== null && row.profile.publicRead;
        if (isPublic !== q.hasPublicProfile) return false;
      }
      if (q.nameContains) {
        if (
          row.profile?.name == null ||
          !row.profile.name.toLowerCase().includes(q.nameContains.toLowerCase())
        ) {
          return false;
        }
      }
      return true;
    });
    return pageRows(rows, (row) => row.did, q.after, q.limit);
  }

  async queryIndexContent(q: {
    creator?: string;
    docSchema?: string;
    documentCID?: string;
    publicRead?: boolean;
    after?: string;
    limit: number;
  }): Promise<IndexContentRow[]> {
    const rows = [...this.indexContentRows.values()].filter((row) => {
      if (q.creator !== undefined && row.creatorDID !== q.creator) return false;
      if (q.docSchema !== undefined && row.docSchema !== q.docSchema) return false;
      if (q.documentCID !== undefined && row.currentDocumentCID !== q.documentCID) return false;
      if (q.publicRead !== undefined && row.publicRead !== q.publicRead) return false;
      return true;
    });
    return pageRows(rows, (row) => row.contentId, q.after, q.limit);
  }

  async queryIndexCountersignatures(q: {
    witness: string;
    after?: string;
    limit: number;
  }): Promise<IndexCountersignatureRow[]> {
    const rows = [...this.indexCountersignatureRows.values()].filter(
      (row) => row.witnessDID === q.witness,
    );
    // Strip the witnessDID column — the wire row never carries it (the witness
    // is echoed at the response top level).
    const wire = rows.map(({ witnessDID: _witnessDID, ...row }) => row);
    return pageRows(wire, (row) => row.cid, q.after, q.limit);
  }

  async queryIndexCredentials(q: {
    issuer?: string;
    resource?: string;
    after?: string;
    limit: number;
  }): Promise<IndexCredentialRow[]> {
    const rows = [...this.publicCredentials.values()]
      .filter((cred) => {
        if (q.issuer !== undefined && cred.issuerDID !== q.issuer) return false;
        if (q.resource !== undefined) {
          const isChainRequest = q.resource.startsWith('chain:');
          return cred.att.some(
            (entry) =>
              entry.resource === q.resource || (isChainRequest && entry.resource === 'chain:*'),
          );
        }
        return true;
      })
      .map((cred) => ({
        cid: cred.cid,
        issuerDID: cred.issuerDID,
        // Project att down to {resource, action} only. The Attenuation schema is a
        // looseObject, so a credential MAY carry extra att keys — but the Go relay
        // rebuilds att as a fixed {resource, action} pair at ingest, so emitting
        // extras here would break byte-parity on this (the first route to serialize
        // att structurally). The full-fidelity att lives in the self-proving
        // jwsToken; this decoded projection is an amber convenience.
        att: cred.att.map((a) => ({ resource: a.resource, action: a.action })),
        exp: cred.exp,
        jwsToken: cred.jwsToken,
      }));
    return pageRows(rows, (row) => row.cid, q.after, q.limit);
  }

  async putIndexIdentityRow(row: IndexIdentityRow): Promise<void> {
    this.indexIdentityRows.set(row.did, row);
  }

  async putIndexContentRow(row: IndexContentRow): Promise<void> {
    this.indexContentRows.set(row.contentId, row);
  }

  async putIndexCountersignatureRow(
    row: IndexCountersignatureRow & { witnessDID: string },
  ): Promise<void> {
    this.indexCountersignatureRows.set(row.cid, row);
  }

  async getIndexIdentityDIDsByProfileAnchor(contentId: string): Promise<string[]> {
    const dids: string[] = [];
    for (const row of this.indexIdentityRows.values()) {
      if (row.profile?.anchor === contentId) dids.push(row.did);
    }
    return dids;
  }

  async getIndexContentIdsByDocumentCID(documentCID: string): Promise<string[]> {
    const contentIds: string[] = [];
    for (const row of this.indexContentRows.values()) {
      if (row.currentDocumentCID === documentCID) contentIds.push(row.contentId);
    }
    return contentIds;
  }

  // --- public credentials ---

  async getPublicCredentials(resource: string): Promise<string[]> {
    const tokens: string[] = [];
    const isChainRequest = resource.startsWith('chain:');
    for (const cred of this.publicCredentials.values()) {
      for (const att of cred.att) {
        if (att.resource === resource) {
          tokens.push(cred.jwsToken);
          break;
        }
        // chain:* credentials match any chain: resource
        if (isChainRequest && att.resource === 'chain:*') {
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
    // Return a resume cursor whenever the page has entries — NOT only when full — so
    // a caught-up puller advances past the final partial page instead of re-fetching
    // the tail every sync cycle (anti-entropy chatter). Its next fetch from this
    // cursor returns an empty page and it stops. Mirrors the Go twin's ReadLog.
    const cursor = entries.length > 0 ? entries[entries.length - 1]!.cid : null;
    return { entries, cursor };
  }

  async getStats(): Promise<RelayStats> {
    const countsByKind: RelayStats['countsByKind'] = {
      identity: 0,
      content: 0,
      artifact: 0,
      credential: 0,
      countersign: 0,
      revocation: 0,
    };

    for (const entry of this.operationLog) {
      switch (entry.kind) {
        case 'identity-op':
          countsByKind.identity++;
          break;
        case 'content-op':
          countsByKind.content++;
          break;
        case 'artifact':
        case 'credential':
        case 'countersign':
        case 'revocation':
          countsByKind[entry.kind]++;
          break;
      }
    }

    const first = this.operationLog[0];
    const last = this.operationLog[this.operationLog.length - 1];
    const decoded = first ? decodeJwsUnsafe(first.jwsToken) : null;
    const createdAt = decoded?.payload?.createdAt;

    return {
      opCount: this.operationLog.length,
      countsByKind,
      oldestOpAt: typeof createdAt === 'string' ? createdAt : null,
      headCid: last?.cid ?? null,
    };
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
    // Permanently drop the raw op. A permanent rejection is deterministic and
    // never retried, so the row has no recovery value; keeping it let an
    // unauthenticated submitter grow the raw store without bound by mutating one
    // byte per op to mint a fresh CID. Dependency-pending ops are not routed here
    // (the sequencer gates on permanence), so retries are unaffected.
    this.rawOps.delete(cid);
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
