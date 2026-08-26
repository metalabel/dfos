/*

  MEMORY RELAY STORE

  In-memory implementation of RelayStore for development and testing

*/

import type { VerifiedContentChain, VerifiedIdentity } from '@metalabel/dfos-protocol/chain';
import {
  parseProtocolTimestampUnix,
  verifyContentChain,
  verifyIdentityChain,
} from '@metalabel/dfos-protocol/chain';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import type {
  IndexArtifactRow,
  IndexContentRow,
  IndexCountersignatureQueryRow,
  IndexCredentialRow,
  IndexCreditCursor,
  IndexCreditRow,
  IndexIdentityRow,
  IndexOperationRow,
  IndexOrder,
  IndexOrderedCursor,
  IndexRecencyOrder,
} from './index-routes';
import { createKeyResolver } from './ingest';
import { decodeSigningCursor, encodeSigningCursor } from './types';
import type {
  BlobKey,
  LogEntry,
  OpOrigin,
  PendingOp,
  RelayStats,
  RelayStore,
  StoredContentChain,
  StoredIdentityChain,
  StoredOperation,
  StoredPublicCredential,
  StoredRevocation,
  StoredSignRequest,
} from './types';

/** Ascending bytewise comparator — JS UTF-16 order over ASCII DIDs/CIDs. */
const ascending = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
export const MAX_PENDING_SIGN_REQUESTS_PER_SUBJECT = 1024;

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

const pageOrderedRows = <T>(
  rows: T[],
  keyOf: (row: T) => string,
  timestampOf: (row: T) => string,
  after: IndexOrderedCursor | undefined,
  limit: number,
): T[] => {
  const sorted = [...rows].sort((a, b) => {
    const ats = timestampOf(a);
    const bts = timestampOf(b);
    if (ats !== bts) return ats > bts ? -1 : 1;
    return ascending(keyOf(a), keyOf(b));
  });
  const gated =
    after === undefined
      ? sorted
      : sorted.filter((row) => {
          const ts = timestampOf(row);
          const key = keyOf(row);
          return ts < after.timestamp || (ts === after.timestamp && key > after.key);
        });
  return gated.slice(0, limit);
};

const timestampOfOrder = (
  order: IndexOrder,
): ((row: { genesisAt: string; headAt: string }) => string) =>
  order === 'genesisAt.desc' ? (row) => row.genesisAt : (row) => row.headAt;

/** Serialize a BlobKey to a string for map indexing */
const blobKeyString = (key: BlobKey): string => `${key.creatorDID}::${key.documentCID}`;

/**
 * A revocation's signed `createdAt` as integer unix seconds — the as-of boundary.
 *
 * Parsed through the protocol's canonical grammar, NOT a lenient `new Date()`: a
 * lenient parse accepts inputs the protocol rejects (numeric offsets, a missing
 * `Z` that some runtimes then read as LOCAL time), which would make the boundary
 * timezone-dependent. Returns null when the stored timestamp is missing or
 * off-grammar, which callers MUST read as "no usable boundary" and answer
 * timelessly (i.e. revoked) — failing open would let a malformed row silently
 * un-revoke history. MUST match the Go twin (`revocationCreatedAtUnix`).
 */
const revocationCreatedAtUnix = (revocation: StoredRevocation): number | null =>
  parseProtocolTimestampUnix(revocation.createdAt);

/**
 * Should `candidate` replace `incumbent` as the stored revocation for a
 * (issuerDID, credentialCID) pair?
 *
 * **The earliest boundary wins.** Nothing stops an issuer from signing two
 * distinct revocations for the same credential — they have different artifact
 * CIDs, so ingest idempotence (keyed on the artifact) admits both. Under as-of
 * semantics the stored one sets the validity boundary for all of history, so
 * last-write-wins would make that boundary depend on gossip arrival order, and a
 * later re-revocation could retroactively RE-VALIDATE operations an earlier
 * revocation had already invalidated. Keeping the minimum is monotonic: a
 * revocation's reach can only ever grow.
 *
 * A null (off-grammar) boundary is the STRONGEST — it means "timeless", so it
 * sorts before every real instant. Ties break on the artifact CID so the survivor
 * is a pure function of the set rather than of arrival order (the same
 * determinism rule `getRevocationForCredential` uses for multi-issuer
 * collisions). MUST match the Go twin (`revocationSupersedes`).
 */
const revocationSupersedes = (
  candidate: StoredRevocation,
  incumbent: StoredRevocation,
): boolean => {
  const candidateAt = revocationCreatedAtUnix(candidate);
  const incumbentAt = revocationCreatedAtUnix(incumbent);
  if (candidateAt === null) return incumbentAt !== null || candidate.cid < incumbent.cid;
  if (incumbentAt === null) return false;
  if (candidateAt !== incumbentAt) return candidateAt < incumbentAt;
  return candidate.cid < incumbent.cid;
};

/**
 * In-memory relay store — all data lives in Maps, lost on restart
 *
 * Suitable for development, testing, and short-lived relay instances.
 */
export class MemoryRelayStore implements RelayStore {
  private signRequests = new Map<string, StoredSignRequest>();
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
  /** Public-head credit projection rows grouped by contentId. */
  private indexCreditRows = new Map<string, IndexCreditRow[]>();
  /** Accepted content-operation signer sets keyed by contentId. */
  private indexContentSigners = new Map<string, Set<string>>();
  /** Countersignature projection rows keyed by cid (carry witnessDID column). */
  private indexCountersignatureRows = new Map<
    string,
    IndexCountersignatureQueryRow & { witnessDID: string }
  >();
  /** Relay-observed operation-log rows keyed by operation CID. */
  private indexOperationRows = new Map<string, IndexOperationRow>();
  /** Standalone artifact projection rows keyed by artifact cid. */
  private indexArtifactRows = new Map<string, IndexArtifactRow>();

  async pruneExpiredSignRequests(now: number): Promise<void> {
    for (const [cid, request] of this.signRequests) {
      if (now >= Date.parse(request.expiresAt)) this.signRequests.delete(cid);
    }
  }

  async getSignRequest(cid: string, now: number): Promise<StoredSignRequest | undefined> {
    await this.pruneExpiredSignRequests(now);
    return this.signRequests.get(cid);
  }

  async putSignRequest(
    request: StoredSignRequest,
    now: number,
  ): Promise<'created' | 'identical' | 'conflict' | 'capacity'> {
    await this.pruneExpiredSignRequests(now);
    const existing = this.signRequests.get(request.cid);
    if (existing) return existing.request === request.request ? 'identical' : 'conflict';
    const pendingForSubject = [...this.signRequests.values()].filter(
      (candidate) =>
        candidate.subjectDID === request.subjectDID &&
        candidate.response === undefined &&
        now < Date.parse(candidate.expiresAt),
    ).length;
    if (pendingForSubject >= MAX_PENDING_SIGN_REQUESTS_PER_SUBJECT) {
      return 'capacity';
    }
    this.signRequests.set(request.cid, request);
    return 'created';
  }

  async listPendingSignRequests(params: {
    subjectDID: string;
    after?: string;
    limit: number;
    now: number;
  }): Promise<{ requests: StoredSignRequest[]; next: string | null } | null> {
    await this.pruneExpiredSignRequests(params.now);
    const rows = [...this.signRequests.values()]
      .filter(
        (request) =>
          request.subjectDID === params.subjectDID &&
          params.now < Date.parse(request.expiresAt) &&
          request.response === undefined,
      )
      .sort((a, b) =>
        a.depositedAt === b.depositedAt
          ? ascending(a.cid, b.cid)
          : ascending(a.depositedAt, b.depositedAt),
      );
    const after = params.after ? decodeSigningCursor(params.after) : undefined;
    if (params.after && (!after || after.subjectDID !== params.subjectDID)) return null;
    const gated = after
      ? rows.filter(
          (request) =>
            request.depositedAt > after.depositedAt ||
            (request.depositedAt === after.depositedAt && request.cid > after.cid),
        )
      : rows;
    const requests = gated.slice(0, params.limit);
    const last = requests.at(-1);
    const next =
      requests.length === params.limit && last
        ? encodeSigningCursor({
            subjectDID: params.subjectDID,
            depositedAt: last.depositedAt,
            cid: last.cid,
          })
        : null;
    return { requests, next };
  }

  async putSignResponse(
    cid: string,
    response: string,
    now: number,
  ): Promise<'created' | 'identical' | 'conflict' | 'not-found'> {
    await this.pruneExpiredSignRequests(now);
    const request = this.signRequests.get(cid);
    if (!request) return 'not-found';
    if (request.response !== undefined) {
      return request.response === response ? 'identical' : 'conflict';
    }
    request.response = response;
    return 'created';
  }

  async declineSignRequest(
    cid: string,
    now: number,
  ): Promise<'declined' | 'responded' | 'not-found'> {
    await this.pruneExpiredSignRequests(now);
    const request = this.signRequests.get(cid);
    if (!request) return 'not-found';
    if (request.response !== undefined) return 'responded';
    request.declined = true;
    return 'declined';
  }

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
    // earliest boundary wins — see revocationSupersedes. The survivor is kept
    // WHOLE (artifact + boundary together), so the revocation this store serves
    // from /revocations/v1 is always the one that actually sets the boundary.
    const existing = this.revocations.get(key);
    if (existing && !revocationSupersedes(revocation, existing)) return;
    this.revocations.set(key, revocation);
  }

  async isCredentialRevoked(
    issuerDID: string,
    credentialCID: string,
    asOfUnix?: number,
  ): Promise<boolean> {
    const rev = this.revocations.get(`${issuerDID}::${credentialCID}`);
    if (!rev) return false;
    // asOf omitted OR <= 0 is the timeless (freshness) question — see the
    // RelayStore contract. Go cannot express "as of epoch 0" (0 is its sentinel),
    // so TS must not either, or the twins would answer that input oppositely.
    if (asOfUnix === undefined || asOfUnix <= 0) return true;
    const revokedAt = revocationCreatedAtUnix(rev);
    return revokedAt === null || revokedAt <= asOfUnix;
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
    const revs = [...this.revocations.values()].filter((rev) => rev.issuerDID === issuerDID);
    revs.sort((a, b) => ascending(a.credentialCID, b.credentialCID));
    return revs;
  }

  // --- index (v0) materialized projection ---

  async queryIndexIdentities(q: {
    did?: string;
    hasPublicProfile?: boolean;
    nameContains?: string;
    after?: string;
    orderedAfter?: IndexOrderedCursor;
    order?: IndexOrder;
    limit: number;
  }): Promise<IndexIdentityRow[]> {
    const rows = [...this.indexIdentityRows.values()].filter((row) => {
      if (q.did !== undefined && row.did !== q.did) return false;
      if (q.hasPublicProfile !== undefined) {
        const isPublic = row.profile !== null && row.profile.publicRead;
        if (isPublic !== q.hasPublicProfile) return false;
      }
      if (q.nameContains) {
        // Match only rows whose name is servable (public) — closes the oracle on
        // any non-public name a pre-gate builder may have persisted.
        if (
          !row.profile?.publicRead ||
          row.profile.name == null ||
          !row.profile.name.toLowerCase().includes(q.nameContains.toLowerCase())
        ) {
          return false;
        }
      }
      return true;
    });
    if (q.order) {
      return pageOrderedRows(
        rows,
        (row) => row.did,
        timestampOfOrder(q.order),
        q.orderedAfter,
        q.limit,
      );
    }
    return pageRows(rows, (row) => row.did, q.after, q.limit);
  }

  async queryIndexContent(q: {
    contentId?: string;
    creator?: string;
    signer?: string;
    docSchema?: string;
    documentCID?: string;
    publicRead?: boolean;
    isDeleted?: boolean;
    titleContains?: string;
    after?: string;
    orderedAfter?: IndexOrderedCursor;
    order?: IndexOrder;
    limit: number;
  }): Promise<IndexContentRow[]> {
    const rows = [...this.indexContentRows.values()].filter((row) => {
      if (q.contentId !== undefined && row.contentId !== q.contentId) return false;
      if (q.creator !== undefined && row.creatorDID !== q.creator) return false;
      if (q.signer !== undefined && !this.indexContentSigners.get(row.contentId)?.has(q.signer)) {
        return false;
      }
      if (q.docSchema !== undefined && row.docSchema !== q.docSchema) return false;
      if (q.documentCID !== undefined && row.currentDocumentCID !== q.documentCID) return false;
      if (q.publicRead !== undefined && row.publicRead !== q.publicRead) return false;
      if (q.isDeleted !== undefined && row.isDeleted !== q.isDeleted) return false;
      if (q.titleContains !== undefined) {
        if (
          !row.publicRead ||
          row.title === null ||
          !row.title.toLowerCase().includes(q.titleContains.toLowerCase())
        ) {
          return false;
        }
      }
      return true;
    });
    if (q.order) {
      return pageOrderedRows(
        rows,
        (row) => row.contentId,
        timestampOfOrder(q.order),
        q.orderedAfter,
        q.limit,
      );
    }
    return pageRows(rows, (row) => row.contentId, q.after, q.limit);
  }

  async queryIndexCredits(q: {
    did?: string;
    contentId?: string;
    role?: string;
    after?: IndexCreditCursor;
    limit: number;
  }): Promise<IndexCreditRow[]> {
    const rows = [...this.indexCreditRows.values()]
      .flat()
      .filter(
        (row) =>
          (q.did === undefined || row.did === q.did) &&
          (q.contentId === undefined || row.contentId === q.contentId) &&
          (q.role === undefined || row.role === q.role) &&
          (q.after === undefined ||
            row.contentId > q.after.contentId ||
            (row.contentId === q.after.contentId && row.position > q.after.position)),
      );
    rows.sort((a, b) =>
      a.contentId < b.contentId ? -1 : a.contentId > b.contentId ? 1 : a.position - b.position,
    );
    return rows.slice(0, q.limit);
  }

  async queryIndexArtifacts(q: {
    cid?: string;
    signer?: string;
    docSchema?: string;
    after?: string;
    orderedAfter?: IndexOrderedCursor;
    order?: IndexRecencyOrder;
    limit: number;
  }): Promise<IndexArtifactRow[]> {
    const rows = [...this.indexArtifactRows.values()].filter(
      (row) =>
        (q.cid === undefined || row.cid === q.cid) &&
        (q.signer === undefined || row.signerDID === q.signer) &&
        (q.docSchema === undefined || row.docSchema === q.docSchema),
    );
    if (q.order) {
      return pageOrderedRows(
        rows,
        (row) => row.cid,
        (row) => row[q.order === 'createdAt.desc' ? 'createdAt' : 'ingestedAt'],
        q.orderedAfter,
        q.limit,
      );
    }
    return pageRows(rows, (row) => row.cid, q.after, q.limit);
  }

  async queryIndexCountersignatures(q: {
    witness: string;
    relation?: string;
    after?: string;
    orderedAfter?: IndexOrderedCursor;
    order?: IndexRecencyOrder;
    limit: number;
  }): Promise<IndexCountersignatureQueryRow[]> {
    const rows = [...this.indexCountersignatureRows.values()].filter(
      (row) =>
        row.witnessDID === q.witness && (q.relation === undefined || row.relation === q.relation),
    );
    // Strip the witnessDID column — the wire row never carries it (the witness
    // is echoed at the response top level).
    const wire = rows.map(({ witnessDID: _witnessDID, ...row }) => row);
    if (q.order) {
      return pageOrderedRows(
        wire,
        (row) => row.cid,
        (row) => row[q.order === 'createdAt.desc' ? 'createdAt' : 'ingestedAt'],
        q.orderedAfter,
        q.limit,
      );
    }
    return pageRows(wire, (row) => row.cid, q.after, q.limit);
  }

  async queryIndexCredentials(q: {
    issuer?: string;
    resource?: string;
    action?: string;
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
        if (q.action !== undefined && !cred.att.some((entry) => entry.action === q.action)) {
          return false;
        }
        return true;
      })
      .map((cred) => ({
        cid: cred.cid,
        issuerDID: cred.issuerDID,
        aud: '*' as const,
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

  async putIndexCreditRows(contentId: string, rows: IndexCreditRow[]): Promise<void> {
    this.indexCreditRows.set(contentId, [...rows]);
  }

  async putIndexArtifactRow(row: IndexArtifactRow): Promise<void> {
    this.indexArtifactRows.set(row.cid, row);
  }

  async putIndexContentSigner(contentId: string, did: string): Promise<void> {
    const signers = this.indexContentSigners.get(contentId) ?? new Set<string>();
    signers.add(did);
    this.indexContentSigners.set(contentId, signers);
  }

  async putIndexCountersignatureRow(
    row: IndexCountersignatureQueryRow & { witnessDID: string },
  ): Promise<void> {
    this.indexCountersignatureRows.set(row.cid, row);
  }

  async queryIndexOperations(q: {
    kind?: import('./types').OperationKind;
    chainId?: string;
    orderedAfter?: IndexOrderedCursor;
    order: IndexRecencyOrder;
    limit: number;
  }): Promise<IndexOperationRow[]> {
    const rows = [...this.indexOperationRows.values()].filter(
      (row) =>
        (q.kind === undefined || row.kind === q.kind) &&
        (q.chainId === undefined || row.chainId === q.chainId),
    );
    return pageOrderedRows(
      rows,
      (row) => row.cid,
      (row) => row[q.order === 'createdAt.desc' ? 'createdAt' : 'ingestedAt'],
      q.orderedAfter,
      q.limit,
    );
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

  async getPublicCredentialByCID(cid: string): Promise<StoredPublicCredential | undefined> {
    return this.publicCredentials.get(cid);
  }

  async addPublicCredential(credential: StoredPublicCredential): Promise<void> {
    this.publicCredentials.set(credential.cid, credential);
  }

  async removePublicCredential(credentialCID: string): Promise<void> {
    this.publicCredentials.delete(credentialCID);
  }

  // --- operation log ---

  // One op, one receipt stamp: this is the ONLY place an operation's receipt
  // time is read off the wall clock. `putOperation` holds no receipt, so the
  // operation-log row is the single source, and every other projection writer
  // sources it back out through `getIndexOperationRow` (the Go twin sources
  // from its op store instead, but the invariant is the same — one clock read
  // per op, so no two index surfaces can disagree by a millisecond).
  async appendToLog(entry: LogEntry): Promise<void> {
    this.operationLog.push(entry);
    const payload = decodeJwsUnsafe(entry.jwsToken)?.payload;
    const authoredAt = payload?.createdAt;
    const issuedAt = payload?.iat;
    const createdAt =
      typeof authoredAt === 'string'
        ? authoredAt
        : typeof issuedAt === 'number' && Number.isFinite(issuedAt)
          ? new Date(issuedAt * 1000).toISOString()
          : '';
    this.indexOperationRows.set(entry.cid, {
      cid: entry.cid,
      kind: entry.kind,
      chainId: entry.chainId,
      createdAt,
      ingestedAt: new Date().toISOString(),
    });
  }

  async getIndexOperationRow(cid: string): Promise<IndexOperationRow | undefined> {
    return this.indexOperationRows.get(cid);
  }

  async readLog(params: {
    after?: string;
    limit: number;
  }): Promise<{ entries: LogEntry[]; next: string | null } | null> {
    let startIdx = 0;
    if (params.after) {
      const idx = this.operationLog.findIndex((e) => e.cid === params.after);
      if (idx < 0) return null; // relay-local cursor this log never issued → 400 at the route
      startIdx = idx + 1;
    }

    const entries = this.operationLog.slice(startIdx, startIdx + params.limit);
    // `next` only on a FULL page — a partial page means caught up (the shared list
    // envelope's contract). Pullers advance their persisted cursor from the last
    // ingested entry's cid, so a null here never strands progress; the sync loop
    // already does exactly that. Mirrors the Go twin's ReadLog.
    const next = entries.length === params.limit ? entries[entries.length - 1]!.cid : null;
    return { entries, next };
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
    // Historical replay is a VALIDITY decision, so authorization is enforced and
    // revocation is evaluated AS OF each op's own createdAt: a credential revoked
    // after an op was signed leaves that op — and therefore the fork state
    // derived from it — valid. Without the as-of basis this replay would start
    // failing the moment any credential in the chain's history was revoked, which
    // would make a legitimate fork extension unverifiable. Mirrors the Go twins
    // (store_memory.go / store_sqlite.go GetContentStateAtCID).
    const content = await verifyContentChain({
      log: path,
      resolveKey,
      enforceAuthorization: true,
      resolveIdentity,
      isRevoked: (issuerDID, credentialCID, asOfUnix) =>
        this.isCredentialRevoked(issuerDID, credentialCID, asOfUnix),
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
    { jwsToken: string; origin: OpOrigin; status: 'pending' | 'sequenced' | 'rejected' }
  >();

  async putRawOp(cid: string, jwsToken: string, origin: OpOrigin = 'direct'): Promise<void> {
    if (!this.rawOps.has(cid)) {
      this.rawOps.set(cid, { jwsToken, origin, status: 'pending' });
    }
  }

  async getUnsequencedOps(limit: number): Promise<PendingOp[]> {
    const out: PendingOp[] = [];
    for (const entry of this.rawOps.values()) {
      if (entry.status === 'pending') {
        out.push({ jwsToken: entry.jwsToken, origin: entry.origin });
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
