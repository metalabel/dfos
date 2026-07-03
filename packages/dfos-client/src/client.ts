/*

  CLIENT

  The four concerns the protocol lib deliberately refuses — fetch, resolve,
  verify-orchestration, cache — assembled into one read-only, no-custody client.
  Every proof still comes from @metalabel/dfos-protocol; this file only routes,
  wraps values in trust-as-data, and fails over across an untrusted relay set.

*/

import {
  CONTENT_ID_ANCHOR_RE,
  verifyRevocation,
  type VerifiedContentChain,
  type VerifiedIdentity,
} from '@metalabel/dfos-protocol/chain';
import { verifyDFOSCredential } from '@metalabel/dfos-protocol/credentials';
import { dagCborCanonicalEncode, decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { createHttpPeerClient } from '@metalabel/dfos-web-relay';
import { createResolvers, type Resolvers } from './resolvers';
import { createRevocationChecker } from './revocation';
import { memoryStore } from './store/memory';
import { operationPager } from './transport';
import type {
  Callbacks,
  CallOptions,
  Client,
  ClientConfig,
  DocumentBlob,
  GlobalLogPage,
  LogOp,
  Provenance,
  RelayHealth,
  Resolution,
  Resolved,
  ResolvedContent,
  ResolvedCredential,
  Trust,
  UnverifiableAxis,
  VerifyResult,
} from './types';

// -----------------------------------------------------------------------------
// trust helpers
// -----------------------------------------------------------------------------

const trust = (ok: boolean, axes: UnverifiableAxis[]): Trust =>
  axes.length > 0 ? { ok, unverifiable: axes } : { ok };

/** A content chain carries the `revocation` axis iff it has any delegated (credentialed) write. */
const hasDelegatedOps = (log: string[]): boolean =>
  log.some((jws) => {
    const decoded = decodeJwsUnsafe(jws);
    return (
      typeof (decoded?.payload as Record<string, unknown> | undefined)?.['authorization'] ===
      'string'
    );
  });

const opMeta = (jws: string): LogOp => {
  const decoded = decodeJwsUnsafe(jws);
  return { cid: typeof decoded?.header.cid === 'string' ? decoded.header.cid : '', jwsToken: jws };
};

// -----------------------------------------------------------------------------
// createClient
// -----------------------------------------------------------------------------

export const createClient = (config: ClientConfig): Client => {
  if (config.relays.length === 0) throw new Error('createClient requires at least one relay');

  const relays = [...config.relays];
  const quorum = config.quorum ?? 1;
  const store = config.store ?? memoryStore();
  const fetchImpl = config.fetch ?? globalThis.fetch;
  const nowMs = config.now ?? Date.now;
  const peerClient = config.peerClient ?? createHttpPeerClient();
  const isRevoked = config.isRevoked ?? createRevocationChecker(relays, fetchImpl);

  const resolvers: Resolvers = createResolvers({ relays, quorum, store, peerClient, isRevoked });
  const relaysFor = (o?: CallOptions) => o?.relays ?? relays;

  // --- identity ---
  const identity = async (
    did: string,
    options?: CallOptions,
  ): Promise<Resolved<VerifiedIdentity>> => {
    const { state, provenance } = await resolvers.getIdentityChain(did, options);
    const axes: UnverifiableAxis[] = provenance.fromCache ? ['tip'] : [];
    return { value: state, trust: trust(true, axes), provenance };
  };

  // --- content ---
  const content = async (
    contentId: string,
    options?: CallOptions,
  ): Promise<Resolved<ResolvedContent>> => {
    const { state, log, provenance } = await resolvers.getContentChain(contentId, options);
    const creator = await resolvers.getIdentityChain(state.creatorDID, options);
    const axes: UnverifiableAxis[] = [];
    if (provenance.fromCache) axes.push('tip');
    if (hasDelegatedOps(log)) axes.push('revocation');
    const value: ResolvedContent = { chain: state, creator: creator.state };
    return { value, trust: trust(true, axes), provenance };
  };

  // --- credential ---
  const credential = async (
    jws: string,
    options?: CallOptions,
  ): Promise<Resolved<ResolvedCredential>> => {
    const decoded = decodeJwsUnsafe(jws);
    const iss = (decoded?.payload as Record<string, unknown> | undefined)?.['iss'];
    if (typeof iss !== 'string') throw new Error('credential payload missing iss');

    const issuer = await resolvers.getIdentityChain(iss, options);
    const verified = await verifyDFOSCredential(jws, {
      resolveIdentity: resolvers.callbacks().resolveIdentity,
      now: Math.floor(nowMs() / 1000),
    });
    const revoked = await isRevoked(verified.iss, verified.credentialCID);

    const axes: UnverifiableAxis[] = [];
    if (issuer.provenance.fromCache) axes.push('tip');
    if (!revoked) axes.push('revocation'); // non-revocation is never provable in v1
    const value: ResolvedCredential = { credential: verified, issuer: issuer.state, revoked };
    return { value, trust: trust(!revoked, axes), provenance: issuer.provenance };
  };

  // --- document ---
  const document = async (
    contentId: string,
    options?: CallOptions,
  ): Promise<Resolved<DocumentBlob>> => {
    const { state, provenance } = await resolvers.getContentChain(contentId, options);
    const documentCID = state.currentDocumentCID;
    if (!documentCID) throw new Error(`content ${contentId} has no current document`);

    const blob = await fetchBlob(contentId, relaysFor(options), fetchImpl);
    if (!blob) throw new Error(`no relay served the blob for ${contentId}`);

    let decodedDoc: unknown;
    let integrity = false;
    try {
      decodedDoc = JSON.parse(new TextDecoder().decode(blob.bytes));
      const encoded = await dagCborCanonicalEncode(decodedDoc as Record<string, unknown>);
      integrity = encoded.cid.toString() === documentCID;
    } catch {
      integrity = false;
    }

    const value: DocumentBlob = {
      bytes: blob.bytes,
      documentCID,
      integrity,
      ...(blob.mediaType ? { mediaType: blob.mediaType } : {}),
      ...(decodedDoc !== undefined ? { decoded: decodedDoc } : {}),
    };
    const axes: UnverifiableAxis[] = provenance.fromCache ? ['tip'] : [];
    return { value, trust: trust(integrity, axes), provenance };
  };

  // --- verify (no-throw, self-routing) ---
  const verify = async (jws: string): Promise<VerifyResult<unknown>> => {
    try {
      const decoded = decodeJwsUnsafe(jws);
      if (!decoded) return { ok: false, error: 'failed to decode JWS' };
      const typ = decoded.header.typ;
      const cb = resolvers.callbacks();

      if (typ === 'did:dfos:credential') {
        const verified = await verifyDFOSCredential(jws, {
          resolveIdentity: cb.resolveIdentity,
          now: Math.floor(nowMs() / 1000),
        });
        const revoked = await isRevoked(verified.iss, verified.credentialCID);
        if (revoked) return { ok: false, error: 'credential revoked', value: verified };
        return { ok: true, value: verified, unverifiable: ['revocation'] };
      }

      if (typ === 'did:dfos:revocation') {
        const verified = await verifyRevocation({ jwsToken: jws, resolveKey: cb.resolveKey });
        return { ok: true, value: verified };
      }

      return { ok: false, error: `unsupported token type for standalone verify: ${typ}` };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : 'verification failed' };
    }
  };

  // --- resolve (paste-a-string dispatcher) ---
  const resolve = async (ref: string, options?: CallOptions): Promise<Resolution> => {
    const trimmed = ref.trim();

    if (trimmed.startsWith('did:dfos:') && !trimmed.includes('.')) {
      const r = await identity(trimmed, options);
      return { kind: 'identity', ...r };
    }
    if (CONTENT_ID_ANCHOR_RE.test(trimmed)) {
      const r = await content(trimmed, options);
      return { kind: 'content', ...r };
    }
    if (trimmed.split('.').length === 3) {
      const decoded = decodeJwsUnsafe(trimmed);
      const typ = decoded?.header.typ;
      if (typ === 'did:dfos:credential') {
        const r = await credential(trimmed, options);
        return { kind: 'credential', ...r };
      }
      throw new Error(`unsupported JWS type for resolve: ${typ}`);
    }
    throw new Error(`unrecognized reference: ${ref}`);
  };

  // --- raw floor ---
  const log = async (
    kind: 'identity' | 'content',
    id: string,
    options?: CallOptions,
  ): Promise<Resolved<LogOp[]>> => {
    const res =
      kind === 'identity'
        ? await resolvers.getIdentityChain(id, options)
        : await resolvers.getContentChain(id, options);
    const value = res.log.map(opMeta);
    const axes: UnverifiableAxis[] = res.provenance.fromCache ? ['tip'] : [];
    return { value, trust: trust(true, axes), provenance: res.provenance };
  };

  const globalLog = async (cursor?: string, options?: CallOptions): Promise<GlobalLogPage> => {
    const pager = operationPager(peerClient);
    // a single page from the first reachable relay — a seam, not a sync engine
    for (const url of relaysFor(options)) {
      const page = await pager(url, cursor ? { after: cursor, limit: 100 } : { limit: 100 });
      if (page === null) continue;
      const provenance: Provenance = {
        answeredBy: url,
        responses: [{ url, ok: true, digest: '' }],
        agreed: true,
        fromCache: false,
      };
      return { entries: page.entries, cursor: page.cursor, provenance };
    }
    return {
      entries: [],
      cursor: null,
      provenance: { answeredBy: '', responses: [], agreed: false, fromCache: false },
    };
  };

  const health = async (options?: CallOptions): Promise<RelayHealth[]> => {
    const out: RelayHealth[] = [];
    for (const url of relaysFor(options)) {
      try {
        const res = await fetchImpl(new URL('/.well-known/dfos-relay', url).toString());
        if (!res.ok) {
          out.push({ url, ok: false });
          continue;
        }
        const body = (await res.json()) as Record<string, unknown>;
        out.push({ url, ok: true, ...body });
      } catch {
        out.push({ url, ok: false });
      }
    }
    return out;
  };

  const callbacks = (): Callbacks => resolvers.callbacks();

  return {
    callbacks,
    resolve,
    identity,
    content,
    credential,
    document,
    verify,
    log,
    globalLog,
    health,
  };
};

// -----------------------------------------------------------------------------
// blob fetch — a single GET with failover (NOT a pager; the peer client has no
// blob method, so this is the one small non-log fetch the client owns)
// -----------------------------------------------------------------------------

const fetchBlob = async (
  contentId: string,
  relays: string[],
  fetchImpl: typeof fetch,
): Promise<{ bytes: Uint8Array; mediaType: string | null } | null> => {
  for (const url of relays) {
    try {
      const target = new URL(`/content/${encodeURIComponent(contentId)}/blob`, url).toString();
      const res = await fetchImpl(target);
      if (!res.ok) continue;
      const bytes = new Uint8Array(await res.arrayBuffer());
      return { bytes, mediaType: res.headers.get('content-type') };
    } catch {
      continue;
    }
  }
  return null;
};

// -----------------------------------------------------------------------------
// free floor — zero object graph, for someone who wants just one resolveKey
// -----------------------------------------------------------------------------

/**
 * The true minimalist floor: the bound protocol-lib callbacks over a relay set,
 * with no client object, no cache tuning, no verbs. For a one-off verify.
 */
export const resolvers = (relays: string[]): Callbacks => createClient({ relays }).callbacks();
