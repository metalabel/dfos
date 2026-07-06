/*

  RELAY

  Hono app factory — createRelay(options) returns a portable Hono application
  implementing the DFOS web relay HTTP interface.

  Proof plane routes are public. Content plane routes require authentication
  via DID-signed auth tokens and DFOS credentials for authorization.

*/

import type { VerifiedAuthToken } from '@metalabel/dfos-protocol/credentials';
import { dagCborCanonicalEncode, decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { Hono } from 'hono';
import { z } from 'zod';
// Version is inlined from package.json at build time (tsup/esbuild bundles the
// JSON import as a literal). Avoid `createRequire(import.meta.url)` — that breaks
// when a downstream consumer re-bundles this ESM dist into a CJS target (esbuild
// stubs `import.meta` so `import.meta.url` is undefined → createRequire throws at
// module init). The JSON import survives both native ESM and CJS re-bundling.
import { version as RELAY_VERSION } from '../package.json';
import {
  authenticateRequest,
  DEFAULT_MAX_AUTH_TOKEN_TTL_SECONDS,
  hasPublicStandingAuth,
  verifyContentAccess,
} from './auth';
import { bootstrapRelayIdentity } from './bootstrap';
import { isValidDfosDid, resolveDidDocument } from './did-document';
import { maintainIndexAfterBlob } from './index-maintenance';
import { INDEX_BASE_PATH, parseBooleanQuery } from './index-routes';
import { ingestOperations } from './ingest';
import {
  credentialRevocationStatus,
  issuerRevocationList,
  isValidCredentialCid,
  REVOCATIONS_BASE_PATH,
} from './revocations';
import { computeOpCID, sequenceOps } from './sequencer';
import { PROOF_BASE_PATH } from './types';
import type {
  PeerClient,
  PeerConfig,
  RelayOptions,
  RelayStats,
  RelayStore,
  StoredContentChain,
} from './types';

// -----------------------------------------------------------------------------
// relay result type
// -----------------------------------------------------------------------------

export interface CreatedRelay {
  /** Hono application implementing the DFOS web relay HTTP API */
  app: Hono;
  /** The relay's DID */
  did: string;
  /** Sync operations from all configured sync peers (call on a schedule) */
  syncFromPeers: () => Promise<void>;
}

// -----------------------------------------------------------------------------
// request schemas
// -----------------------------------------------------------------------------

/** Max operations per /operations POST. The receiver 400s any larger batch. */
const MAX_OPERATIONS_PER_BATCH = 100;

const IngestBody = z.object({
  operations: z.array(z.string()).min(1).max(MAX_OPERATIONS_PER_BATCH),
});

/**
 * Max ops per gossip POST. The receiver's /operations endpoint rejects any
 * batch over MAX_OPERATIONS_PER_BATCH items, so larger gossip runs must be
 * chunked or the whole push is silently 400'd and dropped. Mirrors the Go
 * twin's maxGossipBatch (sequencer.go).
 */
const MAX_GOSSIP_BATCH = MAX_OPERATIONS_PER_BATCH;

/**
 * Split items into batches of at most `size`, preserving order with no loss.
 * gossip() uses this to stay within the receiver's per-batch cap; exported so
 * the split behavior is directly testable (mirrors Go's maxGossipBatch chunking,
 * whose TestGossipChunksLargeBatches drives the split directly).
 */
export const chunkOps = <T>(items: T[], size: number): T[][] => {
  const chunks: T[][] = [];
  for (let start = 0; start < items.length; start += size) {
    chunks.push(items.slice(start, start + size));
  }
  return chunks;
};

/** Max request body size for POST /operations and PUT blob — mirrors the Go twin's 16MB cap. */
const MAX_BODY_BYTES = 16 << 20;

/**
 * Returns true if a Content-Length header is present and exceeds the 16MB body
 * cap. A missing/unparseable header returns false — the streamed length is
 * bounded separately (PUT blob re-checks the materialized size; serve.ts caps
 * the unauthenticated streaming path above this route cap).
 */
const exceedsBodyCap = (contentLength: string | undefined): boolean => {
  if (!contentLength) return false;
  const n = Number(contentLength);
  return Number.isFinite(n) && n > MAX_BODY_BYTES;
};

// -----------------------------------------------------------------------------
// query helpers
// -----------------------------------------------------------------------------

/**
 * Parse a `limit` query param. Mirrors the Go relay's parseLimit (routes.go):
 * empty → default; non-finite / non-integer / < 1 → default; > max → clamp.
 *
 * The previous inline `Math.min(Number(q || 100), 1000)` broke on every
 * non-numeric input (`Number('abc') → NaN`, and `Math.min(NaN, 1000) → NaN`),
 * and silently accepted negatives, zero, and fractions. This helper makes the
 * TS relay byte-for-byte equivalent to the Go twin across all those inputs.
 */
export const parseLimit = (
  raw: string | undefined,
  defaultLimit: number,
  maxLimit: number,
): number => {
  if (raw === undefined || raw === '') return defaultLimit;
  // Only accept a plain decimal integer literal, matching Go's strconv.Atoi
  // (which rejects "1.5", "1e3", "0x10", whitespace, etc. → default). This
  // keeps the TS and Go clamp byte-identical across all probed inputs.
  if (!/^-?\d+$/.test(raw)) return defaultLimit;
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n < 1) return defaultLimit;
  if (n > maxLimit) return maxLimit;
  return n;
};

// -----------------------------------------------------------------------------
// factory
// -----------------------------------------------------------------------------

/**
 * Create a DFOS web relay Hono application
 *
 * The returned app is portable — mount it on any Hono-compatible runtime
 * (Node.js, Cloudflare Workers, Deno, Bun, etc.).
 *
 * When `identity` is provided, the relay uses the given DID and profile. When
 * omitted, a JIT identity and profile artifact are generated at startup.
 */
export const createRelay = async (options: RelayOptions): Promise<CreatedRelay> => {
  const { store } = options;
  const contentEnabled = options.content !== false;
  const logEnabled = options.log !== false;
  const indexEnabled = options.index !== false;
  const writeEnabled = options.write !== false;
  const maxAuthTokenTTLSeconds =
    options.maxAuthTokenTTLSeconds ?? DEFAULT_MAX_AUTH_TOKEN_TTL_SECONDS;

  // peer configuration
  const peers = options.peers ?? [];
  const peerClient: PeerClient | undefined = options.peerClient;
  const gossipPeers = peers.filter((p) => p.gossip !== false);
  const readThroughPeers = peers.filter((p) => p.readThrough !== false);
  const syncPeers = peers.filter((p) => p.sync !== false);

  // resolve relay identity — use provided or JIT bootstrap
  const identity = options.identity ?? (await bootstrapRelayIdentity(store));
  const relayDID = identity.did;
  const profileArtifactJws = identity.profileArtifactJws;

  // gossip helper — chunk to <= MAX_GOSSIP_BATCH so the receiver's /operations
  // endpoint (which 400s any batch over MAX_OPERATIONS_PER_BATCH items) never
  // silently drops the whole gossip run. Mirrors the Go twin's maxGossipBatch
  // chunking in sequencer.go.
  const gossip = (ops: string[]) => {
    if (ops.length === 0 || gossipPeers.length === 0 || !peerClient) return;
    for (const peer of gossipPeers) {
      for (const chunk of chunkOps(ops, MAX_GOSSIP_BATCH)) {
        peerClient.submitOperations(peer.url, chunk).catch(() => {});
      }
    }
  };

  // ingest wrapper: store raw → process → mark results → sequence pending → gossip
  const ingestWithGossip = async (tokens: string[]) => {
    // store raw ops first — they can never be lost
    for (const token of tokens) {
      const cid = await computeOpCID(token);
      if (cid) await store.putRawOp(cid, token);
    }

    // process batch
    const results = await ingestOperations(tokens, store, { logEnabled });

    // mark results in raw store
    const newOps: string[] = [];
    for (let i = 0; i < results.length; i++) {
      const res = results[i]!;
      if (!res.cid) continue;
      if (res.status === 'new') {
        await store.markOpsSequenced([res.cid]);
        newOps.push(tokens[i]!);
      } else if (res.status === 'duplicate') {
        await store.markOpsSequenced([res.cid]);
      }
    }

    // run sequencer — resolves pending ops whose deps just arrived
    const { newOps: seqNewOps } = await sequenceOps(store);

    // gossip outside the critical path
    gossip(newOps);
    gossip(seqNewOps);

    return results;
  };

  const app = new Hono();

  // -------------------------------------------------------------------------
  // CORS — allow browser clients to read the proof plane
  // -------------------------------------------------------------------------

  // Policy matches the Go relay byte-for-byte. Applied to every route so
  // browser-based proof-plane reads (and writes) succeed cross-origin.
  app.use('*', async (c, next) => {
    // preflight: answer directly with 204 and the CORS headers
    if (c.req.method === 'OPTIONS') {
      return c.body(null, 204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      });
    }
    await next();
    // set headers on the final response (survives handler-created responses)
    c.res.headers.set('Access-Control-Allow-Origin', '*');
    c.res.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
    c.res.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    return;
  });

  // -------------------------------------------------------------------------
  // well-known
  // -------------------------------------------------------------------------

  app.get('/.well-known/dfos-relay', async (c) => {
    // Operational telemetry, kept in a nested "stats" object so the protocol
    // contract (did/capabilities/profile) stays clean. pendingOps is the raw_ops
    // backlog awaiting sequencing — a healthy idle relay reads 0; a wedged or
    // backed-up one reads >0. Surfacing it here makes the otherwise-invisible
    // sequencer-backlog failure mode a single curl. Best-effort: a transient read
    // error reports -1 rather than 500ing the status endpoint.
    let pendingOps = -1;
    try {
      pendingOps = await store.countUnsequenced();
    } catch {
      pendingOps = -1;
    }
    let stats: RelayStats | undefined;
    try {
      stats = store.getStats ? await store.getStats() : undefined;
    } catch {
      stats = undefined;
    }
    const peerInfos = peers.map((p) => ({ endpoint: p.url }));
    return c.json({
      did: relayDID,
      protocol: 'dfos-web-relay',
      version: RELAY_VERSION,
      capabilities: {
        proof: true,
        write: writeEnabled,
        content: contentEnabled,
        log: logEnabled,
        // The reference relay always serves the revocation-status index
        // (/revocations/v1). A relay that does not would advertise false and
        // 501 those routes, mirroring the content/log capability semantics.
        revocations: true,
        index: indexEnabled,
      },
      profile: profileArtifactJws,
      peers: peerInfos,
      stats: {
        pendingOps,
        ...(stats ?? {}),
      },
    });
  });

  // -------------------------------------------------------------------------
  // proof plane — public routes
  // -------------------------------------------------------------------------

  /** Submit operations for ingestion */
  app.post(`${PROOF_BASE_PATH}/operations`, async (c) => {
    // LITE pull-only node: writes (and therefore peer gossip-in, which posts
    // here too) are disabled by role. 501 matches the content-disabled
    // convention — the well-known advertises write:false so clients/peers know
    // in advance. Such a node still ingests by pulling from peers.
    if (!writeEnabled) {
      return c.json({ error: 'this relay is pull-only; writes are disabled' }, 501);
    }
    // Per-route DoS cap: reject an oversized body before buffering it. Mirrors
    // the Go twin's 16MB MaxBytesReader on the blob route. The Content-Length
    // header (when present) is the cheap pre-read check; serve.ts streams a
    // hard cap above this for the Content-Length-absent (chunked) case.
    if (exceedsBodyCap(c.req.header('content-length'))) {
      return c.json({ error: 'request body too large' }, 413);
    }

    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: 'invalid JSON body' }, 400);
    }

    const parsed = IngestBody.safeParse(body);
    if (!parsed.success) {
      return c.json({ error: 'invalid request', details: parsed.error.issues }, 400);
    }

    const results = await ingestWithGossip(parsed.data.operations);
    return c.json({ results });
  });

  /** Get an operation by CID */
  app.get(`${PROOF_BASE_PATH}/operations/:cid`, async (c) => {
    const cid = c.req.param('cid');
    const op = await store.getOperation(cid);
    if (!op) return c.json({ error: 'not found' }, 404);

    return c.json({
      cid: op.cid,
      jwsToken: op.jwsToken,
      chainType: op.chainType,
      chainId: op.chainId,
    });
  });

  /** Get an identity chain by DID */
  app.get(`${PROOF_BASE_PATH}/identities/:did/log`, async (c) => {
    const did = c.req.param('did');
    const chain = await store.getIdentityChain(did);
    if (!chain) return c.json({ error: 'not found' }, 404);

    const after = c.req.query('after');
    const limit = parseLimit(c.req.query('limit'), 100, 1000);

    const entries = chain.log.map((jws) => {
      const decoded = decodeJwsUnsafe(jws);
      return { cid: decoded?.header.cid || '', jwsToken: jws };
    });

    let startIdx = 0;
    if (after) {
      const idx = entries.findIndex((e) => e.cid === after);
      startIdx = idx >= 0 ? idx + 1 : entries.length;
    }

    const page = entries.slice(startIdx, startIdx + limit);
    const cursor = page.length === limit ? page[page.length - 1]!.cid : null;

    return c.json({ entries: page, cursor });
  });

  app.get(`${PROOF_BASE_PATH}/identities/:did{.+}`, async (c) => {
    const did = c.req.param('did');
    let chain = await store.getIdentityChain(did);

    // read-through: try peers on local miss (paginate through full log)
    if (!chain && readThroughPeers.length > 0 && peerClient) {
      for (const peer of readThroughPeers) {
        let after: string | undefined;
        while (true) {
          const logPage = await peerClient.getIdentityLog(peer.url, did, {
            ...(after ? { after } : {}),
            limit: 1000,
          });
          if (!logPage || logPage.entries.length === 0) break;
          await ingestWithGossip(logPage.entries.map((e) => e.jwsToken));
          if (!logPage.cursor) break;
          after = logPage.cursor;
        }
        chain = await store.getIdentityChain(did);
        if (chain) break;
      }
    }

    if (!chain) return c.json({ error: 'not found' }, 404);

    return c.json({
      did: chain.did,
      headCID: chain.headCID,
      state: chain.state,
    });
  });

  // ---------------------------------------------------------------------------
  // universal DID resolver (DIF-compat, additive, own clock)
  //
  // Read-only DID-core projection of the SAME self-certified terminal state the
  // proof-plane /identities route serves. Mounts at ROOT (not under
  // PROOF_BASE_PATH) — it rides the frozen v1 surface without touching the wire,
  // the proof plane, or the parity contract. DIF Universal Resolver HTTP binding:
  // GET /1.0/identifiers/{did} → { didDocument, didResolutionMetadata,
  // didDocumentMetadata }. See specs/DID-METHOD.md §4 for the normative mapping.
  // ---------------------------------------------------------------------------
  app.get('/1.0/identifiers/:did{.+}', async (c) => {
    const did = c.req.param('did');

    // reject any non-canonical did:dfos (wrong width/charset/method) — §3.1:63
    if (!isValidDfosDid(did)) {
      return c.json(
        {
          didDocument: null,
          didResolutionMetadata: { error: 'invalidDid' },
          didDocumentMetadata: {},
        },
        400,
      );
    }

    let chain = await store.getIdentityChain(did);

    // read-through: try peers on local miss (paginate through full log)
    if (!chain && readThroughPeers.length > 0 && peerClient) {
      for (const peer of readThroughPeers) {
        let after: string | undefined;
        while (true) {
          const logPage = await peerClient.getIdentityLog(peer.url, did, {
            ...(after ? { after } : {}),
            limit: 1000,
          });
          if (!logPage || logPage.entries.length === 0) break;
          await ingestWithGossip(logPage.entries.map((e) => e.jwsToken));
          if (!logPage.cursor) break;
          after = logPage.cursor;
        }
        chain = await store.getIdentityChain(did);
        if (chain) break;
      }
    }

    if (!chain) {
      return c.json(
        {
          didDocument: null,
          didResolutionMetadata: { error: 'notFound' },
          didDocumentMetadata: {},
        },
        404,
      );
    }

    // deactivated identities are NOT an error: 200 with empty VMs + deactivated:true
    return c.json(resolveDidDocument(chain));
  });

  // ---------------------------------------------------------------------------
  // revocation status (frozen v1, own clock)
  //
  // Read-only projection of the relay's revocation set — the same
  // (issuerDID, credentialCID) index credential enforcement already consults.
  // Mounts at ROOT under REVOCATIONS_BASE_PATH (not under the proof plane).
  // Every positive answer carries the revocation JWS so a zero-trust caller
  // re-verifies it instead of trusting the relay's boolean; `revoked: false`
  // only means THIS relay has not ingested a revocation (honest absence — not
  // proof of non-revocation). See src/revocations.ts for the projection.
  // ---------------------------------------------------------------------------

  /** Revocation status for a single credential CID */
  app.get(`${REVOCATIONS_BASE_PATH}/credential/:credentialCID`, async (c) => {
    const credentialCID = c.req.param('credentialCID');

    // reject anything that is not a credential-shaped CID — a malformed param
    // gets a 400, never a well-formed-looking `revoked: false`
    if (!isValidCredentialCid(credentialCID)) {
      return c.json({ error: 'invalid credential CID' }, 400);
    }

    const revocation = await store.getRevocationForCredential(credentialCID);
    return c.json(credentialRevocationStatus(credentialCID, revocation));
  });

  /** All revocations issued by a DID */
  app.get(`${REVOCATIONS_BASE_PATH}/issuer/:did{.+}`, async (c) => {
    const did = c.req.param('did');

    // must be the exact canonical 31-char did:dfos form
    if (!isValidDfosDid(did)) {
      return c.json({ error: 'invalid DID' }, 400);
    }

    const revocations = await store.getRevocationsByIssuer(did);
    const after = c.req.query('after');
    const limit = parseLimit(c.req.query('limit'), 100, 1000);

    let startIdx = 0;
    if (after) {
      const idx = revocations.findIndex((rev) => rev.credentialCID === after);
      startIdx = idx >= 0 ? idx + 1 : revocations.length;
    }

    const page = revocations.slice(startIdx, startIdx + limit);
    const next = page.length === limit ? page[page.length - 1]!.credentialCID : null;

    return c.json(issuerRevocationList(did, page, next));
  });

  // ---------------------------------------------------------------------------
  // index (v0, own clock)
  // ---------------------------------------------------------------------------

  app.get(`${INDEX_BASE_PATH}/identities`, async (c) => {
    if (!indexEnabled) return c.json({ error: 'index not available' }, 501);

    const hasPublicProfile = parseBooleanQuery(c.req.query('hasPublicProfile'));
    const after = c.req.query('after');
    const limit = parseLimit(c.req.query('limit'), 100, 1000);
    const rows = await store.queryIndexIdentities({
      ...(hasPublicProfile !== undefined ? { hasPublicProfile } : {}),
      ...(after ? { after } : {}),
      limit,
    });
    const next = rows.length === limit ? rows[rows.length - 1]!.did : null;

    return c.json({ identities: rows, next });
  });

  app.get(`${INDEX_BASE_PATH}/content`, async (c) => {
    if (!indexEnabled) return c.json({ error: 'index not available' }, 501);

    const creator = c.req.query('creator');
    if (creator && !isValidDfosDid(creator)) {
      return c.json({ error: 'invalid DID' }, 400);
    }

    const docSchema = c.req.query('docSchema');
    const documentCID = c.req.query('documentCID');
    const publicRead = parseBooleanQuery(c.req.query('publicRead'));
    const after = c.req.query('after');
    const limit = parseLimit(c.req.query('limit'), 100, 1000);
    const rows = await store.queryIndexContent({
      ...(creator ? { creator } : {}),
      ...(docSchema !== undefined ? { docSchema } : {}),
      ...(documentCID !== undefined ? { documentCID } : {}),
      ...(publicRead !== undefined ? { publicRead } : {}),
      ...(after ? { after } : {}),
      limit,
    });
    const next = rows.length === limit ? rows[rows.length - 1]!.contentId : null;

    return c.json({ content: rows, next });
  });

  app.get(`${INDEX_BASE_PATH}/countersignatures`, async (c) => {
    if (!indexEnabled) return c.json({ error: 'index not available' }, 501);

    const witness = c.req.query('witness');
    if (!witness || !isValidDfosDid(witness)) {
      return c.json({ error: 'invalid DID' }, 400);
    }

    const after = c.req.query('after');
    const limit = parseLimit(c.req.query('limit'), 100, 1000);
    const rows = await store.queryIndexCountersignatures({
      witness,
      ...(after ? { after } : {}),
      limit,
    });
    const next = rows.length === limit ? rows[rows.length - 1]!.cid : null;

    return c.json({ witness, countersignatures: rows, next });
  });

  /** Get a content chain log */
  app.get(`${PROOF_BASE_PATH}/content/:contentId/log`, async (c) => {
    const contentId = c.req.param('contentId');
    const chain = await store.getContentChain(contentId);
    if (!chain) return c.json({ error: 'not found' }, 404);

    const after = c.req.query('after');
    const limit = parseLimit(c.req.query('limit'), 100, 1000);

    const entries = chain.log.map((jws) => {
      const decoded = decodeJwsUnsafe(jws);
      return { cid: decoded?.header.cid || '', jwsToken: jws };
    });

    let startIdx = 0;
    if (after) {
      const idx = entries.findIndex((e) => e.cid === after);
      startIdx = idx >= 0 ? idx + 1 : entries.length;
    }

    const page = entries.slice(startIdx, startIdx + limit);
    const cursor = page.length === limit ? page[page.length - 1]!.cid : null;

    return c.json({ entries: page, cursor });
  });

  /** Get a content chain by content ID */
  app.get(`${PROOF_BASE_PATH}/content/:contentId`, async (c) => {
    const contentId = c.req.param('contentId');
    let chain = await store.getContentChain(contentId);

    // read-through: try peers on local miss (paginate through full log)
    if (!chain && readThroughPeers.length > 0 && peerClient) {
      for (const peer of readThroughPeers) {
        let after: string | undefined;
        while (true) {
          const logPage = await peerClient.getContentLog(peer.url, contentId, {
            ...(after ? { after } : {}),
            limit: 1000,
          });
          if (!logPage || logPage.entries.length === 0) break;
          await ingestWithGossip(logPage.entries.map((e) => e.jwsToken));
          if (!logPage.cursor) break;
          after = logPage.cursor;
        }
        chain = await store.getContentChain(contentId);
        if (chain) break;
      }
    }

    if (!chain) return c.json({ error: 'not found' }, 404);

    return c.json({
      contentId: chain.contentId,
      genesisCID: chain.genesisCID,
      headCID: chain.state.headCID,
      state: chain.state,
    });
  });

  /** Get countersignatures for an operation CID */
  app.get(`${PROOF_BASE_PATH}/countersignatures/:cid`, async (c) => {
    const cid = c.req.param('cid');

    const op = await store.getOperation(cid);
    const all = await store.getCountersignatures(cid);
    if (!op && all.length === 0) return c.json({ error: 'not found' }, 404);

    const decorated = all.map((jws) => ({
      jws,
      csCid: decodeJwsUnsafe(jws)?.header.cid ?? '',
    }));
    decorated.sort((a, b) => (a.csCid < b.csCid ? -1 : a.csCid > b.csCid ? 1 : 0));

    const after = c.req.query('after');
    const limit = parseLimit(c.req.query('limit'), 100, 1000);

    let startIdx = 0;
    if (after) {
      const idx = decorated.findIndex((d) => d.csCid === after);
      startIdx = idx >= 0 ? idx + 1 : decorated.length;
    }

    const page = decorated.slice(startIdx, startIdx + limit);
    const next = page.length === limit ? page[page.length - 1]!.csCid : null;

    return c.json({ cid, countersignatures: page.map((d) => d.jws), next });
  });

  // -------------------------------------------------------------------------
  // global operation log
  // -------------------------------------------------------------------------

  /** Read the global append-only operation log */
  app.get(`${PROOF_BASE_PATH}/log`, async (c) => {
    if (!logEnabled) return c.json({ error: 'global log not available' }, 501);
    const afterParam = c.req.query('after');
    const limit = parseLimit(c.req.query('limit'), 100, 1000);
    const result = await store.readLog(afterParam ? { after: afterParam, limit } : { limit });
    return c.json(result);
  });

  // -------------------------------------------------------------------------
  // content plane — authenticated routes
  // -------------------------------------------------------------------------

  /** Upload a blob for a content chain, keyed by operation CID */
  app.put('/content/:contentId/blob/:operationCID', async (c) => {
    if (!contentEnabled) return c.json({ error: 'content plane not available' }, 501);
    const contentId = c.req.param('contentId');
    const operationCID = c.req.param('operationCID');

    // Per-route DoS cap (16MB, mirrors the Go twin's MaxBytesReader on this
    // route). Reject by Content-Length before authenticating or buffering.
    if (exceedsBodyCap(c.req.header('content-length'))) {
      return c.json({ error: 'request body too large' }, 413);
    }

    // authenticate
    const auth = await authenticateRequest(
      c.req.header('authorization'),
      relayDID,
      store,
      maxAuthTokenTTLSeconds,
    );
    if (!auth) return c.json({ error: 'authentication required' }, 401);

    // verify chain exists
    const chain = await store.getContentChain(contentId);
    if (!chain) return c.json({ error: 'content chain not found' }, 404);

    // find the referenced operation in the chain and extract documentCID + signer
    let documentCID: string | null = null;
    let operationSignerDID: string | null = null;
    for (const token of chain.log) {
      const decoded = decodeJwsUnsafe(token);
      if (!decoded) continue;
      if (decoded.header.cid !== operationCID) continue;
      const payload = decoded.payload as Record<string, unknown>;
      documentCID = typeof payload['documentCID'] === 'string' ? payload['documentCID'] : null;
      operationSignerDID = typeof payload['did'] === 'string' ? payload['did'] : null;
      break;
    }

    if (!documentCID) {
      return c.json({ error: 'operation not found in chain or has no documentCID' }, 404);
    }

    // authorize: caller must be chain creator or the operation signer
    if (auth.iss !== chain.state.creatorDID && auth.iss !== operationSignerDID) {
      return c.json({ error: 'not authorized — must be chain creator or operation signer' }, 403);
    }

    // read blob bytes and verify they match the documentCID from the operation.
    // Bound the post-read size too: a Content-Length-absent (chunked) body
    // bypasses the header check above, so re-check the materialized length.
    const bytes = new Uint8Array(await c.req.arrayBuffer());
    if (bytes.byteLength > MAX_BODY_BYTES) {
      return c.json({ error: 'request body too large' }, 413);
    }
    try {
      const parsed = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
      const encoded = await dagCborCanonicalEncode(parsed);
      if (encoded.cid.toString() !== documentCID) {
        return c.json({ error: 'blob bytes do not match documentCID' }, 400);
      }
    } catch {
      return c.json({ error: 'blob bytes do not match documentCID' }, 400);
    }

    await store.putBlob({ creatorDID: chain.state.creatorDID, documentCID }, bytes);
    // A document blob just landed — often out of band, after the content op that
    // referenced it. Recompute the content rows that project this documentCID
    // (docSchema/name/profile), cascading to their anchored identities.
    await maintainIndexAfterBlob(documentCID, store);

    return c.json({ status: 'stored', contentId, documentCID, operationCID });
  });

  /** Download a blob for a content chain */
  app.get('/content/:contentId/blob', async (c) => {
    if (!contentEnabled) return c.json({ error: 'content plane not available' }, 501);
    return await readBlob({
      contentId: c.req.param('contentId'),
      ref: 'head',
      authHeader: c.req.header('authorization'),
      credHeader: c.req.header('x-credential'),
      relayDID,
      store,
      maxAuthTokenTTLSeconds,
    });
  });

  app.get('/content/:contentId/blob/:ref', async (c) => {
    if (!contentEnabled) return c.json({ error: 'content plane not available' }, 501);
    return await readBlob({
      contentId: c.req.param('contentId'),
      ref: c.req.param('ref'),
      authHeader: c.req.header('authorization'),
      credHeader: c.req.header('x-credential'),
      relayDID,
      store,
      maxAuthTokenTTLSeconds,
    });
  });

  // -------------------------------------------------------------------------
  // sync-in: pull from peer logs
  // -------------------------------------------------------------------------

  // maxOpsPerSyncCycle caps how many ops are fetched from a single peer in one
  // sync cycle (parity with the Go relay). A peer with a large backlog would
  // otherwise block the relay for the whole catch-up inside one cycle; the cursor
  // is persisted each page, so catch-up resumes from where it left off next cycle.
  const maxOpsPerSyncCycle = 5000;

  const syncFromPeers = async (): Promise<void> => {
    if (!peerClient) return;
    for (const peer of syncPeers) {
      let cursor = await store.getPeerCursor(peer.url);
      let fetched = 0;
      while (fetched < maxOpsPerSyncCycle) {
        const page = await peerClient.getOperationLog(peer.url, {
          ...(cursor ? { after: cursor } : {}),
          limit: 1000,
        });
        if (!page || page.entries.length === 0) break;
        await ingestWithGossip(page.entries.map((e) => e.jwsToken));
        fetched += page.entries.length;
        cursor = page.cursor ?? page.entries[page.entries.length - 1]!.cid;
        await store.setPeerCursor(peer.url, cursor);
        if (!page.cursor) break;
      }
    }
  };

  return { app, did: relayDID, syncFromPeers };
};

// -----------------------------------------------------------------------------
// blob read — extracted from routes for clean typing
// -----------------------------------------------------------------------------

const jsonResponse = (body: Record<string, unknown>, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });

const readBlob = async (params: {
  contentId: string;
  ref: string;
  authHeader: string | undefined;
  credHeader: string | undefined;
  relayDID: string;
  store: RelayStore;
  maxAuthTokenTTLSeconds: number;
}): Promise<Response> => {
  const { contentId, ref, authHeader, credHeader, relayDID, store, maxAuthTokenTTLSeconds } =
    params;

  // look up chain
  const chain = await store.getContentChain(contentId);
  if (!chain) return jsonResponse({ error: 'content chain not found' }, 404);

  // check for public standing authorization (no auth needed)
  const publicAccess = await hasPublicStandingAuth(contentId, 'read', store);
  if (!publicAccess) {
    // require auth token
    const auth = await authenticateRequest(authHeader, relayDID, store, maxAuthTokenTTLSeconds);
    if (!auth) return jsonResponse({ error: 'authentication required' }, 401);

    // verify read credential — unless the caller is the chain creator
    const credError = await verifyReadAccess(auth, chain, contentId, credHeader, store);
    if (credError) return credError;
  }

  // resolve documentCID for the requested ref
  let documentCID: string | null = null;
  let operationFound = ref === 'head';

  if (ref === 'head') {
    documentCID = chain.state.currentDocumentCID;
  } else {
    for (const token of chain.log) {
      const decoded = decodeJwsUnsafe(token);
      if (!decoded) continue;
      if (decoded.header.cid === ref) {
        operationFound = true;
        const payload = decoded.payload as Record<string, unknown>;
        documentCID = typeof payload['documentCID'] === 'string' ? payload['documentCID'] : null;
        break;
      }
    }
  }

  if (!operationFound) return jsonResponse({ error: 'operation not found in chain' }, 404);
  if (!documentCID) return jsonResponse({ error: 'no document at this ref' }, 404);

  const blob = await store.getBlob({ creatorDID: chain.state.creatorDID, documentCID });
  if (!blob) return jsonResponse({ error: 'blob not found' }, 404);

  return new Response(blob, {
    headers: {
      'content-type': 'application/octet-stream',
      'x-document-cid': documentCID,
    },
  });
};

/** Verify read access — delegates to verifyContentAccess. Returns an error Response or null. */
const verifyReadAccess = async (
  auth: VerifiedAuthToken,
  chain: StoredContentChain,
  contentId: string,
  credHeader: string | undefined,
  store: RelayStore,
): Promise<Response | null> => {
  const result = await verifyContentAccess({
    ...(credHeader ? { credentialJWS: credHeader } : {}),
    requestedResource: `chain:${contentId}`,
    action: 'read',
    store,
    creatorDID: chain.state.creatorDID,
    requesterDID: auth.iss,
  });

  if (result.granted) return null;
  return jsonResponse({ error: 'read credential required' }, 403);
};
