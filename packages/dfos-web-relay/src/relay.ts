/*

  RELAY

  Hono app factory — createRelay(options) returns a portable Hono application
  implementing the DFOS web relay HTTP interface.

  Proof plane READS are public. Authenticated routes consume the API-AUTH
  identity proof (`Authorization: DFOS <jws>`) for AuthN and DFOS credentials for
  AuthZ; ingestion sits behind the admission ladder (WEB-RELAY.md, Ingestion
  Admission).

*/

import { signApiIdentityRequest } from '@metalabel/dfos-protocol/credentials';
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
  authenticateIdentityProof,
  createJtiReplayCache,
  DEFAULT_PROOF_SKEW_SECONDS,
  DEFAULT_PROOF_WINDOW_SECONDS,
  hasPublicStandingAuth,
  verifyContentAccess,
  type AuthenticatedPrincipal,
  type JtiReplayCache,
} from './auth';
import { bootstrapRelayIdentity } from './bootstrap';
import { isValidDfosDid, resolveDidDocument } from './did-document';
import { maintainIndexAfterBlob } from './index-maintenance';
import {
  decodeIndexCreditCursor,
  decodeIndexOrderedCursor,
  encodeIndexCreditCursor,
  encodeIndexOrderedCursor,
  INDEX_BASE_PATH,
  parseBooleanQuery,
  parseIndexOrder,
  parseIndexRecencyOrder,
  redactNonPublicContentRow,
  redactNonPublicIdentityRow,
} from './index-routes';
import { ingestOperations, type AdmissionMode } from './ingest';
import {
  credentialRevocationStatus,
  issuerRevocationList,
  isValidCredentialCid,
  REVOCATIONS_BASE_PATH,
} from './revocations';
import { computeOpCID, sequenceOps } from './sequencer';
import { registerSigningRoutes } from './signing';
import { INGESTION_MODES, PROOF_BASE_PATH } from './types';
import type {
  AdmissionPolicy,
  GossipProofSigner,
  IngestionMode,
  PeerClient,
  PeerConfig,
  RelayOptions,
  RelayStats,
  RelayStore,
  StoredContentChain,
} from './types';

/** Optional SIGNING 0.1 courier clock; byte twin of signingBasePath in routes.go. */
export const SIGNING_BASE_PATH = '/signing/v0';

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
 * cap. A missing/unparseable header returns false; readCappedBytes still
 * enforces the limit incrementally while consuming the request stream.
 */
const exceedsBodyCap = (contentLength: string | undefined): boolean => {
  if (!contentLength) return false;
  const n = Number(contentLength);
  return Number.isFinite(n) && n > MAX_BODY_BYTES;
};

const readCappedBytes = async (
  request: Request,
  maximum: number,
): Promise<{ ok: true; bytes: Uint8Array } | { ok: false; tooLarge: boolean }> => {
  if (exceedsBodyCap(request.headers.get('content-length') ?? undefined)) {
    return { ok: false, tooLarge: true };
  }
  if (!request.body) return { ok: true, bytes: new Uint8Array() };

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximum) {
        await reader.cancel().catch(() => {});
        return { ok: false, tooLarge: true };
      }
      chunks.push(value);
    }
  } catch {
    return { ok: false, tooLarge: false };
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, bytes };
};

/**
 * The ORIGIN-FORM request target — path plus query string, byte for byte, as the
 * request line carried it.
 *
 * This is what an identity proof's `path` binds, and it is deliberately NOT a
 * route template and NOT a normalization: no percent-decoding, no query
 * reordering, no trailing-slash equivalence. The signer built the request and
 * the proof from the same string, so byte equality is free for the honest party.
 */
export const originFormTarget = (requestUrl: string): string => {
  const url = new URL(requestUrl);
  return url.pathname + url.search;
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
  const revocationsEnabled = options.revocations !== false;
  const indexEnabled = options.index !== false;
  const writeEnabled = options.write !== false;
  const signingEnabled = options.signing === true;
  if (
    signingEnabled &&
    [
      store.getSignRequest,
      store.pruneExpiredSignRequests,
      store.putSignRequest,
      store.listPendingSignRequests,
      store.putSignResponse,
      store.declineSignRequest,
    ].some((member) => typeof member !== 'function')
  ) {
    throw new Error('signing capability requires a store implementing the signing members');
  }
  if (typeof store.pruneExpiredSignRequests === 'function') {
    await store.pruneExpiredSignRequests(Date.now());
  }
  // THE RELAY'S OWN CONFIGURED AUTHORITY — the host binding for every identity
  // proof. Never read from a request; see RelayOptions.authority.
  const authority = options.authority;
  const proofWindowSeconds = options.proofWindowSeconds ?? DEFAULT_PROOF_WINDOW_SECONDS;
  const proofSkewSeconds = options.proofSkewSeconds ?? DEFAULT_PROOF_SKEW_SECONDS;
  // Injected when the deployment needs a replay cache wider than this process;
  // see RelayOptions.replayCache.
  const replayCache: JtiReplayCache = options.replayCache ?? createJtiReplayCache();

  // Ingestion admission. Explicit wins; absent derives from the write capability
  // (WEB-RELAY.md, well-known `ingestion`). A relay with writes off is closed
  // whatever it asked for — the capability gate fires first and answers 501.
  //
  // An unrecognized spelling is refused HERE rather than serving as its silent
  // fallback: the routes special-case only `closed` and `proof-required`, so a
  // typo would run OPEN while the well-known advertised the typo.
  if (options.ingestion !== undefined && !INGESTION_MODES.includes(options.ingestion)) {
    throw new Error(
      `unknown ingestion mode: ${JSON.stringify(options.ingestion)} (expected ${INGESTION_MODES.join(', ')})`,
    );
  }
  const ingestionMode: IngestionMode = !writeEnabled ? 'closed' : (options.ingestion ?? 'open');
  // Default policy: ADMIT EVERYTHING — today's behavior, stated as a policy
  // rather than as the absence of one.
  const admissionPolicy: AdmissionPolicy = options.admissionPolicy ?? (() => true);

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
  // Gossip-out can announce this relay as a NAMED peer by signing an identity
  // proof of its own DID — OPT-IN, because a presented proof is not optional to
  // the receiver: a peer that has never ingested this relay's identity chain
  // answers 503, so signing unilaterally would refuse pushes that were being
  // accepted. See RelayOptions.gossipIdentityProof.
  const relaySigner = identity.sign;
  const relayKeyId = identity.keyId;
  const gossipProofEnabled =
    options.gossipIdentityProof === true && relaySigner !== undefined && relayKeyId !== undefined;

  const signGossipProof: GossipProofSigner | undefined = gossipProofEnabled
    ? async ({ method, host, path, body }) => {
        try {
          const { proof } = await signApiIdentityRequest({
            method,
            host,
            path,
            body,
            kid: `${relayDID}#${relayKeyId}`,
            sign: relaySigner!,
            // POST /operations is WRITE-SHAPED, so the proof MUST carry jti.
            // A fresh random value per push: the receiver's replay cache is
            // keyed (jti, presenter), so a re-gossip of the same ops is a new
            // request, not a replay.
            extraMembers: { jti: crypto.randomUUID() },
          });
          return proof;
        } catch {
          // A relay that cannot sign gossips anonymously rather than dropping
          // the push: gossip is best-effort, and sync is the consistency
          // backstop.
          return null;
        }
      }
    : undefined;

  const gossip = (ops: string[]) => {
    if (ops.length === 0 || gossipPeers.length === 0 || !peerClient) return;
    for (const peer of gossipPeers) {
      for (const chunk of chunkOps(ops, MAX_GOSSIP_BATCH)) {
        peerClient
          .submitOperations(peer.url, chunk, signGossipProof ? { signProof: signGossipProof } : {})
          .catch(() => {});
      }
    }
  };

  // ingest wrapper: store raw → process → mark results → sequence pending → gossip
  const ingestWithGossip = async (tokens: string[], admissionMode: AdmissionMode = 'current') => {
    const origin = admissionMode === 'historical' ? 'peer' : 'direct';
    // store raw ops first — they can never be lost
    for (const token of tokens) {
      const cid = await computeOpCID(token);
      if (cid) await store.putRawOp(cid, token, origin);
    }

    // process batch
    const results = await ingestOperations(tokens, store, { logEnabled, admissionMode });

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

  const ingestPeerLogWithOneRestart = async (
    getPage: (
      after: string | undefined,
    ) => Promise<
      { entries: { jwsToken: string }[]; next: string | null } | 'invalid-cursor' | null
    >,
  ): Promise<boolean> => {
    let after: string | undefined;
    let restarted = false;
    while (true) {
      const page = await getPage(after);
      if (page === 'invalid-cursor') {
        if (restarted) return false;
        restarted = true;
        after = undefined;
        continue;
      }
      if (!page) return false;
      if (page.entries.length === 0) return true;
      await ingestWithGossip(
        page.entries.map((entry) => entry.jwsToken),
        'historical',
      );
      if (!page.next) return true;
      after = page.next;
    }
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
        revocations: revocationsEnabled,
        index: indexEnabled,
        signing: signingEnabled,
      },
      // The admission-mode HINT, so a client knows before attempting. The policy
      // decision is still the authority.
      ingestion: ingestionMode,
      profile: profileArtifactJws,
      peers: peerInfos,
      stats: {
        pendingOps,
        ...(stats ?? {}),
      },
    });
  });

  registerSigningRoutes({
    app,
    store,
    relayDID,
    basePath: SIGNING_BASE_PATH,
    enabled: signingEnabled,
    authority,
    proofWindowSeconds,
    proofSkewSeconds,
  });

  // -------------------------------------------------------------------------
  // proof plane — public routes
  // -------------------------------------------------------------------------

  /**
   * Submit operations for ingestion.
   *
   * THE ADMISSION LADDER IS NORMATIVE, CHEAPEST FIRST (WEB-RELAY.md, Ingestion
   * Admission): structural caps (400/413) -> proof verification when one is
   * presented (401 invalid / 503 unverifiable) -> admission policy over
   * (principal | anonymous), a request-level 403 -> full per-item verification.
   * The expensive step is never spent on a submission policy refuses, and a
   * refusal produces NO per-item results.
   *
   * Peers are not special: gossip-in, client submission, and open deposit are
   * one door with one grammar.
   */
  app.post(`${PROOF_BASE_PATH}/operations`, async (c) => {
    // 0. Capability gates, BEFORE anything else. LITE pull-only nodes (and a
    // relay whose ingestion is configured `closed`) present no ingestion surface
    // at all; the well-known advertises both so clients/peers know in advance.
    if (!writeEnabled) {
      return c.json({ error: 'this relay is pull-only; writes are disabled' }, 501);
    }
    if (ingestionMode === 'closed') {
      return c.json({ error: 'this relay does not accept external ingestion' }, 501);
    }

    // 1. Structural caps. Enforced while consuming the stream: Content-Length is
    // a cheap early rejection, but chunked/direct Fetch requests are bounded too.
    const read = await readCappedBytes(c.req.raw, MAX_BODY_BYTES);
    if (!read.ok && read.tooLarge) return c.json({ error: 'request body too large' }, 413);
    if (!read.ok) return c.json({ error: 'invalid JSON body' }, 400);

    let body: unknown;
    try {
      body = JSON.parse(new TextDecoder().decode(read.bytes));
    } catch {
      return c.json({ error: 'invalid JSON body' }, 400);
    }

    const parsed = IngestBody.safeParse(body);
    if (!parsed.success) {
      return c.json({ error: 'invalid request', details: parsed.error.issues }, 400);
    }

    // 2. Proof verification, when a proof is presented. An identity proof here is
    // OPTIONAL — anonymous is a valid admission mode — but presenting an invalid
    // one is a 401, not a downgrade to anonymous. jti is REQUIRED: this is a
    // write-shaped surface, and policy runs before full verification, so the
    // relay grants admission-layer effects before it knows the payload is a
    // duplicate.
    const auth = await authenticateIdentityProof({
      authHeader: c.req.header('authorization'),
      method: c.req.method,
      path: originFormTarget(c.req.url),
      body: read.bytes,
      authority,
      store,
      requireJti: true,
      replayCache,
      windowSeconds: proofWindowSeconds,
      skewSeconds: proofSkewSeconds,
    });
    if (!auth.ok) return c.json({ error: auth.error }, auth.status as 401 | 503);
    const principal = auth.principal?.did ?? null;

    // 3. Admission policy over (principal | anonymous). A refusal is
    // REQUEST-LEVEL: nothing in the batch is examined further and no per-item
    // results are produced. A policy that cannot be evaluated FAILS CLOSED — the
    // server's condition, not a judgment on the caller.
    if (ingestionMode === 'proof-required' && principal === null) {
      return c.json({ error: 'ingestion requires an identity proof' }, 403);
    }
    let admitted: boolean;
    try {
      admitted = await admissionPolicy(principal);
    } catch {
      return c.json({ error: 'admission policy could not be evaluated' }, 503);
    }
    if (!admitted) return c.json({ error: 'submission refused by admission policy' }, 403);

    // 4. Full verification — the per-item chain and signature work, only for
    // admitted submissions.
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
      // Relay-local positional cursor: an `after` not on the served branch is a
      // caller error (or a fork/head switch) — 400 tells the client to restart
      // instead of silently claiming it is caught up.
      if (idx < 0) return c.json({ error: 'invalid cursor' }, 400);
      startIdx = idx + 1;
    }

    const page = entries.slice(startIdx, startIdx + limit);
    const next = page.length === limit ? page[page.length - 1]!.cid : null;

    return c.json({ entries: page, next });
  });

  app.get(`${PROOF_BASE_PATH}/identities/:did{.+}`, async (c) => {
    const did = c.req.param('did');
    let chain = await store.getIdentityChain(did);

    // read-through: try peers on local miss (paginate through full log)
    if (!chain && readThroughPeers.length > 0 && peerClient) {
      for (const peer of readThroughPeers) {
        const completed = await ingestPeerLogWithOneRestart((after) =>
          peerClient.getIdentityLog(peer.url, did, {
            ...(after ? { after } : {}),
            limit: 1000,
          }),
        );
        chain = await store.getIdentityChain(did);
        if (completed && chain) break;
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
        const completed = await ingestPeerLogWithOneRestart((after) =>
          peerClient.getIdentityLog(peer.url, did, {
            ...(after ? { after } : {}),
            limit: 1000,
          }),
        );
        chain = await store.getIdentityChain(did);
        if (completed && chain) break;
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
    if (!revocationsEnabled) {
      return c.json({ error: 'revocation status not available' }, 501);
    }
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
    if (!revocationsEnabled) {
      return c.json({ error: 'revocation status not available' }, 501);
    }
    const did = c.req.param('did');

    // must be the exact canonical 31-char did:dfos form
    if (!isValidDfosDid(did)) {
      return c.json({ error: 'invalid DID' }, 400);
    }

    const revocations = await store.getRevocationsByIssuer(did);
    const after = c.req.query('after');
    const limit = parseLimit(c.req.query('limit'), 100, 1000);

    const eligible = after
      ? revocations.filter((revocation) => revocation.credentialCID > after)
      : revocations;
    const page = eligible.slice(0, limit);
    const next = page.length === limit ? page[page.length - 1]!.credentialCID : null;

    return c.json(issuerRevocationList(did, page, next));
  });

  // ---------------------------------------------------------------------------
  // index (v0, own clock)
  // ---------------------------------------------------------------------------

  app.get(`${INDEX_BASE_PATH}/identities`, async (c) => {
    if (!indexEnabled) return c.json({ error: 'index not available' }, 501);

    const hasPublicProfile = parseBooleanQuery(c.req.query('hasPublicProfile'));
    if (hasPublicProfile === null) return c.json({ error: 'invalid boolean' }, 400);
    const did = c.req.query('did');
    if (did !== undefined && !isValidDfosDid(did)) {
      return c.json({ error: 'invalid DID' }, 400);
    }
    const nameContains = c.req.query('nameContains');
    const order = parseIndexOrder(c.req.query('order'));
    if (order === null) return c.json({ error: 'invalid order' }, 400);
    const after = c.req.query('after');
    const orderedAfter = order && after ? decodeIndexOrderedCursor(after) : undefined;
    if (order && after && !orderedAfter) return c.json({ error: 'invalid cursor' }, 400);
    const limit = parseLimit(c.req.query('limit'), 100, 1000);
    const rows = (
      await store.queryIndexIdentities({
        ...(did !== undefined ? { did } : {}),
        ...(hasPublicProfile !== undefined ? { hasPublicProfile } : {}),
        ...(nameContains ? { nameContains } : {}),
        ...(order ? { order } : {}),
        ...(order ? (orderedAfter ? { orderedAfter } : {}) : after ? { after } : {}),
        limit,
      })
    ).map(redactNonPublicIdentityRow);
    const next =
      rows.length === limit
        ? order
          ? encodeIndexOrderedCursor(
              rows[rows.length - 1]![order === 'genesisAt.desc' ? 'genesisAt' : 'headAt'],
              rows[rows.length - 1]!.did,
            )
          : rows[rows.length - 1]!.did
        : null;

    return c.json({ identities: rows, next });
  });

  app.get(`${INDEX_BASE_PATH}/content`, async (c) => {
    if (!indexEnabled) return c.json({ error: 'index not available' }, 501);

    const creator = c.req.query('creator');
    if (creator && !isValidDfosDid(creator)) {
      return c.json({ error: 'invalid DID' }, 400);
    }
    const signer = c.req.query('signer');
    if (signer && !isValidDfosDid(signer)) {
      return c.json({ error: 'invalid DID' }, 400);
    }

    const docSchema = c.req.query('docSchema');
    const documentCID = c.req.query('documentCID');
    const contentId = c.req.query('contentId');
    const titleContainsPresent = c.req.queries('titleContains') !== undefined;
    const titleContains = c.req.query('titleContains');
    const publicRead = parseBooleanQuery(c.req.query('publicRead'));
    if (publicRead === null) return c.json({ error: 'invalid boolean' }, 400);
    if (titleContainsPresent && publicRead === false) {
      return c.json({ error: 'invalid filter combination' }, 400);
    }
    const isDeleted = parseBooleanQuery(c.req.query('isDeleted'));
    if (isDeleted === null) return c.json({ error: 'invalid boolean' }, 400);
    const order = parseIndexOrder(c.req.query('order'));
    if (order === null) return c.json({ error: 'invalid order' }, 400);
    const after = c.req.query('after');
    const orderedAfter = order && after ? decodeIndexOrderedCursor(after) : undefined;
    if (order && after && !orderedAfter) return c.json({ error: 'invalid cursor' }, 400);
    const limit = parseLimit(c.req.query('limit'), 100, 1000);
    const rows = (
      await store.queryIndexContent({
        ...(contentId !== undefined ? { contentId } : {}),
        ...(creator ? { creator } : {}),
        ...(signer ? { signer } : {}),
        ...(docSchema !== undefined ? { docSchema } : {}),
        ...(documentCID !== undefined ? { documentCID } : {}),
        ...(titleContainsPresent
          ? { publicRead: true }
          : publicRead !== undefined
            ? { publicRead }
            : {}),
        ...(isDeleted !== undefined ? { isDeleted } : {}),
        ...(titleContains ? { titleContains } : {}),
        ...(order ? { order } : {}),
        ...(order ? (orderedAfter ? { orderedAfter } : {}) : after ? { after } : {}),
        limit,
      })
    ).map(redactNonPublicContentRow);
    const next =
      rows.length === limit
        ? order
          ? encodeIndexOrderedCursor(
              rows[rows.length - 1]![order === 'genesisAt.desc' ? 'genesisAt' : 'headAt'],
              rows[rows.length - 1]!.contentId,
            )
          : rows[rows.length - 1]!.contentId
        : null;

    return c.json({ content: rows, next });
  });

  app.get(`${INDEX_BASE_PATH}/credits`, async (c) => {
    if (!indexEnabled) return c.json({ error: 'index not available' }, 501);

    const did = c.req.query('did');
    if (did !== undefined && !isValidDfosDid(did)) {
      return c.json({ error: 'invalid DID' }, 400);
    }
    const contentId = c.req.query('contentId');
    const rolePresent = c.req.queries('role') !== undefined;
    const role = c.req.query('role');
    const afterRaw = c.req.query('after');
    const after = afterRaw ? decodeIndexCreditCursor(afterRaw) : undefined;
    if (afterRaw && !after) return c.json({ error: 'invalid cursor' }, 400);
    const limit = parseLimit(c.req.query('limit'), 100, 1000);
    const rows = await store.queryIndexCredits({
      ...(did !== undefined ? { did } : {}),
      ...(contentId !== undefined ? { contentId } : {}),
      ...(rolePresent ? { role: role ?? '' } : {}),
      ...(after ? { after } : {}),
      limit,
    });
    const last = rows[rows.length - 1];
    const next =
      rows.length === limit && last ? encodeIndexCreditCursor(last.contentId, last.position) : null;
    return c.json({ credits: rows, next });
  });

  app.get(`${INDEX_BASE_PATH}/artifacts`, async (c) => {
    if (!indexEnabled) return c.json({ error: 'index not available' }, 501);

    const signer = c.req.query('signer');
    if (signer !== undefined && !isValidDfosDid(signer)) {
      return c.json({ error: 'invalid DID' }, 400);
    }
    const cid = c.req.query('cid');
    const docSchema = c.req.query('docSchema');
    const order = parseIndexRecencyOrder(c.req.query('order'));
    if (order === null) return c.json({ error: 'invalid order' }, 400);
    const after = c.req.query('after');
    const orderedAfter = order && after ? decodeIndexOrderedCursor(after) : undefined;
    if (order && after && !orderedAfter) return c.json({ error: 'invalid cursor' }, 400);
    const limit = parseLimit(c.req.query('limit'), 100, 1000);
    const rows = await store.queryIndexArtifacts({
      ...(cid !== undefined ? { cid } : {}),
      ...(signer !== undefined ? { signer } : {}),
      ...(docSchema !== undefined ? { docSchema } : {}),
      ...(order ? { order } : {}),
      ...(order ? (orderedAfter ? { orderedAfter } : {}) : after ? { after } : {}),
      limit,
    });
    const next =
      rows.length === limit
        ? order
          ? encodeIndexOrderedCursor(
              rows[rows.length - 1]![order === 'createdAt.desc' ? 'createdAt' : 'ingestedAt'],
              rows[rows.length - 1]!.cid,
            )
          : rows[rows.length - 1]!.cid
        : null;
    return c.json({ artifacts: rows, next });
  });

  app.get(`${INDEX_BASE_PATH}/countersignatures`, async (c) => {
    if (!indexEnabled) return c.json({ error: 'index not available' }, 501);

    const witness = c.req.query('witness');
    if (!witness || !isValidDfosDid(witness)) {
      return c.json({ error: 'invalid DID' }, 400);
    }

    const relation = c.req.query('relation');
    const order = parseIndexRecencyOrder(c.req.query('order'));
    if (order === null) return c.json({ error: 'invalid order' }, 400);
    const after = c.req.query('after');
    const orderedAfter = order && after ? decodeIndexOrderedCursor(after) : undefined;
    if (order && after && !orderedAfter) return c.json({ error: 'invalid cursor' }, 400);
    const limit = parseLimit(c.req.query('limit'), 100, 1000);
    const rows = await store.queryIndexCountersignatures({
      witness,
      ...(relation !== undefined ? { relation } : {}),
      ...(order ? { order } : {}),
      ...(order ? (orderedAfter ? { orderedAfter } : {}) : after ? { after } : {}),
      limit,
    });
    const next =
      rows.length === limit
        ? order
          ? encodeIndexOrderedCursor(
              rows[rows.length - 1]![order === 'createdAt.desc' ? 'createdAt' : 'ingestedAt'],
              rows[rows.length - 1]!.cid,
            )
          : rows[rows.length - 1]!.cid
        : null;
    const countersignatures = rows.map(
      ({ createdAt: _createdAt, ingestedAt: _ingestedAt, ...row }) => row,
    );

    return c.json({ witness, countersignatures, next });
  });

  app.get(`${INDEX_BASE_PATH}/credentials`, async (c) => {
    if (!indexEnabled) return c.json({ error: 'index not available' }, 501);

    const issuer = c.req.query('issuer');
    if (issuer && !isValidDfosDid(issuer)) {
      return c.json({ error: 'invalid DID' }, 400);
    }

    const resource = c.req.query('resource');
    const action = c.req.query('action');
    const after = c.req.query('after');
    const limit = parseLimit(c.req.query('limit'), 100, 1000);
    const rows = await store.queryIndexCredentials({
      ...(issuer ? { issuer } : {}),
      ...(resource !== undefined ? { resource } : {}),
      ...(action !== undefined ? { action } : {}),
      ...(after ? { after } : {}),
      limit,
    });
    const next = rows.length === limit ? rows[rows.length - 1]!.cid : null;

    return c.json({ credentials: rows, next });
  });

  app.get(`${INDEX_BASE_PATH}/operations`, async (c) => {
    if (!indexEnabled) return c.json({ error: 'index not available' }, 501);

    const rawKind = c.req.query('kind');
    const operationKinds = new Set([
      'identity-op',
      'content-op',
      'artifact',
      'countersign',
      'revocation',
      'credential',
    ]);
    if (rawKind !== undefined && !operationKinds.has(rawKind)) {
      return c.json({ error: 'invalid kind' }, 400);
    }
    const kind = rawKind as import('./types').OperationKind | undefined;
    const chainId = c.req.query('chainId');
    const order = parseIndexRecencyOrder(c.req.query('order'), 'ingestedAt.desc');
    if (order === null || order === undefined) return c.json({ error: 'invalid order' }, 400);
    const after = c.req.query('after');
    const orderedAfter = after ? decodeIndexOrderedCursor(after) : undefined;
    if (after && !orderedAfter) return c.json({ error: 'invalid cursor' }, 400);
    const limit = parseLimit(c.req.query('limit'), 100, 1000);
    const rows = await store.queryIndexOperations({
      ...(kind !== undefined ? { kind } : {}),
      ...(chainId !== undefined ? { chainId } : {}),
      ...(orderedAfter ? { orderedAfter } : {}),
      order,
      limit,
    });
    const next =
      rows.length === limit
        ? encodeIndexOrderedCursor(
            rows[rows.length - 1]![order === 'createdAt.desc' ? 'createdAt' : 'ingestedAt'],
            rows[rows.length - 1]!.cid,
          )
        : null;

    return c.json({ operations: rows, next });
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
      // Same relay-local rule as the identity log: off-branch cursor → 400.
      if (idx < 0) return c.json({ error: 'invalid cursor' }, 400);
      startIdx = idx + 1;
    }

    const page = entries.slice(startIdx, startIdx + limit);
    const next = page.length === limit ? page[page.length - 1]!.cid : null;

    return c.json({ entries: page, next });
  });

  /** Get a content chain by content ID */
  app.get(`${PROOF_BASE_PATH}/content/:contentId`, async (c) => {
    const contentId = c.req.param('contentId');
    let chain = await store.getContentChain(contentId);

    // read-through: try peers on local miss (paginate through full log)
    if (!chain && readThroughPeers.length > 0 && peerClient) {
      for (const peer of readThroughPeers) {
        const completed = await ingestPeerLogWithOneRestart((after) =>
          peerClient.getContentLog(peer.url, contentId, {
            ...(after ? { after } : {}),
            limit: 1000,
          }),
        );
        chain = await store.getContentChain(contentId);
        if (completed && chain) break;
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

    // True keyset over the CID sort order: resume strictly past `after`, whether
    // or not it names a present row — cursors survive concurrent additions and
    // cross-relay replay (the enumeration key IS the sort key here).
    const remaining = after ? decorated.filter((d) => d.csCid > after) : decorated;

    const page = remaining.slice(0, limit);
    const next = page.length === limit ? page[page.length - 1]!.csCid : null;

    // Rows are { cid, jwsToken } — the per-chain log entry shape. targetCID and
    // relation live inside the signed payload; the token is the truth.
    return c.json({
      countersignatures: page.map((d) => ({ cid: d.csCid, jwsToken: d.jws })),
      next,
    });
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
    // null = relay-local cursor this log never issued (or another relay's) → 400.
    if (!result) return c.json({ error: 'invalid cursor' }, 400);
    return c.json({ entries: result.entries, next: result.next });
  });

  // -------------------------------------------------------------------------
  // content plane — authenticated routes
  // -------------------------------------------------------------------------

  /** Upload a blob for a content chain, keyed by operation CID */
  app.put('/content/:contentId/blob/:operationCID', async (c) => {
    if (!contentEnabled) return c.json({ error: 'content plane not available' }, 501);
    // Blob upload is a WRITE. A node advertising write:false must present no
    // write surface at all — otherwise the one route that accepts a 16MB body is
    // still open on the node whose whole point is a minimal attack surface, and
    // the well-known's capability advertisement lies about it. Both gates apply:
    // content:false disables the plane, write:false disables writing to it.
    if (!writeEnabled) {
      return c.json({ error: 'this relay is pull-only; writes are disabled' }, 501);
    }
    const contentId = c.req.param('contentId');
    const operationCID = c.req.param('operationCID');

    // Enforce the route cap while consuming the stream, before authentication.
    // This covers both declared lengths and chunked/direct Fetch requests.
    const read = await readCappedBytes(c.req.raw, MAX_BODY_BYTES);
    if (!read.ok && read.tooLarge) return c.json({ error: 'request body too large' }, 413);
    if (!read.ok) return c.json({ error: 'blob bytes do not match documentCID' }, 400);

    // Authenticate with an identity proof. Blob upload is WRITE-SHAPED, so the
    // proof MUST carry jti and is recorded against the replay cache.
    const auth = await authenticateIdentityProof({
      authHeader: c.req.header('authorization'),
      method: c.req.method,
      path: originFormTarget(c.req.url),
      body: read.bytes,
      authority,
      store,
      requireJti: true,
      replayCache,
      windowSeconds: proofWindowSeconds,
      skewSeconds: proofSkewSeconds,
    });
    if (!auth.ok) return c.json({ error: auth.error }, auth.status as 401 | 503);
    if (!auth.principal) return c.json({ error: 'authentication required' }, 401);
    const uploaderDID = auth.principal.did;

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
    if (uploaderDID !== chain.state.creatorDID && uploaderDID !== operationSignerDID) {
      return c.json({ error: 'not authorized — must be chain creator or operation signer' }, 403);
    }

    // Verify the bounded blob bytes match the documentCID from the operation.
    const bytes = read.bytes;
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
      method: c.req.method,
      path: originFormTarget(c.req.url),
      authority,
      store,
      proofWindowSeconds,
      proofSkewSeconds,
    });
  });

  app.get('/content/:contentId/blob/:ref', async (c) => {
    if (!contentEnabled) return c.json({ error: 'content plane not available' }, 501);
    return await readBlob({
      contentId: c.req.param('contentId'),
      ref: c.req.param('ref'),
      authHeader: c.req.header('authorization'),
      credHeader: c.req.header('x-credential'),
      method: c.req.method,
      path: originFormTarget(c.req.url),
      authority,
      store,
      proofWindowSeconds,
      proofSkewSeconds,
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
      let resetAttempted = false;
      let resetPending = false;
      while (fetched < maxOpsPerSyncCycle) {
        const page = await peerClient.getOperationLog(peer.url, {
          ...(cursor ? { after: cursor } : {}),
          limit: 1000,
        });
        if (page === 'invalid-cursor') {
          if (resetAttempted) {
            console.warn(`peer ${peer.url} rejected its cursor twice; abandoning sync cycle`);
            break;
          }
          resetAttempted = true;
          resetPending = true;
          cursor = undefined;
          continue;
        }
        if (!page) break;
        if (page.entries.length === 0) {
          if (resetPending) await store.setPeerCursor(peer.url, page.next ?? '');
          break;
        }
        await ingestWithGossip(
          page.entries.map((e) => e.jwsToken),
          'historical',
        );
        fetched += page.entries.length;
        if (resetPending) {
          // Only a successful from-scratch page proves that the old cursor was
          // genuinely invalid. Until then, preserve the persisted high-water
          // mark against transient edge-generated 400s.
          if (!page.next) await store.setPeerCursor(peer.url, '');
          resetPending = false;
        }
        // Persist ONLY peer-supplied cursors — never fabricate one from the last
        // entry's CID. A peer whose cursor format is not a bare CID (production
        // pages a timestamp|cid token) would 400 a fabricated cursor and force a
        // full resync every cycle. `next` null = caught up: break retaining the
        // last persisted cursor; the final partial page re-fetches next cycle
        // and dedups cheaply. Mirrors the Go twin's pullPeerOps.
        if (!page.next) break;
        cursor = page.next;
        await store.setPeerCursor(peer.url, cursor);
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
  method: string;
  path: string;
  authority: string | undefined;
  store: RelayStore;
  proofWindowSeconds: number;
  proofSkewSeconds: number;
}): Promise<Response> => {
  const { contentId, ref, authHeader, credHeader, store } = params;

  // look up chain
  const chain = await store.getContentChain(contentId);
  if (!chain) return jsonResponse({ error: 'content chain not found' }, 404);

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

  // A standing public grant asserts the publicness of the chain's current head
  // only; a request for any other revision requires authenticated or credentialed
  // access, and even then a public grant does not count (see verifyReadAccess).
  const isHeadRef = documentCID === chain.state.currentDocumentCID;
  const publicAccess = isHeadRef && (await hasPublicStandingAuth(contentId, 'read', store));
  if (!publicAccess) {
    // The AuthN half: an identity proof. A blob read is READ-SHAPED, so it relies
    // on the freshness window alone — no jti (API-AUTH's accepted within-window
    // replay bound: a replay is a re-read returning the same bytes).
    //
    // An accompanying `X-Credential` is NOT malformed here, unlike on an
    // `api:<host>` surface: the identity proof is the AuthN half and the DFOS
    // credential is a separate authorization artifact (WEB-RELAY.md,
    // Authentication) — two halves of one answer, not two competing claims.
    const auth = await authenticateIdentityProof({
      authHeader,
      method: params.method,
      path: params.path,
      body: new Uint8Array(),
      authority: params.authority,
      store,
      requireJti: false,
      windowSeconds: params.proofWindowSeconds,
      skewSeconds: params.proofSkewSeconds,
    });
    if (!auth.ok) return jsonResponse({ error: auth.error }, auth.status);
    if (!auth.principal) return jsonResponse({ error: 'authentication required' }, 401);

    // The AuthZ half — unless the caller is the chain creator, who can always
    // read their own blobs with just an identity proof.
    const credError = await verifyReadAccess(
      auth.principal,
      chain,
      contentId,
      credHeader,
      store,
      isHeadRef,
    );
    if (credError) return credError;
  }

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
  principal: AuthenticatedPrincipal,
  chain: StoredContentChain,
  contentId: string,
  credHeader: string | undefined,
  store: RelayStore,
  isHeadRef: boolean,
): Promise<Response | null> => {
  const result = await verifyContentAccess({
    ...(credHeader ? { credentialJWS: credHeader } : {}),
    requestedResource: `chain:${contentId}`,
    action: 'read',
    store,
    creatorDID: chain.state.creatorDID,
    requesterDID: principal.did,
    // public grants convey head-only publicness; a non-head read needs the
    // creator or an audience-scoped credential.
    allowPublicGrant: isHeadRef,
  });

  if (result.granted) return null;
  return jsonResponse({ error: 'read credential required' }, 403);
};
