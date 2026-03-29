/*

  RELAY

  Hono app factory — createRelay(options) returns a portable Hono application
  implementing the DFOS web relay HTTP interface.

  Proof plane routes are public. Content plane routes require authentication
  via DID-signed auth tokens and optional VC-JWT credentials.

*/

import { VC_TYPE_CONTENT_READ, verifyCredential } from '@metalabel/dfos-protocol/credentials';
import type { VerifiedAuthToken } from '@metalabel/dfos-protocol/credentials';
import { dagCborCanonicalEncode, decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { Hono } from 'hono';
import { z } from 'zod';
import { authenticateRequest } from './auth';
import { bootstrapRelayIdentity } from './bootstrap';
import { createCurrentKeyResolver, ingestOperations } from './ingest';
import { computeOpCID, sequenceOps } from './sequencer';
import type { PeerClient, PeerConfig, RelayOptions, RelayStore, StoredContentChain } from './types';

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

const IngestBody = z.object({
  operations: z.array(z.string()).min(1).max(100),
});

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

  // gossip helper
  const gossip = (ops: string[]) => {
    if (ops.length === 0 || gossipPeers.length === 0 || !peerClient) return;
    for (const peer of gossipPeers) {
      peerClient.submitOperations(peer.url, ops).catch(() => {});
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
  // well-known
  // -------------------------------------------------------------------------

  app.get('/.well-known/dfos-relay', (c) => {
    return c.json({
      did: relayDID,
      protocol: 'dfos-web-relay',
      version: '0.6.0',
      proof: true,
      content: contentEnabled,
      log: logEnabled,
      profile: profileArtifactJws,
    });
  });

  // -------------------------------------------------------------------------
  // proof plane — public routes
  // -------------------------------------------------------------------------

  /** Submit operations for ingestion */
  app.post('/operations', async (c) => {
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
  app.get('/operations/:cid', async (c) => {
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
  app.get('/identities/:did/log', async (c) => {
    const did = c.req.param('did');
    const chain = await store.getIdentityChain(did);
    if (!chain) return c.json({ error: 'not found' }, 404);

    const after = c.req.query('after');
    const limit = Math.min(Number(c.req.query('limit') || 100), 1000);

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

  app.get('/identities/:did{.+}', async (c) => {
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

  /** Get a content chain log */
  app.get('/content/:contentId/log', async (c) => {
    const contentId = c.req.param('contentId');
    const chain = await store.getContentChain(contentId);
    if (!chain) return c.json({ error: 'not found' }, 404);

    const after = c.req.query('after');
    const limit = Math.min(Number(c.req.query('limit') || 100), 1000);

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
  app.get('/content/:contentId', async (c) => {
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

  /** Get countersignatures for an operation or beacon CID */
  app.get('/countersignatures/:cid', async (c) => {
    const cid = c.req.param('cid');

    // check if it's a known operation or beacon CID
    const op = await store.getOperation(cid);
    if (!op) {
      // not an operation — check if any beacon has this CID
      const countersigs = await store.getCountersignatures(cid);
      if (countersigs.length === 0) return c.json({ error: 'not found' }, 404);
      return c.json({ cid, countersignatures: countersigs });
    }

    const countersigs = await store.getCountersignatures(cid);
    return c.json({ operationCID: cid, countersignatures: countersigs });
  });

  /** Get countersignatures for an operation CID (legacy path) */
  app.get('/operations/:cid/countersignatures', async (c) => {
    const cid = c.req.param('cid');
    const op = await store.getOperation(cid);
    if (!op) return c.json({ error: 'not found' }, 404);

    const countersigs = await store.getCountersignatures(cid);
    return c.json({ operationCID: cid, countersignatures: countersigs });
  });

  /** Get the latest beacon for a DID */
  app.get('/beacons/:did{.+}', async (c) => {
    const did = c.req.param('did');
    const beacon = await store.getBeacon(did);
    if (!beacon) return c.json({ error: 'not found' }, 404);

    return c.json({
      did: beacon.did,
      jwsToken: beacon.jwsToken,
      beaconCID: beacon.beaconCID,
      payload: beacon.state.payload,
    });
  });

  // -------------------------------------------------------------------------
  // global operation log
  // -------------------------------------------------------------------------

  /** Read the global append-only operation log */
  app.get('/log', async (c) => {
    if (!logEnabled) return c.json({ error: 'global log not available' }, 501);
    const afterParam = c.req.query('after');
    const limit = Math.min(Number(c.req.query('limit') || 100), 1000);
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

    // authenticate
    const auth = await authenticateRequest(c.req.header('authorization'), relayDID, store);
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

    // read blob bytes and verify they match the documentCID from the operation
    const bytes = new Uint8Array(await c.req.arrayBuffer());
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
    });
  });

  // -------------------------------------------------------------------------
  // sync-in: pull from peer logs
  // -------------------------------------------------------------------------

  const syncFromPeers = async (): Promise<void> => {
    if (!peerClient) return;
    for (const peer of syncPeers) {
      let cursor = await store.getPeerCursor(peer.url);
      while (true) {
        const page = await peerClient.getOperationLog(peer.url, {
          ...(cursor ? { after: cursor } : {}),
          limit: 1000,
        });
        if (!page || page.entries.length === 0) break;
        await ingestWithGossip(page.entries.map((e) => e.jwsToken));
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
}): Promise<Response> => {
  const { contentId, ref, authHeader, credHeader, relayDID, store } = params;

  // authenticate
  const auth = await authenticateRequest(authHeader, relayDID, store);
  if (!auth) return jsonResponse({ error: 'authentication required' }, 401);

  // look up chain
  const chain = await store.getContentChain(contentId);
  if (!chain) return jsonResponse({ error: 'content chain not found' }, 404);

  // verify read credential — unless the caller is the chain creator
  const credError = await verifyReadCredential(auth, chain, contentId, credHeader, store);
  if (credError) return credError;

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

/** Verify the read credential if the caller is not the chain creator. Returns an error Response or null. */
const verifyReadCredential = async (
  auth: VerifiedAuthToken,
  chain: StoredContentChain,
  contentId: string,
  credHeader: string | undefined,
  store: RelayStore,
): Promise<Response | null> => {
  if (auth.iss === chain.state.creatorDID) return null;

  if (!credHeader) {
    return jsonResponse({ error: 'DFOSContentRead credential required' }, 403);
  }

  const resolveKey = createCurrentKeyResolver(store);
  try {
    const vcDecoded = decodeJwsUnsafe(credHeader);
    if (!vcDecoded) throw new Error('invalid credential format');
    const vcHeader = vcDecoded.header as { kid?: string };
    if (!vcHeader.kid) throw new Error('credential missing kid');

    const kidHashIdx = vcHeader.kid.indexOf('#');
    if (kidHashIdx < 0) throw new Error('credential kid must be a DID URL');
    const vcIssuerDID = vcHeader.kid.substring(0, kidHashIdx);
    if (vcIssuerDID !== chain.state.creatorDID) {
      throw new Error('credential must be issued by the chain creator');
    }

    // reject credentials from deleted issuers — identity deletion revokes
    // all authority, including outstanding credentials
    const issuerIdentity = await store.getIdentityChain(vcIssuerDID);
    if (issuerIdentity?.state.isDeleted) {
      throw new Error('credential issuer identity is deleted');
    }

    const creatorKey = await resolveKey(vcHeader.kid);
    const credential = verifyCredential({
      token: credHeader,
      publicKey: creatorKey,
      subject: auth.iss,
      expectedType: VC_TYPE_CONTENT_READ,
    });

    if (credential.iss !== chain.state.creatorDID) {
      throw new Error('credential issuer is not the chain creator');
    }

    if (credential.contentId && credential.contentId !== contentId) {
      return jsonResponse({ error: 'credential contentId does not match' }, 403);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'credential verification failed';
    return jsonResponse({ error: message }, 403);
  }

  return null;
};
