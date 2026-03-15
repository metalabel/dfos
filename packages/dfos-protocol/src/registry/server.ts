/*

  REFERENCE REGISTRY SERVER

  Hono HTTP server implementing the DFOS Protocol registry spec.
  In-memory storage, linear chain enforcement, cursor-based pagination.

*/

import { Hono } from 'hono';
import { decodeMultikey, verifyContentChain, verifyIdentityChain } from '../chain';
import { dagCborCanonicalEncode, decodeJwsUnsafe } from '../crypto';
import type { OperationEntry } from './schemas';
import { ChainStore } from './store';

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

const err = (code: 'BAD_REQUEST' | 'CONFLICT' | 'NOT_FOUND', message: string) => ({
  error: code,
  message,
});

const STATUS = { BAD_REQUEST: 400, NOT_FOUND: 404, CONFLICT: 409 } as const;

/** Extract operation entries (cid + jwsToken + createdAt) from JWS tokens */
const extractOperationEntries = async (chain: string[]): Promise<OperationEntry[]> => {
  const entries: OperationEntry[] = [];
  for (const jwsToken of chain) {
    const decoded = decodeJwsUnsafe(jwsToken);
    if (!decoded) throw new Error('invalid JWS token');
    const payload = decoded.payload as Record<string, unknown>;
    const encoded = await dagCborCanonicalEncode(payload);
    entries.push({
      cid: encoded.cid.toString(),
      jwsToken,
      createdAt: (payload.createdAt as string) ?? '',
    });
  }
  return entries;
};

/** Paginate an array newest-first with cursor support */
const paginate = (
  operations: OperationEntry[],
  cursor: string | undefined,
  limit: number,
): { operations: OperationEntry[]; nextCursor: string | null } => {
  const reversed = [...operations].reverse();
  let startIdx = 0;
  if (cursor) {
    const cursorIdx = reversed.findIndex((op) => op.cid === cursor);
    if (cursorIdx >= 0) startIdx = cursorIdx + 1;
  }
  const page = reversed.slice(startIdx, startIdx + limit);
  const hasMore = startIdx + limit < reversed.length;
  return {
    operations: page,
    nextCursor: hasMore ? page[page.length - 1]!.cid : null,
  };
};

/** Parse pagination query params */
const paginationParams = (c: { query: (k: string) => string | undefined }) => ({
  cursor: c.query('cursor'),
  limit: Math.min(Math.max(parseInt(c.query('limit') ?? '25'), 1), 100),
});

/** Resolve a kid (DID URL) to raw Ed25519 public key bytes via the store */
const createKeyResolver =
  (store: ChainStore) =>
  async (kid: string): Promise<Uint8Array> => {
    const hashIdx = kid.indexOf('#');
    if (hashIdx < 0) throw new Error(`invalid kid format: ${kid}`);
    const did = kid.substring(0, hashIdx);
    const keyId = kid.substring(hashIdx + 1);

    const identityChain = store.getIdentityChain(did);
    if (!identityChain) throw new Error(`identity not found: ${did}`);

    const identity = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: identityChain.operations.map((o) => o.jwsToken),
    });

    const allKeys = [...identity.authKeys, ...identity.assertKeys, ...identity.controllerKeys];
    const key = allKeys.find((k) => k.id === keyId);
    if (!key) throw new Error(`key not found: ${keyId}`);

    return decodeMultikey(key.publicKeyMultibase).keyBytes;
  };

// -----------------------------------------------------------------------------
// server factory
// -----------------------------------------------------------------------------

export const createRegistryServer = (store = new ChainStore()) => {
  const app = new Hono();
  const resolveKey = createKeyResolver(store);

  // --- POST /identities ---
  app.post('/identities', async (c) => {
    const body = await c.req.json<{ chain: string[] }>();
    if (!body.chain || !Array.isArray(body.chain) || body.chain.length === 0) {
      return c.json(err('BAD_REQUEST', 'chain must be a non-empty array of JWS tokens'), 400);
    }

    let verified;
    try {
      verified = await verifyIdentityChain({
        didPrefix: 'did:dfos',
        log: body.chain,
      });
    } catch (e) {
      return c.json(err('BAD_REQUEST', `chain verification failed: ${(e as Error).message}`), 400);
    }

    const operations = await extractOperationEntries(body.chain);
    const result = store.submitIdentityChain(verified.did, operations);
    if (result === 'conflict') {
      return c.json(err('CONFLICT', 'submitted chain conflicts with stored chain'), 409);
    }

    return c.json(
      {
        did: verified.did,
        isDeleted: verified.isDeleted,

        authKeys: verified.authKeys,
        assertKeys: verified.assertKeys,
        controllerKeys: verified.controllerKeys,
      },
      result === 'accepted' ? 201 : 200,
    );
  });

  // --- GET /identities/:did ---
  app.get('/identities/:did', async (c) => {
    const did = c.req.param('did');
    const chain = store.getIdentityChain(did);
    if (!chain) return c.json(err('NOT_FOUND', 'identity not found'), 404);

    const verified = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: chain.operations.map((o) => o.jwsToken),
    });

    return c.json({
      did: verified.did,
      isDeleted: verified.isDeleted,
      authKeys: verified.authKeys,
      assertKeys: verified.assertKeys,
      controllerKeys: verified.controllerKeys,
    });
  });

  // --- GET /identities/:did/operations ---
  app.get('/identities/:did/operations', (c) => {
    const did = c.req.param('did');
    const chain = store.getIdentityChain(did);
    if (!chain) return c.json(err('NOT_FOUND', 'identity not found'), 404);
    const { cursor, limit } = paginationParams(c.req);
    return c.json(paginate(chain.operations, cursor, limit));
  });

  // --- POST /content ---
  app.post('/content', async (c) => {
    const body = await c.req.json<{ chain: string[] }>();
    if (!body.chain || !Array.isArray(body.chain) || body.chain.length === 0) {
      return c.json(err('BAD_REQUEST', 'chain must be a non-empty array of JWS tokens'), 400);
    }

    const operations = await extractOperationEntries(body.chain);

    let verified;
    try {
      verified = await verifyContentChain({ log: body.chain, resolveKey });
    } catch (e) {
      return c.json(err('BAD_REQUEST', `chain verification failed: ${(e as Error).message}`), 400);
    }

    const result = store.submitContentChain(verified.contentId, operations);
    if (result === 'conflict') {
      return c.json(err('CONFLICT', 'submitted chain conflicts with stored chain'), 409);
    }

    return c.json(
      {
        contentId: verified.contentId,
        isDeleted: verified.isDeleted,
        currentDocumentCID: verified.currentDocumentCID,
        genesisCID: verified.genesisCID,
        headCID: verified.headCID,
      },
      result === 'accepted' ? 201 : 200,
    );
  });

  // --- GET /content/:contentId ---
  app.get('/content/:contentId', (c) => {
    const contentId = c.req.param('contentId');
    const chain = store.getContentChain(contentId);
    if (!chain) return c.json(err('NOT_FOUND', 'content not found'), 404);

    const genesis = chain.operations[0]!;
    const head = chain.operations[chain.operations.length - 1]!;
    const headDecoded = decodeJwsUnsafe(head.jwsToken);
    const headPayload = headDecoded?.payload as Record<string, unknown> | undefined;
    const headType = headPayload?.type as string;

    return c.json({
      contentId,
      isDeleted: headType === 'delete',
      currentDocumentCID:
        headType === 'delete' ? null : ((headPayload?.documentCID as string | null) ?? null),
      genesisCID: genesis.cid,
      headCID: head.cid,
    });
  });

  // --- GET /content/:contentId/operations ---
  app.get('/content/:contentId/operations', (c) => {
    const contentId = c.req.param('contentId');
    const chain = store.getContentChain(contentId);
    if (!chain) return c.json(err('NOT_FOUND', 'content not found'), 404);
    const { cursor, limit } = paginationParams(c.req);
    return c.json(paginate(chain.operations, cursor, limit));
  });

  // --- GET /operations/:cid ---
  app.get('/operations/:cid', (c) => {
    const cid = c.req.param('cid');
    const op = store.getOperation(cid);
    if (!op) return c.json(err('NOT_FOUND', 'operation not found'), 404);
    return c.json({ cid: op.cid, jwsToken: op.jwsToken });
  });

  return { app, store };
};
