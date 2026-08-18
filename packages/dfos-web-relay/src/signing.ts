/* Optional SIGNING 0.1 mailbox courier routes. */

import {
  decodeMultikey,
  verifyIdentityChain,
  verifySignRequest,
  type VerifiedIdentity,
} from '@metalabel/dfos-protocol/chain';
import {
  matchesResource,
  verifyDelegationChain,
  verifyDFOSCredential,
} from '@metalabel/dfos-protocol/credentials';
import {
  assertJwsProfile,
  base64urlDecode,
  base64urlEncode,
  decodeJwsUnsafe,
  isValidEd25519Signature,
} from '@metalabel/dfos-protocol/crypto';
import { Hono, type Context } from 'hono';
import { authenticateRequest, DEFAULT_MAX_AUTH_TOKEN_TTL_SECONDS } from './auth';
import { createHistoricalIdentityResolver, mergeHistoricalIdentity } from './ingest';
import { decodeSigningCursor } from './types';
import type { RelayStore, SigningStore, StoredSignRequest } from './types';

const MAX_DEPOSIT_BODY_BYTES = 524_288;
const MAX_RESPONSE_TOKEN_BYTES = 8_192;
const MAX_RESPONSE_BODY_BYTES = MAX_RESPONSE_TOKEN_BYTES + 512;
const MAX_DECLINE_BODY_BYTES = 512;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const parseSigningLimit = (raw: string | undefined): number => {
  if (raw === undefined || raw === '') return 100;
  if (!/^-?\d+$/.test(raw)) return 100;
  const limit = Number(raw);
  if (!Number.isSafeInteger(limit) || limit < 1) return 100;
  return Math.min(limit, 1000);
};

type BundledIdentity = { state: VerifiedIdentity; log: string[] };

/** Verify every supplied identity chain and index it ephemerally by DID. */
const verifyBundle = async (tokens: string[]): Promise<Map<string, BundledIdentity>> => {
  const grouped = new Map<string, string[]>();
  for (const token of tokens) {
    const decoded = decodeJwsUnsafe(token);
    if (!decoded) throw new Error('invalid identity operation in chain bundle');
    const payload = decoded.payload as Record<string, unknown>;
    let did: string;
    if (payload['type'] === 'create') {
      did = (await verifyIdentityChain({ didPrefix: 'did:dfos', log: [token] })).did;
    } else {
      const kid = decoded.header.kid;
      const hash = typeof kid === 'string' ? kid.indexOf('#') : -1;
      if (hash < 0) throw new Error('invalid identity operation kid in chain bundle');
      did = kid.substring(0, hash);
    }
    grouped.set(did, [...(grouped.get(did) ?? []), token]);
  }

  const verified = new Map<string, BundledIdentity>();
  for (const [did, log] of grouped) {
    const state = await verifyIdentityChain({ didPrefix: 'did:dfos', log });
    if (state.did !== did) throw new Error('identity bundle DID mismatch');
    verified.set(did, { state, log });
  }
  return verified;
};

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, index) => byte === b[index]);

const exactMailboxDeposit = async (
  att: { resource: string; action: string }[],
  subjectDID: string,
): Promise<boolean> => {
  const resource = `mailbox:${subjectDID.replace(/^did:dfos:/, '')}`;
  const exactEntries = att.filter((entry) => entry.resource === resource);
  return matchesResource(exactEntries, resource, 'deposit');
};

const readCappedBytes = async (
  request: Request,
  maximum: number,
): Promise<{ ok: true; bytes: Uint8Array } | { ok: false }> => {
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maximum) {
    return { ok: false };
  }
  // With no Content-Length, serve.ts still bounds the incoming stream at 17 MiB;
  // this aggregate check enforces the route-specific ceiling after materialization.
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.length > maximum) return { ok: false };
  return { ok: true, bytes };
};

const readCappedJSON = async (
  request: Request,
  maximum: number,
): Promise<{ ok: true; body: unknown } | { ok: false; tooLarge: boolean }> => {
  const read = await readCappedBytes(request, maximum);
  if (!read.ok) return { ok: false, tooLarge: true };
  try {
    return { ok: true, body: JSON.parse(decoder.decode(read.bytes)) };
  } catch {
    return { ok: false, tooLarge: false };
  }
};

const verifyResponse = async (response: string, request: StoredSignRequest, store: RelayStore) => {
  if (encoder.encode(response).length > MAX_RESPONSE_TOKEN_BYTES) {
    throw new Error('response exceeds maximum size');
  }
  const parts = response.split('.');
  if (parts.length !== 3) throw new Error('invalid response JWS');
  let header: Record<string, unknown>;
  try {
    const headerBytes = base64urlDecode(parts[0]!);
    if (base64urlEncode(headerBytes) !== parts[0]) throw new Error('non-canonical header');
    header = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(headerBytes)) as Record<
      string,
      unknown
    >;
  } catch {
    throw new Error('invalid response JWS');
  }
  assertJwsProfile(header, (message) => new Error(message));
  if (header['typ'] !== request.payloadTyp) throw new Error('response typ mismatch');
  const kid = header['kid'];
  if (typeof kid !== 'string') throw new Error('response kid missing');
  const hash = kid.indexOf('#');
  if (hash < 0 || kid.substring(0, hash) !== request.subjectDID) {
    throw new Error('response signer does not match subject');
  }
  const payloadBytes = base64urlDecode(parts[1]!);
  if (base64urlEncode(payloadBytes) !== parts[1]) throw new Error('invalid response payload');
  if (!bytesEqual(payloadBytes, request.payloadBytes)) throw new Error('response payload mismatch');

  const resolveIdentity = createHistoricalIdentityResolver(store);
  const identity = await resolveIdentity(request.subjectDID);
  if (!identity) throw new Error('subject identity unavailable');
  const keyID = kid.substring(hash + 1);
  const key = [...identity.authKeys, ...identity.assertKeys, ...identity.controllerKeys].find(
    (candidate) => candidate.id === keyID,
  );
  if (!key) throw new Error('response key unavailable');
  const signature = base64urlDecode(parts[2]!);
  if (base64urlEncode(signature) !== parts[2]) throw new Error('invalid response signature');
  const signingInput = encoder.encode(`${parts[0]}.${parts[1]}`);
  if (
    !isValidEd25519Signature(
      signingInput,
      signature,
      decodeMultikey(key.publicKeyMultibase).keyBytes,
    )
  ) {
    throw new Error('invalid response signature');
  }
};

export const registerSigningRoutes = (options: {
  app: Hono;
  store: RelayStore;
  relayDID: string;
  basePath: string;
  enabled: boolean;
  maxAuthTokenTTLSeconds?: number;
}): void => {
  const { app, store, relayDID, basePath, enabled } = options;
  const signingStore = store as SigningStore;
  const unavailable = (c: Context) => c.json({ error: 'signing mailbox not available' }, 501);

  app.post(`${basePath}/requests`, async (c) => {
    if (!enabled) return unavailable(c);
    const read = await readCappedJSON(c.req.raw, MAX_DEPOSIT_BODY_BYTES);
    if (!read.ok) {
      return c.json(
        { error: read.tooLarge ? 'request body too large' : 'invalid JSON body' },
        read.tooLarge ? 413 : 400,
      );
    }
    const body = read.body as Record<string, unknown> | null;
    if (
      !body ||
      typeof body !== 'object' ||
      typeof body.request !== 'string' ||
      typeof body.credential !== 'string' ||
      (body.chain !== undefined &&
        (!Array.isArray(body.chain) || !body.chain.every((token) => typeof token === 'string')))
    ) {
      return c.json({ error: 'invalid request' }, 400);
    }

    let bundle: Map<string, BundledIdentity>;
    try {
      bundle = await verifyBundle((body.chain as string[] | undefined) ?? []);
    } catch {
      return c.json({ error: 'invalid identity chain bundle' }, 400);
    }

    const resolveCurrent = async (did: string): Promise<VerifiedIdentity | undefined> => {
      const local = await store.getIdentityChain(did);
      return local?.state ?? bundle.get(did)?.state;
    };
    const localHistorical = createHistoricalIdentityResolver(store);
    const resolveHistorical = async (did: string): Promise<VerifiedIdentity | undefined> => {
      const local = await localHistorical(did);
      const bundled = bundle.get(did);
      return local ?? (bundled ? mergeHistoricalIdentity(bundled.state, bundled.log) : undefined);
    };

    let verifiedRequest: Awaited<ReturnType<typeof verifySignRequest>>;
    try {
      verifiedRequest = await verifySignRequest(body.request, { resolveIdentity: resolveCurrent });
    } catch {
      return c.json({ error: 'invalid sign request' }, 400);
    }

    const subject = await store.getIdentityChain(verifiedRequest.subject);
    if (!subject || subject.state.isDeleted) {
      return c.json({ error: 'subject identity not found' }, 404);
    }

    try {
      const credential = await verifyDFOSCredential(body.credential, {
        resolveIdentity: resolveHistorical,
      });
      if (await store.isCredentialRevoked(credential.iss, credential.credentialCID)) {
        throw new Error('credential revoked');
      }
      await verifyDelegationChain(credential, {
        resolveIdentity: resolveHistorical,
        rootDID: verifiedRequest.subject,
        isRevoked: (issuer, cid) => store.isCredentialRevoked(issuer, cid),
      });
      if (credential.aud !== '*' && credential.aud !== verifiedRequest.did) {
        throw new Error('credential audience mismatch');
      }
      if (!(await exactMailboxDeposit(credential.att, verifiedRequest.subject))) {
        throw new Error('credential does not cover mailbox deposit');
      }
    } catch {
      return c.json({ error: 'deposit credential rejected' }, 403);
    }

    const now = Date.now();
    const result = await signingStore.putSignRequest(
      {
        cid: verifiedRequest.requestCID,
        request: body.request,
        requesterDID: verifiedRequest.did,
        subjectDID: verifiedRequest.subject,
        payloadTyp: verifiedRequest.payloadTyp,
        payloadBytes: verifiedRequest.payloadBytes,
        expiresAt: verifiedRequest.expiresAt,
        depositedAt: new Date(now).toISOString(),
        declined: false,
      },
      now,
    );
    if (result === 'conflict') return c.json({ error: 'request CID conflict' }, 409);
    return c.json(
      { cid: verifiedRequest.requestCID, expiresAt: verifiedRequest.expiresAt },
      result === 'created' ? 201 : 200,
    );
  });

  app.get(`${basePath}/requests`, async (c) => {
    if (!enabled) return unavailable(c);
    const auth = await authenticateRequest(
      c.req.header('authorization'),
      relayDID,
      store,
      options.maxAuthTokenTTLSeconds ?? DEFAULT_MAX_AUTH_TOKEN_TTL_SECONDS,
    );
    if (!auth) return c.json({ error: 'authentication required' }, 401);
    const after = c.req.query('after');
    if (after && !decodeSigningCursor(after)) return c.json({ error: 'invalid cursor' }, 400);
    const limit = parseSigningLimit(c.req.query('limit'));
    const result = await signingStore.listPendingSignRequests({
      subjectDID: auth.iss,
      ...(after ? { after } : {}),
      limit,
      now: Date.now(),
    });
    return c.json({
      requests: result.requests.map((request) => ({
        cid: request.cid,
        request: request.request,
        depositedAt: request.depositedAt,
        declined: request.declined,
      })),
      next: result.next,
    });
  });

  app.post(`${basePath}/requests/:cid/response`, async (c) => {
    if (!enabled) return unavailable(c);
    const request = await signingStore.getSignRequest(c.req.param('cid'), Date.now());
    if (!request) return c.json({ error: 'sign request not found' }, 404);
    const read = await readCappedJSON(c.req.raw, MAX_RESPONSE_BODY_BYTES);
    if (!read.ok) {
      return c.json(
        { error: read.tooLarge ? 'request body too large' : 'invalid JSON body' },
        read.tooLarge ? 413 : 400,
      );
    }
    const body = read.body;
    const response = (body as { response?: unknown } | null)?.response;
    if (typeof response !== 'string') return c.json({ error: 'invalid response' }, 400);
    try {
      await verifyResponse(response, request, store);
    } catch {
      return c.json({ error: 'invalid response' }, 400);
    }
    const result = await signingStore.putSignResponse(request.cid, response, Date.now());
    if (result === 'not-found') return c.json({ error: 'sign request not found' }, 404);
    if (result === 'conflict') return c.json({ error: 'response already exists' }, 409);
    return c.json({ status: 'stored' }, result === 'created' ? 201 : 200);
  });

  app.get(`${basePath}/requests/:cid/response`, async (c) => {
    if (!enabled) return unavailable(c);
    const request = await signingStore.getSignRequest(c.req.param('cid'), Date.now());
    if (!request) return c.json({ error: 'sign request not found' }, 404);
    if (request.response !== undefined) {
      return c.json({ status: 'responded', response: request.response });
    }
    return c.json({ status: request.declined ? 'declined' : 'pending' });
  });

  app.post(`${basePath}/requests/:cid/decline`, async (c) => {
    if (!enabled) return unavailable(c);
    const read = await readCappedBytes(c.req.raw, MAX_DECLINE_BODY_BYTES);
    if (!read.ok) return c.json({ error: 'request body too large' }, 413);
    if (read.bytes.some((byte) => ![9, 10, 13, 32].includes(byte))) {
      return c.json({ error: 'request body must be empty' }, 400);
    }
    const result = await signingStore.declineSignRequest(c.req.param('cid'), Date.now());
    if (result === 'not-found') return c.json({ error: 'sign request not found' }, 404);
    if (result === 'responded') return c.json({ error: 'response already exists' }, 409);
    return c.body(null, 204);
  });
};
