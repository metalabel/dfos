/*

  INGESTION ADMISSION

  The admission ladder of specs/WEB-RELAY.md "Ingestion Admission", asserted in
  its normative order: structural caps -> proof verification when one is
  presented -> the relay-local admission policy -> full per-item verification.

  Two properties are load-bearing and each has its own test here. A policy
  REFUSAL is request-level — no per-item results are produced, and the expensive
  per-item work never runs. A policy that cannot be evaluated FAILS CLOSED (503),
  because an unevaluable gate is the server's condition, not a judgment about the
  caller.

*/

import {
  deriveChainIdentifier,
  encodeEd25519Multikey,
  signIdentityOperation,
  type IdentityOperation,
} from '@metalabel/dfos-protocol/chain';
import { signApiIdentityRequest } from '@metalabel/dfos-protocol/credentials';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  generateId,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { describe, expect, it } from 'vitest';
import { createRelay, MemoryRelayStore } from '../src';
import type { AdmissionPolicy, RelayOptions } from '../src';

/**
 * THE RELAY'S OWN CONFIGURED AUTHORITY in these tests. Requests go to
 * `http://localhost/...`, so a proof binds `localhost` — from configuration,
 * never from the request.
 */
const AUTHORITY = 'localhost';
const OPERATIONS_PATH = '/proof/v1/operations';

const createIdentity = async () => {
  const authKeypair = createNewEd25519Keypair();
  const authKeyId = generateId('key');
  const controllerKeypair = createNewEd25519Keypair();
  const controllerKeyId = generateId('key');
  const key = (id: string, publicKey: Uint8Array) => ({
    id,
    type: 'Multikey' as const,
    publicKeyMultibase: encodeEd25519Multikey(publicKey),
  });
  const operation: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [key(authKeyId, authKeypair.publicKey)],
    assertKeys: [],
    controllerKeys: [key(controllerKeyId, controllerKeypair.publicKey)],
    createdAt: '2026-01-01T00:00:00.000Z',
  };
  const { jwsToken, operationCID } = await signIdentityOperation({
    operation,
    signer: async (msg: Uint8Array) => signPayloadEd25519(msg, controllerKeypair.privateKey),
    keyId: controllerKeyId,
  });
  // The DID is derived from the genesis operation's CID — self-certifying, no
  // registry, and computable before the relay has ever seen the operation.
  const encoded = await dagCborCanonicalEncode(operation);
  const did = deriveChainIdentifier(encoded.cid.bytes, 'did:dfos');
  return {
    did,
    jwsToken,
    operationCID,
    authKeyId,
    sign: async (msg: Uint8Array) => signPayloadEd25519(msg, authKeypair.privateKey),
  };
};

const relayWith = async (options: Partial<RelayOptions> = {}) => {
  const store = new MemoryRelayStore();
  const relay = await createRelay({ store, authority: AUTHORITY, ...options });
  return { store, relay };
};

let jtiCounter = 0;

const submit = async (
  relay: Awaited<ReturnType<typeof createRelay>>,
  operations: string[],
  signer?: Awaited<ReturnType<typeof createIdentity>>,
  proofOverrides: { jti?: string | false; iat?: number; host?: string } = {},
) => {
  const body = new TextEncoder().encode(JSON.stringify({ operations }));
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (signer) {
    const jti =
      proofOverrides.jti === false
        ? undefined
        : (proofOverrides.jti ?? `admission-${(jtiCounter += 1)}`);
    const { proof } = await signApiIdentityRequest({
      method: 'POST',
      host: proofOverrides.host ?? AUTHORITY,
      path: OPERATIONS_PATH,
      body,
      kid: `${signer.did}#${signer.authKeyId}`,
      sign: signer.sign,
      ...(proofOverrides.iat !== undefined ? { iat: proofOverrides.iat } : {}),
      ...(jti !== undefined ? { extraMembers: { jti } } : {}),
    });
    headers['authorization'] = `DFOS ${proof}`;
  }
  return relay.app.request(`http://localhost${OPERATIONS_PATH}`, {
    method: 'POST',
    headers,
    body,
  });
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const json = async (res: Response): Promise<any> => res.json();

describe('ingestion admission', () => {
  // ---------------------------------------------------------------------------
  // the well-known hint
  // ---------------------------------------------------------------------------

  describe('the ingestion advertisement', () => {
    it('derives "open" from write:true when no mode is configured', async () => {
      const { relay } = await relayWith();
      const body = await json(await relay.app.request('http://localhost/.well-known/dfos-relay'));
      expect(body.ingestion).toBe('open');
    });

    it('derives "closed" from write:false — the capability gate is the authority', async () => {
      const { relay } = await relayWith({ write: false });
      const body = await json(await relay.app.request('http://localhost/.well-known/dfos-relay'));
      expect(body.ingestion).toBe('closed');
      expect(body.capabilities.write).toBe(false);
    });

    it('advertises an explicitly configured mode', async () => {
      const { relay } = await relayWith({ ingestion: 'proof-required' });
      const body = await json(await relay.app.request('http://localhost/.well-known/dfos-relay'));
      expect(body.ingestion).toBe('proof-required');
    });

    it('lets write:false override a configured "open" — a lite node ingests nothing', async () => {
      const { relay } = await relayWith({ write: false, ingestion: 'open' });
      const body = await json(await relay.app.request('http://localhost/.well-known/dfos-relay'));
      expect(body.ingestion).toBe('closed');
    });

    it('answers 501 on the ingestion route when the mode is "closed"', async () => {
      const { relay } = await relayWith({ ingestion: 'closed' });
      const identity = await createIdentity();
      const res = await submit(relay, [identity.jwsToken]);
      expect(res.status).toBe(501);
    });
  });

  // ---------------------------------------------------------------------------
  // the ladder
  // ---------------------------------------------------------------------------

  describe('the evaluation ladder', () => {
    it('admits anonymous submissions by default — the default policy admits everything', async () => {
      const { relay } = await relayWith();
      const identity = await createIdentity();
      const res = await submit(relay, [identity.jwsToken]);
      expect(res.status).toBe(200);
      expect((await json(res)).results[0].status).toBe('new');
    });

    it('admits an identity-proven submission and names the principal to the policy', async () => {
      const seen: (string | null)[] = [];
      const policy: AdmissionPolicy = (principal) => {
        seen.push(principal);
        return true;
      };
      const { relay } = await relayWith({ admissionPolicy: policy });
      const submitter = await createIdentity();
      // The submitter's own chain has to be resolvable before its proof can be
      // verified: current-state key resolution is a LOCAL lookup.
      expect((await submit(relay, [submitter.jwsToken])).status).toBe(200);

      const other = await createIdentity();
      const res = await submit(relay, [other.jwsToken], submitter);
      expect(res.status).toBe(200);
      expect(seen).toEqual([null, submitter.did]);
    });

    it('refuses at the POLICY step, request-level, BEFORE any per-item verification', async () => {
      // The refusal must produce NO per-item results: "nothing in the batch is
      // examined further". A well-formed op that WOULD have been accepted is the
      // probe — if per-item work had run, it would be in the store.
      const { store, relay } = await relayWith({ admissionPolicy: () => false });
      const identity = await createIdentity();
      const res = await submit(relay, [identity.jwsToken]);

      expect(res.status).toBe(403);
      const body = await json(res);
      expect(body).toHaveProperty('error');
      expect(body).not.toHaveProperty('results');
      // The expensive step was never spent: the chain is not in the store.
      expect(await store.getIdentityChain(identity.did)).toBeUndefined();
    });

    it('refuses ANONYMOUS submissions under proof-required, and admits proven ones', async () => {
      const { relay } = await relayWith({ ingestion: 'proof-required' });
      const submitter = await createIdentity();

      // Bootstrapping problem, stated honestly: a proof-required relay cannot be
      // handed the submitter's own genesis anonymously, so the chain arrives by
      // some other path. Here the store is seeded directly.
      const anonymous = await submit(relay, [submitter.jwsToken]);
      expect(anonymous.status).toBe(403);

      const openStore = new MemoryRelayStore();
      const openRelay = await createRelay({ store: openStore, authority: AUTHORITY });
      expect((await submit(openRelay, [submitter.jwsToken])).status).toBe(200);
      const seeded = await createRelay({
        store: openStore,
        authority: AUTHORITY,
        ingestion: 'proof-required',
      });

      const other = await createIdentity();
      expect((await submit(seeded, [other.jwsToken])).status).toBe(403);
      expect((await submit(seeded, [other.jwsToken], submitter)).status).toBe(200);
    });

    it('FAILS CLOSED with 503 when the policy cannot be evaluated', async () => {
      const { store, relay } = await relayWith({
        admissionPolicy: () => {
          throw new Error('quota backend unreachable');
        },
      });
      const identity = await createIdentity();
      const res = await submit(relay, [identity.jwsToken]);
      // 503, not 403: the server could not answer the question. Reporting it as a
      // refusal would blame the caller for the relay's outage.
      expect(res.status).toBe(503);
      expect(await store.getIdentityChain(identity.did)).toBeUndefined();
    });

    it('rejects an INVALID proof with 401 rather than downgrading to anonymous', async () => {
      const { relay } = await relayWith();
      const submitter = await createIdentity();
      expect((await submit(relay, [submitter.jwsToken])).status).toBe(200);

      const other = await createIdentity();
      // Bound to a different authority: a proof this relay must not accept.
      const res = await submit(relay, [other.jwsToken], submitter, {
        host: 'other-relay.example.com',
      });
      expect(res.status).toBe(401);
    });

    it('reports an unresolvable presenter as 503, never 401', async () => {
      const { relay } = await relayWith();
      const stranger = await createIdentity(); // never ingested here
      const other = await createIdentity();
      const res = await submit(relay, [other.jwsToken], stranger);
      // "Could not check" is the server's condition; only "checked and failed"
      // is the caller's.
      expect(res.status).toBe(503);
    });

    it('answers 503 when a proof is presented but the relay has no configured authority', async () => {
      const store = new MemoryRelayStore();
      const unconfigured = await createRelay({ store });
      const submitter = await createIdentity();
      expect((await submit(unconfigured, [submitter.jwsToken])).status).toBe(200);

      const other = await createIdentity();
      const res = await submit(unconfigured, [other.jwsToken], submitter);
      expect(res.status).toBe(503);
    });

    it('keeps the capability gate ahead of the whole ladder', async () => {
      // write:false answers 501 before authentication, body parsing, or policy.
      const policyCalls: unknown[] = [];
      const { relay } = await relayWith({
        write: false,
        admissionPolicy: (principal: string | null) => {
          policyCalls.push(principal);
          return true;
        },
      });
      const identity = await createIdentity();
      expect((await submit(relay, [identity.jwsToken])).status).toBe(501);
      expect(policyCalls).toEqual([]);
    });

    it('keeps structural caps ahead of the proof and the policy', async () => {
      const policyCalls: unknown[] = [];
      const { relay } = await relayWith({
        admissionPolicy: (principal: string | null) => {
          policyCalls.push(principal);
          return false;
        },
      });
      const res = await relay.app.request(`http://localhost${OPERATIONS_PATH}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ operations: [] }),
      });
      // A structurally invalid batch is a 400, never the policy's 403 — the
      // ladder is cheapest-first and each rung has its own status code.
      expect(res.status).toBe(400);
      expect(policyCalls).toEqual([]);
    });
  });

  // ---------------------------------------------------------------------------
  // jti on the write-shaped ingestion surface
  // ---------------------------------------------------------------------------

  describe('jti', () => {
    const provenRelay = async () => {
      const { store, relay } = await relayWith();
      const submitter = await createIdentity();
      expect((await submit(relay, [submitter.jwsToken])).status).toBe(200);
      return { store, relay, submitter };
    };

    it('rejects a proof with NO jti — ingestion is write-shaped', async () => {
      const { relay, submitter } = await provenRelay();
      const other = await createIdentity();
      const res = await submit(relay, [other.jwsToken], submitter, { jti: false });
      expect(res.status).toBe(401);
    });

    it('rejects a REPLAYED jti', async () => {
      const { relay, submitter } = await provenRelay();
      const other = await createIdentity();
      const body = new TextEncoder().encode(JSON.stringify({ operations: [other.jwsToken] }));
      const { proof } = await signApiIdentityRequest({
        method: 'POST',
        host: AUTHORITY,
        path: OPERATIONS_PATH,
        body,
        kid: `${submitter.did}#${submitter.authKeyId}`,
        sign: submitter.sign,
        extraMembers: { jti: 'ingest-replay-once' },
      });
      const send = () =>
        relay.app.request(`http://localhost${OPERATIONS_PATH}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: `DFOS ${proof}` },
          body,
        });
      expect((await send()).status).toBe(200);
      // Idempotent ingestion does NOT make the replay free: policy already ran,
      // and a quota or reputation effect was already granted.
      expect((await send()).status).toBe(401);
    });

    it('keys the replay cache by (presenter, jti) — two presenters may share one', async () => {
      const { relay } = await relayWith();
      const first = await createIdentity();
      const second = await createIdentity();
      expect((await submit(relay, [first.jwsToken, second.jwsToken])).status).toBe(200);

      const other = await createIdentity();
      expect((await submit(relay, [other.jwsToken], first, { jti: 'shared' })).status).toBe(200);
      expect((await submit(relay, [other.jwsToken], second, { jti: 'shared' })).status).toBe(200);
    });

    it('rejects a jti over the 256-byte cap', async () => {
      const { relay, submitter } = await provenRelay();
      const other = await createIdentity();
      const res = await submit(relay, [other.jwsToken], submitter, { jti: 'x'.repeat(257) });
      expect(res.status).toBe(401);
    });
  });
});
