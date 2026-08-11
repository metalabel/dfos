import {
  buildSignRequest,
  deriveChainIdentifier,
  encodeEd25519Multikey,
  signCreditClaim,
  signIdentityOperation,
  signRevocation,
  type IdentityOperation,
  type MultikeyPublicKey,
} from '@metalabel/dfos-protocol/chain';
import { createAuthToken, createDFOSCredential } from '@metalabel/dfos-protocol/credentials';
import {
  base64urlDecode,
  base64urlEncode,
  createJws,
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  decodeJwsUnsafe,
  generateId,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { describe, expect, it } from 'vitest';
import { ingestOperations } from '../src/ingest';
import { createRelay } from '../src/relay';
import { MemoryRelayStore } from '../src/store';

const CONTENT_ID = 'cv7n8vkvr64cctf3294h9k4eanhff8z';
const SIGNING = '/signing/v1';

const key = () => {
  const pair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const publicKey: MultikeyPublicKey = {
    id: keyId,
    type: 'Multikey',
    publicKeyMultibase: encodeEd25519Multikey(pair.publicKey),
  };
  return {
    pair,
    keyId,
    publicKey,
    signer: async (message: Uint8Array) => signPayloadEd25519(message, pair.privateKey),
  };
};

const identity = async () => {
  const controller = key();
  const auth = key();
  const operation: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [auth.publicKey],
    assertKeys: [],
    controllerKeys: [controller.publicKey],
    createdAt: new Date().toISOString(),
  };
  const signed = await signIdentityOperation({
    operation,
    signer: controller.signer,
    keyId: controller.keyId,
  });
  const encoded = await dagCborCanonicalEncode(operation);
  return {
    did: deriveChainIdentifier(encoded.cid.bytes, 'did:dfos'),
    controller,
    auth,
    token: signed.jwsToken,
    headCID: signed.operationCID,
  };
};

type TestIdentity = Awaited<ReturnType<typeof identity>>;

const seed = async (store: MemoryRelayStore, ...identities: TestIdentity[]) => {
  const results = await ingestOperations(
    identities.map((item) => item.token),
    store,
  );
  expect(results.every((result) => result.status === 'new')).toBe(true);
};

const credential = async (
  issuer: TestIdentity,
  audience: string,
  resource: string,
  action = 'deposit',
  options?: { prf?: string[]; exp?: number },
) =>
  createDFOSCredential({
    issuerDID: issuer.did,
    audienceDID: audience,
    att: [{ resource, action }],
    ...(options?.prf ? { prf: options.prf } : {}),
    exp: options?.exp ?? Math.floor(Date.now() / 1000) + 600,
    signer: issuer.auth.signer,
    keyId: issuer.auth.keyId,
  });

const mailbox = (subject: TestIdentity) => `mailbox:${subject.did.replace('did:dfos:', '')}`;

const target = async (subject: TestIdentity, role = 'signer') => {
  const artifact = await signCreditClaim({
    contentId: CONTENT_ID,
    did: subject.did,
    role,
    signer: subject.auth.signer,
    keyId: subject.auth.keyId,
  });
  return {
    response: artifact.jwsToken,
    bytes: base64urlDecode(artifact.jwsToken.split('.')[1]!),
  };
};

const fixture = async (store: MemoryRelayStore, role = 'signer') => {
  const requester = await identity();
  const subject = await identity();
  await seed(store, requester, subject);
  const artifact = await target(subject, role);
  const request = await buildSignRequest({
    did: requester.did,
    subject: subject.did,
    payloadTyp: 'did:dfos:credit-claim',
    payload: artifact.bytes,
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
    signer: requester.auth.signer,
    keyId: requester.auth.keyId,
  });
  return {
    requester,
    subject,
    ...artifact,
    ...request,
    credential: await credential(subject, requester.did, mailbox(subject)),
  };
};

const postJSON = (
  app: Awaited<ReturnType<typeof createRelay>>['app'],
  path: string,
  body: unknown,
) =>
  app.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

const postEmpty = (app: Awaited<ReturnType<typeof createRelay>>['app'], path: string) =>
  app.request(path, { method: 'POST' });

const nonCanonicalSignatureSpelling = (token: string): string => {
  const parts = token.split('.');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const signature = parts[2]!;
  const last = alphabet.indexOf(signature.at(-1)!);
  parts[2] = `${signature.slice(0, -1)}${alphabet[last + 1]}`;
  return parts.join('.');
};

const authFor = async (relayDID: string, subject: TestIdentity) => {
  const now = Math.floor(Date.now() / 1000);
  return createAuthToken({
    iss: subject.did,
    aud: relayDID,
    exp: now + 300,
    iat: now,
    kid: `${subject.did}#${subject.auth.keyId}`,
    sign: subject.auth.signer,
  });
};

const rawResponse = async (
  subject: TestIdentity,
  signer: TestIdentity['auth'],
  payload: Uint8Array,
  typ = 'did:dfos:credit-claim',
) => {
  const header = base64urlEncode(
    JSON.stringify({ alg: 'EdDSA', typ, kid: `${subject.did}#${signer.keyId}` }),
  );
  const body = base64urlEncode(payload);
  const signature = await signer.signer(new TextEncoder().encode(`${header}.${body}`));
  return `${header}.${body}.${base64urlEncode(signature)}`;
};

const customRequest = async (
  requester: TestIdentity,
  subjectDID: string,
  bytes: Uint8Array,
  createdAt: string,
  expiresAt: string,
  extra: Record<string, unknown> = {},
) => {
  const payload = {
    version: 1,
    type: 'sign-request',
    did: requester.did,
    subject: subjectDID,
    payloadTyp: 'did:dfos:credit-claim',
    payload: base64urlEncode(bytes),
    createdAt,
    expiresAt,
    ...extra,
  };
  const encoded = await dagCborCanonicalEncode(payload);
  return createJws({
    header: {
      alg: 'EdDSA',
      typ: 'did:dfos:sign-request',
      kid: `${requester.did}#${requester.auth.keyId}`,
      cid: encoded.cid.toString(),
    },
    payload,
    sign: requester.auth.signer,
  });
};

describe('signing mailbox', () => {
  it('defaults off, advertises false, and gates all five routes before parsing or auth', async () => {
    const relay = await createRelay({ store: new MemoryRelayStore() });
    const metadata = await relay.app.request('/.well-known/dfos-relay');
    expect(
      ((await metadata.json()) as { capabilities: { signing: boolean } }).capabilities.signing,
    ).toBe(false);
    const cid = 'bafyreidummy';
    const responses = await Promise.all([
      postJSON(relay.app, `${SIGNING}/requests`, { nope: true }),
      relay.app.request(`${SIGNING}/requests`),
      postJSON(relay.app, `${SIGNING}/requests/${cid}/response`, { nope: true }),
      relay.app.request(`${SIGNING}/requests/${cid}/response`),
      postJSON(relay.app, `${SIGNING}/requests/${cid}/decline`, null),
    ]);
    expect(responses.map((response) => response.status)).toEqual([501, 501, 501, 501, 501]);
  });

  it('runs deposit → authenticated poll → respond → requester fetch idempotently', async () => {
    const store = new MemoryRelayStore();
    const relay = await createRelay({ store, signing: true });
    const f = await fixture(store);
    const deposit = { request: f.jwsToken, credential: f.credential };
    expect((await postJSON(relay.app, `${SIGNING}/requests`, deposit)).status).toBe(201);
    expect((await postJSON(relay.app, `${SIGNING}/requests`, deposit)).status).toBe(200);

    expect((await relay.app.request(`${SIGNING}/requests`)).status).toBe(401);
    const token = await authFor(relay.did, f.subject);
    const poll = await relay.app.request(`${SIGNING}/requests`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(poll.status).toBe(200);
    expect(await poll.json()).toMatchObject({
      requests: [{ cid: f.requestCID, request: f.jwsToken, declined: false }],
      cursor: null,
    });

    const responsePath = `${SIGNING}/requests/${f.requestCID}/response`;
    expect((await postJSON(relay.app, responsePath, { response: f.response })).status).toBe(201);
    expect((await postJSON(relay.app, responsePath, { response: f.response })).status).toBe(200);
    expect(await (await relay.app.request(responsePath)).json()).toEqual({
      status: 'responded',
      response: f.response,
    });
    const emptyPoll = await relay.app.request(`${SIGNING}/requests`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(((await emptyPoll.json()) as { requests: unknown[] }).requests).toEqual([]);
  });

  it('enforces root, audience, exact resource, action, expiry, and revocation', async () => {
    const store = new MemoryRelayStore();
    const relay = await createRelay({ store, signing: true });
    const f = await fixture(store, 'credential-gates');
    const third = await identity();
    await seed(store, third);

    const rejected = [
      await credential(third, f.requester.did, mailbox(f.subject)),
      await credential(f.subject, third.did, mailbox(f.subject)),
      await credential(f.subject, f.requester.did, 'mailbox:*'),
      await credential(f.subject, f.requester.did, mailbox(third)),
      await credential(f.subject, f.requester.did, mailbox(f.subject), 'read'),
      await credential(f.subject, f.requester.did, mailbox(f.subject), 'deposit', {
        exp: Math.floor(Date.now() / 1000) - 1,
      }),
    ];
    for (const token of rejected) {
      expect(
        (
          await postJSON(relay.app, `${SIGNING}/requests`, {
            request: f.jwsToken,
            credential: token,
          })
        ).status,
      ).toBe(403);
    }

    const revokedLeaf = await credential(f.subject, f.requester.did, mailbox(f.subject));
    const leafCID = decodeJwsUnsafe(revokedLeaf)!.header.cid!;
    const leafRevocation = await signRevocation({
      issuerDID: f.subject.did,
      credentialCID: leafCID,
      signer: f.subject.auth.signer,
      keyId: f.subject.auth.keyId,
    });
    await ingestOperations([leafRevocation.jwsToken], store);
    expect(
      (
        await postJSON(relay.app, `${SIGNING}/requests`, {
          request: f.jwsToken,
          credential: revokedLeaf,
        })
      ).status,
    ).toBe(403);

    const platform = await identity();
    await seed(store, platform);
    const parent = await credential(f.subject, platform.did, mailbox(f.subject));
    const child = await credential(platform, f.requester.did, mailbox(f.subject), 'deposit', {
      prf: [parent],
    });
    const delegated = await fixture(store, 'delegated-success');
    const delegatedParent = await credential(
      delegated.subject,
      platform.did,
      mailbox(delegated.subject),
    );
    const delegatedChild = await credential(
      platform,
      delegated.requester.did,
      mailbox(delegated.subject),
      'deposit',
      { prf: [delegatedParent] },
    );
    expect(
      (
        await postJSON(relay.app, `${SIGNING}/requests`, {
          request: delegated.jwsToken,
          credential: delegatedChild,
        })
      ).status,
    ).toBe(201);

    const parentRevocation = await signRevocation({
      issuerDID: f.subject.did,
      credentialCID: decodeJwsUnsafe(parent)!.header.cid!,
      signer: f.subject.auth.signer,
      keyId: f.subject.auth.keyId,
    });
    await ingestOperations([parentRevocation.jwsToken], store);
    expect(
      (await postJSON(relay.app, `${SIGNING}/requests`, { request: f.jwsToken, credential: child }))
        .status,
    ).toBe(403);
  });

  it('accepts open-mailbox grants and ephemeral identity bundles without ingesting them', async () => {
    const store = new MemoryRelayStore();
    const relay = await createRelay({ store, signing: true });
    const f = await fixture(store, 'open-mailbox');
    const open = await credential(f.subject, '*', mailbox(f.subject));
    expect(
      (await postJSON(relay.app, `${SIGNING}/requests`, { request: f.jwsToken, credential: open }))
        .status,
    ).toBe(201);

    const foreignRequester = await identity();
    const foreignTarget = await target(f.subject, 'bundle-requester');
    const foreignRequest = await buildSignRequest({
      did: foreignRequester.did,
      subject: f.subject.did,
      payloadTyp: 'did:dfos:credit-claim',
      payload: foreignTarget.bytes,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      signer: foreignRequester.auth.signer,
      keyId: foreignRequester.auth.keyId,
    });
    const grant = await credential(f.subject, foreignRequester.did, mailbox(f.subject));
    expect(
      (
        await postJSON(relay.app, `${SIGNING}/requests`, {
          request: foreignRequest.jwsToken,
          credential: grant,
          chain: [foreignRequester.token],
        })
      ).status,
    ).toBe(201);
    expect(await store.getIdentityChain(foreignRequester.did)).toBeUndefined();
    expect(
      await store.getOperation(decodeJwsUnsafe(foreignRequester.token)!.header.cid!),
    ).toBeUndefined();
  });

  it('rejects invalid envelope windows/sizes, unknown subjects, and oversized bodies in order', async () => {
    const store = new MemoryRelayStore();
    const relay = await createRelay({ store, signing: true });
    const f = await fixture(store, 'envelope-gates');
    const now = Date.now();
    const expired = await customRequest(
      f.requester,
      f.subject.did,
      f.bytes,
      new Date(now - 60_000).toISOString().replace(/\.\d{3}Z$/, '.000Z'),
      new Date(now - 1_000).toISOString().replace(/\.\d{3}Z$/, '.000Z'),
    );
    const longWindow = await customRequest(
      f.requester,
      f.subject.did,
      f.bytes,
      new Date(now).toISOString().replace(/\.\d{3}Z$/, '.000Z'),
      new Date(now + 604_801_000).toISOString().replace(/\.\d{3}Z$/, '.000Z'),
    );
    const oversized = await customRequest(
      f.requester,
      f.subject.did,
      f.bytes,
      new Date(now).toISOString().replace(/\.\d{3}Z$/, '.000Z'),
      new Date(now + 60_000).toISOString().replace(/\.\d{3}Z$/, '.000Z'),
      { padding: 'x'.repeat(9_000) },
    );
    for (const request of [expired, longWindow, oversized]) {
      expect(
        (await postJSON(relay.app, `${SIGNING}/requests`, { request, credential: f.credential }))
          .status,
      ).toBe(400);
    }

    const unknown = await identity();
    const unknownTarget = await target(unknown, 'unknown-subject');
    const unknownRequest = await buildSignRequest({
      did: f.requester.did,
      subject: unknown.did,
      payloadTyp: 'did:dfos:credit-claim',
      payload: unknownTarget.bytes,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      signer: f.requester.auth.signer,
      keyId: f.requester.auth.keyId,
    });
    const unknownGrant = await credential(unknown, f.requester.did, mailbox(unknown));
    expect(
      (
        await postJSON(relay.app, `${SIGNING}/requests`, {
          request: unknownRequest.jwsToken,
          credential: unknownGrant,
          chain: [unknown.token],
        })
      ).status,
    ).toBe(404);

    const huge = await relay.app.request(`${SIGNING}/requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ padding: 'x'.repeat(524_288) }),
    });
    expect(huge.status).toBe(413);
  });

  it('validates responses and keeps the response slot first-write-wins across enrolled keys', async () => {
    const store = new MemoryRelayStore();
    const relay = await createRelay({ store, signing: true });
    const f = await fixture(store, 'response-gates');
    expect(
      (
        await postJSON(relay.app, `${SIGNING}/requests`, {
          request: f.jwsToken,
          credential: f.credential,
        })
      ).status,
    ).toBe(201);
    const path = `${SIGNING}/requests/${f.requestCID}/response`;
    expect(
      (await postJSON(relay.app, `${SIGNING}/requests/unknown/response`, { response: f.response }))
        .status,
    ).toBe(404);
    expect(
      (
        await postJSON(relay.app, path, {
          response: nonCanonicalSignatureSpelling(f.response),
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await relay.app.request(path, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ response: 'x'.repeat(8_700) }),
        })
      ).status,
    ).toBe(413);
    expect(
      (
        await postJSON(relay.app, path, {
          response: await rawResponse(f.subject, f.subject.auth, f.bytes, 'wrong'),
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await postJSON(relay.app, path, {
          response: await rawResponse(f.requester, f.requester.auth, f.bytes),
        })
      ).status,
    ).toBe(400);
    const changed = new Uint8Array(f.bytes);
    changed[changed.length - 2] = changed[changed.length - 2]! ^ 1;
    expect(
      (
        await postJSON(relay.app, path, {
          response: await rawResponse(f.subject, f.subject.auth, changed),
        })
      ).status,
    ).toBe(400);

    const second = key();
    const update: IdentityOperation = {
      version: 1,
      type: 'update',
      authKeys: [f.subject.auth.publicKey, second.publicKey],
      assertKeys: [],
      controllerKeys: [f.subject.controller.publicKey],
      previousOperationCID: f.subject.headCID,
      createdAt: new Date(Date.now() + 1_000).toISOString(),
    };
    const signedUpdate = await signIdentityOperation({
      operation: update,
      signer: f.subject.controller.signer,
      keyId: f.subject.controller.keyId,
      identityDID: f.subject.did,
    });
    expect((await ingestOperations([signedUpdate.jwsToken], store))[0]!.status).toBe('new');
    expect((await postJSON(relay.app, path, { response: f.response })).status).toBe(201);
    expect(
      (await postJSON(relay.app, path, { response: await rawResponse(f.subject, second, f.bytes) }))
        .status,
    ).toBe(409);
  });

  it('supports decline, isolation, expiry, and signing on a write-disabled relay', async () => {
    const store = new MemoryRelayStore();
    const f = await fixture(store, 'decline-expiry');
    const relay = await createRelay({ store, signing: true, write: false });
    expect(
      (
        await postJSON(relay.app, `${SIGNING}/requests`, {
          request: f.jwsToken,
          credential: f.credential,
        })
      ).status,
    ).toBe(201);
    const declinePath = `${SIGNING}/requests/${f.requestCID}/decline`;
    expect((await postJSON(relay.app, declinePath, { unexpected: true })).status).toBe(400);
    expect(
      (
        await relay.app.request(declinePath, {
          method: 'POST',
          body: 'x'.repeat(513),
        })
      ).status,
    ).toBe(413);
    expect((await postEmpty(relay.app, declinePath)).status).toBe(204);
    expect(
      await (await relay.app.request(`${SIGNING}/requests/${f.requestCID}/response`)).json(),
    ).toEqual({ status: 'declined' });
    const token = await authFor(relay.did, f.subject);
    const poll = await relay.app.request(`${SIGNING}/requests`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(
      ((await poll.json()) as { requests: { declined: boolean }[] }).requests[0]!.declined,
    ).toBe(true);
    const stranger = await identity();
    await seed(store, stranger);
    const strangerToken = await authFor(relay.did, stranger);
    const strangerPoll = await relay.app.request(`${SIGNING}/requests`, {
      headers: { authorization: `Bearer ${strangerToken}` },
    });
    expect(((await strangerPoll.json()) as { requests: unknown[] }).requests).toEqual([]);
    expect(
      (
        await postJSON(relay.app, `${SIGNING}/requests/${f.requestCID}/response`, {
          response: f.response,
        })
      ).status,
    ).toBe(201);
    expect((await postEmpty(relay.app, declinePath)).status).toBe(409);
    expect(
      (await postJSON(relay.app, '/proof/v1/operations', { operations: [f.requester.token] }))
        .status,
    ).toBe(501);

    const expiringTarget = await target(f.subject, 'expires');
    const expiresMs = Math.floor(Date.now() / 1000) * 1000 + 2_000;
    const expiring = await buildSignRequest({
      did: f.requester.did,
      subject: f.subject.did,
      payloadTyp: 'did:dfos:credit-claim',
      payload: expiringTarget.bytes,
      createdAt: new Date(Date.now() - 5_000).toISOString(),
      expiresAt: new Date(expiresMs).toISOString(),
      signer: f.requester.auth.signer,
      keyId: f.requester.auth.keyId,
    });
    expect(
      (
        await postJSON(relay.app, `${SIGNING}/requests`, {
          request: expiring.jwsToken,
          credential: f.credential,
        })
      ).status,
    ).toBe(201);
    await new Promise((resolve) => setTimeout(resolve, Math.max(0, expiresMs - Date.now() + 25)));
    const afterExpiry = await relay.app.request(`${SIGNING}/requests`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(((await afterExpiry.json()) as { requests: unknown[] }).requests).toEqual([]);
    expect(
      (await relay.app.request(`${SIGNING}/requests/${expiring.requestCID}/response`)).status,
    ).toBe(404);
    expect(
      (
        await postJSON(relay.app, `${SIGNING}/requests/${expiring.requestCID}/response`, {
          response: expiringTarget.response,
        })
      ).status,
    ).toBe(404);
    const internal = store as unknown as { signRequests: Map<string, unknown> };
    expect(internal.signRequests.has(expiring.requestCID)).toBe(false);
  }, 5_000);

  it('keeps signing pagination stable when the cursor row leaves the pending set', async () => {
    const store = new MemoryRelayStore();
    const now = Date.now();
    const subjectDID = 'did:dfos:pagination-subject';
    const makeRequest = (cid: string, depositedAt: string) => ({
      cid,
      request: `request-${cid}`,
      requesterDID: 'did:dfos:pagination-requester',
      subjectDID,
      payloadTyp: 'test',
      payloadBytes: new Uint8Array([1]),
      expiresAt: new Date(now + 60_000).toISOString(),
      depositedAt,
      declined: false,
    });
    await store.putSignRequest(makeRequest('a', '2026-01-01T00:00:00.000Z'), now);
    await store.putSignRequest(makeRequest('b', '2026-01-01T00:00:01.000Z'), now);
    await store.putSignRequest(makeRequest('c', '2026-01-01T00:00:02.000Z'), now);

    const first = await store.listPendingSignRequests({ subjectDID, limit: 1, now });
    const second = await store.listPendingSignRequests({
      subjectDID,
      after: first.cursor!,
      limit: 1,
      now,
    });
    expect(second.requests.map((request) => request.cid)).toEqual(['b']);
    await store.putSignResponse('b', 'response-b', now);
    const third = await store.listPendingSignRequests({
      subjectDID,
      after: second.cursor!,
      limit: 1,
      now,
    });
    expect(third.requests.map((request) => request.cid)).toEqual(['c']);

    const foreign = await store.listPendingSignRequests({
      subjectDID: 'did:dfos:other-subject',
      after: first.cursor!,
      limit: 1,
      now,
    });
    expect(foreign).toEqual({ requests: [], cursor: null });
  });
});
