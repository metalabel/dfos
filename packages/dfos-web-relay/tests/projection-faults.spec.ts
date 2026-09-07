/*

  THE PROJECTION IS A HINT PLANE, AND ITS FAILURE MODES HAVE TO STAY HONEST.

  Three ways a run can persist something it never actually established, each
  with a Go twin that already gets it right:

   - a store fault swallowed as "not public" (auth.ts / auth.go),
   - two overlapping public runs applying rows out of order (Go: TryLock),
   - an identity genesis arriving late and dirtying nothing (index_projection.go
     already sweeps on `create`).

*/

import {
  encodeEd25519Multikey,
  signContentOperation,
  signIdentityOperation,
  type ContentOperation,
  type IdentityOperation,
  type MultikeyPublicKey,
} from '@metalabel/dfos-protocol/chain';
import { createDFOSCredential } from '@metalabel/dfos-protocol/credentials';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  generateId,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import { bootstrapRelayIdentity, createRelay, MemoryRelayStore } from '../src';
import type { RelayIdentity } from '../src';

const ts = (offsetMinutes = 0) => new Date(Date.now() + offsetMinutes * 60_000).toISOString();

const makeKey = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const multibase = encodeEd25519Multikey(keypair.publicKey);
  const key: MultikeyPublicKey = { id: keyId, type: 'Multikey', publicKeyMultibase: multibase };
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  return { keyId, key, signer };
};

/** A genesis declaring one key in all three roles, proved by its own signature. */
const mintIdentity = async () => {
  const controller = makeKey();
  const operation: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [controller.key],
    assertKeys: [controller.key],
    controllerKeys: [controller.key],
    createdAt: ts(-60),
  };
  const { jwsToken, operationCID } = await signIdentityOperation({
    operation,
    signer: controller.signer,
    keyId: controller.keyId,
  });
  const encoded = await dagCborCanonicalEncode(operation);
  const { deriveChainIdentifier } = await import('@metalabel/dfos-protocol/chain');
  return {
    did: deriveChainIdentifier(encoded.cid.bytes, 'did:dfos'),
    authKey: controller,
    jwsToken,
    operationCID,
  };
};

type TestIdentity = Awaited<ReturnType<typeof mintIdentity>>;

describe('projection failure modes', () => {
  let store: MemoryRelayStore;
  let relay: Awaited<ReturnType<typeof createRelay>>;
  let relayIdentity: RelayIdentity;

  const makeRelay = async (indexProjection: 'inline' | 'external' = 'inline') => {
    store = new MemoryRelayStore();
    relayIdentity = await bootstrapRelayIdentity(store);
    relay = await createRelay({
      store,
      identity: relayIdentity,
      authority: 'localhost',
      indexProjection,
    });
  };

  beforeEach(async () => {
    await makeRelay();
  });

  const req = (path: string, init?: RequestInit) =>
    relay.app.request(`http://localhost${path}`, init);

  const postOps = (operations: string[]) =>
    req('/proof/v1/operations', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ operations }),
    });

  const ingest = async (operations: string[]) => {
    const res = await postOps(operations);
    expect(res.status).toBe(200);
    return (await res.json()) as {
      results: { status: string; chainId?: string; error?: string }[];
    };
  };

  const createIdentity = async () => {
    const identity = await mintIdentity();
    const body = await ingest([identity.jwsToken]);
    expect(body.results[0]!.status).toBe('new');
    return identity;
  };

  const createContent = async (identity: TestIdentity, document: Record<string, unknown>) => {
    const encoded = await dagCborCanonicalEncode(document);
    const operation: ContentOperation = {
      version: 1,
      type: 'create',
      did: identity.did,
      documentCID: encoded.cid.toString(),
      baseDocumentCID: null,
      createdAt: ts(1),
      note: null,
    };
    const { jwsToken, operationCID } = await signContentOperation({
      operation,
      signer: identity.authKey.signer,
      kid: `${identity.did}#${identity.authKey.keyId}`,
    });
    const body = await ingest([jwsToken]);
    expect(body.results[0]!.status).toBe('new');
    return { contentId: body.results[0]!.chainId as string, operationCID };
  };

  const mintGrant = (args: {
    issuer: TestIdentity;
    audienceDID: string;
    resource: string;
    prf?: string[];
  }) => {
    const now = Math.floor(Date.now() / 1000);
    return createDFOSCredential({
      issuerDID: args.issuer.did,
      audienceDID: args.audienceDID,
      att: [{ resource: args.resource, action: 'read' }],
      ...(args.prf ? { prf: args.prf } : {}),
      exp: now + 3600,
      signer: args.issuer.authKey.signer,
      keyId: args.issuer.authKey.keyId,
      iat: now,
    });
  };

  const contentRow = async (contentId: string) => {
    const res = await req('/index/v0/content?limit=1000');
    const body = (await res.json()) as { content: { contentId: string; publicRead: boolean }[] };
    return body.content.find((row) => row.contentId === contentId);
  };

  // -------------------------------------------------------------------------

  // A revocation lookup that FAILED is not a credential that does not grant. The
  // projection persists the answer and advances its cursor, so swallowing the
  // fault makes an outage permanent: the worker reports itself caught up and
  // nothing ever recomputes the row.
  it('aborts the run when the revocation store faults, and repairs it after recovery', async () => {
    await makeRelay('external');
    const creator = await createIdentity();
    const content = await createContent(creator, { $schema: 'x', title: 'hello' });
    await ingest([
      await mintGrant({
        issuer: creator,
        audienceDID: '*',
        resource: `chain:${content.contentId}`,
      }),
    ]);

    const healthy = store.isCredentialRevoked.bind(store);
    let faulting = true;
    store.isCredentialRevoked = async (issuerDID: string, credentialCID: string) => {
      if (faulting) throw new Error('injected revocation-store failure');
      return healthy(issuerDID, credentialCID);
    };

    const failed = await relay.projectIndex();
    expect(failed.caughtUp).toBe(false);
    expect(await contentRow(content.contentId)).toBeUndefined();
    expect((await store.getIndexCursor())?.logCursor ?? null).toBeNull();

    faulting = false;
    let recovered = await relay.projectIndex();
    for (let run = 0; run < 10 && !recovered.caughtUp; run++)
      recovered = await relay.projectIndex();
    expect(recovered.caughtUp).toBe(true);
    expect((await contentRow(content.contentId))?.publicRead).toBe(true);
  });

  // The public entry point is the ONLY projection an `external` deployment runs,
  // so two timer calls landing together must not read the same cursor and apply
  // their rows in either order. Go guards the same overlap with a TryLock.
  it('serializes two overlapping public projection runs', async () => {
    await makeRelay('external');
    const creator = await createIdentity();
    await createContent(creator, { $schema: 'x', title: 'hello' });

    const events: string[] = [];
    const readCursor = store.getIndexCursor.bind(store);
    const writeCursor = store.setIndexCursor.bind(store);
    store.getIndexCursor = async () => {
      events.push('start');
      await new Promise((resolve) => setTimeout(resolve, 0));
      return readCursor();
    };
    store.setIndexCursor = async (cursor) => {
      events.push('end');
      return writeCursor(cursor);
    };

    await Promise.all([relay.projectIndex(), relay.projectIndex()]);

    expect(events).toEqual(['start', 'end', 'start', 'end']);
  });

  // A genesis is not always the first thing a relay learns about an identity. A
  // public leaf is admitted on its own signature, so a grant whose INTERMEDIATE
  // issuer is unsynced projects private — and without a sweep on `create` it
  // stays private after that issuer finally arrives.
  it('re-folds standing grants when a missing intermediate genesis arrives', async () => {
    const creator = await createIdentity();
    const middle = await mintIdentity(); // deliberately NOT ingested
    const leaf = await createIdentity();
    const content = await createContent(creator, { $schema: 'x', title: 'hello' });

    const resource = `chain:${content.contentId}`;
    const rootGrant = await mintGrant({ issuer: creator, audienceDID: middle.did, resource });
    const midGrant = await mintGrant({
      issuer: middle,
      audienceDID: leaf.did,
      resource,
      prf: [rootGrant],
    });
    const publicGrant = await mintGrant({
      issuer: leaf,
      audienceDID: '*',
      resource,
      prf: [midGrant],
    });
    const admitted = await ingest([publicGrant]);
    expect(admitted.results[0]!.status).toBe('new');

    // The delegation cannot be walked: the middle issuer's chain is not here.
    expect((await contentRow(content.contentId))?.publicRead).toBe(false);

    await ingest([middle.jwsToken]);
    expect((await contentRow(content.contentId))?.publicRead).toBe(true);
  });
});
