import {
  encodeEd25519Multikey,
  signArtifact,
  signContentOperation,
  signCountersignature,
  signIdentityOperation,
  signRevocation,
  type ArtifactPayload,
  type ContentOperation,
  type CountersignPayload,
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
import { describe, expect, it, vi } from 'vitest';
import { ingestOperations, NONCURRENT_SIGNING_KEY_ERROR } from '../src/ingest';
import { createRelay } from '../src/relay';
import { MemoryRelayStore } from '../src/store';
import type { PeerClient } from '../src/types';

const makeKey = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const key: MultikeyPublicKey = {
    id: keyId,
    type: 'Multikey',
    publicKeyMultibase: encodeEd25519Multikey(keypair.publicKey),
  };
  const signer = async (message: Uint8Array) => signPayloadEd25519(message, keypair.privateKey);
  return { keyId, key, signer };
};

const timestamp = (offsetMinutes = 0) =>
  new Date(Date.now() + offsetMinutes * 60_000).toISOString();

const createIdentity = async () => {
  const controller = makeKey();
  const oldAuth = makeKey();
  const operation: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [oldAuth.key],
    assertKeys: [],
    controllerKeys: [controller.key],
    createdAt: timestamp(),
  };
  const genesis = await signIdentityOperation({
    operation,
    signer: controller.signer,
    keyId: controller.keyId,
  });
  const encoded = await dagCborCanonicalEncode(operation);
  const { deriveChainIdentifier } = await import('@metalabel/dfos-protocol/chain');
  const did = deriveChainIdentifier(encoded.cid.bytes, 'did:dfos');
  return { did, controller, oldAuth, ...genesis };
};

const rotateIdentity = async (
  identity: Awaited<ReturnType<typeof createIdentity>>,
  store: MemoryRelayStore,
) => {
  const currentAuth = makeKey();
  const operation: IdentityOperation = {
    version: 1,
    type: 'update',
    previousOperationCID: identity.operationCID,
    authKeys: [currentAuth.key],
    assertKeys: [],
    controllerKeys: [identity.controller.key],
    createdAt: timestamp(1),
  };
  const rotation = await signIdentityOperation({
    operation,
    signer: identity.controller.signer,
    keyId: identity.controller.keyId,
    identityDID: identity.did,
  });
  expect((await ingestOperations([rotation.jwsToken], store))[0]!.status).toBe('new');
  return { currentAuth, ...rotation };
};

const signContent = async (
  did: string,
  key: ReturnType<typeof makeKey>,
  title: string,
  offsetMinutes: number,
) => {
  const document = await dagCborCanonicalEncode({ type: 'post', title });
  const operation: ContentOperation = {
    version: 1,
    type: 'create',
    did,
    documentCID: document.cid.toString(),
    baseDocumentCID: null,
    createdAt: timestamp(offsetMinutes),
    note: null,
  };
  return signContentOperation({
    operation,
    signer: key.signer,
    kid: `${did}#${key.keyId}`,
  });
};

const expectPermanentNoncurrentRejection = (
  result: Awaited<ReturnType<typeof ingestOperations>>[number],
) => {
  expect(result.status).toBe('rejected');
  expect(result.error).toBe(NONCURRENT_SIGNING_KEY_ERROR);
  expect(result.dependencyMissing).not.toBe(true);
};

describe('current-state first admission', () => {
  it('rejects fresh old-key artifacts and accepts current-key artifacts', async () => {
    const store = new MemoryRelayStore();
    const identity = await createIdentity();
    await ingestOperations([identity.jwsToken], store);
    const { currentAuth } = await rotateIdentity(identity, store);

    const payload = (title: string, offset: number): ArtifactPayload => ({
      version: 1,
      type: 'artifact',
      did: identity.did,
      content: { $schema: 'test/v1', title },
      createdAt: timestamp(offset),
    });
    const oldArtifact = await signArtifact({
      payload: payload('old', 2),
      signer: identity.oldAuth.signer,
      kid: `${identity.did}#${identity.oldAuth.keyId}`,
    });
    expectPermanentNoncurrentRejection((await ingestOperations([oldArtifact.jwsToken], store))[0]!);

    const currentArtifact = await signArtifact({
      payload: payload('current', 3),
      signer: currentAuth.signer,
      kid: `${identity.did}#${currentAuth.keyId}`,
    });
    expect((await ingestOperations([currentArtifact.jwsToken], store))[0]!.status).toBe('new');
  });

  it('rejects fresh old-key countersignatures and accepts current-key countersignatures', async () => {
    const store = new MemoryRelayStore();
    const author = await createIdentity();
    const witness = await createIdentity();
    await ingestOperations([author.jwsToken, witness.jwsToken], store);
    const { currentAuth } = await rotateIdentity(witness, store);

    const payload = (relation: string, offset: number): CountersignPayload => ({
      version: 1,
      type: 'countersign',
      did: witness.did,
      targetCID: author.operationCID,
      relation,
      createdAt: timestamp(offset),
    });
    const oldCountersign = await signCountersignature({
      payload: payload('old', 2),
      signer: witness.oldAuth.signer,
      kid: `${witness.did}#${witness.oldAuth.keyId}`,
    });
    expectPermanentNoncurrentRejection(
      (await ingestOperations([oldCountersign.jwsToken], store))[0]!,
    );

    const currentCountersign = await signCountersignature({
      payload: payload('current', 3),
      signer: currentAuth.signer,
      kid: `${witness.did}#${currentAuth.keyId}`,
    });
    expect((await ingestOperations([currentCountersign.jwsToken], store))[0]!.status).toBe('new');
  });

  it('rejects fresh old-key content operations and accepts current-key content operations', async () => {
    const store = new MemoryRelayStore();
    const identity = await createIdentity();
    await ingestOperations([identity.jwsToken], store);
    const { currentAuth } = await rotateIdentity(identity, store);

    const oldContent = await signContent(identity.did, identity.oldAuth, 'old', 2);
    expectPermanentNoncurrentRejection((await ingestOperations([oldContent.jwsToken], store))[0]!);

    const currentContent = await signContent(identity.did, currentAuth, 'current', 3);
    expect((await ingestOperations([currentContent.jwsToken], store))[0]!.status).toBe('new');
  });

  it('resolves the fresh operation signer currently but its credential issuer historically', async () => {
    const store = new MemoryRelayStore();
    const creator = await createIdentity();
    const delegate = await createIdentity();
    const genesis = await signContent(creator.did, creator.oldAuth, 'genesis', 1);
    const seeded = await ingestOperations(
      [creator.jwsToken, delegate.jwsToken, genesis.jwsToken],
      store,
    );
    const contentID = seeded[2]!.chainId!;

    const now = Math.floor(Date.now() / 1000);
    const credential = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: delegate.did,
      att: [{ resource: `chain:${contentID}`, action: 'write' }],
      exp: now + 3600,
      signer: creator.oldAuth.signer,
      keyId: creator.oldAuth.keyId,
      iat: now,
    });
    await rotateIdentity(creator, store);

    const document = await dagCborCanonicalEncode({ type: 'post', title: 'delegated' });
    const delegated = await signContentOperation({
      operation: {
        version: 1,
        type: 'update',
        did: delegate.did,
        previousOperationCID: genesis.operationCID,
        documentCID: document.cid.toString(),
        baseDocumentCID: null,
        createdAt: timestamp(3),
        note: null,
        authorization: credential,
      },
      signer: delegate.oldAuth.signer,
      kid: `${delegate.did}#${delegate.oldAuth.keyId}`,
    });
    expect((await ingestOperations([delegated.jwsToken], store))[0]!.status).toBe('new');

    await rotateIdentity(delegate, store);
    const staleDocument = await dagCborCanonicalEncode({ type: 'post', title: 'stale signer' });
    const staleSigner = await signContentOperation({
      operation: {
        version: 1,
        type: 'update',
        did: delegate.did,
        previousOperationCID: delegated.operationCID,
        documentCID: staleDocument.cid.toString(),
        baseDocumentCID: null,
        createdAt: timestamp(4),
        note: null,
        authorization: credential,
      },
      signer: delegate.oldAuth.signer,
      kid: `${delegate.did}#${delegate.oldAuth.keyId}`,
    });
    expectPermanentNoncurrentRejection((await ingestOperations([staleSigner.jwsToken], store))[0]!);
  });

  it('keeps committed old-key content verifiable, served, and peer-syncable after rotation', async () => {
    const origin = new MemoryRelayStore();
    const identity = await createIdentity();
    const committed = await signContent(identity.did, identity.oldAuth, 'committed', 1);
    const committedResults = await ingestOperations(
      [identity.jwsToken, committed.jwsToken],
      origin,
    );
    const contentID = committedResults[1]!.chainId!;
    const rotation = await rotateIdentity(identity, origin);

    const replayed = await origin.getContentStateAtCID(contentID, committed.operationCID);
    expect(replayed?.state.headCID).toBe(committed.operationCID);
    const relay = await createRelay({ store: origin });
    expect((await relay.app.request(`http://localhost/proof/v1/content/${contentID}`)).status).toBe(
      200,
    );

    const peer = new MemoryRelayStore();
    const synced = await ingestOperations(
      [identity.jwsToken, rotation.jwsToken, committed.jwsToken],
      peer,
      { admissionMode: 'historical' },
    );
    expect(synced.map((result) => result.status)).toEqual(['new', 'new', 'new']);
    expect(await peer.getContentChain(contentID)).toBeDefined();
  });

  it('keeps direct revocation and credential admission historical after rotation', async () => {
    const store = new MemoryRelayStore();
    const identity = await createIdentity();
    await ingestOperations([identity.jwsToken], store);
    await rotateIdentity(identity, store);

    const now = Math.floor(Date.now() / 1000);
    const credential = await createDFOSCredential({
      issuerDID: identity.did,
      audienceDID: '*',
      att: [{ resource: 'chain:*', action: 'read' }],
      exp: now + 3600,
      signer: identity.oldAuth.signer,
      keyId: identity.oldAuth.keyId,
      iat: now,
    });
    const credentialResult = (await ingestOperations([credential], store))[0]!;
    expect(credentialResult.status).toBe('new');

    const revocation = await signRevocation({
      issuerDID: identity.did,
      credentialCID: credentialResult.cid,
      signer: identity.oldAuth.signer,
      keyId: identity.oldAuth.keyId,
    });
    expect((await ingestOperations([revocation.jwsToken], store))[0]!.status).toBe('new');
  });
});

describe('pending-op admission provenance', () => {
  it('keeps a direct pending op current-state-only when its identity arrives from a peer', async () => {
    const source = new MemoryRelayStore();
    const identity = await createIdentity();
    await ingestOperations([identity.jwsToken], source);
    const rotation = await rotateIdentity(identity, source);
    const staleArtifact = await signArtifact({
      payload: {
        version: 1,
        type: 'artifact',
        did: identity.did,
        content: { $schema: 'test/v1', title: 'direct pending' },
        createdAt: timestamp(2),
      },
      signer: identity.oldAuth.signer,
      kid: `${identity.did}#${identity.oldAuth.keyId}`,
    });

    const peerOps = [identity.jwsToken, rotation.jwsToken];
    const peerClient: PeerClient = {
      async getIdentityLog() {
        return null;
      },
      async getContentLog() {
        return null;
      },
      async getOperationLog() {
        return {
          entries: peerOps.map((jwsToken) => ({ cid: '', jwsToken })),
          next: null,
        };
      },
      async submitOperations() {},
    };
    const target = new MemoryRelayStore();
    const relay = await createRelay({
      store: target,
      peers: [{ url: 'http://peer' }],
      peerClient,
    });
    const directResponse = await relay.app.request('http://localhost/proof/v1/operations', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ operations: [staleArtifact.jwsToken] }),
    });
    const directBody = (await directResponse.json()) as {
      results: Array<{ dependencyMissing?: boolean }>;
    };
    expect(directBody.results[0]!.dependencyMissing).toBe(true);
    expect(await target.countUnsequenced()).toBe(1);

    const warning = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await relay.syncFromPeers();

    expect(await target.getOperation(staleArtifact.artifactCID)).toBeUndefined();
    expect(await target.countUnsequenced()).toBe(0);
    expect(warning.mock.calls.flat().join(' ')).toContain(NONCURRENT_SIGNING_KEY_ERROR);
    warning.mockRestore();
  });

  it('keeps a peer pending op historical when a direct submission triggers sequencing', async () => {
    const source = new MemoryRelayStore();
    const identity = await createIdentity();
    await ingestOperations([identity.jwsToken], source);
    const committedArtifact = await signArtifact({
      payload: {
        version: 1,
        type: 'artifact',
        did: identity.did,
        content: { $schema: 'test/v1', title: 'peer committed' },
        createdAt: timestamp(1),
      },
      signer: identity.oldAuth.signer,
      kid: `${identity.did}#${identity.oldAuth.keyId}`,
    });
    expect((await ingestOperations([committedArtifact.jwsToken], source))[0]!.status).toBe('new');
    const rotation = await rotateIdentity(identity, source);

    let peerOps = [committedArtifact.jwsToken];
    const peerClient: PeerClient = {
      async getIdentityLog() {
        return null;
      },
      async getContentLog() {
        return null;
      },
      async getOperationLog() {
        return {
          entries: peerOps.map((jwsToken) => ({ cid: '', jwsToken })),
          next: null,
        };
      },
      async submitOperations() {},
    };
    const target = new MemoryRelayStore();
    const relay = await createRelay({
      store: target,
      peers: [{ url: 'http://peer' }],
      peerClient,
    });
    await relay.syncFromPeers();
    expect(await target.countUnsequenced()).toBe(1);

    peerOps = [];
    const directResponse = await relay.app.request('http://localhost/proof/v1/operations', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ operations: [identity.jwsToken, rotation.jwsToken] }),
    });
    expect(directResponse.status).toBe(200);

    expect(await target.getOperation(committedArtifact.artifactCID)).toBeDefined();
    expect(await target.countUnsequenced()).toBe(0);
  });
});
