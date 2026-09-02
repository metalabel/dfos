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
  decodeJwsUnsafe,
  generateId,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { describe, expect, it, vi } from 'vitest';
import { ingestOperations, NONCURRENT_SIGNING_KEY_ERROR } from '../src/ingest';
import { createRelay } from '../src/relay';
import { sequenceOps } from '../src/sequencer';
import { MemoryRelayStore } from '../src/store';
import type { PeerClient } from '../src/types';
import { chainKeyProof } from './key-proofs';

const makeKey = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const key: MultikeyPublicKey = {
    id: keyId,
    type: 'Multikey',
    publicKeyMultibase: encodeEd25519Multikey(keypair.publicKey),
  };
  const signer = async (message: Uint8Array) => signPayloadEd25519(message, keypair.privateKey);
  return { keypair, keyId, key, signer };
};

const timestamp = (offsetMinutes = 0) =>
  new Date(Date.now() + offsetMinutes * 60_000).toISOString();

/**
 * A genesis, which declares exactly ONE key in all three roles and proves it by
 * signing itself with it. `oldAuth` is that key under the name the rotation
 * tests read it by — after `rotateIdentity` it is the key that is no longer
 * current, in every role at once.
 */
const createIdentity = async () => {
  const controller = makeKey();
  const oldAuth = controller;
  const operation: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [controller.key],
    assertKeys: [controller.key],
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

/**
 * Rotate the genesis key out completely and a fresh one in, carrying the key
 * proof that admits the new key to all three roles. The OLD key signs it: signer
 * validity reads the prior DECLARED controller set, so a key can author the very
 * operation that removes it.
 */
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
    assertKeys: [currentAuth.key],
    controllerKeys: [currentAuth.key],
    createdAt: timestamp(1),
    keyProofs: [
      await chainKeyProof({
        privateKey: currentAuth.keypair.privateKey,
        did: identity.did,
        prevCID: identity.operationCID,
      }),
    ],
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

/*

  DEPENDENCY CLASSIFICATION IS A TYPED FACT, NOT A SPELLING.

  The relay keeps a rejected op pending when the rejection is a missing
  dependency and DELETES the raw op otherwise. That branch used to be decided by
  substring-matching the human-readable error, and much of that text quotes what
  the submitter wrote — a credential's audience is echoed verbatim into
  "credential audience ${aud} does not match operation signer ${did}". Spelling
  one of the watched phrases inside that field made a PERMANENT rejection
  classify as retryable, so the op was never deleted and was re-verified on every
  sequencer cycle. The Go twin carries the same pair
  (dfos-web-relay-go/ingest_typed_dependency_test.go).

*/

/** One of the phrases the deleted substring list matched. */
const POISON_PHRASE = 'unknown identity: ';

/**
 * A delegated content update whose authorization credential names an audience
 * the submitter chose. The credential verifies; it simply does not authorize
 * this signer, so the rejection is permanent — and the audience reaches the
 * error text verbatim, which is where the old classifier read it.
 */
const ingestPoisonedAudience = async (store: MemoryRelayStore, audienceDID: string) => {
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
    audienceDID,
    att: [{ resource: `chain:${contentID}`, action: 'write' }],
    exp: now + 3600,
    signer: creator.oldAuth.signer,
    keyId: creator.oldAuth.keyId,
    iat: now,
  });

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
  return {
    jwsToken: delegated.jwsToken,
    result: (await ingestOperations([delegated.jwsToken], store))[0]!,
  };
};

describe('typed dependency classification', () => {
  it('does not let submitter-chosen text buy retryability', async () => {
    const store = new MemoryRelayStore();
    const { result } = await ingestPoisonedAudience(
      store,
      `${POISON_PHRASE}chosen-by-the-submitter`,
    );
    expect(result.status).toBe('rejected');
    expect(result.dependencyMissing).not.toBe(true);
  });

  it('durably deletes the raw op a poisoned rejection produced', async () => {
    const store = new MemoryRelayStore();
    const { jwsToken } = await ingestPoisonedAudience(
      store,
      `${POISON_PHRASE}chosen-by-the-submitter`,
    );
    const decoded = decodeJwsUnsafe(jwsToken)!;
    const cid = (await dagCborCanonicalEncode(decoded.payload)).cid.toString();
    await store.putRawOp(cid, jwsToken);

    const { result } = await sequenceOps(store);
    expect(result.rejected).toBe(1);
    expect(await store.countUnsequenced()).toBe(0);
  });

  it('keeps a genuine dependency miss retryable on every op kind', async () => {
    // A well-formed identity no store below has ever seen: every op it signs
    // verifies once its chain arrives.
    const stranger = await createIdentity();
    const strangerKid = `${stranger.did}#${stranger.oldAuth.keyId}`;
    const expectRetryable = (result: Awaited<ReturnType<typeof ingestOperations>>[number]) => {
      expect(result.status).toBe('rejected');
      expect(result.dependencyMissing).toBe(true);
    };

    const content = await signContent(stranger.did, stranger.oldAuth, 'orphan', 1);
    expectRetryable((await ingestOperations([content.jwsToken], new MemoryRelayStore()))[0]!);

    const artifact = await signArtifact({
      payload: {
        version: 1,
        type: 'artifact',
        did: stranger.did,
        content: { $schema: 'test/v1', title: 'orphan' },
        createdAt: timestamp(1),
      } as ArtifactPayload,
      signer: stranger.oldAuth.signer,
      kid: strangerKid,
    });
    expectRetryable((await ingestOperations([artifact.jwsToken], new MemoryRelayStore()))[0]!);

    const countersign = await signCountersignature({
      payload: {
        version: 1,
        type: 'countersign',
        did: stranger.did,
        targetCID: stranger.operationCID,
        relation: 'witness',
        createdAt: timestamp(1),
      } as CountersignPayload,
      signer: stranger.oldAuth.signer,
      kid: strangerKid,
    });
    expectRetryable((await ingestOperations([countersign.jwsToken], new MemoryRelayStore()))[0]!);

    const revocation = await signRevocation({
      issuerDID: stranger.did,
      credentialCID: stranger.operationCID,
      signer: stranger.oldAuth.signer,
      keyId: stranger.oldAuth.keyId,
    });
    expectRetryable((await ingestOperations([revocation.jwsToken], new MemoryRelayStore()))[0]!);

    const now = Math.floor(Date.now() / 1000);
    const publicCredential = await createDFOSCredential({
      issuerDID: stranger.did,
      audienceDID: '*',
      att: [{ resource: 'chain:*', action: 'read' }],
      exp: now + 3600,
      signer: stranger.oldAuth.signer,
      keyId: stranger.oldAuth.keyId,
      iat: now,
    });
    expectRetryable((await ingestOperations([publicCredential], new MemoryRelayStore()))[0]!);
  });

  it('keeps a delegated op retryable when only its credential issuer is unsynced', async () => {
    // The credential path resolves the ISSUER through the caller's resolver, so
    // this miss happens a layer below the op's own signer and has to cross the
    // authorization re-wrap in the protocol to be classified correctly.
    const store = new MemoryRelayStore();
    const creator = await createIdentity();
    const delegate = await createIdentity();
    const middle = await createIdentity(); // deliberately NOT ingested
    const genesis = await signContent(creator.did, creator.oldAuth, 'genesis', 1);
    const seeded = await ingestOperations(
      [creator.jwsToken, delegate.jwsToken, genesis.jwsToken],
      store,
    );
    const contentID = seeded[2]!.chainId!;

    const now = Math.floor(Date.now() / 1000);
    const parent = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: middle.did,
      att: [{ resource: `chain:${contentID}`, action: 'write' }],
      exp: now + 3600,
      signer: creator.oldAuth.signer,
      keyId: creator.oldAuth.keyId,
      iat: now,
    });
    const leaf = await createDFOSCredential({
      issuerDID: middle.did,
      audienceDID: delegate.did,
      att: [{ resource: `chain:${contentID}`, action: 'write' }],
      prf: [parent],
      exp: now + 3600,
      signer: middle.oldAuth.signer,
      keyId: middle.oldAuth.keyId,
      iat: now,
    });

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
        authorization: leaf,
      },
      signer: delegate.oldAuth.signer,
      kid: `${delegate.did}#${delegate.oldAuth.keyId}`,
    });
    const result = (await ingestOperations([delegated.jwsToken], store))[0]!;
    expect(result.status).toBe('rejected');
    expect(result.dependencyMissing).toBe(true);
  });
});
