import {
  encodeEd25519Multikey,
  signContentOperation,
  signCountersignature,
  signIdentityOperation,
  type ContentOperation,
  type CountersignPayload,
  type IdentityOperation,
  type MultikeyPublicKey,
  type ServiceEntry,
} from '@metalabel/dfos-protocol/chain';
import { createAuthToken, createDFOSCredential } from '@metalabel/dfos-protocol/credentials';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  decodeJwsUnsafe,
  generateId,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import { bootstrapRelayIdentity, createRelay, MemoryRelayStore } from '../src';
import type { RelayIdentity } from '../src';

const PROFILE_SCHEMA = 'https://schemas.dfos.com/profile/v1';
const ARTIFACT_ANCHOR = `bafyrei${'a'.repeat(52)}`;

const makeKey = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const multibase = encodeEd25519Multikey(keypair.publicKey);
  const key: MultikeyPublicKey = { id: keyId, type: 'Multikey', publicKeyMultibase: multibase };
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  return { keypair, keyId, key, signer };
};

const ts = (offset = 0) =>
  new Date(Date.now() + offset * 60_000).toISOString().replace(/\d{4}Z$/, (m) => m);

const createIdentityOp = async (services?: ServiceEntry[]) => {
  const controller = makeKey();
  const authKey = makeKey();
  const createOp: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [authKey.key],
    assertKeys: [],
    controllerKeys: [controller.key],
    ...(services ? { services } : {}),
    createdAt: ts(),
  };
  const { jwsToken, operationCID } = await signIdentityOperation({
    operation: createOp,
    signer: controller.signer,
    keyId: controller.keyId,
  });
  const encoded = await dagCborCanonicalEncode(createOp);
  const { deriveChainIdentifier } = await import('@metalabel/dfos-protocol/chain');
  const did = deriveChainIdentifier(encoded.cid.bytes, 'did:dfos');
  return { did, controller, authKey, jwsToken, operationCID };
};

type TestIdentity = Awaited<ReturnType<typeof createIdentityOp>>;

describe('index v0', () => {
  let store: MemoryRelayStore;
  let relay: Awaited<ReturnType<typeof createRelay>>;
  let relayIdentity: RelayIdentity;
  let relayDID: string;

  beforeEach(async () => {
    store = new MemoryRelayStore();
    relayIdentity = await bootstrapRelayIdentity(store);
    relayDID = relayIdentity.did;
    relay = await createRelay({ store, identity: relayIdentity });
  });

  const req = (path: string, init?: RequestInit) =>
    relay.app.request(`http://localhost${path}`, init);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const json = async (res: Response): Promise<any> => res.json();

  const postOps = (operations: string[]) =>
    req('/proof/v1/operations', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ operations }),
    });

  const createIdentity = async (services?: ServiceEntry[]) => {
    const identity = await createIdentityOp(services);
    const res = await postOps([identity.jwsToken]);
    expect(res.status).toBe(200);
    return identity;
  };

  const updateServices = async (identity: TestIdentity, services: ServiceEntry[]) => {
    const updateOp: IdentityOperation = {
      version: 1,
      type: 'update',
      previousOperationCID: identity.operationCID,
      authKeys: [identity.authKey.key],
      assertKeys: [],
      controllerKeys: [identity.controller.key],
      services,
      createdAt: ts(2),
    };
    const { jwsToken, operationCID } = await signIdentityOperation({
      operation: updateOp,
      signer: identity.controller.signer,
      keyId: identity.controller.keyId,
      identityDID: identity.did,
    });
    const res = await postOps([jwsToken]);
    expect(res.status).toBe(200);
    return { jwsToken, operationCID };
  };

  const createContent = async (
    identity: TestIdentity,
    document: Record<string, unknown>,
    offset = 1,
  ) => {
    const encoded = await dagCborCanonicalEncode(document);
    const documentCID = encoded.cid.toString();
    const op: ContentOperation = {
      version: 1,
      type: 'create',
      did: identity.did,
      documentCID,
      baseDocumentCID: null,
      createdAt: ts(offset),
      note: null,
    };
    const { jwsToken, operationCID } = await signContentOperation({
      operation: op,
      signer: identity.authKey.signer,
      kid: `${identity.did}#${identity.authKey.keyId}`,
    });
    const res = await postOps([jwsToken]);
    expect(res.status).toBe(200);
    const body = await json(res);
    return {
      contentId: body.results[0].chainId as string,
      jwsToken,
      operationCID,
      documentCID,
      document,
    };
  };

  const authToken = async (identity: TestIdentity) => {
    const now = Math.floor(Date.now() / 1000);
    return createAuthToken({
      iss: identity.did,
      aud: relayDID,
      exp: now + 300,
      kid: `${identity.did}#${identity.authKey.keyId}`,
      iat: now,
      sign: identity.authKey.signer,
    });
  };

  const uploadBlob = async (
    identity: TestIdentity,
    contentId: string,
    operationCID: string,
    document: Record<string, unknown>,
  ) => {
    const token = await authToken(identity);
    const res = await req(`/content/${contentId}/blob/${operationCID}`, {
      method: 'PUT',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/octet-stream',
      },
      body: new TextEncoder().encode(JSON.stringify(document)),
    });
    expect(res.status).toBe(200);
  };

  const addPublicReadGrant = async (identity: TestIdentity, contentId: string) => {
    const now = Math.floor(Date.now() / 1000);
    const credential = await createDFOSCredential({
      issuerDID: identity.did,
      audienceDID: '*',
      att: [{ resource: `chain:${contentId}`, action: 'read' }],
      exp: now + 3600,
      signer: identity.authKey.signer,
      keyId: identity.authKey.keyId,
      iat: now,
    });
    const res = await postOps([credential]);
    expect(res.status).toBe(200);
  };

  it('advertises the index capability by default and can disable it', async () => {
    const body = await json(await req('/.well-known/dfos-relay'));
    expect(body.capabilities.index).toBe(true);

    const disabled = await createRelay({ store, identity: relayIdentity, index: false });
    const disabledWellKnown = await disabled.app.request('http://localhost/.well-known/dfos-relay');
    const disabledBody = (await disabledWellKnown.json()) as {
      capabilities: { index: boolean };
    };
    expect(disabledBody.capabilities.index).toBe(false);
    for (const path of [
      '/index/v0/identities',
      '/index/v0/content',
      `/index/v0/countersignatures?witness=${relayDID}`,
    ]) {
      const res = await disabled.app.request(`http://localhost${path}`);
      expect(res.status).toBe(501);
    }
  });

  it('enumerates identities with profile projection, filters, pagination, and deleted rows', async () => {
    const subject = await createIdentity();
    const unprofiled = await createIdentity();
    const profileDoc = { $schema: PROFILE_SCHEMA, name: 'asha' };
    const profileContent = await createContent(subject, profileDoc);
    await uploadBlob(subject, profileContent.contentId, profileContent.operationCID, profileDoc);
    await addPublicReadGrant(subject, profileContent.contentId);
    await updateServices(subject, [
      {
        id: 'profile',
        type: 'ContentAnchor',
        label: 'profile',
        anchor: profileContent.contentId,
      },
    ]);

    const deleteOp: IdentityOperation = {
      version: 1,
      type: 'delete',
      previousOperationCID: unprofiled.operationCID,
      createdAt: ts(3),
    };
    const { jwsToken: deleteToken } = await signIdentityOperation({
      operation: deleteOp,
      signer: unprofiled.controller.signer,
      keyId: unprofiled.controller.keyId,
      identityDID: unprofiled.did,
    });
    await postOps([deleteToken]);

    const body = await json(await req('/index/v0/identities'));
    const dids = body.identities.map((row: { did: string }) => row.did);
    expect(dids).toEqual([...dids].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)));

    const subjectRow = body.identities.find((row: { did: string }) => row.did === subject.did);
    expect(subjectRow).toMatchObject({
      did: subject.did,
      headCID: expect.any(String),
      opCount: 2,
      isDeleted: false,
      profile: {
        anchor: profileContent.contentId,
        publicRead: true,
        docSchema: PROFILE_SCHEMA,
        name: 'asha',
      },
    });
    expect(subjectRow.genesisAt).toEqual(expect.any(String));
    expect(subjectRow.headAt).toEqual(expect.any(String));

    const deletedRow = body.identities.find((row: { did: string }) => row.did === unprofiled.did);
    expect(deletedRow.isDeleted).toBe(true);

    const publicProfiles = await json(await req('/index/v0/identities?hasPublicProfile=true'));
    expect(publicProfiles.identities.map((row: { did: string }) => row.did)).toContain(subject.did);

    const nonPublicProfiles = await json(await req('/index/v0/identities?hasPublicProfile=false'));
    expect(nonPublicProfiles.identities.map((row: { did: string }) => row.did)).not.toContain(
      subject.did,
    );
    expect(nonPublicProfiles.identities.map((row: { did: string }) => row.did)).toContain(
      unprofiled.did,
    );

    const page1 = await json(await req('/index/v0/identities?limit=2'));
    expect(page1.identities).toHaveLength(2);
    expect(page1.next).toBe(page1.identities[1].did);
    const page2 = await json(
      await req(`/index/v0/identities?after=${encodeURIComponent(page1.next)}&limit=100`),
    );
    expect(page2.identities.map((row: { did: string }) => row.did)).not.toContain(
      page1.identities[0].did,
    );
  });

  it('applies profile projection circuit breakers', async () => {
    const nonProfile = await createIdentity();
    const nonProfileContent = await createContent(nonProfile, {
      $schema: 'example/post',
      name: 'no',
    });
    await uploadBlob(
      nonProfile,
      nonProfileContent.contentId,
      nonProfileContent.operationCID,
      nonProfileContent.document,
    );
    await updateServices(nonProfile, [
      {
        id: 'profile',
        type: 'ContentAnchor',
        label: 'profile',
        anchor: nonProfileContent.contentId,
      },
    ]);

    const missingBlob = await createIdentity();
    const missingBlobContent = await createContent(missingBlob, {
      $schema: PROFILE_SCHEMA,
      name: 'held',
    });
    await updateServices(missingBlob, [
      {
        id: 'profile',
        type: 'ContentAnchor',
        label: 'profile',
        anchor: missingBlobContent.contentId,
      },
    ]);

    const artifactAnchor = await createIdentity([
      { id: 'profile', type: 'ContentAnchor', label: 'profile', anchor: ARTIFACT_ANCHOR },
    ]);

    const winner = await createIdentity();
    const losingContent = await createContent(winner, { $schema: PROFILE_SCHEMA, name: 'loser' });
    const winningContent = await createContent(winner, { $schema: PROFILE_SCHEMA, name: 'winner' });
    await uploadBlob(
      winner,
      losingContent.contentId,
      losingContent.operationCID,
      losingContent.document,
    );
    await uploadBlob(
      winner,
      winningContent.contentId,
      winningContent.operationCID,
      winningContent.document,
    );
    await updateServices(winner, [
      { id: 'z-profile', type: 'ContentAnchor', label: 'profile', anchor: losingContent.contentId },
      {
        id: 'a-profile',
        type: 'ContentAnchor',
        label: 'PROFILE',
        anchor: winningContent.contentId,
      },
    ]);

    const nameBreakers = await Promise.all([createIdentity(), createIdentity(), createIdentity()]);
    const breakerDocs = [
      { $schema: PROFILE_SCHEMA },
      { $schema: PROFILE_SCHEMA, name: '' },
      { $schema: PROFILE_SCHEMA, name: 123 },
    ];
    for (const [i, identity] of nameBreakers.entries()) {
      const content = await createContent(identity, breakerDocs[i]!);
      await uploadBlob(identity, content.contentId, content.operationCID, content.document);
      await updateServices(identity, [
        { id: 'profile', type: 'ContentAnchor', label: 'profile', anchor: content.contentId },
      ]);
    }

    const body = await json(await req('/index/v0/identities'));
    const byDid = new Map<string, { profile: unknown }>(
      body.identities.map((row: { did: string; profile: unknown }) => [row.did, row]),
    );

    expect(byDid.get(nonProfile.did)?.profile).toMatchObject({
      anchor: nonProfileContent.contentId,
      docSchema: 'example/post',
      name: null,
    });
    expect(byDid.get(missingBlob.did)?.profile).toMatchObject({
      anchor: missingBlobContent.contentId,
      docSchema: null,
      name: null,
    });
    expect(byDid.get(artifactAnchor.did)?.profile).toBeNull();
    expect(byDid.get(winner.did)?.profile).toMatchObject({
      anchor: winningContent.contentId,
      name: 'winner',
    });
    for (const identity of nameBreakers) {
      expect(byDid.get(identity.did)?.profile).toMatchObject({
        docSchema: PROFILE_SCHEMA,
        name: null,
      });
    }
  });

  it('enumerates and filters content chains', async () => {
    const creator = await createIdentity();
    const other = await createIdentity();
    const publicDoc = { $schema: 'example/post', title: 'public' };
    const privateDoc = { $schema: 'example/post', title: 'private' };
    const otherDoc = { $schema: 'example/note', title: 'other' };
    const publicContent = await createContent(creator, publicDoc);
    const privateContent = await createContent(creator, privateDoc);
    const otherContent = await createContent(other, otherDoc);

    await uploadBlob(creator, publicContent.contentId, publicContent.operationCID, publicDoc);
    await uploadBlob(creator, privateContent.contentId, privateContent.operationCID, privateDoc);
    await uploadBlob(other, otherContent.contentId, otherContent.operationCID, otherDoc);
    await addPublicReadGrant(creator, publicContent.contentId);

    const all = await json(await req('/index/v0/content'));
    const ids = all.content.map((row: { contentId: string }) => row.contentId);
    expect(ids).toEqual([...ids].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)));

    const filtered = await json(
      await req(
        `/index/v0/content?creator=${encodeURIComponent(
          creator.did,
        )}&docSchema=example/post&publicRead=true`,
      ),
    );
    expect(filtered.content).toHaveLength(1);
    expect(filtered.content[0]).toMatchObject({
      contentId: publicContent.contentId,
      genesisCID: publicContent.operationCID,
      headCID: publicContent.operationCID,
      creatorDID: creator.did,
      isDeleted: false,
      opCount: 1,
      currentDocumentCID: publicContent.documentCID,
      publicRead: true,
      docSchema: 'example/post',
    });

    const noSchemaCoverage = await json(await req('/index/v0/content?docSchema=missing/schema'));
    expect(noSchemaCoverage.content).toEqual([]);

    const page1 = await json(await req('/index/v0/content?limit=2'));
    expect(page1.content).toHaveLength(2);
    expect(page1.next).toBe(page1.content[1].contentId);
    const page2 = await json(
      await req(`/index/v0/content?after=${encodeURIComponent(page1.next)}&limit=2`),
    );
    expect(page2.content.length).toBeGreaterThanOrEqual(1);

    const malformed = await req('/index/v0/content?creator=did:dfos:tooshort');
    expect(malformed.status).toBe(400);
  });

  it('enumerates countersignatures by witness', async () => {
    const author = await createIdentity();
    const witness = await createIdentity();
    const otherWitness = await createIdentity();
    const contentA = await createContent(author, { $schema: 'example/post', title: 'a' });
    const contentB = await createContent(author, { $schema: 'example/post', title: 'b' });

    const tokens: string[] = [];
    for (const [i, content] of [contentA, contentB].entries()) {
      const payload: CountersignPayload = {
        version: 1,
        type: 'countersign',
        did: witness.did,
        targetCID: content.operationCID,
        ...(i === 0 ? { relation: 'endorses' } : {}),
        createdAt: ts(3 + i),
      };
      tokens.push(
        (
          await signCountersignature({
            payload,
            signer: witness.authKey.signer,
            kid: `${witness.did}#${witness.authKey.keyId}`,
          })
        ).jwsToken,
      );
    }
    tokens.push(
      (
        await signCountersignature({
          payload: {
            version: 1,
            type: 'countersign',
            did: otherWitness.did,
            targetCID: contentA.operationCID,
            createdAt: ts(5),
          },
          signer: otherWitness.authKey.signer,
          kid: `${otherWitness.did}#${otherWitness.authKey.keyId}`,
        })
      ).jwsToken,
    );
    await postOps(tokens);

    const page1 = await json(
      await req(`/index/v0/countersignatures?witness=${encodeURIComponent(witness.did)}&limit=1`),
    );
    expect(page1.witness).toBe(witness.did);
    expect(page1.countersignatures).toHaveLength(1);
    expect(page1.next).toBe(page1.countersignatures[0].cid);

    const page2 = await json(
      await req(
        `/index/v0/countersignatures?witness=${encodeURIComponent(
          witness.did,
        )}&after=${encodeURIComponent(page1.next)}&limit=2`,
      ),
    );
    expect(page2.countersignatures).toHaveLength(1);
    expect(page2.next).toBeNull();

    const rows = [...page1.countersignatures, ...page2.countersignatures];
    expect(rows.map((row) => row.cid)).toEqual(
      [...rows.map((row) => row.cid)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)),
    );
    expect(rows.map((row) => row.targetCID).sort()).toEqual(
      [contentA.operationCID, contentB.operationCID].sort(),
    );
    expect(rows.map((row) => row.jwsToken)).toEqual(expect.arrayContaining(tokens.slice(0, 2)));
    expect(rows.map((row) => row.relation).sort()).toEqual(['endorses', null].sort());
    expect(rows.map((row) => decodeJwsUnsafe(row.jwsToken)?.payload?.did)).toEqual([
      witness.did,
      witness.did,
    ]);

    expect((await req('/index/v0/countersignatures')).status).toBe(400);
    expect((await req('/index/v0/countersignatures?witness=did:dfos:tooshort')).status).toBe(400);
  });
});
