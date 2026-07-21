import {
  encodeEd25519Multikey,
  signContentOperation,
  signCountersignature,
  signIdentityOperation,
  signRevocation,
  type ContentOperation,
  type CountersignPayload,
  type IdentityOperation,
  type MultikeyPublicKey,
  type ServiceEntry,
} from '@metalabel/dfos-protocol/chain';
import {
  createAuthToken,
  createDFOSCredential,
  decodeDFOSCredentialUnsafe,
} from '@metalabel/dfos-protocol/credentials';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  decodeJwsUnsafe,
  generateId,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { bootstrapRelayIdentity, createRelay, MemoryRelayStore } from '../src';
import type { RelayIdentity } from '../src';

const PROFILE_SCHEMA = 'https://schemas.dfos.com/profile/v1';
const POST_SCHEMA = 'https://schemas.dfos.com/post/v1';
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

  const updateContent = async (
    signer: TestIdentity,
    previousOperationCID: string,
    document: Record<string, unknown>,
    offset = 2,
    authorization?: string,
  ) => {
    const encoded = await dagCborCanonicalEncode(document);
    const op: ContentOperation = {
      version: 1,
      type: 'update',
      did: signer.did,
      previousOperationCID,
      documentCID: encoded.cid.toString(),
      baseDocumentCID: null,
      createdAt: ts(offset),
      note: null,
      ...(authorization ? { authorization } : {}),
    };
    const { jwsToken, operationCID } = await signContentOperation({
      operation: op,
      signer: signer.authKey.signer,
      kid: `${signer.did}#${signer.authKey.keyId}`,
    });
    const res = await postOps([jwsToken]);
    expect(res.status).toBe(200);
    const body = await json(res);
    expect(body.results[0].status).toBe('new');
    return { jwsToken, operationCID, documentCID: encoded.cid.toString(), document };
  };

  const createWriteGrant = async (
    creator: TestIdentity,
    delegate: TestIdentity,
    contentId: string,
  ) => {
    const now = Math.floor(Date.now() / 1000);
    const credential = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: delegate.did,
      att: [{ resource: `chain:${contentId}`, action: 'write' }],
      exp: now + 3600,
      signer: creator.authKey.signer,
      keyId: creator.authKey.keyId,
      iat: now,
    });
    const res = await postOps([credential]);
    expect(res.status).toBe(200);
    return credential;
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

  /** Grant public read and return the credential CID (so the grant can be revoked). */
  const mintPublicReadGrant = async (identity: TestIdentity, resource: string) => {
    const now = Math.floor(Date.now() / 1000);
    const credential = await createDFOSCredential({
      issuerDID: identity.did,
      audienceDID: '*',
      att: [{ resource, action: 'read' }],
      exp: now + 3600,
      signer: identity.authKey.signer,
      keyId: identity.authKey.keyId,
      iat: now,
    });
    return {
      credential,
      credentialCID: decodeDFOSCredentialUnsafe(credential)!.header.cid as string,
    };
  };

  const grantPublicReadResource = async (
    identity: TestIdentity,
    resource: string,
  ): Promise<string> => {
    const { credential, credentialCID } = await mintPublicReadGrant(identity, resource);
    const res = await postOps([credential]);
    expect(res.status).toBe(200);
    return credentialCID;
  };

  const grantPublicRead = (identity: TestIdentity, contentId: string): Promise<string> =>
    grantPublicReadResource(identity, `chain:${contentId}`);

  const revokeGrant = async (identity: TestIdentity, credentialCID: string) => {
    const { jwsToken } = await signRevocation({
      issuerDID: identity.did,
      credentialCID,
      signer: identity.authKey.signer,
      keyId: identity.authKey.keyId,
    });
    const res = await postOps([jwsToken]);
    expect(res.status).toBe(200);
  };

  const identityRow = async (did: string) => {
    const body = await json(await req('/index/v0/identities?limit=1000'));
    return body.identities.find((row: { did: string }) => row.did === did);
  };

  const contentRow = async (contentId: string) => {
    const body = await json(await req('/index/v0/content?limit=1000'));
    return body.content.find((row: { contentId: string }) => row.contentId === contentId);
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

  it('filters identities by nameContains (case-insensitive substring over profile.name)', async () => {
    const seed = async (name: string): Promise<string> => {
      const id = await createIdentity();
      const doc = { $schema: PROFILE_SCHEMA, name };
      const content = await createContent(id, doc);
      await uploadBlob(id, content.contentId, content.operationCID, doc);
      await addPublicReadGrant(id, content.contentId);
      await updateServices(id, [
        { id: 'profile', type: 'ContentAnchor', label: 'profile', anchor: content.contentId },
      ]);
      return id.did;
    };
    const asha = await seed('Asha'); // contains 'sh'
    const boris = await seed('Boris'); // contains 'or'

    const dids = async (path: string): Promise<string[]> =>
      (await json(await req(path))).identities.map((row: { did: string }) => row.did);

    // positive substring, case-insensitive (stored 'Asha' vs lowercase query 'sh')
    const sh = await dids('/index/v0/identities?nameContains=sh');
    expect(sh).toContain(asha);
    expect(sh).not.toContain(boris);

    // an uppercase query returns the same row
    expect(await dids('/index/v0/identities?nameContains=SH')).toContain(asha);

    // a different substring selects the other row
    const or = await dids('/index/v0/identities?nameContains=or');
    expect(or).toContain(boris);
    expect(or).not.toContain(asha);

    // every returned row genuinely contains the needle — no non-matching row leaks
    const shBody = await json(await req('/index/v0/identities?nameContains=sh'));
    for (const row of shBody.identities) {
      expect(row.profile?.name?.toLowerCase()).toContain('sh');
    }

    // a no-match query returns neither
    const none = await dids('/index/v0/identities?nameContains=zzq-no-such');
    expect(none).not.toContain(asha);
    expect(none).not.toContain(boris);
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
    // name projects only for a publicly-readable profile; grant so this case
    // isolates the anchor-tiebreak breaker, not the publicRead gate
    await addPublicReadGrant(winner, winningContent.contentId);
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
      // name projects only for a publicly-readable profile; grant so these cases
      // isolate the doc-level name breakers, not the publicRead gate
      await addPublicReadGrant(identity, content.contentId);
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

  it('projects post titles with circuit breakers and late blob recompute', async () => {
    const creator = await createIdentity();
    const post = await createContent(creator, { $schema: POST_SCHEMA, title: 'hello' });
    await uploadBlob(creator, post.contentId, post.operationCID, post.document);

    const nonRegistry = await createContent(creator, { $schema: 'example/post', title: 'no' });
    const missing = await createContent(creator, { $schema: POST_SCHEMA });
    const empty = await createContent(creator, { $schema: POST_SCHEMA, title: '' });
    const nonString = await createContent(creator, { $schema: POST_SCHEMA, title: 123 });
    const late = await createContent(creator, { $schema: POST_SCHEMA, title: 'late' });
    // title projects only for a publicly-readable chain; grant so these cases
    // isolate the doc-level title breakers, not the publicRead gate
    for (const content of [post, nonRegistry, missing, empty, nonString, late]) {
      await addPublicReadGrant(creator, content.contentId);
    }
    for (const content of [nonRegistry, missing, empty, nonString]) {
      await uploadBlob(creator, content.contentId, content.operationCID, content.document);
    }

    expect((await contentRow(post.contentId)).title).toBe('hello');
    for (const content of [nonRegistry, missing, empty, nonString, late]) {
      expect((await contentRow(content.contentId)).title).toBeNull();
    }

    await uploadBlob(creator, late.contentId, late.operationCID, late.document);
    expect((await contentRow(late.contentId)).title).toBe('late');
  });

  it('orders identity and content pages by time with opaque cursors', async () => {
    const a = await createIdentity();
    await new Promise((resolve) => setTimeout(resolve, 2));
    const b = await createIdentity();
    await new Promise((resolve) => setTimeout(resolve, 2));
    const c = await createIdentity();
    const c1 = await createContent(a, { $schema: 'example/order', title: 'a' }, 1);
    const c2 = await createContent(a, { $schema: 'example/order', title: 'b' }, 3);
    const c3 = await createContent(b, { $schema: 'example/order', title: 'c' }, 2);

    const walkIdentityDids = async (path: string): Promise<string[]> => {
      const walked: string[] = [];
      let next: string | null = null;
      for (let pages = 0; ; pages++) {
        expect(pages).toBeLessThanOrEqual(20);
        const page = await json(
          await req(`${path}${next ? `&after=${encodeURIComponent(next)}` : ''}`),
        );
        walked.push(...page.identities.map((row: { did: string }) => row.did));
        if (page.next === null) break;
        next = page.next;
      }
      return walked;
    };

    const walkContentIds = async (path: string): Promise<string[]> => {
      const walked: string[] = [];
      let next: string | null = null;
      for (let pages = 0; ; pages++) {
        expect(pages).toBeLessThanOrEqual(20);
        const page = await json(
          await req(`${path}${next ? `&after=${encodeURIComponent(next)}` : ''}`),
        );
        walked.push(...page.content.map((row: { contentId: string }) => row.contentId));
        if (page.next === null) break;
        next = page.next;
      }
      return walked;
    };

    const genesis = await json(await req('/index/v0/content?order=genesisAt.desc&limit=1000'));
    const scoped = genesis.content.filter((row: { contentId: string }) =>
      [c1.contentId, c2.contentId, c3.contentId].includes(row.contentId),
    );
    expect(scoped.map((row: { contentId: string }) => row.contentId)).toEqual([
      c2.contentId,
      c3.contentId,
      c1.contentId,
    ]);

    const expectedContent = genesis.content.map((row: { contentId: string }) => row.contentId);
    const walkedContent = await walkContentIds('/index/v0/content?order=genesisAt.desc&limit=1');
    expect(walkedContent).toEqual(expectedContent);
    expect(walkedContent.length).toBeGreaterThanOrEqual(3);

    const update = await updateContent(
      a,
      c1.operationCID,
      { $schema: POST_SCHEMA, title: 'new' },
      10,
    );
    await uploadBlob(a, c1.contentId, update.operationCID, update.document);
    expect(update.operationCID).toEqual(expect.any(String));
    const head = await json(await req('/index/v0/content?order=headAt.desc&limit=1000'));
    expect(head.content[0].contentId).toBe(c1.contentId);

    const creatorHead = await json(
      await req(
        `/index/v0/content?order=headAt.desc&creator=${encodeURIComponent(a.did)}&limit=1000`,
      ),
    );
    expect(creatorHead.content.map((row: { contentId: string }) => row.contentId)).toEqual([
      c1.contentId,
      c2.contentId,
    ]);
    const walkedCreatorHead = await walkContentIds(
      `/index/v0/content?order=headAt.desc&creator=${encodeURIComponent(a.did)}&limit=1`,
    );
    expect(walkedCreatorHead).toEqual([c1.contentId, c2.contentId]);

    const orderedBySignerSchema = await json(
      await req(
        `/index/v0/content?order=headAt.desc&signer=${encodeURIComponent(
          a.did,
        )}&docSchema=${encodeURIComponent(POST_SCHEMA)}&limit=1000`,
      ),
    );
    expect(
      orderedBySignerSchema.content.map((row: { contentId: string }) => row.contentId),
    ).toEqual([c1.contentId]);

    const identityPage = await json(await req('/index/v0/identities?order=genesisAt.desc&limit=1'));
    expect(identityPage.identities).toHaveLength(1);
    expect(identityPage.identities[0].did).toBe(c.did);
    expect(identityPage.next).toEqual(expect.any(String));

    const allIdentities = await json(
      await req('/index/v0/identities?order=headAt.desc&limit=1000'),
    );
    const expectedDids = allIdentities.identities.map((row: { did: string }) => row.did);
    const walkedDids = await walkIdentityDids('/index/v0/identities?order=headAt.desc&limit=1');
    expect(walkedDids).toEqual(expectedDids);
    expect(walkedDids.length).toBeGreaterThanOrEqual(3);

    await updateServices(a, [
      { id: 'identity-order-head', type: 'ContentAnchor', label: 'noop', anchor: ARTIFACT_ANCHOR },
    ]);
    const identityHead = await json(await req('/index/v0/identities?order=headAt.desc&limit=1'));
    expect(identityHead.identities[0].did).toBe(a.did);

    await store.putIndexIdentityRow({
      did: 'did:dfos:identity-tie-b',
      headCID: 'h',
      opCount: 1,
      genesisAt: '2999-01-01T00:00:00.000Z',
      headAt: '2999-01-01T00:00:00.000Z',
      isDeleted: false,
      profile: null,
    });
    await store.putIndexIdentityRow({
      did: 'did:dfos:identity-tie-a',
      headCID: 'h',
      opCount: 1,
      genesisAt: '2999-01-01T00:00:00.000Z',
      headAt: '2999-01-01T00:00:00.000Z',
      isDeleted: false,
      profile: null,
    });
    const identityTied = await json(await req('/index/v0/identities?order=genesisAt.desc&limit=2'));
    expect(identityTied.identities.map((row: { did: string }) => row.did)).toEqual([
      'did:dfos:identity-tie-a',
      'did:dfos:identity-tie-b',
    ]);

    await store.putIndexContentRow({
      contentId: 'tie-a',
      genesisCID: 'g',
      headCID: 'h',
      creatorDID: a.did,
      isDeleted: false,
      opCount: 1,
      genesisAt: '2999-01-01T00:00:00.000Z',
      headAt: '2999-01-01T00:00:00.000Z',
      currentDocumentCID: null,
      publicRead: false,
      docSchema: null,
      title: null,
    });
    await store.putIndexContentRow({
      contentId: 'tie-b',
      genesisCID: 'g',
      headCID: 'h',
      creatorDID: a.did,
      isDeleted: false,
      opCount: 1,
      genesisAt: '2999-01-01T00:00:00.000Z',
      headAt: '2999-01-01T00:00:00.000Z',
      currentDocumentCID: null,
      publicRead: false,
      docSchema: null,
      title: null,
    });
    const tied = await json(await req('/index/v0/content?order=genesisAt.desc&limit=2'));
    expect(tied.content.map((row: { contentId: string }) => row.contentId)).toEqual([
      'tie-a',
      'tie-b',
    ]);

    expect((await req('/index/v0/content?order=bogus')).status).toBe(400);
    expect((await req('/index/v0/identities?order=bogus')).status).toBe(400);
    expect((await req('/index/v0/content?order=genesisAt.desc&after=not-a-cursor')).status).toBe(
      400,
    );
    expect((await req('/index/v0/identities?order=genesisAt.desc&after=not-a-token')).status).toBe(
      400,
    );
  });

  it('filters content by accepted signer and composes with other filters', async () => {
    const creator = await createIdentity();
    const delegate = await createIdentity();
    const never = await createIdentity();
    const doc = { $schema: POST_SCHEMA, title: 'signed' };
    const content = await createContent(creator, doc);
    await uploadBlob(creator, content.contentId, content.operationCID, doc);
    await addPublicReadGrant(creator, content.contentId);

    const credential = await createWriteGrant(creator, delegate, content.contentId);
    const update = await updateContent(
      delegate,
      content.operationCID,
      { $schema: POST_SCHEMA, title: 'delegate' },
      2,
      credential,
    );
    await uploadBlob(delegate, content.contentId, update.operationCID, update.document);

    const byCreator = await json(
      await req(`/index/v0/content?signer=${encodeURIComponent(creator.did)}&limit=1000`),
    );
    expect(byCreator.content.map((row: { contentId: string }) => row.contentId)).toContain(
      content.contentId,
    );

    const byDelegate = await json(
      await req(
        `/index/v0/content?signer=${encodeURIComponent(
          delegate.did,
        )}&creator=${encodeURIComponent(creator.did)}&docSchema=${encodeURIComponent(
          POST_SCHEMA,
        )}&publicRead=true&limit=1000`,
      ),
    );
    expect(byDelegate.content.map((row: { contentId: string }) => row.contentId)).toContain(
      content.contentId,
    );

    const byNever = await json(
      await req(`/index/v0/content?signer=${encodeURIComponent(never.did)}&limit=1000`),
    );
    expect(byNever.content.map((row: { contentId: string }) => row.contentId)).not.toContain(
      content.contentId,
    );
    expect((await req('/index/v0/content?signer=not-a-did')).status).toBe(400);
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

  // ---------------------------------------------------------------------------
  // materialized projection: keyset cursor + recompute-on-change
  // ---------------------------------------------------------------------------

  it('resumes at the next key on an unknown/mutated cursor (strictly-greater keyset)', async () => {
    await Promise.all([createIdentity(), createIdentity(), createIdentity(), createIdentity()]);
    const all = await json(await req('/index/v0/identities?limit=1000'));
    const dids: string[] = all.identities.map((row: { did: string }) => row.did);
    expect(dids.length).toBeGreaterThanOrEqual(4);
    expect(dids).toEqual([...dids].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)));

    // A cursor that is NOT a stored key but sorts strictly between dids[1] and
    // dids[2] (append a char ⇒ longer than dids[1] so > dids[1]; the shared
    // prefix with dids[2] diverges before the appended char so < dids[2]).
    const between = `${dids[1]}x`;
    expect(between > dids[1]!).toBe(true);
    expect(between < dids[2]!).toBe(true);

    const page = await json(
      await req(`/index/v0/identities?after=${encodeURIComponent(between)}&limit=1000`),
    );
    const pageDids: string[] = page.identities.map((row: { did: string }) => row.did);
    // The old exact-match cursor returned an EMPTY page here (silent truncation);
    // keyset resumes at the next key.
    expect(pageDids.length).toBeGreaterThan(0);
    expect(pageDids[0]).toBe(dids[2]);
    expect(pageDids).not.toContain(dids[0]);
    expect(pageDids).not.toContain(dids[1]);
  });

  it('resumes correctly when the cursor row is mutated out of the filter between pages', async () => {
    // three public-read contents from one creator
    const creator = await createIdentity();
    const made = [];
    for (let i = 0; i < 3; i++) {
      const doc = { $schema: 'example/post', title: `p${i}` };
      const content = await createContent(creator, doc, i + 1);
      await uploadBlob(creator, content.contentId, content.operationCID, doc);
      const credentialCID = await grantPublicRead(creator, content.contentId);
      made.push({ ...content, credentialCID });
    }
    const sorted = [...made].sort((a, b) =>
      a.contentId < b.contentId ? -1 : a.contentId > b.contentId ? 1 : 0,
    );

    const page1 = await json(await req('/index/v0/content?publicRead=true&limit=1'));
    expect(page1.content).toHaveLength(1);
    const cursor: string = page1.next;
    expect(cursor).toBe(page1.content[0].contentId);

    // Revoke the CURSOR row's grant → publicRead flips false → it drops out of the
    // publicRead=true filtered set entirely. The old exact-match cursor would
    // findIndex(-1) and return an empty page (enumeration truncation).
    const cursorEntry = made.find((m) => m.contentId === cursor)!;
    await revokeGrant(creator, cursorEntry.credentialCID);

    const page2 = await json(
      await req(`/index/v0/content?publicRead=true&after=${encodeURIComponent(cursor)}&limit=1000`),
    );
    const remaining: string[] = page2.content.map((row: { contentId: string }) => row.contentId);
    // still-public contents whose contentId > cursor
    const expected = sorted
      .filter((m) => m.contentId > cursor && m.contentId !== cursor)
      .map((m) => m.contentId);
    expect(remaining.length).toBeGreaterThan(0);
    expect(remaining).toEqual(expected);
    // the mutated cursor row is now absent from the publicRead=true projection
    const revokedRow = await contentRow(cursor);
    expect(revokedRow.publicRead).toBe(false);
  });

  it('recomputes content + anchored identity rows when a blob lands late', async () => {
    const subject = await createIdentity();
    const profileDoc = { $schema: PROFILE_SCHEMA, name: 'lena' };
    const profileContent = await createContent(subject, profileDoc);
    await grantPublicRead(subject, profileContent.contentId);
    await updateServices(subject, [
      { id: 'profile', type: 'ContentAnchor', label: 'profile', anchor: profileContent.contentId },
    ]);

    // blob not yet uploaded → docSchema/name unknown on both rows
    const beforeContent = await contentRow(profileContent.contentId);
    expect(beforeContent.currentDocumentCID).toBe(profileContent.documentCID);
    expect(beforeContent.docSchema).toBeNull();
    const beforeIdentity = await identityRow(subject.did);
    expect(beforeIdentity.profile).toMatchObject({
      anchor: profileContent.contentId,
      docSchema: null,
      name: null,
    });

    // blob lands late → recompute cascades content → anchored identity
    await uploadBlob(subject, profileContent.contentId, profileContent.operationCID, profileDoc);

    const afterContent = await contentRow(profileContent.contentId);
    expect(afterContent.docSchema).toBe(PROFILE_SCHEMA);
    const afterIdentity = await identityRow(subject.did);
    expect(afterIdentity.profile).toMatchObject({
      anchor: profileContent.contentId,
      publicRead: true,
      docSchema: PROFILE_SCHEMA,
      name: 'lena',
    });
  });

  it('flips publicRead on a content row AND an anchored profile when a grant is added then revoked', async () => {
    const subject = await createIdentity();
    const profileDoc = { $schema: PROFILE_SCHEMA, name: 'ravi' };
    const profileContent = await createContent(subject, profileDoc);
    await uploadBlob(subject, profileContent.contentId, profileContent.operationCID, profileDoc);
    await updateServices(subject, [
      { id: 'profile', type: 'ContentAnchor', label: 'profile', anchor: profileContent.contentId },
    ]);

    // before any grant: private on both the content row and the anchored profile
    expect((await contentRow(profileContent.contentId)).publicRead).toBe(false);
    expect((await identityRow(subject.did)).profile.publicRead).toBe(false);
    expect(
      (await json(await req('/index/v0/identities?hasPublicProfile=true'))).identities.map(
        (row: { did: string }) => row.did,
      ),
    ).not.toContain(subject.did);

    // grant flips both true
    const credentialCID = await grantPublicRead(subject, profileContent.contentId);
    expect((await contentRow(profileContent.contentId)).publicRead).toBe(true);
    expect((await identityRow(subject.did)).profile.publicRead).toBe(true);
    expect(
      (await json(await req('/index/v0/identities?hasPublicProfile=true'))).identities.map(
        (row: { did: string }) => row.did,
      ),
    ).toContain(subject.did);

    // revoke flips both back to false
    await revokeGrant(subject, credentialCID);
    expect((await contentRow(profileContent.contentId)).publicRead).toBe(false);
    expect((await identityRow(subject.did)).profile.publicRead).toBe(false);
    expect(
      (await json(await req('/index/v0/identities?hasPublicProfile=true'))).identities.map(
        (row: { did: string }) => row.did,
      ),
    ).not.toContain(subject.did);
  });

  it('narrows named grant revocation maintenance to its att-named chain', async () => {
    const creator = await createIdentity();
    const contentA = await createContent(creator, { $schema: POST_SCHEMA, title: 'a' }, 1);
    const contentB = await createContent(creator, { $schema: POST_SCHEMA, title: 'b' }, 2);
    const credentialA = await grantPublicRead(creator, contentA.contentId);
    await grantPublicRead(creator, contentB.contentId);
    expect((await contentRow(contentA.contentId)).publicRead).toBe(true);
    expect((await contentRow(contentB.contentId)).publicRead).toBe(true);

    const putContentRow = vi.spyOn(store, 'putIndexContentRow');
    await revokeGrant(creator, credentialA);

    expect((await contentRow(contentA.contentId)).publicRead).toBe(false);
    expect((await contentRow(contentB.contentId)).publicRead).toBe(true);
    expect(putContentRow.mock.calls.map(([row]) => row.contentId)).toEqual([contentA.contentId]);
  });

  it('falls back to the public sweep for wildcard grant revocation', async () => {
    const creator = await createIdentity();
    const contentA = await createContent(creator, { $schema: POST_SCHEMA, title: 'a' }, 1);
    const contentB = await createContent(creator, { $schema: POST_SCHEMA, title: 'b' }, 2);
    const credentialCID = await grantPublicReadResource(creator, 'chain:*');
    expect((await contentRow(contentA.contentId)).publicRead).toBe(true);
    expect((await contentRow(contentB.contentId)).publicRead).toBe(true);

    const putContentRow = vi.spyOn(store, 'putIndexContentRow');
    await revokeGrant(creator, credentialCID);

    expect((await contentRow(contentA.contentId)).publicRead).toBe(false);
    expect((await contentRow(contentB.contentId)).publicRead).toBe(false);
    const recomputed = putContentRow.mock.calls.map(([row]) => row.contentId);
    expect(recomputed).toHaveLength(2);
    expect(new Set(recomputed)).toEqual(new Set([contentA.contentId, contentB.contentId]));
  });

  it('falls back to the public sweep for an unresolvable revoked credential', async () => {
    const creator = await createIdentity();
    const contentA = await createContent(creator, { $schema: POST_SCHEMA, title: 'a' }, 1);
    const contentB = await createContent(creator, { $schema: POST_SCHEMA, title: 'b' }, 2);
    await grantPublicRead(creator, contentA.contentId);
    await grantPublicRead(creator, contentB.contentId);
    const { credentialCID: unheldCredentialCID } = await mintPublicReadGrant(
      creator,
      'chain:unheld',
    );

    const putContentRow = vi.spyOn(store, 'putIndexContentRow');
    await revokeGrant(creator, unheldCredentialCID);

    expect((await contentRow(contentA.contentId)).publicRead).toBe(true);
    expect((await contentRow(contentB.contentId)).publicRead).toBe(true);
    const recomputed = putContentRow.mock.calls.map(([row]) => row.contentId);
    expect(recomputed).toHaveLength(2);
    expect(new Set(recomputed)).toEqual(new Set([contentA.contentId, contentB.contentId]));
  });

  it('flips publicRead false when the identity that granted it is deleted (issuer no longer a valid credential hop)', async () => {
    // Creator self-issues a public-read grant on its own content, anchors its
    // profile there, then deletes its own identity. hasPublicStandingAuth
    // re-verifies the grant's issuer live and rejects a deleted identity, so the
    // materialized content row (and the anchored profile) MUST flip true→false —
    // even though the only op is on the IDENTITY chain, not the content chain.
    const creator = await createIdentity();
    const profileDoc = { $schema: PROFILE_SCHEMA, name: 'mara' };
    const content = await createContent(creator, profileDoc);
    await uploadBlob(creator, content.contentId, content.operationCID, profileDoc);
    await grantPublicRead(creator, content.contentId);
    const update = await updateServices(creator, [
      { id: 'profile', type: 'ContentAnchor', label: 'profile', anchor: content.contentId },
    ]);

    // grant + anchor in place: public on both the content row and the profile
    expect((await contentRow(content.contentId)).publicRead).toBe(true);
    expect((await identityRow(creator.did)).profile.publicRead).toBe(true);

    // delete the granting identity (terminal op on its own chain)
    const deleteOp: IdentityOperation = {
      version: 1,
      type: 'delete',
      previousOperationCID: update.operationCID,
      createdAt: ts(4),
    };
    const { jwsToken: deleteToken } = await signIdentityOperation({
      operation: deleteOp,
      signer: creator.controller.signer,
      keyId: creator.controller.keyId,
      identityDID: creator.did,
    });
    expect((await postOps([deleteToken])).status).toBe(200);

    // the content row's publicRead must reflect the now-invalid issuer, and the
    // deleted identity's own profile projection likewise
    expect((await contentRow(content.contentId)).publicRead).toBe(false);
    const deletedRow = await identityRow(creator.did);
    expect(deletedRow.isDeleted).toBe(true);
    expect(deletedRow.profile.publicRead).toBe(false);
    expect(
      (await json(await req('/index/v0/content?publicRead=true&limit=1000'))).content.map(
        (row: { contentId: string }) => row.contentId,
      ),
    ).not.toContain(content.contentId);
  });

  it('reflects the ACCEPTED (deduped) countersign set in the projection, not raw ops', async () => {
    const author = await createIdentity();
    const witness = await createIdentity();
    const content = await createContent(author, { $schema: 'example/post', title: 'dedup' });

    const signCs = async (relation: string | undefined, offset: number) => {
      const payload: CountersignPayload = {
        version: 1,
        type: 'countersign',
        did: witness.did,
        targetCID: content.operationCID,
        ...(relation ? { relation } : {}),
        createdAt: ts(offset),
      };
      const { jwsToken } = await signCountersignature({
        payload,
        signer: witness.authKey.signer,
        kid: `${witness.did}#${witness.authKey.keyId}`,
      });
      return jwsToken;
    };

    const first = await signCs('endorses', 3);
    await postOps([first]);

    const afterFirst = await json(
      await req(`/index/v0/countersignatures?witness=${encodeURIComponent(witness.did)}&limit=100`),
    );
    expect(afterFirst.countersignatures).toHaveLength(1);
    const acceptedCid = afterFirst.countersignatures[0].cid;
    expect(afterFirst.countersignatures[0].relation).toBe('endorses');

    // second countersign, same witness + same target, different createdAt ⇒ the
    // store dedups it (status 'duplicate'). The projection must NOT gain a row.
    const second = await signCs('revised', 6);
    const res = await postOps([second]);
    const body = await json(res);
    expect(body.results[0].status).toBe('duplicate');

    const afterSecond = await json(
      await req(`/index/v0/countersignatures?witness=${encodeURIComponent(witness.did)}&limit=100`),
    );
    expect(afterSecond.countersignatures).toHaveLength(1);
    expect(afterSecond.countersignatures[0].cid).toBe(acceptedCid);
    expect(afterSecond.countersignatures[0].relation).toBe('endorses');
  });

  // ---------------------------------------------------------------------------
  // confidentiality: extracted display-name fields are public-only
  // ---------------------------------------------------------------------------

  it('withholds a non-public profile name at rest, on the wire, and from nameContains', async () => {
    const subject = await createIdentity();
    const profileDoc = { $schema: PROFILE_SCHEMA, name: 'hidden' };
    const profileContent = await createContent(subject, profileDoc);
    await uploadBlob(subject, profileContent.contentId, profileContent.operationCID, profileDoc);
    await updateServices(subject, [
      { id: 'profile', type: 'ContentAnchor', label: 'profile', anchor: profileContent.contentId },
    ]);

    // non-public: the stored row carries no name (write gate), the served row is
    // likewise gated, and nameContains cannot confirm the hidden name
    const stored = (await store.queryIndexIdentities({ limit: 1000 })).find(
      (row) => row.did === subject.did,
    );
    expect(stored?.profile).toMatchObject({ publicRead: false, name: null });
    const served = await identityRow(subject.did);
    expect(served.profile).toMatchObject({ publicRead: false, name: null });
    expect(
      (await json(await req('/index/v0/identities?nameContains=hidden'))).identities.map(
        (row: { did: string }) => row.did,
      ),
    ).not.toContain(subject.did);

    // grant public read → the same name projects everywhere
    await addPublicReadGrant(subject, profileContent.contentId);
    expect((await identityRow(subject.did)).profile).toMatchObject({
      publicRead: true,
      name: 'hidden',
    });
    expect(
      (await json(await req('/index/v0/identities?nameContains=hidden'))).identities.map(
        (row: { did: string }) => row.did,
      ),
    ).toContain(subject.did);
  });

  it('withholds a non-public content title until public read is granted', async () => {
    const creator = await createIdentity();
    const doc = { $schema: POST_SCHEMA, title: 'secret' };
    const post = await createContent(creator, doc);
    await uploadBlob(creator, post.contentId, post.operationCID, doc);

    const stored = (await store.queryIndexContent({ limit: 1000 })).find(
      (row) => row.contentId === post.contentId,
    );
    expect(stored).toMatchObject({ publicRead: false, title: null });
    expect(await contentRow(post.contentId)).toMatchObject({ publicRead: false, title: null });

    await addPublicReadGrant(creator, post.contentId);
    expect(await contentRow(post.contentId)).toMatchObject({ publicRead: true, title: 'secret' });
  });

  it('redacts a stale non-public row at serve time and keeps it out of nameContains', async () => {
    // A row a pre-gate builder might have persisted: non-public but carrying an
    // extracted name/title. Serve-time redaction must null both, and nameContains
    // must not confirm the stale name — the current builder never writes this.
    await store.putIndexIdentityRow({
      did: 'did:dfos:stale-identity',
      headCID: 'h',
      opCount: 1,
      genesisAt: '2999-01-01T00:00:00.000Z',
      headAt: '2999-01-01T00:00:00.000Z',
      isDeleted: false,
      profile: {
        anchor: 'stale-anchor',
        publicRead: false,
        docSchema: PROFILE_SCHEMA,
        name: 'stale',
      },
    });
    await store.putIndexContentRow({
      contentId: 'stale-content',
      genesisCID: 'g',
      headCID: 'h',
      creatorDID: relayDID,
      isDeleted: false,
      opCount: 1,
      genesisAt: '2999-01-01T00:00:00.000Z',
      headAt: '2999-01-01T00:00:00.000Z',
      currentDocumentCID: null,
      publicRead: false,
      docSchema: POST_SCHEMA,
      title: 'stale-title',
    });

    expect((await identityRow('did:dfos:stale-identity')).profile.name).toBeNull();
    expect((await contentRow('stale-content')).title).toBeNull();
    expect(
      (await json(await req('/index/v0/identities?nameContains=stale'))).identities.map(
        (row: { did: string }) => row.did,
      ),
    ).not.toContain('did:dfos:stale-identity');
  });
});
