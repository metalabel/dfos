import {
  encodeEd25519Multikey,
  signBeacon,
  signContentOperation,
  signCountersignature,
  signIdentityOperation,
  type BeaconPayload,
  type ContentOperation,
  type IdentityOperation,
  type MultikeyPublicKey,
} from '@metalabel/dfos-protocol/chain';
import {
  createAuthToken,
  createCredential,
  VC_TYPE_CONTENT_READ,
} from '@metalabel/dfos-protocol/credentials';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  generateId,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import { createRelay, MemoryRelayStore } from '../src';

// =============================================================================
// helpers
// =============================================================================

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

const RELAY_DID = 'did:dfos:testrelay00000000000';

/** Create a complete identity chain (genesis) and return the DID and signing info */
const createIdentity = async () => {
  const controller = makeKey();
  const authKey = makeKey();

  const createOp: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [authKey.key],
    assertKeys: [],
    controllerKeys: [controller.key],
    createdAt: ts(),
  };

  const { jwsToken, operationCID } = await signIdentityOperation({
    operation: createOp,
    signer: controller.signer,
    keyId: controller.keyId,
  });

  // derive DID from the genesis operation CID
  const encoded = await dagCborCanonicalEncode(createOp);
  const { deriveChainIdentifier } = await import('@metalabel/dfos-protocol/chain');
  const did = deriveChainIdentifier(encoded.cid.bytes, 'did:dfos');

  return { did, controller, authKey, jwsToken, operationCID };
};

/** Create a content chain genesis operation signed by a given identity */
const createContentOp = async (identity: Awaited<ReturnType<typeof createIdentity>>) => {
  // create a document and derive its CID
  const document = { type: 'post', title: 'hello world', body: 'test content' };
  const docEncoded = await dagCborCanonicalEncode(document as unknown as Record<string, unknown>);
  const documentCID = docEncoded.cid.toString();

  const op: ContentOperation = {
    version: 1,
    type: 'create',
    did: identity.did,
    documentCID,
    baseDocumentCID: null,
    createdAt: ts(1),
    note: null,
  };

  const kid = `${identity.did}#${identity.authKey.keyId}`;
  const { jwsToken, operationCID } = await signContentOperation({
    operation: op,
    signer: identity.authKey.signer,
    kid,
  });

  return { jwsToken, operationCID, documentCID, document };
};

/** Create an auth token for a given identity targeting the test relay */
const createTestAuthToken = async (
  identity: Awaited<ReturnType<typeof createIdentity>>,
  keyOverride?: { keyId: string; signer: (msg: Uint8Array) => Promise<Uint8Array> },
) => {
  const now = Math.floor(Date.now() / 1000);
  const key = keyOverride ?? identity.authKey;
  return createAuthToken({
    iss: identity.did,
    aud: RELAY_DID,
    exp: now + 300,
    kid: `${identity.did}#${key.keyId}`,
    iat: now,
    sign: key.signer,
  });
};

// =============================================================================
// tests
// =============================================================================

describe('web relay', () => {
  let store: MemoryRelayStore;
  let app: ReturnType<typeof createRelay>;

  beforeEach(() => {
    store = new MemoryRelayStore();
    app = createRelay({ relayDID: RELAY_DID, store });
  });

  const req = (path: string, init?: RequestInit) => app.request(`http://localhost${path}`, init);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const json = async (res: Response): Promise<any> => res.json();

  const postOps = (operations: string[]) =>
    req('/operations', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ operations }),
    });

  // ---------------------------------------------------------------------------
  // well-known
  // ---------------------------------------------------------------------------

  describe('well-known', () => {
    it('should return relay metadata', async () => {
      const res = await req('/.well-known/dfos-relay');
      expect(res.status).toBe(200);
      const body = await json(res);
      expect(body.did).toBe(RELAY_DID);
      expect(body.protocol).toBe('dfos-web-relay');
    });
  });

  // ---------------------------------------------------------------------------
  // identity chain lifecycle
  // ---------------------------------------------------------------------------

  describe('identity chain ingestion', () => {
    it('should accept a genesis identity operation', async () => {
      const identity = await createIdentity();
      const res = await postOps([identity.jwsToken]);
      expect(res.status).toBe(200);

      const body = await json(res);
      expect(body.results).toHaveLength(1);
      expect(body.results[0].status).toBe('accepted');
      expect(body.results[0].kind).toBe('identity-op');
      expect(body.results[0].chainId).toBe(identity.did);
    });

    it('should serve identity chain via GET', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      const res = await req(`/identities/${identity.did}`);
      expect(res.status).toBe(200);

      const body = await json(res);
      expect(body.did).toBe(identity.did);
      expect(body.log).toHaveLength(1);
      expect(body.state.isDeleted).toBe(false);
    });

    it('should return 404 for unknown identity', async () => {
      const res = await req('/identities/did:dfos:unknown000000000000');
      expect(res.status).toBe(404);
    });

    it('should accept identity chain extension', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      // create an update operation
      const newKey = makeKey();
      const updateOp: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID: identity.operationCID,
        authKeys: [identity.authKey.key, newKey.key],
        assertKeys: [],
        controllerKeys: [identity.controller.key],
        createdAt: ts(2),
      };

      const { jwsToken: updateToken } = await signIdentityOperation({
        operation: updateOp,
        signer: identity.controller.signer,
        keyId: identity.controller.keyId,
        identityDID: identity.did,
      });

      const res = await postOps([updateToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('accepted');

      // verify chain now has 2 ops
      const chainRes = await req(`/identities/${identity.did}`);
      const chainBody = await json(chainRes);
      expect(chainBody.log).toHaveLength(2);
    });

    it('should accept identity create + update in a single batch', async () => {
      const identity = await createIdentity();

      // create an update operation that chains off the genesis
      const newKey = makeKey();
      const updateOp: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID: identity.operationCID,
        authKeys: [identity.authKey.key, newKey.key],
        assertKeys: [],
        controllerKeys: [identity.controller.key],
        createdAt: ts(2),
      };

      const { jwsToken: updateToken } = await signIdentityOperation({
        operation: updateOp,
        signer: identity.controller.signer,
        keyId: identity.controller.keyId,
        identityDID: identity.did,
      });

      // submit in REVERSE order — update first, then genesis
      // the intra-kind topological sort should fix the processing order
      // but results must come back in SUBMISSION order
      const res = await postOps([updateToken, identity.jwsToken]);
      const body = await json(res);
      const accepted = body.results.filter((r: { status: string }) => r.status === 'accepted');
      expect(accepted).toHaveLength(2);

      // results[0] should be the update (submitted first), results[1] should be the genesis
      expect(body.results[0].cid).toBeTruthy();
      expect(body.results[1].cid).toBeTruthy();
      expect(body.results[0].cid).not.toBe(body.results[1].cid);

      // verify chain has both ops
      const chainRes = await req(`/identities/${identity.did}`);
      const chainBody = await json(chainRes);
      expect(chainBody.log).toHaveLength(2);
    });

    it('should accept a 3-step identity chain in a single batch (any order)', async () => {
      const identity = await createIdentity();

      // update1 chains off genesis
      const key2 = makeKey();
      const update1Op: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID: identity.operationCID,
        authKeys: [identity.authKey.key, key2.key],
        assertKeys: [],
        controllerKeys: [identity.controller.key],
        createdAt: ts(2),
      };
      const { jwsToken: update1Token, operationCID: update1CID } = await signIdentityOperation({
        operation: update1Op,
        signer: identity.controller.signer,
        keyId: identity.controller.keyId,
        identityDID: identity.did,
      });

      // update2 chains off update1
      const key3 = makeKey();
      const update2Op: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID: update1CID,
        authKeys: [key3.key],
        assertKeys: [],
        controllerKeys: [identity.controller.key],
        createdAt: ts(3),
      };
      const { jwsToken: update2Token } = await signIdentityOperation({
        operation: update2Op,
        signer: identity.controller.signer,
        keyId: identity.controller.keyId,
        identityDID: identity.did,
      });

      // submit in REVERSE order: update2, update1, genesis
      const res = await postOps([update2Token, update1Token, identity.jwsToken]);
      const body = await json(res);
      const accepted = body.results.filter((r: { status: string }) => r.status === 'accepted');
      expect(accepted).toHaveLength(3);

      // verify the chain has all 3 ops
      const chainRes = await req(`/identities/${identity.did}`);
      const chainBody = await json(chainRes);
      expect(chainBody.log).toHaveLength(3);
    });

    it('should be idempotent for duplicate operations', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);
      const res = await postOps([identity.jwsToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('accepted');
    });
  });

  // ---------------------------------------------------------------------------
  // content chain lifecycle
  // ---------------------------------------------------------------------------

  describe('content chain ingestion', () => {
    it('should accept a content chain genesis after identity exists', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);

      // submit both in one batch — content FIRST, identity SECOND
      // dependency sort processes identity first, but results must match submission order
      const res = await postOps([content.jwsToken, identity.jwsToken]);
      const body = await json(res);

      // both should be accepted (dependency sort ensures identity is processed first)
      const accepted = body.results.filter((r: { status: string }) => r.status === 'accepted');
      expect(accepted).toHaveLength(2);

      // results must be in submission order: content-op first, identity-op second
      expect(body.results[0].kind).toBe('content-op');
      expect(body.results[1].kind).toBe('identity-op');
    });

    it('should serve content chain via GET', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      // find the contentId from the ingestion result
      const ingestRes = await postOps([content.jwsToken]); // idempotent re-submit
      const ingestBody = await json(ingestRes);
      const contentId = ingestBody.results[0].chainId;

      const res = await req(`/content/${contentId}`);
      expect(res.status).toBe(200);

      const body = await json(res);
      expect(body.contentId).toBe(contentId);
      expect(body.log).toHaveLength(1);
      expect(body.state.currentDocumentCID).toBe(content.documentCID);
    });

    it('should reject content operation when identity is unknown', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);

      // submit content op without identity — should fail
      const res = await postOps([content.jwsToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('rejected');
    });
  });

  // ---------------------------------------------------------------------------
  // operation lookup
  // ---------------------------------------------------------------------------

  describe('operation lookup', () => {
    it('should serve individual operations by CID', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      const res = await req(`/operations/${identity.operationCID}`);
      expect(res.status).toBe(200);

      const body = await json(res);
      expect(body.cid).toBe(identity.operationCID);
      expect(body.jwsToken).toBe(identity.jwsToken);
      expect(body.chainType).toBe('identity');
    });

    it('should return 404 for unknown operation', async () => {
      const res = await req(
        '/operations/bafyreibogus000000000000000000000000000000000000000000000',
      );
      expect(res.status).toBe(404);
    });
  });

  // ---------------------------------------------------------------------------
  // beacon lifecycle
  // ---------------------------------------------------------------------------

  describe('beacon ingestion', () => {
    it('should accept a beacon from a known identity', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      const beaconPayload: BeaconPayload = {
        version: 1,
        type: 'beacon',
        did: identity.did,
        merkleRoot: 'a'.repeat(64),
        createdAt: ts(2),
      };

      const kid = `${identity.did}#${identity.controller.keyId}`;
      const { jwsToken: beaconToken } = await signBeacon({
        payload: beaconPayload,
        signer: identity.controller.signer,
        kid,
      });

      const res = await postOps([beaconToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('accepted');
      expect(body.results[0].kind).toBe('beacon');

      // query the beacon
      const beaconRes = await req(`/beacons/${identity.did}`);
      expect(beaconRes.status).toBe(200);
      const beaconBody = await json(beaconRes);
      expect(beaconBody.payload.merkleRoot).toBe('a'.repeat(64));
    });

    it('should replace beacon with newer one', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      const kid = `${identity.did}#${identity.controller.keyId}`;

      const beacon1: BeaconPayload = {
        version: 1,
        type: 'beacon',
        did: identity.did,
        merkleRoot: 'a'.repeat(64),
        createdAt: ts(2),
      };
      const { jwsToken: token1 } = await signBeacon({
        payload: beacon1,
        signer: identity.controller.signer,
        kid,
      });

      const beacon2: BeaconPayload = {
        version: 1,
        type: 'beacon',
        did: identity.did,
        merkleRoot: 'b'.repeat(64),
        createdAt: ts(3),
      };
      const { jwsToken: token2 } = await signBeacon({
        payload: beacon2,
        signer: identity.controller.signer,
        kid,
      });

      await postOps([token1]);
      await postOps([token2]);

      const beaconRes = await req(`/beacons/${identity.did}`);
      const beaconBody = await json(beaconRes);
      expect(beaconBody.payload.merkleRoot).toBe('b'.repeat(64));
    });
  });

  // ---------------------------------------------------------------------------
  // countersignature lifecycle
  // ---------------------------------------------------------------------------

  describe('countersignature ingestion', () => {
    it('should accept a countersignature on a known content operation', async () => {
      const author = await createIdentity();
      const witness = await createIdentity();
      const content = await createContentOp(author);

      // ingest identities + content op
      await postOps([author.jwsToken, witness.jwsToken, content.jwsToken]);

      // find the content operation's payload to countersign
      const decoded = (await import('@metalabel/dfos-protocol/crypto')).decodeJwsUnsafe(
        content.jwsToken,
      );
      const { ContentOperation } = await import('@metalabel/dfos-protocol/chain');
      const parsed = ContentOperation.safeParse(decoded!.payload);
      const opPayload = parsed.data!;

      const witnessKid = `${witness.did}#${witness.authKey.keyId}`;
      const { jwsToken: csToken } = await signCountersignature({
        operationPayload: opPayload,
        signer: witness.authKey.signer,
        kid: witnessKid,
      });

      const res = await postOps([csToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('accepted');
      expect(body.results[0].kind).toBe('countersig');
      expect(body.results[0].chainId).toBeDefined();

      // query countersignatures
      const csRes = await req(`/operations/${content.operationCID}/countersignatures`);
      expect(csRes.status).toBe(200);
      const csBody = await json(csRes);
      expect(csBody.countersignatures).toHaveLength(1);
    });

    it('should be idempotent for duplicate countersignatures', async () => {
      const author = await createIdentity();
      const witness = await createIdentity();
      const content = await createContentOp(author);

      await postOps([author.jwsToken, witness.jwsToken, content.jwsToken]);

      const decoded = (await import('@metalabel/dfos-protocol/crypto')).decodeJwsUnsafe(
        content.jwsToken,
      );
      const { ContentOperation } = await import('@metalabel/dfos-protocol/chain');
      const parsed = ContentOperation.safeParse(decoded!.payload);
      const opPayload = parsed.data!;

      const witnessKid = `${witness.did}#${witness.authKey.keyId}`;
      const { jwsToken: csToken } = await signCountersignature({
        operationPayload: opPayload,
        signer: witness.authKey.signer,
        kid: witnessKid,
      });

      // submit the same countersignature twice
      await postOps([csToken]);
      await postOps([csToken]);

      // should still only have one
      const csRes = await req(`/operations/${content.operationCID}/countersignatures`);
      const csBody = await json(csRes);
      expect(csBody.countersignatures).toHaveLength(1);
    });

    it('should accept a beacon countersignature from a witness', async () => {
      const controller = await createIdentity();
      const witness = await createIdentity();
      await postOps([controller.jwsToken, witness.jwsToken]);

      // create and ingest a beacon
      const beaconPayload: BeaconPayload = {
        version: 1,
        type: 'beacon',
        did: controller.did,
        merkleRoot: 'c'.repeat(64),
        createdAt: ts(2),
      };

      const controllerKid = `${controller.did}#${controller.controller.keyId}`;
      const { jwsToken: beaconToken } = await signBeacon({
        payload: beaconPayload,
        signer: controller.controller.signer,
        kid: controllerKid,
      });
      await postOps([beaconToken]);

      // witness signs the same beacon payload
      const witnessKid = `${witness.did}#${witness.authKey.keyId}`;
      const { jwsToken: beaconCsToken } = await signBeacon({
        payload: beaconPayload,
        signer: witness.authKey.signer,
        kid: witnessKid,
      });

      const res = await postOps([beaconCsToken]);
      const body = await json(res);
      expect(body.results[0].status).toBe('accepted');
      expect(body.results[0].kind).toBe('beacon-countersig');
      expect(body.results[0].chainId).toBe(controller.did);

      // query beacon countersignatures via the general countersig route
      const beaconRes = await req(`/beacons/${controller.did}`);
      const beaconBody = await json(beaconRes);
      const beaconCID = beaconBody.beaconCID;

      const csRes = await req(`/countersignatures/${beaconCID}`);
      expect(csRes.status).toBe(200);
      const csBody = await json(csRes);
      expect(csBody.countersignatures).toHaveLength(1);
    });
  });

  // ---------------------------------------------------------------------------
  // content plane — blob upload/download
  // ---------------------------------------------------------------------------

  describe('content plane blobs', () => {
    it('should allow chain creator to upload and download a blob', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      // find contentId
      const chainLookup = await postOps([content.jwsToken]);
      const contentId = (await json(chainLookup)).results[0].chainId;

      // create auth token
      const authToken = await createTestAuthToken(identity);

      // encode the document as the blob (must match documentCID)
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));

      // upload
      const uploadRes = await req(`/content/${contentId}/blob`, {
        method: 'PUT',
        headers: {
          authorization: `Bearer ${authToken}`,
          'x-document-cid': content.documentCID,
          'content-type': 'application/octet-stream',
        },
        body: docBytes,
      });
      expect(uploadRes.status).toBe(200);

      // download as creator (no credential needed)
      const downloadRes = await req(`/content/${contentId}/blob`, {
        headers: { authorization: `Bearer ${authToken}` },
      });
      expect(downloadRes.status).toBe(200);
      const downloaded = new Uint8Array(await downloadRes.arrayBuffer());
      expect(downloaded).toEqual(docBytes);
      expect(downloadRes.headers.get('x-document-cid')).toBe(content.documentCID);
    });

    it('should reject blob upload when bytes do not match documentCID', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      const chainLookup = await postOps([content.jwsToken]);
      const contentId = (await json(chainLookup)).results[0].chainId;

      const authToken = await createTestAuthToken(identity);

      // upload wrong bytes — doesn't match documentCID
      const uploadRes = await req(`/content/${contentId}/blob`, {
        method: 'PUT',
        headers: {
          authorization: `Bearer ${authToken}`,
          'x-document-cid': content.documentCID,
          'content-type': 'application/octet-stream',
        },
        body: new TextEncoder().encode('completely wrong data'),
      });
      expect(uploadRes.status).toBe(400);
      const body = await json(uploadRes);
      expect(body.error).toContain('documentCID');
    });

    it('should require auth for blob upload', async () => {
      const identity = await createIdentity();
      const content = await createContentOp(identity);
      await postOps([identity.jwsToken, content.jwsToken]);

      const chainLookup = await postOps([content.jwsToken]);
      const contentId = (await json(chainLookup)).results[0].chainId;

      const res = await req(`/content/${contentId}/blob`, {
        method: 'PUT',
        headers: { 'x-document-cid': content.documentCID },
        body: new Uint8Array([1, 2, 3]),
      });
      expect(res.status).toBe(401);
    });

    it('should allow reader with DFOSContentRead credential to download', async () => {
      const creator = await createIdentity();
      const reader = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, reader.jwsToken, content.jwsToken]);

      const chainLookup = await postOps([content.jwsToken]);
      const contentId = (await json(chainLookup)).results[0].chainId;

      // upload blob as creator (encode doc as blob to match CID)
      const creatorToken = await createTestAuthToken(creator);
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await req(`/content/${contentId}/blob`, {
        method: 'PUT',
        headers: {
          authorization: `Bearer ${creatorToken}`,
          'x-document-cid': content.documentCID,
          'content-type': 'application/octet-stream',
        },
        body: docBytes,
      });

      // create a read credential from creator to reader
      const now = Math.floor(Date.now() / 1000);
      const readCredential = await createCredential({
        iss: creator.did,
        sub: reader.did,
        exp: now + 300,
        kid: `${creator.did}#${creator.authKey.keyId}`,
        type: VC_TYPE_CONTENT_READ,
        iat: now,
        sign: creator.authKey.signer,
      });

      // download as reader with credential
      const readerToken = await createTestAuthToken(reader);
      const downloadRes = await req(`/content/${contentId}/blob`, {
        headers: {
          authorization: `Bearer ${readerToken}`,
          'x-credential': readCredential,
        },
      });
      expect(downloadRes.status).toBe(200);
      const downloaded = new Uint8Array(await downloadRes.arrayBuffer());
      expect(downloaded).toEqual(docBytes);
    });

    it('should reject reader without credential', async () => {
      const creator = await createIdentity();
      const reader = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, reader.jwsToken, content.jwsToken]);

      const chainLookup = await postOps([content.jwsToken]);
      const contentId = (await json(chainLookup)).results[0].chainId;

      // upload blob (encode doc to match CID)
      const creatorToken = await createTestAuthToken(creator);
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await req(`/content/${contentId}/blob`, {
        method: 'PUT',
        headers: {
          authorization: `Bearer ${creatorToken}`,
          'x-document-cid': content.documentCID,
        },
        body: docBytes,
      });

      // try to download as reader without credential
      const readerToken = await createTestAuthToken(reader);
      const res = await req(`/content/${contentId}/blob`, {
        headers: { authorization: `Bearer ${readerToken}` },
      });
      expect(res.status).toBe(403);
    });

    it('should reject read credential issued by non-creator', async () => {
      const creator = await createIdentity();
      const attacker = await createIdentity();
      const reader = await createIdentity();
      const content = await createContentOp(creator);
      await postOps([creator.jwsToken, attacker.jwsToken, reader.jwsToken, content.jwsToken]);

      const chainLookup = await postOps([content.jwsToken]);
      const contentId = (await json(chainLookup)).results[0].chainId;

      // upload blob as creator
      const creatorToken = await createTestAuthToken(creator);
      const docBytes = new TextEncoder().encode(JSON.stringify(content.document));
      await req(`/content/${contentId}/blob`, {
        method: 'PUT',
        headers: {
          authorization: `Bearer ${creatorToken}`,
          'x-document-cid': content.documentCID,
        },
        body: docBytes,
      });

      // attacker issues a read credential to reader (not the creator!)
      const now = Math.floor(Date.now() / 1000);
      const fakeCredential = await createCredential({
        iss: attacker.did,
        sub: reader.did,
        exp: now + 300,
        kid: `${attacker.did}#${attacker.authKey.keyId}`,
        type: VC_TYPE_CONTENT_READ,
        iat: now,
        sign: attacker.authKey.signer,
      });

      // reader tries to download with attacker-issued credential
      const readerToken = await createTestAuthToken(reader);
      const res = await req(`/content/${contentId}/blob`, {
        headers: {
          authorization: `Bearer ${readerToken}`,
          'x-credential': fakeCredential,
        },
      });
      expect(res.status).toBe(403);
    });
  });

  // ---------------------------------------------------------------------------
  // key rotation — auth must use current keys only
  // ---------------------------------------------------------------------------

  describe('key rotation security', () => {
    it('should reject auth tokens signed with rotated-out keys', async () => {
      const identity = await createIdentity();
      await postOps([identity.jwsToken]);

      // rotate the auth key
      const newAuthKey = makeKey();
      const updateOp: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID: identity.operationCID,
        authKeys: [newAuthKey.key], // old auth key removed
        assertKeys: [],
        controllerKeys: [identity.controller.key],
        createdAt: ts(2),
      };

      const { jwsToken: updateToken } = await signIdentityOperation({
        operation: updateOp,
        signer: identity.controller.signer,
        keyId: identity.controller.keyId,
        identityDID: identity.did,
      });
      await postOps([updateToken]);

      // create an auth token with the OLD (rotated-out) key
      const oldAuthToken = await createTestAuthToken(identity); // uses identity.authKey (the old one)

      // create a content chain to have something to access
      const content = await createContentOp(identity);
      // but this content op was signed with the old auth key during createContentOp...
      // actually just test the auth endpoint directly
      const contentOpRes = await postOps([content.jwsToken]);
      const contentBody = await json(contentOpRes);
      // content op might fail since it was signed with old key — that's fine
      // the important test is the auth token rejection

      // try to access content plane with old auth token
      const chainLookup = await req(`/content/someid/blob`, {
        headers: { authorization: `Bearer ${oldAuthToken}` },
      });
      // should be 401 because the old key is no longer in current state
      expect(chainLookup.status).toBe(401);

      // create auth token with the NEW key — should work (404 because no blob, but not 401)
      const newAuthToken = await createTestAuthToken(identity, newAuthKey);
      const newAuthRes = await req(`/content/someid/blob`, {
        headers: { authorization: `Bearer ${newAuthToken}` },
      });
      expect(newAuthRes.status).toBe(404); // 404 = authenticated but no content, not 401
    });
  });

  // ---------------------------------------------------------------------------
  // error handling
  // ---------------------------------------------------------------------------

  describe('error handling', () => {
    it('should reject invalid JSON body', async () => {
      const res = await req('/operations', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: 'not json',
      });
      expect(res.status).toBe(400);
    });

    it('should reject empty operations array', async () => {
      const res = await req('/operations', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ operations: [] }),
      });
      expect(res.status).toBe(400);
    });

    it('should reject malformed JWS tokens', async () => {
      const res = await postOps(['not.a.valid.jws']);
      const body = await json(res);
      expect(body.results[0].status).toBe('rejected');
    });
  });
});
