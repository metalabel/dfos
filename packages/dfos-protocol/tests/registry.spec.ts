import { beforeEach, describe, expect, it } from 'vitest';
import { encodeEd25519Multikey, signContentOperation, signIdentityOperation } from '../src/chain';
import type { ContentOperation, IdentityOperation, MultikeyPublicKey } from '../src/chain';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  generateId,
  signPayloadEd25519,
} from '../src/crypto';
import { createRegistryServer } from '../src/registry';

describe('protocol registry', () => {
  let app: ReturnType<typeof createRegistryServer>['app'];
  let store: ReturnType<typeof createRegistryServer>['store'];

  beforeEach(() => {
    const server = createRegistryServer();
    app = server.app;
    store = server.store;
  });

  // --- helpers ---

  const makeKey = () => {
    const keypair = createNewEd25519Keypair();
    const keyId = generateId('key');
    const multibase = encodeEd25519Multikey(keypair.publicKey);
    const key: MultikeyPublicKey = { id: keyId, type: 'Multikey', publicKeyMultibase: multibase };
    const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
    return { keypair, keyId, key, signer };
  };

  const ts = (offset = 0) => new Date(Date.now() + offset * 60_000).toISOString();

  const createIdentityChain = async () => {
    const k = makeKey();
    const op: IdentityOperation = {
      version: 1,
      type: 'create',
      authKeys: [k.key],
      assertKeys: [k.key],
      controllerKeys: [k.key],
      createdAt: ts(),
    };
    const { jwsToken, operationCID } = await signIdentityOperation({
      operation: op,
      signer: k.signer,
      keyId: k.keyId,
    });
    return { ...k, op, jwsToken, operationCID };
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const post = async (path: string, body: unknown): Promise<{ status: number; body: any }> => {
    const res = await app.request(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const get = async (path: string): Promise<{ status: number; body: any }> => {
    const res = await app.request(path);
    return { status: res.status, body: await res.json() };
  };

  // =========================================================================
  // POST /identities
  // =========================================================================

  describe('POST /identities', () => {
    it('should accept a valid identity chain', async () => {
      const { jwsToken } = await createIdentityChain();
      const res = await post('/identities', { chain: [jwsToken] });
      expect(res.status).toBe(201);
      expect(res.body.did).toMatch(/^did:dfos:/);

      expect(res.body.isDeleted).toBe(false);
      expect(res.body.controllerKeys).toHaveLength(1);
    });

    it('should return 200 on resubmission of same chain (noop)', async () => {
      const { jwsToken } = await createIdentityChain();
      await post('/identities', { chain: [jwsToken] });
      const res = await post('/identities', { chain: [jwsToken] });
      expect(res.status).toBe(200);
    });

    it('should accept chain extension', async () => {
      const gen = await createIdentityChain();
      const res1 = await post('/identities', { chain: [gen.jwsToken] });
      expect(res1.status).toBe(201);

      const newK = makeKey();
      const update: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID: gen.operationCID,
        authKeys: [newK.key],
        assertKeys: [newK.key],
        controllerKeys: [newK.key],
        createdAt: ts(1),
      };
      const { jwsToken: updateJws } = await signIdentityOperation({
        operation: update,
        signer: gen.signer,
        keyId: gen.keyId,
        identityDID: res1.body.did,
      });

      const res2 = await post('/identities', { chain: [gen.jwsToken, updateJws] });
      expect(res2.status).toBe(201);
      expect(res2.body.controllerKeys[0].id).toBe(newK.keyId);
    });

    it('should reject invalid chain with 400', async () => {
      const res = await post('/identities', { chain: ['not-a-jws'] });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('BAD_REQUEST');
    });

    it('should reject empty chain with 400', async () => {
      const res = await post('/identities', { chain: [] });
      expect(res.status).toBe(400);
    });

    it('should reject fork with 409', async () => {
      const gen = await createIdentityChain();
      await post('/identities', { chain: [gen.jwsToken] });

      // create a different extension (fork)
      const k2 = makeKey();
      const k3 = makeKey();

      const fork1: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID: gen.operationCID,
        authKeys: [k2.key],
        assertKeys: [k2.key],
        controllerKeys: [k2.key],
        createdAt: ts(1),
      };

      // submit the first extension
      const res1 = await post('/identities', { chain: [gen.jwsToken] });
      const did = res1.body.did;

      const { jwsToken: fork1Jws } = await signIdentityOperation({
        operation: fork1,
        signer: gen.signer,
        keyId: gen.keyId,
        identityDID: did,
      });
      await post('/identities', { chain: [gen.jwsToken, fork1Jws] });

      // create a DIFFERENT extension from same parent
      const fork2: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID: gen.operationCID,
        authKeys: [k3.key],
        assertKeys: [k3.key],
        controllerKeys: [k3.key],
        createdAt: ts(2),
      };
      const { jwsToken: fork2Jws } = await signIdentityOperation({
        operation: fork2,
        signer: gen.signer,
        keyId: gen.keyId,
        identityDID: did,
      });

      const res = await post('/identities', { chain: [gen.jwsToken, fork2Jws] });
      expect(res.status).toBe(409);
      expect(res.body.error).toBe('CONFLICT');
    });
  });

  // =========================================================================
  // GET /identities/:did
  // =========================================================================

  describe('GET /identities/:did', () => {
    it('should resolve a submitted identity', async () => {
      const { jwsToken } = await createIdentityChain();
      const submitRes = await post('/identities', { chain: [jwsToken] });
      const res = await get(`/identities/${submitRes.body.did}`);
      expect(res.status).toBe(200);
      expect(res.body.did).toBe(submitRes.body.did);
      expect(res.body.controllerKeys).toHaveLength(1);
    });

    it('should return 404 for unknown DID', async () => {
      const res = await get('/identities/did:dfos:nonexistent');
      expect(res.status).toBe(404);
    });
  });

  // =========================================================================
  // GET /identities/:did/operations
  // =========================================================================

  describe('GET /identities/:did/operations', () => {
    it('should return operations newest-first', async () => {
      const gen = await createIdentityChain();
      const res1 = await post('/identities', { chain: [gen.jwsToken] });
      const did = res1.body.did;

      const update: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID: gen.operationCID,
        authKeys: [gen.key],
        assertKeys: [gen.key],
        controllerKeys: [gen.key],
        createdAt: ts(1),
      };
      const { jwsToken: updateJws } = await signIdentityOperation({
        operation: update,
        signer: gen.signer,
        keyId: gen.keyId,
        identityDID: did,
      });
      await post('/identities', { chain: [gen.jwsToken, updateJws] });

      const res = await get(`/identities/${did}/operations`);
      expect(res.status).toBe(200);
      expect(res.body.operations).toHaveLength(2);
      // newest first — update before genesis
      expect(res.body.operations[0].cid).not.toBe(res.body.operations[1].cid);
      expect(res.body.nextCursor).toBeNull();
    });

    it('should paginate with cursor', async () => {
      const gen = await createIdentityChain();
      const res1 = await post('/identities', { chain: [gen.jwsToken] });
      const did = res1.body.did;

      // extend with a second op
      const update: IdentityOperation = {
        version: 1,
        type: 'update',
        previousOperationCID: gen.operationCID,
        authKeys: [gen.key],
        assertKeys: [gen.key],
        controllerKeys: [gen.key],
        createdAt: ts(1),
      };
      const { jwsToken: updateJws } = await signIdentityOperation({
        operation: update,
        signer: gen.signer,
        keyId: gen.keyId,
        identityDID: did,
      });
      await post('/identities', { chain: [gen.jwsToken, updateJws] });

      // page 1: limit=1
      const page1 = await get(`/identities/${did}/operations?limit=1`);
      expect(page1.body.operations).toHaveLength(1);
      expect(page1.body.nextCursor).toBeTruthy();

      // page 2: use cursor
      const page2 = await get(
        `/identities/${did}/operations?limit=1&cursor=${page1.body.nextCursor}`,
      );
      expect(page2.body.operations).toHaveLength(1);
      expect(page2.body.nextCursor).toBeNull();

      // different CIDs
      expect(page1.body.operations[0].cid).not.toBe(page2.body.operations[0].cid);
    });

    it('should return 404 for unknown DID', async () => {
      const res = await get('/identities/did:dfos:nonexistent/operations');
      expect(res.status).toBe(404);
    });
  });

  // =========================================================================
  // POST /content + GET /content/:contentId
  // =========================================================================

  describe('POST /content + GET /content/:contentId', () => {
    it('should accept a content chain and derive content ID', async () => {
      // first submit an identity
      const gen = await createIdentityChain();
      const idRes = await post('/identities', { chain: [gen.jwsToken] });
      const did = idRes.body.did;
      const kid = `${did}#${gen.keyId}`;

      // create content
      const docCID = (await dagCborCanonicalEncode({ title: 'test' })).cid.toString();
      const contentOp: ContentOperation = {
        version: 1,
        type: 'create',
        documentCID: docCID,
        createdAt: ts(1),
        note: null,
      };
      const { jwsToken } = await signContentOperation({
        operation: contentOp,
        signer: gen.signer,
        kid,
      });

      const res = await post('/content', { chain: [jwsToken] });
      expect(res.status).toBe(201);
      expect(res.body.contentId).toMatch(/^[2346789acdefhknrtvz]{22}$/);
      expect(res.body.currentDocumentCID).toBe(docCID);
      expect(res.body.isDeleted).toBe(false);

      // resolve it
      const resolveRes = await get(`/content/${res.body.contentId}`);
      expect(resolveRes.status).toBe(200);
      expect(resolveRes.body.contentId).toBe(res.body.contentId);
    });

    it('should return 400 if signing identity is not registered', async () => {
      const k = makeKey();
      const docCID = (await dagCborCanonicalEncode({ test: true })).cid.toString();
      const op: ContentOperation = {
        version: 1,
        type: 'create',
        documentCID: docCID,
        createdAt: ts(),
        note: null,
      };
      const { jwsToken } = await signContentOperation({
        operation: op,
        signer: k.signer,
        kid: `did:dfos:unknown#${k.keyId}`,
      });
      const res = await post('/content', { chain: [jwsToken] });
      expect(res.status).toBe(400);
    });

    it('should return 404 for unknown content', async () => {
      const res = await get('/content/nonexistent22charshash');
      expect(res.status).toBe(404);
    });
  });

  // =========================================================================
  // GET /operations/:cid
  // =========================================================================

  describe('GET /operations/:cid', () => {
    it('should resolve a submitted operation by CID', async () => {
      const { jwsToken, operationCID } = await createIdentityChain();
      await post('/identities', { chain: [jwsToken] });

      const res = await get(`/operations/${operationCID}`);
      expect(res.status).toBe(200);
      expect(res.body.cid).toBe(operationCID);
      expect(res.body.jwsToken).toBe(jwsToken);
    });

    it('should return 404 for unknown CID', async () => {
      const res = await get('/operations/bafyreifake');
      expect(res.status).toBe(404);
    });
  });
});
