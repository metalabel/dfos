import { base58btc } from 'multiformats/bases/base58';
import { describe, expect, it } from 'vitest';
import {
  decodeMultikey,
  ED25519_PUB_MULTICODEC,
  encodeEd25519Multikey,
  signContentOperation,
  signIdentityOperation,
  verifyContentChain,
  verifyIdentityChain,
} from '../src/chain';
import type {
  ContentOperation,
  IdentityOperation,
  MultikeyPublicKey,
  VerifiedIdentity,
} from '../src/chain';
import {
  ContentOperation as ContentOperationSchema,
  IdentityOperation as IdentityOperationSchema,
} from '../src/chain/schemas';
import { createDFOSCredential } from '../src/credentials';
import {
  base64urlEncode,
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  decodeJwsUnsafe,
  generateId,
  signPayloadEd25519,
} from '../src/crypto';

// =============================================================================
// multikey
// =============================================================================

describe('multikey', () => {
  it('should encode and decode an Ed25519 public key round-trip', () => {
    const keypair = createNewEd25519Keypair();
    const encoded = encodeEd25519Multikey(keypair.publicKey);
    const decoded = decodeMultikey(encoded);
    expect(decoded.keyBytes).toEqual(keypair.publicKey);
    expect(decoded.codec).toBe(ED25519_PUB_MULTICODEC);
  });

  it('should produce z6Mk prefix', () => {
    const keypair = createNewEd25519Keypair();
    const encoded = encodeEd25519Multikey(keypair.publicKey);
    expect(encoded).toMatch(/^z6Mk/);
  });

  it('should reject wrong length public key', () => {
    expect(() => encodeEd25519Multikey(new Uint8Array(16))).toThrow(/expected 32-byte/);
  });

  it('should reject unsupported codec', () => {
    const badBytes = new Uint8Array(34);
    badBytes[0] = 0x00;
    badBytes[1] = 0x00;
    const encoded = base58btc.encode(badBytes);
    expect(() => decodeMultikey(encoded)).toThrow(/unsupported multikey codec/);
  });

  it('should produce consistent encoding across calls', () => {
    const keypair = createNewEd25519Keypair();
    const encoded1 = encodeEd25519Multikey(keypair.publicKey);
    const encoded2 = encodeEd25519Multikey(keypair.publicKey);
    expect(encoded1).toBe(encoded2);
  });
});

// =============================================================================
// identity chain
// =============================================================================

describe('identity chain', () => {
  const makeKey = () => {
    const keypair = createNewEd25519Keypair();
    const keyId = generateId('key');
    const multibase = encodeEd25519Multikey(keypair.publicKey);
    const key: MultikeyPublicKey = { id: keyId, type: 'Multikey', publicKeyMultibase: multibase };
    const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
    return { keypair, keyId, key, signer };
  };

  const ts = (offset = 0) => new Date(Date.now() + offset * 60_000).toISOString();

  const createGenesis = async () => {
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
    const identity = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [jwsToken],
    });
    return { ...k, op, jwsToken, operationCID, identity };
  };

  // --- basic lifecycle ---

  it('should create and verify identity from genesis', async () => {
    const { identity } = await createGenesis();
    expect(identity.did).toMatch(/^did:dfos:[2346789acdefhknrtvz]{22}$/);

    expect(identity.isDeleted).toBe(false);
    expect(identity.controllerKeys).toHaveLength(1);
  });

  it('should produce deterministic DID from same genesis', async () => {
    const { jwsToken } = await createGenesis();
    const r1 = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [jwsToken],
    });
    const r2 = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [jwsToken],
    });
    expect(r1.did).toBe(r2.did);
  });

  it('should verify key rotation (genesis + update)', async () => {
    const gen = await createGenesis();
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
      signer: gen.signer, // old key signs rotation
      keyId: gen.keyId,
      identityDID: gen.identity.did,
    });

    const result = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [gen.jwsToken, updateJws],
    });

    expect(result.did).toBe(gen.identity.did);
    expect(result.controllerKeys[0]?.id).toBe(newK.keyId);

    expect(result.isDeleted).toBe(false);
  });

  it('should reject update with empty controller keys', async () => {
    const gen = await createGenesis();

    const emptyKeys: IdentityOperation = {
      version: 1,
      type: 'update',
      previousOperationCID: gen.operationCID,
      authKeys: [],
      assertKeys: [],
      controllerKeys: [],
      createdAt: ts(1),
    };
    const { jwsToken: emptyKeysJws } = await signIdentityOperation({
      operation: emptyKeys,
      signer: gen.signer,
      keyId: gen.keyId,
      identityDID: gen.identity.did,
    });

    await expect(
      verifyIdentityChain({
        didPrefix: 'did:dfos',
        log: [gen.jwsToken, emptyKeysJws],
      }),
    ).rejects.toThrow(/at least one controller key/i);
  });

  it('should verify delete operation', async () => {
    const gen = await createGenesis();

    const del: IdentityOperation = {
      version: 1,
      type: 'delete',
      previousOperationCID: gen.operationCID,
      createdAt: ts(1),
    };
    const { jwsToken: delJws } = await signIdentityOperation({
      operation: del,
      signer: gen.signer,
      keyId: gen.keyId,
      identityDID: gen.identity.did,
    });

    const result = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [gen.jwsToken, delJws],
    });
    expect(result.isDeleted).toBe(true);
    expect(result.did).toBe(gen.identity.did);
  });

  // --- CID consistency ---

  it('should derive CID from JWS payload consistent with dagCborCanonicalEncode', async () => {
    const { jwsToken, op } = await createGenesis();
    const encoded = await dagCborCanonicalEncode(op);
    const decoded = decodeJwsUnsafe(jwsToken)!;
    const fromPayload = await dagCborCanonicalEncode(decoded.payload);
    expect(fromPayload.cid.toString()).toBe(encoded.cid.toString());
  });

  // --- JWS header format ---

  it('should use bare kid for genesis, DID URL for updates', async () => {
    const gen = await createGenesis();
    const genHeader = decodeJwsUnsafe(gen.jwsToken)!.header;
    expect(genHeader.kid).toBe(gen.keyId); // bare
    expect(genHeader.typ).toBe('did:dfos:identity-op');

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
      identityDID: gen.identity.did,
    });
    const updateHeader = decodeJwsUnsafe(updateJws)!.header;
    expect(updateHeader.kid).toBe(`${gen.identity.did}#${gen.keyId}`); // DID URL
  });

  // --- cid header ---

  it('should include cid in JWS protected header matching operation CID', async () => {
    const { jwsToken, operationCID } = await createGenesis();
    const header = decodeJwsUnsafe(jwsToken)!.header;
    expect(header.cid).toBe(operationCID);
  });

  it('should reject missing cid in protected header', async () => {
    const k = makeKey();
    const op: IdentityOperation = {
      version: 1,
      type: 'create',
      authKeys: [k.key],
      assertKeys: [k.key],
      controllerKeys: [k.key],
      createdAt: ts(),
    };
    // manually construct JWS without cid header
    const header = { alg: 'EdDSA', typ: 'did:dfos:identity-op', kid: k.keyId };
    const headerB64 = base64urlEncode(JSON.stringify(header));
    const payloadB64 = base64urlEncode(JSON.stringify(op as unknown as Record<string, unknown>));
    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const sig = await k.signer(signingInput);
    const jwsToken = `${headerB64}.${payloadB64}.${base64urlEncode(sig)}`;

    await expect(verifyIdentityChain({ didPrefix: 'did:dfos', log: [jwsToken] })).rejects.toThrow(
      /missing cid/i,
    );
  });

  it('should reject mismatched cid in protected header', async () => {
    const k = makeKey();
    const op: IdentityOperation = {
      version: 1,
      type: 'create',
      authKeys: [k.key],
      assertKeys: [k.key],
      controllerKeys: [k.key],
      createdAt: ts(),
    };
    // manually construct JWS with wrong cid header
    const header = {
      alg: 'EdDSA',
      typ: 'did:dfos:identity-op',
      kid: k.keyId,
      cid: 'bafyreifake',
    };
    const headerB64 = base64urlEncode(JSON.stringify(header));
    const payloadB64 = base64urlEncode(JSON.stringify(op as unknown as Record<string, unknown>));
    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const sig = await k.signer(signingInput);
    const jwsToken = `${headerB64}.${payloadB64}.${base64urlEncode(sig)}`;

    await expect(verifyIdentityChain({ didPrefix: 'did:dfos', log: [jwsToken] })).rejects.toThrow(
      /cid mismatch/i,
    );
  });

  // --- error cases ---

  it('should reject empty log', async () => {
    await expect(verifyIdentityChain({ didPrefix: 'did:dfos', log: [] })).rejects.toThrow(
      /at least one/i,
    );
  });

  it('should reject log starting with update', async () => {
    const k = makeKey();
    const op: IdentityOperation = {
      version: 1,
      type: 'update',
      previousOperationCID: 'bafyreifake',
      authKeys: [k.key],
      assertKeys: [k.key],
      controllerKeys: [k.key],
      createdAt: ts(),
    };
    const { jwsToken } = await signIdentityOperation({
      operation: op,
      signer: k.signer,
      keyId: k.keyId,
    });
    await expect(verifyIdentityChain({ didPrefix: 'did:dfos', log: [jwsToken] })).rejects.toThrow(
      /first operation must be create/i,
    );
  });

  it('should reject invalid signature', async () => {
    const { jwsToken } = await createGenesis();
    const parts = jwsToken.split('.');
    const tampered = `${parts[0]}.${parts[1]}.invalidSignatureAAAAAAAAAAAAAAAA`;
    await expect(verifyIdentityChain({ didPrefix: 'did:dfos', log: [tampered] })).rejects.toThrow(
      /invalid signature/i,
    );
  });

  it('should reject incorrect previousCID', async () => {
    const gen = await createGenesis();
    const update: IdentityOperation = {
      version: 1,
      type: 'update',
      previousOperationCID: 'wrong-cid',
      authKeys: [gen.key],
      assertKeys: [gen.key],
      controllerKeys: [gen.key],
      createdAt: ts(1),
    };
    const { jwsToken: updateJws } = await signIdentityOperation({
      operation: update,
      signer: gen.signer,
      keyId: gen.keyId,
      identityDID: gen.identity.did,
    });
    await expect(
      verifyIdentityChain({
        didPrefix: 'did:dfos',
        log: [gen.jwsToken, updateJws],
      }),
    ).rejects.toThrow(/previousCID is incorrect/i);
  });

  it('should reject non-increasing createdAt', async () => {
    const gen = await createGenesis();
    const update: IdentityOperation = {
      version: 1,
      type: 'update',
      previousOperationCID: gen.operationCID,
      authKeys: [gen.key],
      assertKeys: [gen.key],
      controllerKeys: [gen.key],
      createdAt: ts(-10), // in the past
    };
    const { jwsToken: updateJws } = await signIdentityOperation({
      operation: update,
      signer: gen.signer,
      keyId: gen.keyId,
      identityDID: gen.identity.did,
    });
    await expect(
      verifyIdentityChain({
        didPrefix: 'did:dfos',
        log: [gen.jwsToken, updateJws],
      }),
    ).rejects.toThrow(/createdAt/i);
  });

  it('should reject operations after delete', async () => {
    const gen = await createGenesis();
    const del: IdentityOperation = {
      version: 1,
      type: 'delete',
      previousOperationCID: gen.operationCID,
      createdAt: ts(1),
    };
    const { jwsToken: delJws, operationCID: delCID } = await signIdentityOperation({
      operation: del,
      signer: gen.signer,
      keyId: gen.keyId,
      identityDID: gen.identity.did,
    });

    const update: IdentityOperation = {
      version: 1,
      type: 'update',
      previousOperationCID: delCID,
      authKeys: [gen.key],
      assertKeys: [gen.key],
      controllerKeys: [gen.key],
      createdAt: ts(2),
    };
    const { jwsToken: updateJws } = await signIdentityOperation({
      operation: update,
      signer: gen.signer,
      keyId: gen.keyId,
      identityDID: gen.identity.did,
    });

    await expect(
      verifyIdentityChain({
        didPrefix: 'did:dfos',
        log: [gen.jwsToken, delJws, updateJws],
      }),
    ).rejects.toThrow(/deleted/i);
  });

  it('should allow update with empty auth/assert keys if controller keys present', async () => {
    const gen = await createGenesis();
    const newK = makeKey();

    const update: IdentityOperation = {
      version: 1,
      type: 'update',
      previousOperationCID: gen.operationCID,
      authKeys: [],
      assertKeys: [],
      controllerKeys: [newK.key],
      createdAt: ts(1),
    };
    const { jwsToken: updateJws } = await signIdentityOperation({
      operation: update,
      signer: gen.signer,
      keyId: gen.keyId,
      identityDID: gen.identity.did,
    });

    const result = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [gen.jwsToken, updateJws],
    });
    expect(result.controllerKeys).toHaveLength(1);
    expect(result.authKeys).toHaveLength(0);
    expect(result.assertKeys).toHaveLength(0);
    expect(result.isDeleted).toBe(false);
  });

  it('should reject create with no controller keys', async () => {
    const k = makeKey();
    const op: IdentityOperation = {
      version: 1,
      type: 'create',
      authKeys: [k.key],
      assertKeys: [],
      controllerKeys: [],
      createdAt: ts(),
    };
    const { jwsToken } = await signIdentityOperation({
      operation: op,
      signer: k.signer,
      keyId: k.keyId,
    });
    await expect(verifyIdentityChain({ didPrefix: 'did:dfos', log: [jwsToken] })).rejects.toThrow(
      /at least one controller key/i,
    );
  });
});

// =============================================================================
// content chain
// =============================================================================

describe('content chain', () => {
  const makeIdentity = () => {
    const keypair = createNewEd25519Keypair();
    const keyId = generateId('key');
    const did = `did:dfos:${generateId('test').substring(5)}`;
    const kid = `${did}#${keyId}`;
    const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
    const resolveKey = async (_kid: string) => keypair.publicKey;
    return { keypair, keyId, did, kid, signer, resolveKey };
  };

  const ts = (offset = 0) => new Date(Date.now() + offset * 60_000).toISOString();

  const makeDocCID = async (content: object) => {
    const encoded = await dagCborCanonicalEncode(content);
    return encoded.cid.toString();
  };

  // --- basic lifecycle ---

  it('should create and verify a single-op content chain', async () => {
    const id = makeIdentity();
    const docCID = await makeDocCID({ type: 'post', title: 'Hello', body: 'World' });

    const op: ContentOperation = {
      version: 1,
      type: 'create',
      did: id.did,
      documentCID: docCID,
      baseDocumentCID: null,
      createdAt: ts(),
      note: null,
    };
    const { jwsToken } = await signContentOperation({
      operation: op,
      signer: id.signer,
      kid: id.kid,
    });

    const result = await verifyContentChain({
      log: [jwsToken],
      resolveKey: id.resolveKey,
    });

    expect(result.contentId).toMatch(/^[2346789acdefhknrtvz]{22}$/);
    expect(result.genesisCID).toBeTruthy();
    expect(result.headCID).toBe(result.genesisCID);
    expect(result.currentDocumentCID).toBe(docCID);
    expect(result.isDeleted).toBe(false);
    expect(result.length).toBe(1);
  });

  it('should verify create -> update chain', async () => {
    const id = makeIdentity();
    const doc1 = await makeDocCID({ type: 'post', title: 'v1' });
    const doc2 = await makeDocCID({ type: 'post', title: 'v2' });

    const createOp: ContentOperation = {
      version: 1,
      type: 'create',
      did: id.did,
      documentCID: doc1,
      baseDocumentCID: null,
      createdAt: ts(),
      note: null,
    };
    const { jwsToken: createJws, operationCID: createCID } = await signContentOperation({
      operation: createOp,
      signer: id.signer,
      kid: id.kid,
    });

    const updateOp: ContentOperation = {
      version: 1,
      type: 'update',
      did: id.did,
      previousOperationCID: createCID,
      documentCID: doc2,
      baseDocumentCID: null,
      createdAt: ts(1),
      note: 'edited title',
    };
    const { jwsToken: updateJws } = await signContentOperation({
      operation: updateOp,
      signer: id.signer,
      kid: id.kid,
    });

    const result = await verifyContentChain({
      log: [createJws, updateJws],
      resolveKey: id.resolveKey,
    });

    expect(result.currentDocumentCID).toBe(doc2);
    expect(result.headCID).not.toBe(result.genesisCID);
    expect(result.length).toBe(2);
    expect(result.isDeleted).toBe(false);
  });

  it('should verify update with null documentCID (clear)', async () => {
    const id = makeIdentity();
    const doc1 = await makeDocCID({ type: 'post', title: 'v1' });

    const createOp: ContentOperation = {
      version: 1,
      type: 'create',
      did: id.did,
      documentCID: doc1,
      baseDocumentCID: null,
      createdAt: ts(),
      note: null,
    };
    const { jwsToken: createJws, operationCID: createCID } = await signContentOperation({
      operation: createOp,
      signer: id.signer,
      kid: id.kid,
    });

    const clearOp: ContentOperation = {
      version: 1,
      type: 'update',
      did: id.did,
      previousOperationCID: createCID,
      documentCID: null, // clear
      baseDocumentCID: null,
      createdAt: ts(1),
      note: 'cleared content',
    };
    const { jwsToken: clearJws } = await signContentOperation({
      operation: clearOp,
      signer: id.signer,
      kid: id.kid,
    });

    const result = await verifyContentChain({
      log: [createJws, clearJws],
      resolveKey: id.resolveKey,
    });

    expect(result.currentDocumentCID).toBeNull();
    expect(result.isDeleted).toBe(false);
  });

  it('should verify delete terminates chain', async () => {
    const id = makeIdentity();
    const doc1 = await makeDocCID({ type: 'post', title: 'v1' });

    const createOp: ContentOperation = {
      version: 1,
      type: 'create',
      did: id.did,
      documentCID: doc1,
      baseDocumentCID: null,
      createdAt: ts(),
      note: null,
    };
    const { jwsToken: createJws, operationCID: createCID } = await signContentOperation({
      operation: createOp,
      signer: id.signer,
      kid: id.kid,
    });

    const deleteOp: ContentOperation = {
      version: 1,
      type: 'delete',
      did: id.did,
      previousOperationCID: createCID,
      createdAt: ts(1),
      note: 'removing content',
    };
    const { jwsToken: deleteJws } = await signContentOperation({
      operation: deleteOp,
      signer: id.signer,
      kid: id.kid,
    });

    const result = await verifyContentChain({
      log: [createJws, deleteJws],
      resolveKey: id.resolveKey,
    });

    expect(result.isDeleted).toBe(true);
    expect(result.currentDocumentCID).toBeNull();
    expect(result.length).toBe(2);
  });

  it('should verify full lifecycle: create -> update -> update -> delete', async () => {
    const id = makeIdentity();
    const doc1 = await makeDocCID({ type: 'post', title: 'draft' });
    const doc2 = await makeDocCID({ type: 'post', title: 'published' });
    const doc3 = await makeDocCID({ type: 'post', title: 'final edit' });

    const ops: { jwsToken: string; operationCID: string }[] = [];

    // create
    const r1 = await signContentOperation({
      operation: {
        version: 1,
        type: 'create',
        did: id.did,
        documentCID: doc1,
        baseDocumentCID: null,
        createdAt: ts(0),
        note: null,
      },
      signer: id.signer,
      kid: id.kid,
    });
    ops.push(r1);

    // update 1
    const r2 = await signContentOperation({
      operation: {
        version: 1,
        type: 'update',
        did: id.did,
        previousOperationCID: r1.operationCID,
        documentCID: doc2,
        baseDocumentCID: null,
        createdAt: ts(1),
        note: null,
      },
      signer: id.signer,
      kid: id.kid,
    });
    ops.push(r2);

    // update 2
    const r3 = await signContentOperation({
      operation: {
        version: 1,
        type: 'update',
        did: id.did,
        previousOperationCID: r2.operationCID,
        documentCID: doc3,
        baseDocumentCID: null,
        createdAt: ts(2),
        note: 'final',
      },
      signer: id.signer,
      kid: id.kid,
    });
    ops.push(r3);

    // delete
    const r4 = await signContentOperation({
      operation: {
        version: 1,
        type: 'delete',
        did: id.did,
        previousOperationCID: r3.operationCID,
        createdAt: ts(3),
        note: 'removing',
      },
      signer: id.signer,
      kid: id.kid,
    });
    ops.push(r4);

    const result = await verifyContentChain({
      log: ops.map((o) => o.jwsToken),
      resolveKey: id.resolveKey,
    });

    expect(result.length).toBe(4);
    expect(result.isDeleted).toBe(true);
    expect(result.genesisCID).toBe(r1.operationCID);
    expect(result.headCID).toBe(r4.operationCID);
  });

  // --- JWS header format ---

  it('should use did:dfos:content-op as JWS typ', async () => {
    const id = makeIdentity();
    const docCID = await makeDocCID({ test: true });
    const op: ContentOperation = {
      version: 1,
      type: 'create',
      did: id.did,
      documentCID: docCID,
      baseDocumentCID: null,
      createdAt: ts(),
      note: null,
    };
    const { jwsToken } = await signContentOperation({
      operation: op,
      signer: id.signer,
      kid: id.kid,
    });
    const decoded = decodeJwsUnsafe(jwsToken)!;
    expect(decoded.header.typ).toBe('did:dfos:content-op');
    expect(decoded.header.kid).toBe(id.kid);
    expect(decoded.header.alg).toBe('EdDSA');
  });

  // --- CID consistency ---

  it('should derive operation CID consistent with dagCborCanonicalEncode', async () => {
    const id = makeIdentity();
    const docCID = await makeDocCID({ test: true });
    const op: ContentOperation = {
      version: 1,
      type: 'create',
      did: id.did,
      documentCID: docCID,
      baseDocumentCID: null,
      createdAt: ts(),
      note: null,
    };
    const { jwsToken, operationCID } = await signContentOperation({
      operation: op,
      signer: id.signer,
      kid: id.kid,
    });

    // verify CID matches payload round-trip
    const decoded = decodeJwsUnsafe(jwsToken)!;
    const fromPayload = await dagCborCanonicalEncode(decoded.payload);
    expect(fromPayload.cid.toString()).toBe(operationCID);
  });

  // --- cid header ---

  it('should include cid in JWS protected header matching operation CID', async () => {
    const id = makeIdentity();
    const docCID = await makeDocCID({ test: true });
    const op: ContentOperation = {
      version: 1,
      type: 'create',
      did: id.did,
      documentCID: docCID,
      baseDocumentCID: null,
      createdAt: ts(),
      note: null,
    };
    const { jwsToken, operationCID } = await signContentOperation({
      operation: op,
      signer: id.signer,
      kid: id.kid,
    });
    const header = decodeJwsUnsafe(jwsToken)!.header;
    expect(header.cid).toBe(operationCID);
  });

  it('should reject missing cid in content chain protected header', async () => {
    const id = makeIdentity();
    const docCID = await makeDocCID({ test: true });
    const op: ContentOperation = {
      version: 1,
      type: 'create',
      did: id.did,
      documentCID: docCID,
      baseDocumentCID: null,
      createdAt: ts(),
      note: null,
    };
    // manually construct JWS without cid header
    const header = { alg: 'EdDSA', typ: 'did:dfos:content-op', kid: id.kid };
    const headerB64 = base64urlEncode(JSON.stringify(header));
    const payloadB64 = base64urlEncode(JSON.stringify(op as unknown as Record<string, unknown>));
    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const sig = await id.signer(signingInput);
    const jwsToken = `${headerB64}.${payloadB64}.${base64urlEncode(sig)}`;

    await expect(
      verifyContentChain({ log: [jwsToken], resolveKey: id.resolveKey }),
    ).rejects.toThrow(/missing cid/i);
  });

  it('should reject mismatched cid in content chain protected header', async () => {
    const id = makeIdentity();
    const docCID = await makeDocCID({ test: true });
    const op: ContentOperation = {
      version: 1,
      type: 'create',
      did: id.did,
      documentCID: docCID,
      baseDocumentCID: null,
      createdAt: ts(),
      note: null,
    };
    // manually construct JWS with wrong cid header
    const header = {
      alg: 'EdDSA',
      typ: 'did:dfos:content-op',
      kid: id.kid,
      cid: 'bafyreifake',
    };
    const headerB64 = base64urlEncode(JSON.stringify(header));
    const payloadB64 = base64urlEncode(JSON.stringify(op as unknown as Record<string, unknown>));
    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const sig = await id.signer(signingInput);
    const jwsToken = `${headerB64}.${payloadB64}.${base64urlEncode(sig)}`;

    await expect(
      verifyContentChain({ log: [jwsToken], resolveKey: id.resolveKey }),
    ).rejects.toThrow(/cid mismatch/i);
  });

  // --- error cases ---

  it('should reject empty log', async () => {
    const id = makeIdentity();
    await expect(verifyContentChain({ log: [], resolveKey: id.resolveKey })).rejects.toThrow(
      /at least one/i,
    );
  });

  it('should reject log starting with update', async () => {
    const id = makeIdentity();
    const op: ContentOperation = {
      version: 1,
      type: 'update',
      did: id.did,
      previousOperationCID: 'bafyreifake',
      documentCID: 'bafyreifake',
      baseDocumentCID: null,
      createdAt: ts(),
      note: null,
    };
    const { jwsToken } = await signContentOperation({
      operation: op,
      signer: id.signer,
      kid: id.kid,
    });
    await expect(
      verifyContentChain({ log: [jwsToken], resolveKey: id.resolveKey }),
    ).rejects.toThrow(/first operation must be create/i);
  });

  it('should reject incorrect previousOperationCID', async () => {
    const id = makeIdentity();
    const doc = await makeDocCID({ test: true });

    const createOp: ContentOperation = {
      version: 1,
      type: 'create',
      did: id.did,
      documentCID: doc,
      baseDocumentCID: null,
      createdAt: ts(),
      note: null,
    };
    const { jwsToken: createJws } = await signContentOperation({
      operation: createOp,
      signer: id.signer,
      kid: id.kid,
    });

    const updateOp: ContentOperation = {
      version: 1,
      type: 'update',
      did: id.did,
      previousOperationCID: 'wrong-cid',
      documentCID: doc,
      baseDocumentCID: null,
      createdAt: ts(1),
      note: null,
    };
    const { jwsToken: updateJws } = await signContentOperation({
      operation: updateOp,
      signer: id.signer,
      kid: id.kid,
    });

    await expect(
      verifyContentChain({ log: [createJws, updateJws], resolveKey: id.resolveKey }),
    ).rejects.toThrow(/previousOperationCID is incorrect/i);
  });

  it('should reject operations after delete', async () => {
    const id = makeIdentity();
    const doc = await makeDocCID({ test: true });

    const r1 = await signContentOperation({
      operation: {
        version: 1,
        type: 'create',
        did: id.did,
        documentCID: doc,
        baseDocumentCID: null,
        createdAt: ts(0),
        note: null,
      },
      signer: id.signer,
      kid: id.kid,
    });
    const r2 = await signContentOperation({
      operation: {
        version: 1,
        type: 'delete',
        did: id.did,
        previousOperationCID: r1.operationCID,
        createdAt: ts(1),
        note: null,
      },
      signer: id.signer,
      kid: id.kid,
    });
    const r3 = await signContentOperation({
      operation: {
        version: 1,
        type: 'update',
        did: id.did,
        previousOperationCID: r2.operationCID,
        documentCID: doc,
        baseDocumentCID: null,
        createdAt: ts(2),
        note: null,
      },
      signer: id.signer,
      kid: id.kid,
    });

    await expect(
      verifyContentChain({
        log: [r1.jwsToken, r2.jwsToken, r3.jwsToken],
        resolveKey: id.resolveKey,
      }),
    ).rejects.toThrow(/deleted/i);
  });

  it('should reject invalid signature', async () => {
    const id = makeIdentity();
    const wrongKey = createNewEd25519Keypair();
    const doc = await makeDocCID({ test: true });

    const op: ContentOperation = {
      version: 1,
      type: 'create',
      did: id.did,
      documentCID: doc,
      baseDocumentCID: null,
      createdAt: ts(),
      note: null,
    };
    const { jwsToken } = await signContentOperation({
      operation: op,
      signer: id.signer,
      kid: id.kid,
    });

    // resolve to wrong key
    await expect(
      verifyContentChain({
        log: [jwsToken],
        resolveKey: async () => wrongKey.publicKey,
      }),
    ).rejects.toThrow(/invalid signature/i);
  });

  it('should reject non-increasing createdAt', async () => {
    const id = makeIdentity();
    const doc = await makeDocCID({ test: true });

    const r1 = await signContentOperation({
      operation: {
        version: 1,
        type: 'create',
        did: id.did,
        documentCID: doc,
        baseDocumentCID: null,
        createdAt: ts(0),
        note: null,
      },
      signer: id.signer,
      kid: id.kid,
    });
    const r2 = await signContentOperation({
      operation: {
        version: 1,
        type: 'update',
        did: id.did,
        previousOperationCID: r1.operationCID,
        documentCID: doc,
        baseDocumentCID: null,
        createdAt: ts(-5), // in the past
        note: null,
      },
      signer: id.signer,
      kid: id.kid,
    });

    await expect(
      verifyContentChain({
        log: [r1.jwsToken, r2.jwsToken],
        resolveKey: id.resolveKey,
      }),
    ).rejects.toThrow(/createdAt/i);
  });

  it('should reject kid DID that does not match payload did', async () => {
    const author = makeIdentity();
    const other = makeIdentity();
    const doc = await makeDocCID({ test: true });

    const op: ContentOperation = {
      version: 1,
      type: 'create',
      did: author.did,
      documentCID: doc,
      baseDocumentCID: null,
      createdAt: ts(),
      note: null,
    };

    // sign with other's kid (DID mismatch with payload.did)
    const { jwsToken } = await signContentOperation({
      operation: op,
      signer: other.signer,
      kid: other.kid,
    });

    await expect(
      verifyContentChain({
        log: [jwsToken],
        resolveKey: other.resolveKey,
      }),
    ).rejects.toThrow(/kid DID does not match/i);
  });
});

// =============================================================================
// delegated content chain operations
// =============================================================================

describe('delegated content chain', () => {
  const makeIdentity = () => {
    const keypair = createNewEd25519Keypair();
    const keyId = generateId('key');
    const did = `did:dfos:${generateId('test').substring(5)}`;
    const kid = `${did}#${keyId}`;
    const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
    const identity: VerifiedIdentity = {
      did,
      isDeleted: false,
      authKeys: [
        { id: keyId, type: 'Multikey', publicKeyMultibase: encodeEd25519Multikey(keypair.publicKey) },
      ],
      assertKeys: [],
      controllerKeys: [],
    };
    return { keypair, keyId, did, kid, signer, identity };
  };

  const ts = (offset = 0) => new Date(Date.now() + offset * 60_000).toISOString();

  const makeDocCID = async (content: object) => {
    const encoded = await dagCborCanonicalEncode(content);
    return encoded.cid.toString();
  };

  const futureUnix = (minutes: number) => Math.floor(Date.now() / 1000) + minutes * 60;
  const pastUnix = (minutes: number) => Math.floor(Date.now() / 1000) - minutes * 60;

  // helper: create a genesis chain and return everything needed for delegation tests
  const createGenesisChain = async () => {
    const creator = makeIdentity();
    const doc = await makeDocCID({ type: 'post', title: 'genesis' });

    const createOp: ContentOperation = {
      version: 1,
      type: 'create',
      did: creator.did,
      documentCID: doc,
      baseDocumentCID: null,
      createdAt: ts(0),
      note: null,
    };
    const { jwsToken: createJws, operationCID: createCID } = await signContentOperation({
      operation: createOp,
      signer: creator.signer,
      kid: creator.kid,
    });

    // build key resolver that knows both creator and delegates
    const keys = new Map<string, Uint8Array>();
    keys.set(creator.kid, creator.keypair.publicKey);

    // build identity map for resolveIdentity
    const identityMap = new Map<string, VerifiedIdentity>();
    identityMap.set(creator.did, creator.identity);

    const resolveKey = async (kid: string) => {
      const key = keys.get(kid);
      if (!key) throw new Error(`unknown kid: ${kid}`);
      return key;
    };

    const resolveIdentity = async (did: string) => identityMap.get(did);

    const addDelegate = (delegate: ReturnType<typeof makeIdentity>) => {
      keys.set(delegate.kid, delegate.keypair.publicKey);
      identityMap.set(delegate.did, delegate.identity);
    };

    return { creator, createJws, createCID, doc, resolveKey, resolveIdentity, addDelegate };
  };

  it('should accept delegated update with valid write VC', async () => {
    const { creator, createJws, createCID, resolveKey, resolveIdentity, addDelegate } =
      await createGenesisChain();
    const delegate = makeIdentity();
    addDelegate(delegate);

    const doc2 = await makeDocCID({ type: 'post', title: 'delegated edit' });

    // verify the chain to get the contentId
    const chain = await verifyContentChain({ log: [createJws], resolveKey });

    // creator issues write credential to delegate
    const vc = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: delegate.did,
      att: [{ resource: `chain:${chain.contentId}`, action: 'write' }],
      exp: futureUnix(60),
      signer: creator.signer,
      keyId: creator.keyId,
    });

    const updateOp: ContentOperation = {
      version: 1,
      type: 'update',
      did: delegate.did,
      previousOperationCID: createCID,
      documentCID: doc2,
      baseDocumentCID: null,
      createdAt: ts(1),
      note: 'delegated edit',
      authorization: vc,
    };
    const { jwsToken: updateJws } = await signContentOperation({
      operation: updateOp,
      signer: delegate.signer,
      kid: delegate.kid,
    });

    const result = await verifyContentChain({
      log: [createJws, updateJws],
      resolveKey,
      enforceAuthorization: true,
      resolveIdentity,
    });

    expect(result.length).toBe(2);
    expect(result.currentDocumentCID).toBe(doc2);
    expect(result.creatorDID).toBe(creator.did);
    expect(result.isDeleted).toBe(false);
  });

  it('should accept delegated update with contentId-narrowed VC', async () => {
    const { creator, createJws, createCID, resolveKey, resolveIdentity, addDelegate } =
      await createGenesisChain();
    const delegate = makeIdentity();
    addDelegate(delegate);

    // first verify the chain to get the contentId
    const chain = await verifyContentChain({ log: [createJws], resolveKey });

    const doc2 = await makeDocCID({ type: 'post', title: 'narrowed edit' });

    // creator issues narrowed write credential
    const vc = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: delegate.did,
      att: [{ resource: `chain:${chain.contentId}`, action: 'write' }],
      exp: futureUnix(60),
      signer: creator.signer,
      keyId: creator.keyId,
    });

    const updateOp: ContentOperation = {
      version: 1,
      type: 'update',
      did: delegate.did,
      previousOperationCID: createCID,
      documentCID: doc2,
      baseDocumentCID: null,
      createdAt: ts(1),
      note: null,
      authorization: vc,
    };
    const { jwsToken: updateJws } = await signContentOperation({
      operation: updateOp,
      signer: delegate.signer,
      kid: delegate.kid,
    });

    const result = await verifyContentChain({
      log: [createJws, updateJws],
      resolveKey,
      enforceAuthorization: true,
      resolveIdentity,
    });

    expect(result.length).toBe(2);
    expect(result.currentDocumentCID).toBe(doc2);
  });

  it('should reject delegated update without authorization', async () => {
    const { creator, createJws, createCID, resolveKey, resolveIdentity, addDelegate } =
      await createGenesisChain();
    const delegate = makeIdentity();
    addDelegate(delegate);

    const doc2 = await makeDocCID({ type: 'post', title: 'unauthorized' });

    const updateOp: ContentOperation = {
      version: 1,
      type: 'update',
      did: delegate.did,
      previousOperationCID: createCID,
      documentCID: doc2,
      baseDocumentCID: null,
      createdAt: ts(1),
      note: null,
    };
    const { jwsToken: updateJws } = await signContentOperation({
      operation: updateOp,
      signer: delegate.signer,
      kid: delegate.kid,
    });

    await expect(
      verifyContentChain({
        log: [createJws, updateJws],
        resolveKey,
        enforceAuthorization: true,
        resolveIdentity,
      }),
    ).rejects.toThrow(/authorization credential required/i);
  });

  it('should reject delegated update with expired VC', async () => {
    const { creator, createJws, createCID, resolveKey, resolveIdentity, addDelegate } =
      await createGenesisChain();
    const delegate = makeIdentity();
    addDelegate(delegate);

    const doc2 = await makeDocCID({ type: 'post', title: 'expired vc' });

    // credential that expired well before the operation's createdAt
    const vc = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: delegate.did,
      att: [{ resource: 'chain:*', action: 'write' }],
      exp: pastUnix(60),
      signer: creator.signer,
      keyId: creator.keyId,
    });

    const updateOp: ContentOperation = {
      version: 1,
      type: 'update',
      did: delegate.did,
      previousOperationCID: createCID,
      documentCID: doc2,
      baseDocumentCID: null,
      createdAt: ts(1),
      note: null,
      authorization: vc,
    };
    const { jwsToken: updateJws } = await signContentOperation({
      operation: updateOp,
      signer: delegate.signer,
      kid: delegate.kid,
    });

    await expect(
      verifyContentChain({
        log: [createJws, updateJws],
        resolveKey,
        enforceAuthorization: true,
        resolveIdentity,
      }),
    ).rejects.toThrow(/authorization verification failed/i);
  });

  it('should reject delegated update with wrong subject', async () => {
    const { creator, createJws, createCID, resolveKey, resolveIdentity, addDelegate } =
      await createGenesisChain();
    const delegate = makeIdentity();
    const other = makeIdentity();
    addDelegate(delegate);

    const doc2 = await makeDocCID({ type: 'post', title: 'wrong sub' });

    // credential issued to a different DID than the actual signer
    const vc = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: other.did,
      att: [{ resource: 'chain:*', action: 'write' }],
      exp: futureUnix(60),
      signer: creator.signer,
      keyId: creator.keyId,
    });

    const updateOp: ContentOperation = {
      version: 1,
      type: 'update',
      did: delegate.did,
      previousOperationCID: createCID,
      documentCID: doc2,
      baseDocumentCID: null,
      createdAt: ts(1),
      note: null,
      authorization: vc,
    };
    const { jwsToken: updateJws } = await signContentOperation({
      operation: updateOp,
      signer: delegate.signer,
      kid: delegate.kid,
    });

    await expect(
      verifyContentChain({
        log: [createJws, updateJws],
        resolveKey,
        enforceAuthorization: true,
        resolveIdentity,
      }),
    ).rejects.toThrow(/authorization verification failed/i);
  });

  it('should reject delegated update with future-issued VC (iat > op.createdAt)', async () => {
    const { creator, createJws, createCID, resolveKey, resolveIdentity, addDelegate } =
      await createGenesisChain();
    const delegate = makeIdentity();
    addDelegate(delegate);

    const doc2 = await makeDocCID({ type: 'post', title: 'future vc' });

    // credential issued far in the future relative to the operation's createdAt
    const vc = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: delegate.did,
      att: [{ resource: 'chain:*', action: 'write' }],
      exp: futureUnix(120),
      iat: futureUnix(60),
      signer: creator.signer,
      keyId: creator.keyId,
    });

    const updateOp: ContentOperation = {
      version: 1,
      type: 'update',
      did: delegate.did,
      previousOperationCID: createCID,
      documentCID: doc2,
      baseDocumentCID: null,
      createdAt: ts(1),
      note: null,
      authorization: vc,
    };
    const { jwsToken: updateJws } = await signContentOperation({
      operation: updateOp,
      signer: delegate.signer,
      kid: delegate.kid,
    });

    await expect(
      verifyContentChain({
        log: [createJws, updateJws],
        resolveKey,
        enforceAuthorization: true,
        resolveIdentity,
      }),
    ).rejects.toThrow(/authorization verification failed/i);
  });

  it('should reject delegated update with wrong contentId narrowing', async () => {
    const { creator, createJws, createCID, resolveKey, resolveIdentity, addDelegate } =
      await createGenesisChain();
    const delegate = makeIdentity();
    addDelegate(delegate);

    const doc2 = await makeDocCID({ type: 'post', title: 'wrong chain' });

    // credential narrowed to a different contentId
    const vc = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: delegate.did,
      att: [{ resource: 'chain:wrong_content_id', action: 'write' }],
      exp: futureUnix(60),
      signer: creator.signer,
      keyId: creator.keyId,
    });

    const updateOp: ContentOperation = {
      version: 1,
      type: 'update',
      did: delegate.did,
      previousOperationCID: createCID,
      documentCID: doc2,
      baseDocumentCID: null,
      createdAt: ts(1),
      note: null,
      authorization: vc,
    };
    const { jwsToken: updateJws } = await signContentOperation({
      operation: updateOp,
      signer: delegate.signer,
      kid: delegate.kid,
    });

    await expect(
      verifyContentChain({
        log: [createJws, updateJws],
        resolveKey,
        enforceAuthorization: true,
        resolveIdentity,
      }),
    ).rejects.toThrow(/authorization verification failed/i);
  });

  it('should reject delegated update with read credential (wrong action)', async () => {
    const { creator, createJws, createCID, resolveKey, resolveIdentity, addDelegate } =
      await createGenesisChain();
    const delegate = makeIdentity();
    addDelegate(delegate);

    const doc2 = await makeDocCID({ type: 'post', title: 'read vc' });

    // read credential cannot authorize writes
    const vc = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: delegate.did,
      att: [{ resource: 'chain:*', action: 'read' }],
      exp: futureUnix(60),
      signer: creator.signer,
      keyId: creator.keyId,
    });

    const updateOp: ContentOperation = {
      version: 1,
      type: 'update',
      did: delegate.did,
      previousOperationCID: createCID,
      documentCID: doc2,
      baseDocumentCID: null,
      createdAt: ts(1),
      note: null,
      authorization: vc,
    };
    const { jwsToken: updateJws } = await signContentOperation({
      operation: updateOp,
      signer: delegate.signer,
      kid: delegate.kid,
    });

    await expect(
      verifyContentChain({
        log: [createJws, updateJws],
        resolveKey,
        enforceAuthorization: true,
        resolveIdentity,
      }),
    ).rejects.toThrow(/authorization verification failed/i);
  });

  it('should still accept creator operations without VC (backward compat)', async () => {
    const { creator, createJws, createCID, resolveKey } = await createGenesisChain();

    const doc2 = await makeDocCID({ type: 'post', title: 'creator edit' });

    const updateOp: ContentOperation = {
      version: 1,
      type: 'update',
      did: creator.did,
      previousOperationCID: createCID,
      documentCID: doc2,
      baseDocumentCID: null,
      createdAt: ts(1),
      note: null,
    };
    const { jwsToken: updateJws } = await signContentOperation({
      operation: updateOp,
      signer: creator.signer,
      kid: creator.kid,
    });

    const result = await verifyContentChain({
      log: [createJws, updateJws],
      resolveKey,
    });

    expect(result.length).toBe(2);
    expect(result.creatorDID).toBe(creator.did);
  });

  it('should accept non-creator signer when enforceAuthorization is not set', async () => {
    const { createJws, createCID, resolveKey, addDelegate } = await createGenesisChain();
    const delegate = makeIdentity();
    addDelegate(delegate);

    const doc2 = await makeDocCID({ type: 'post', title: 'delegate edit' });

    const updateOp: ContentOperation = {
      version: 1,
      type: 'update',
      did: delegate.did,
      previousOperationCID: createCID,
      documentCID: doc2,
      baseDocumentCID: null,
      createdAt: ts(1),
      note: null,
    };
    const { jwsToken: updateJws } = await signContentOperation({
      operation: updateOp,
      signer: delegate.signer,
      kid: delegate.kid,
    });

    // without enforceAuthorization, non-creator signers are accepted (pre-credential behavior)
    const result = await verifyContentChain({
      log: [createJws, updateJws],
      resolveKey,
    });

    expect(result.length).toBe(2);
  });

  it('should return creatorDID in verified chain result', async () => {
    const { creator, createJws, resolveKey } = await createGenesisChain();

    const result = await verifyContentChain({
      log: [createJws],
      resolveKey,
    });

    expect(result.creatorDID).toBe(creator.did);
  });
});

// =============================================================================
// operation field limits
// =============================================================================

describe('operation field limits', () => {
  const validKey: MultikeyPublicKey = {
    id: 'key_test',
    type: 'Multikey',
    publicKeyMultibase: 'z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb',
  };

  it('should reject key.id exceeding 64 chars', () => {
    const result = IdentityOperationSchema.safeParse({
      version: 1,
      type: 'create',
      authKeys: [{ ...validKey, id: 'k'.repeat(65) }],
      assertKeys: [],
      controllerKeys: [validKey],
      createdAt: '2026-01-01T00:00:00.000Z',
    });
    expect(result.success).toBe(false);
  });

  it('should reject publicKeyMultibase exceeding 128 chars', () => {
    const result = IdentityOperationSchema.safeParse({
      version: 1,
      type: 'create',
      authKeys: [{ ...validKey, publicKeyMultibase: 'z' + 'A'.repeat(128) }],
      assertKeys: [],
      controllerKeys: [validKey],
      createdAt: '2026-01-01T00:00:00.000Z',
    });
    expect(result.success).toBe(false);
  });

  it('should reject more than 16 keys per role', () => {
    const keys = Array.from({ length: 17 }, (_, i) => ({ ...validKey, id: `key_${i}` }));
    const result = IdentityOperationSchema.safeParse({
      version: 1,
      type: 'create',
      authKeys: keys,
      assertKeys: [],
      controllerKeys: [validKey],
      createdAt: '2026-01-01T00:00:00.000Z',
    });
    expect(result.success).toBe(false);
  });

  it('should reject did exceeding 256 chars', () => {
    const result = ContentOperationSchema.safeParse({
      version: 1,
      type: 'create',
      did: 'did:dfos:' + 'x'.repeat(248),
      documentCID: 'bafyreivalid',
      baseDocumentCID: null,
      createdAt: '2026-01-01T00:00:00.000Z',
      note: null,
    });
    expect(result.success).toBe(false);
  });

  it('should reject CID strings exceeding 256 chars', () => {
    const result = ContentOperationSchema.safeParse({
      version: 1,
      type: 'update',
      did: 'did:dfos:test',
      previousOperationCID: 'b'.repeat(257),
      documentCID: 'bafyreivalid',
      baseDocumentCID: null,
      createdAt: '2026-01-01T00:00:00.000Z',
      note: null,
    });
    expect(result.success).toBe(false);
  });

  it('should reject note exceeding 256 chars', () => {
    const result = ContentOperationSchema.safeParse({
      version: 1,
      type: 'create',
      did: 'did:dfos:test',
      documentCID: 'bafyreivalid',
      baseDocumentCID: null,
      createdAt: '2026-01-01T00:00:00.000Z',
      note: 'x'.repeat(257),
    });
    expect(result.success).toBe(false);
  });

  it('should accept values within limits', () => {
    const result = IdentityOperationSchema.safeParse({
      version: 1,
      type: 'create',
      authKeys: [validKey],
      assertKeys: [validKey],
      controllerKeys: [validKey],
      createdAt: '2026-01-01T00:00:00.000Z',
    });
    expect(result.success).toBe(true);
  });
});
