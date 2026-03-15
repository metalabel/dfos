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
import type { ContentOperation, IdentityOperation, MultikeyPublicKey } from '../src/chain';
import {
  ContentOperation as ContentOperationSchema,
  IdentityOperation as IdentityOperationSchema,
} from '../src/chain/schemas';
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
      documentCID: docCID,
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
      documentCID: doc1,
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
      previousOperationCID: createCID,
      documentCID: doc2,
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
      documentCID: doc1,
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
      previousOperationCID: createCID,
      documentCID: null, // clear
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
      documentCID: doc1,
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
      operation: { version: 1, type: 'create', documentCID: doc1, createdAt: ts(0), note: null },
      signer: id.signer,
      kid: id.kid,
    });
    ops.push(r1);

    // update 1
    const r2 = await signContentOperation({
      operation: {
        version: 1,
        type: 'update',
        previousOperationCID: r1.operationCID,
        documentCID: doc2,
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
        previousOperationCID: r2.operationCID,
        documentCID: doc3,
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
      documentCID: docCID,
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
      documentCID: docCID,
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
      documentCID: docCID,
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
      documentCID: docCID,
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
      documentCID: docCID,
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
      previousOperationCID: 'bafyreifake',
      documentCID: 'bafyreifake',
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
      documentCID: doc,
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
      previousOperationCID: 'wrong-cid',
      documentCID: doc,
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
      operation: { version: 1, type: 'create', documentCID: doc, createdAt: ts(0), note: null },
      signer: id.signer,
      kid: id.kid,
    });
    const r2 = await signContentOperation({
      operation: {
        version: 1,
        type: 'delete',
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
        previousOperationCID: r2.operationCID,
        documentCID: doc,
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
      documentCID: doc,
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
      operation: { version: 1, type: 'create', documentCID: doc, createdAt: ts(0), note: null },
      signer: id.signer,
      kid: id.kid,
    });
    const r2 = await signContentOperation({
      operation: {
        version: 1,
        type: 'update',
        previousOperationCID: r1.operationCID,
        documentCID: doc,
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

  it('should reject CID strings exceeding 256 chars', () => {
    const result = ContentOperationSchema.safeParse({
      version: 1,
      type: 'update',
      previousOperationCID: 'b'.repeat(257),
      documentCID: 'bafyreivalid',
      createdAt: '2026-01-01T00:00:00.000Z',
      note: null,
    });
    expect(result.success).toBe(false);
  });

  it('should reject note exceeding 256 chars', () => {
    const result = ContentOperationSchema.safeParse({
      version: 1,
      type: 'create',
      documentCID: 'bafyreivalid',
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
