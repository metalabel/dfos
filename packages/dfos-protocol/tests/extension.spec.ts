import { describe, expect, it } from 'vitest';
import {
  encodeEd25519Multikey,
  signContentOperation,
  signIdentityOperation,
  verifyContentChain,
  verifyContentExtensionFromTrustedState,
  verifyIdentityChain,
  verifyIdentityExtensionFromTrustedState,
} from '../src/chain';
import type {
  ContentOperation,
  IdentityOperation,
  MultikeyPublicKey,
  VerifiedContentChain,
  VerifiedIdentity,
} from '../src/chain';
import { createDFOSCredential } from '../src/credentials';
import {
  createNewEd25519Keypair,
  decodeJwsUnsafe,
  generateId,
  signPayloadEd25519,
} from '../src/crypto';

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

const ts = (offset = 0) => new Date(Date.now() + offset * 60_000).toISOString();

const createIdentityGenesis = async () => {
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
  const identity = await verifyIdentityChain({ didPrefix: 'did:dfos', log: [jwsToken] });
  const createdAt = op.createdAt;
  return { ...k, op, jwsToken, operationCID, identity, createdAt };
};

const createContentGenesis = async (
  creatorDID: string,
  creatorKid: string,
  signer: (msg: Uint8Array) => Promise<Uint8Array>,
) => {
  const op: ContentOperation = {
    version: 1,
    type: 'create',
    did: creatorDID,
    documentCID: 'bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenera6h5y',
    baseDocumentCID: null,
    createdAt: ts(),
    note: null,
  };
  const { jwsToken, operationCID } = await signContentOperation({
    operation: op,
    signer,
    kid: creatorKid,
  });
  return { op, jwsToken, operationCID, createdAt: op.createdAt };
};

// =============================================================================
// identity extension verification
// =============================================================================

describe('verifyIdentityExtensionFromTrustedState', () => {
  it('should produce identical state as full chain verification (update)', async () => {
    const gen = await createIdentityGenesis();
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
      identityDID: gen.identity.did,
    });

    // full chain verification
    const fullResult = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [gen.jwsToken, updateJws],
    });

    // extension verification
    const extResult = await verifyIdentityExtensionFromTrustedState({
      currentState: gen.identity,
      headCID: gen.operationCID,
      lastCreatedAt: gen.createdAt,
      newOp: updateJws,
    });

    expect(extResult.state).toEqual(fullResult);
  });

  it('should produce identical state as full chain verification (delete)', async () => {
    const gen = await createIdentityGenesis();

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

    const fullResult = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [gen.jwsToken, delJws],
    });

    const extResult = await verifyIdentityExtensionFromTrustedState({
      currentState: gen.identity,
      headCID: gen.operationCID,
      lastCreatedAt: gen.createdAt,
      newOp: delJws,
    });

    expect(extResult.state).toEqual(fullResult);
  });

  it('should chain multiple extensions matching full chain replay', async () => {
    const gen = await createIdentityGenesis();
    const k2 = makeKey();
    const k3 = makeKey();

    // step 1: update to k2
    const update1: IdentityOperation = {
      version: 1,
      type: 'update',
      previousOperationCID: gen.operationCID,
      authKeys: [k2.key],
      assertKeys: [k2.key],
      controllerKeys: [k2.key],
      createdAt: ts(1),
    };
    const { jwsToken: update1Jws } = await signIdentityOperation({
      operation: update1,
      signer: gen.signer,
      keyId: gen.keyId,
      identityDID: gen.identity.did,
    });

    const ext1 = await verifyIdentityExtensionFromTrustedState({
      currentState: gen.identity,
      headCID: gen.operationCID,
      lastCreatedAt: gen.createdAt,
      newOp: update1Jws,
    });

    // step 2: update to k3 (signed by k2)
    const update2: IdentityOperation = {
      version: 1,
      type: 'update',
      previousOperationCID: ext1.operationCID,
      authKeys: [k3.key],
      assertKeys: [k3.key],
      controllerKeys: [k3.key],
      createdAt: ts(2),
    };
    const { jwsToken: update2Jws } = await signIdentityOperation({
      operation: update2,
      signer: k2.signer,
      keyId: k2.keyId,
      identityDID: gen.identity.did,
    });

    const ext2 = await verifyIdentityExtensionFromTrustedState({
      currentState: ext1.state,
      headCID: ext1.operationCID,
      lastCreatedAt: ext1.createdAt,
      newOp: update2Jws,
    });

    // full chain replay
    const fullResult = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [gen.jwsToken, update1Jws, update2Jws],
    });

    expect(ext2.state).toEqual(fullResult);
  });

  it('should reject extending a deleted identity', async () => {
    const gen = await createIdentityGenesis();

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

    const extDel = await verifyIdentityExtensionFromTrustedState({
      currentState: gen.identity,
      headCID: gen.operationCID,
      lastCreatedAt: gen.createdAt,
      newOp: delJws,
    });

    // attempt to extend after delete
    const update: IdentityOperation = {
      version: 1,
      type: 'update',
      previousOperationCID: extDel.operationCID,
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
      verifyIdentityExtensionFromTrustedState({
        currentState: extDel.state,
        headCID: extDel.operationCID,
        lastCreatedAt: extDel.createdAt,
        newOp: updateJws,
      }),
    ).rejects.toThrow(/deleted/i);
  });

  it('should reject create as extension', async () => {
    const gen = await createIdentityGenesis();
    const k2 = makeKey();

    const create: IdentityOperation = {
      version: 1,
      type: 'create',
      authKeys: [k2.key],
      assertKeys: [k2.key],
      controllerKeys: [k2.key],
      createdAt: ts(1),
    };
    const { jwsToken: createJws } = await signIdentityOperation({
      operation: create,
      signer: k2.signer,
      keyId: k2.keyId,
    });

    await expect(
      verifyIdentityExtensionFromTrustedState({
        currentState: gen.identity,
        headCID: gen.operationCID,
        lastCreatedAt: gen.createdAt,
        newOp: createJws,
      }),
    ).rejects.toThrow(/create/i);
  });

  it('should reject wrong previousCID', async () => {
    const gen = await createIdentityGenesis();

    const update: IdentityOperation = {
      version: 1,
      type: 'update',
      previousOperationCID: 'bafkreiwrongcid00000000000000000000000000000000000000000000000',
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
      verifyIdentityExtensionFromTrustedState({
        currentState: gen.identity,
        headCID: gen.operationCID,
        lastCreatedAt: gen.createdAt,
        newOp: updateJws,
      }),
    ).rejects.toThrow(/previousCID/i);
  });

  it('should reject timestamp not after last op', async () => {
    const gen = await createIdentityGenesis();

    const update: IdentityOperation = {
      version: 1,
      type: 'update',
      previousOperationCID: gen.operationCID,
      authKeys: [gen.key],
      assertKeys: [gen.key],
      controllerKeys: [gen.key],
      createdAt: gen.createdAt, // same timestamp, not after
    };
    const { jwsToken: updateJws } = await signIdentityOperation({
      operation: update,
      signer: gen.signer,
      keyId: gen.keyId,
      identityDID: gen.identity.did,
    });

    await expect(
      verifyIdentityExtensionFromTrustedState({
        currentState: gen.identity,
        headCID: gen.operationCID,
        lastCreatedAt: gen.createdAt,
        newOp: updateJws,
      }),
    ).rejects.toThrow(/createdAt/i);
  });
});

// =============================================================================
// content extension verification
// =============================================================================

describe('verifyContentExtensionFromTrustedState', () => {
  const setupContentChain = async () => {
    const creator = await createIdentityGenesis();
    const kid = `${creator.identity.did}#${creator.keyId}`;
    const resolveKey = async (_kid: string) => creator.keypair.publicKey;

    const genesis = await createContentGenesis(creator.identity.did, kid, creator.signer);

    const chain = await verifyContentChain({
      log: [genesis.jwsToken],
      resolveKey,
    });

    return { creator, kid, resolveKey, genesis, chain };
  };

  it('should produce identical state as full chain verification (update)', async () => {
    const { creator, kid, resolveKey, genesis, chain } = await setupContentChain();

    const update: ContentOperation = {
      version: 1,
      type: 'update',
      did: creator.identity.did,
      previousOperationCID: genesis.operationCID,
      documentCID: 'bafkreiupdatedocument000000000000000000000000000000000000000',
      baseDocumentCID: null,
      createdAt: ts(1),
      note: 'updated',
    };
    const { jwsToken: updateJws } = await signContentOperation({
      operation: update,
      signer: creator.signer,
      kid,
    });

    // full chain verification
    const fullResult = await verifyContentChain({
      log: [genesis.jwsToken, updateJws],
      resolveKey,
    });

    // extension verification
    const extResult = await verifyContentExtensionFromTrustedState({
      currentState: chain,
      lastCreatedAt: genesis.createdAt,
      newOp: updateJws,
      resolveKey,
    });

    expect(extResult.state).toEqual(fullResult);
  });

  it('should produce identical state as full chain verification (delete)', async () => {
    const { creator, kid, resolveKey, genesis, chain } = await setupContentChain();

    const del: ContentOperation = {
      version: 1,
      type: 'delete',
      did: creator.identity.did,
      previousOperationCID: genesis.operationCID,
      createdAt: ts(1),
      note: null,
    };
    const { jwsToken: delJws } = await signContentOperation({
      operation: del,
      signer: creator.signer,
      kid,
    });

    const fullResult = await verifyContentChain({
      log: [genesis.jwsToken, delJws],
      resolveKey,
    });

    const extResult = await verifyContentExtensionFromTrustedState({
      currentState: chain,
      lastCreatedAt: genesis.createdAt,
      newOp: delJws,
      resolveKey,
    });

    expect(extResult.state).toEqual(fullResult);
  });

  it('should chain multiple extensions matching full chain replay', async () => {
    const { creator, kid, resolveKey, genesis, chain } = await setupContentChain();

    const update1: ContentOperation = {
      version: 1,
      type: 'update',
      did: creator.identity.did,
      previousOperationCID: genesis.operationCID,
      documentCID: 'bafkreiupdatedoc1000000000000000000000000000000000000000000000',
      baseDocumentCID: null,
      createdAt: ts(1),
      note: null,
    };
    const { jwsToken: update1Jws, operationCID: update1CID } = await signContentOperation({
      operation: update1,
      signer: creator.signer,
      kid,
    });

    const ext1 = await verifyContentExtensionFromTrustedState({
      currentState: chain,
      lastCreatedAt: genesis.createdAt,
      newOp: update1Jws,
      resolveKey,
    });

    const update2: ContentOperation = {
      version: 1,
      type: 'update',
      did: creator.identity.did,
      previousOperationCID: update1CID,
      documentCID: 'bafkreiupdatedoc2000000000000000000000000000000000000000000000',
      baseDocumentCID: null,
      createdAt: ts(2),
      note: null,
    };
    const { jwsToken: update2Jws } = await signContentOperation({
      operation: update2,
      signer: creator.signer,
      kid,
    });

    const ext2 = await verifyContentExtensionFromTrustedState({
      currentState: ext1.state,
      lastCreatedAt: ext1.createdAt,
      newOp: update2Jws,
      resolveKey,
    });

    const fullResult = await verifyContentChain({
      log: [genesis.jwsToken, update1Jws, update2Jws],
      resolveKey,
    });

    expect(ext2.state).toEqual(fullResult);
  });

  it('should reject extending a deleted chain', async () => {
    const { creator, kid, resolveKey, genesis, chain } = await setupContentChain();

    const del: ContentOperation = {
      version: 1,
      type: 'delete',
      did: creator.identity.did,
      previousOperationCID: genesis.operationCID,
      createdAt: ts(1),
      note: null,
    };
    const { jwsToken: delJws } = await signContentOperation({
      operation: del,
      signer: creator.signer,
      kid,
    });

    const extDel = await verifyContentExtensionFromTrustedState({
      currentState: chain,
      lastCreatedAt: genesis.createdAt,
      newOp: delJws,
      resolveKey,
    });

    const update: ContentOperation = {
      version: 1,
      type: 'update',
      did: creator.identity.did,
      previousOperationCID: extDel.operationCID,
      documentCID: 'bafkreiupdatedoc3000000000000000000000000000000000000000000000',
      baseDocumentCID: null,
      createdAt: ts(2),
      note: null,
    };
    const { jwsToken: updateJws } = await signContentOperation({
      operation: update,
      signer: creator.signer,
      kid,
    });

    await expect(
      verifyContentExtensionFromTrustedState({
        currentState: extDel.state,
        lastCreatedAt: extDel.createdAt,
        newOp: updateJws,
        resolveKey,
      }),
    ).rejects.toThrow(/deleted/i);
  });

  it('should verify delegated extension with authorization credential', async () => {
    const {
      creator,
      kid,
      resolveKey: creatorResolveKey,
      genesis,
      chain,
    } = await setupContentChain();
    const delegate = await createIdentityGenesis();

    // issue a DFOS credential to the delegate
    const now = Math.floor(Date.now() / 1000);
    const credentialToken = await createDFOSCredential({
      issuerDID: creator.identity.did,
      audienceDID: delegate.identity.did,
      att: [{ resource: `chain:${chain.contentId}`, action: 'write' }],
      exp: now + 3600,
      signer: creator.signer,
      keyId: creator.keyId,
    });

    // combined key resolver
    const resolveKey = async (k: string) => {
      const did = k.substring(0, k.indexOf('#'));
      if (did === creator.identity.did) return creator.keypair.publicKey;
      if (did === delegate.identity.did) return delegate.keypair.publicKey;
      throw new Error(`unknown DID: ${did}`);
    };

    // build identity map for resolveIdentity
    const creatorVerifiedIdentity: VerifiedIdentity = {
      did: creator.identity.did,
      isDeleted: false,
      authKeys: [
        {
          id: creator.keyId,
          type: 'Multikey',
          publicKeyMultibase: encodeEd25519Multikey(creator.keypair.publicKey),
        },
      ],
      assertKeys: [],
      controllerKeys: [],
    };
    const delegateVerifiedIdentity: VerifiedIdentity = {
      did: delegate.identity.did,
      isDeleted: false,
      authKeys: [
        {
          id: delegate.keyId,
          type: 'Multikey',
          publicKeyMultibase: encodeEd25519Multikey(delegate.keypair.publicKey),
        },
      ],
      assertKeys: [],
      controllerKeys: [],
    };
    const identityMap = new Map<string, VerifiedIdentity>();
    identityMap.set(creator.identity.did, creatorVerifiedIdentity);
    identityMap.set(delegate.identity.did, delegateVerifiedIdentity);
    const resolveIdentity = async (did: string) => identityMap.get(did);

    const delegateKid = `${delegate.identity.did}#${delegate.keyId}`;
    const update: ContentOperation = {
      version: 1,
      type: 'update',
      did: delegate.identity.did,
      previousOperationCID: genesis.operationCID,
      documentCID: 'bafkreidelegatedoc0000000000000000000000000000000000000000000',
      baseDocumentCID: null,
      createdAt: ts(1),
      note: null,
      authorization: credentialToken,
    };
    const { jwsToken: updateJws } = await signContentOperation({
      operation: update,
      signer: delegate.signer,
      kid: delegateKid,
    });

    // full chain
    const fullResult = await verifyContentChain({
      log: [genesis.jwsToken, updateJws],
      resolveKey,
      enforceAuthorization: true,
      resolveIdentity,
    });

    // extension
    const extResult = await verifyContentExtensionFromTrustedState({
      currentState: chain,
      lastCreatedAt: genesis.createdAt,
      newOp: updateJws,
      resolveKey,
      enforceAuthorization: true,
      resolveIdentity,
    });

    expect(extResult.state).toEqual(fullResult);
  });
});
