/*

  THE SINGLE TIME BASIS (PROTOCOL.md "Time basis").

  Every verification has one basis time. For a committed artifact — an operation
  in a chain and anything carried inline in it — the basis is the operation's own
  `createdAt`. For an ephemeral presentation the basis is now. At the basis the
  signing key must be effective in the identity's state as of the basis, `exp`
  must exceed the basis, and no revocation effective as of the basis may cover
  it.

  The fixture is one rotation: an identity holds K1 from `T0`, rotates to K2 at
  `T_r`, so K1 is effective on [T0, T_r) and K2 on [T_r, ∞). Everything below is
  a consequence of reading that interval at one instant.

  Twin: dfos-protocol-go/time_basis_test.go — keep the two in lockstep.

*/

import { describe, expect, it } from 'vitest';
import {
  signContentOperation,
  signIdentityOperation,
  verifyContentChain,
  verifyContentExtensionFromTrustedState,
  verifyIdentityChain,
} from '../src/chain';
import type {
  ContentOperation,
  IdentityOperation,
  MultikeyPublicKey,
  VerifiedIdentity,
} from '../src/chain';
import { encodeEd25519Multikey } from '../src/chain/multikey';
import { createDFOSCredential, verifyDFOSCredential } from '../src/credentials';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  generateId,
  signPayloadEd25519,
} from '../src/crypto';
import { KEY_ADD_JWS_TYP, serializeRoleSet, signKeyProof } from '../src/key-proof';

// -----------------------------------------------------------------------------
// fixtures
// -----------------------------------------------------------------------------

const makeKey = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const key: MultikeyPublicKey = {
    id: keyId,
    type: 'Multikey',
    publicKeyMultibase: encodeEd25519Multikey(keypair.publicKey),
  };
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  return { keypair, keyId, key, signer };
};
type Key = ReturnType<typeof makeKey>;

const ts = (minute: number) => new Date(Date.UTC(2026, 2, 7, 0, minute, 0, 0)).toISOString();
const unix = (minute: number) => Math.floor(Date.UTC(2026, 2, 7, 0, minute, 0, 0) / 1000);

const T0 = 0;
const T1 = 5;
const T_R = 10;
const T3 = 20;

let nonces = 0;
const proofFor = async (key: Key, did: string, prevCID: string): Promise<string> => {
  nonces += 1;
  const { proof } = await signKeyProof({
    typ: KEY_ADD_JWS_TYP,
    nonce: `nonce-time-basis-${nonces}`,
    audience: 'relay.example',
    did,
    roleSet: serializeRoleSet(['auth', 'assert', 'controller']),
    prevCID,
    privateKey: key.keypair.privateKey,
  });
  return proof;
};

/** An identity with K1 at `T0` that rotates to K2 at `T_r`. */
const rotatingIdentity = async () => {
  const k1 = makeKey();
  const genesisOp: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [k1.key],
    assertKeys: [k1.key],
    controllerKeys: [k1.key],
    createdAt: ts(T0),
  };
  const genesis = await signIdentityOperation({
    operation: genesisOp,
    signer: k1.signer,
    keyId: k1.keyId,
  });
  const head = await verifyIdentityChain({ didPrefix: 'did:dfos', log: [genesis.jwsToken] });

  const k2 = makeKey();
  const rotationOp: IdentityOperation = {
    version: 1,
    type: 'update',
    previousOperationCID: genesis.operationCID,
    authKeys: [k2.key],
    assertKeys: [k2.key],
    controllerKeys: [k2.key],
    createdAt: ts(T_R),
    keyProofs: [await proofFor(k2, head.did, genesis.operationCID)],
  };
  const rotation = await signIdentityOperation({
    operation: rotationOp,
    signer: k1.signer,
    keyId: k1.keyId,
    identityDID: head.did,
  });

  const log = [genesis.jwsToken, rotation.jwsToken];
  return { did: head.did, k1, k2, log, genesisCID: genesis.operationCID, rotationOp };
};

/** A resolver that answers with the identity's state as of the basis it is given. */
const asOfResolver =
  (did: string, log: string[]) =>
  async (asked: string, basis?: string): Promise<VerifiedIdentity | undefined> => {
    if (asked !== did) return undefined;
    return verifyIdentityChain({
      didPrefix: 'did:dfos',
      log,
      ...(basis !== undefined ? { asOf: basis } : {}),
    });
  };

const keyResolver = (did: string, log: string[]) => async (kid: string, basis?: string) => {
  const identity = await asOfResolver(did, log)(kid.substring(0, kid.indexOf('#')), basis);
  if (!identity) throw new Error(`unknown identity: ${kid}`);
  const keyId = kid.substring(kid.indexOf('#') + 1);
  const key = [...identity.authKeys, ...identity.assertKeys, ...identity.controllerKeys].find(
    (candidate) => candidate.id === keyId,
  );
  if (!key) throw new Error(`unknown key ${keyId}`);
  const { decodeMultikey } = await import('../src/chain/multikey');
  return decodeMultikey(key.publicKeyMultibase).keyBytes;
};

const docCID = async (title: string) =>
  (await dagCborCanonicalEncode({ type: 'post', title })).cid.toString();

// -----------------------------------------------------------------------------
// state as of a basis
// -----------------------------------------------------------------------------

describe('identity state as of a basis', () => {
  it('returns the state the last operation at or before the basis folds to', async () => {
    const { did, k1, k2, log } = await rotatingIdentity();

    const beforeRotation = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log,
      asOf: ts(T1),
    });
    expect(beforeRotation.did).toBe(did);
    expect(beforeRotation.authKeys.map((k) => k.id)).toEqual([k1.keyId]);

    const afterRotation = await verifyIdentityChain({ didPrefix: 'did:dfos', log, asOf: ts(T3) });
    expect(afterRotation.authKeys.map((k) => k.id)).toEqual([k2.keyId]);

    // The basis at the rotation's own instant already sees the successor: the
    // comparison is `createdAt <= basis`.
    const atRotation = await verifyIdentityChain({ didPrefix: 'did:dfos', log, asOf: ts(T_R) });
    expect(atRotation.authKeys.map((k) => k.id)).toEqual([k2.keyId]);

    // Omitting the basis is the head, which is the state as of now.
    const head = await verifyIdentityChain({ didPrefix: 'did:dfos', log });
    expect(head.authKeys.map((k) => k.id)).toEqual([k2.keyId]);
  });

  it('rejects a basis earlier than the genesis: the identity had no state then', async () => {
    const { log } = await rotatingIdentity();
    await expect(
      verifyIdentityChain({ didPrefix: 'did:dfos', log, asOf: ts(-10) }),
    ).rejects.toThrow(/identity has no state as of/);
  });

  it('verifies the whole log whatever the basis, so a broken tail still throws', async () => {
    const { did, log } = await rotatingIdentity();
    const tampered = [log[0]!, `${log[1]!.slice(0, -4)}AAAA`];
    await expect(
      verifyIdentityChain({ didPrefix: 'did:dfos', log: tampered, asOf: ts(T1) }),
    ).rejects.toThrow();
    expect(did).toMatch(/^did:dfos:/);
  });
});

// -----------------------------------------------------------------------------
// the basis in whole seconds
// -----------------------------------------------------------------------------

describe('the basis converts to whole seconds by truncation', () => {
  it('never rounds a sub-second remainder up onto exp', async () => {
    const issuer = await rotatingIdentity();
    const resolveIdentity = asOfResolver(issuer.did, issuer.log);
    const credential = await createDFOSCredential({
      issuerDID: issuer.did,
      audienceDID: '*',
      att: [{ resource: 'chain:*', action: 'read' }],
      exp: unix(T1),
      iat: unix(T0),
      signer: issuer.k1.signer,
      keyId: issuer.k1.keyId,
    });

    // A basis whose whole-second floor is exp-1 is inside the window; the .999
    // remainder is truncated away rather than rounded up onto exp.
    const inside = new Date((unix(T1) - 1) * 1000 + 999).toISOString();
    await expect(
      verifyDFOSCredential(credential, { resolveIdentity, basis: inside }),
    ).resolves.toMatchObject({ iss: issuer.did });

    // A basis whose floor is exp is expired.
    await expect(
      verifyDFOSCredential(credential, { resolveIdentity, basis: ts(T1) }),
    ).rejects.toThrow(/credential expired/);
  });
});

// -----------------------------------------------------------------------------
// forward issuance
// -----------------------------------------------------------------------------

describe('a credential carried inline resolves at the operation basis', () => {
  /** Creator chain plus a delegate, with a write credential the creator's K1 signed. */
  const delegatedChain = async () => {
    const creator = await rotatingIdentity();
    const delegate = await rotatingIdentity();

    const genesisContentOp: ContentOperation = {
      version: 1,
      type: 'create',
      did: creator.did,
      documentCID: await docCID('genesis'),
      baseDocumentCID: null,
      createdAt: ts(T0 + 1),
    };
    const genesis = await signContentOperation({
      operation: genesisContentOp,
      signer: creator.k1.signer,
      kid: `${creator.did}#${creator.k1.keyId}`,
    });
    const encoded = await dagCborCanonicalEncode(genesisContentOp);
    const { deriveContentId } = await import('../src/chain/derivation');
    const contentId = deriveContentId(encoded.cid.bytes);

    // The creator's K1 issues the write credential while it is still effective.
    const credential = await createDFOSCredential({
      issuerDID: creator.did,
      audienceDID: delegate.did,
      att: [{ resource: `chain:${contentId}`, action: 'write' }],
      exp: unix(T3 + 60),
      iat: unix(T0),
      signer: creator.k1.signer,
      keyId: creator.k1.keyId,
    });

    const resolveIdentity = async (
      did: string,
      basis?: string,
    ): Promise<VerifiedIdentity | undefined> =>
      (await asOfResolver(creator.did, creator.log)(did, basis)) ??
      (await asOfResolver(delegate.did, delegate.log)(did, basis));

    const resolveKey = async (kid: string, basis?: string) => {
      const did = kid.substring(0, kid.indexOf('#'));
      return did === creator.did
        ? keyResolver(creator.did, creator.log)(kid, basis)
        : keyResolver(delegate.did, delegate.log)(kid, basis);
    };

    const delegatedOp = async (minute: number, previousOperationCID: string) => {
      const op: ContentOperation = {
        version: 1,
        type: 'update',
        did: delegate.did,
        previousOperationCID,
        documentCID: await docCID(`write at ${minute}`),
        baseDocumentCID: null,
        createdAt: ts(minute),
        authorization: credential,
      };
      // Signed by whichever of the delegate's keys is effective at that minute.
      const signingKey = minute < T_R ? delegate.k1 : delegate.k2;
      return signContentOperation({
        operation: op,
        signer: signingKey.signer,
        kid: `${delegate.did}#${signingKey.keyId}`,
      });
    };

    return {
      creator,
      delegate,
      contentId,
      genesis,
      credential,
      resolveIdentity,
      resolveKey,
      delegatedOp,
    };
  };

  it('accepts a write dated while the issuing key is effective, on both verify paths', async () => {
    const f = await delegatedChain();
    const early = await f.delegatedOp(T1, f.genesis.operationCID);

    const chain = await verifyContentChain({
      log: [f.genesis.jwsToken, early.jwsToken],
      resolveKey: f.resolveKey,
      enforceAuthorization: true,
      resolveIdentity: f.resolveIdentity,
    });
    expect(chain.length).toBe(2);

    const genesisState = await verifyContentChain({
      log: [f.genesis.jwsToken],
      resolveKey: f.resolveKey,
      enforceAuthorization: true,
      resolveIdentity: f.resolveIdentity,
    });
    const extension = await verifyContentExtensionFromTrustedState({
      currentState: genesisState,
      lastCreatedAt: ts(T0 + 1),
      newOp: early.jwsToken,
      resolveKey: f.resolveKey,
      enforceAuthorization: true,
      resolveIdentity: f.resolveIdentity,
    });
    expect(extension.operationCID).toBe(early.operationCID);
  });

  it('rejects a write dated after the issuing key is rotated out, on both verify paths', async () => {
    const f = await delegatedChain();
    const early = await f.delegatedOp(T1, f.genesis.operationCID);
    const late = await f.delegatedOp(T3, early.operationCID);

    await expect(
      verifyContentChain({
        log: [f.genesis.jwsToken, early.jwsToken, late.jwsToken],
        resolveKey: f.resolveKey,
        enforceAuthorization: true,
        resolveIdentity: f.resolveIdentity,
      }),
    ).rejects.toThrow(/authorization verification failed/i);

    const throughEarly = await verifyContentChain({
      log: [f.genesis.jwsToken, early.jwsToken],
      resolveKey: f.resolveKey,
      enforceAuthorization: true,
      resolveIdentity: f.resolveIdentity,
    });
    await expect(
      verifyContentExtensionFromTrustedState({
        currentState: throughEarly,
        lastCreatedAt: ts(T1),
        newOp: late.jwsToken,
        resolveKey: f.resolveKey,
        enforceAuthorization: true,
        resolveIdentity: f.resolveIdentity,
      }),
    ).rejects.toThrow(/authorization verification failed/i);
  });
});

// -----------------------------------------------------------------------------
// the rules that do not run against the basis
// -----------------------------------------------------------------------------

describe('deletion does not run against the basis', () => {
  it('rejects a deleted issuer at every basis, including one before the deletion', async () => {
    const { did, k1, k2, log, genesisCID, rotationOp } = await rotatingIdentity();
    const rotationCID = (await dagCborCanonicalEncode(rotationOp)).cid.toString();
    expect(rotationCID).not.toBe(genesisCID);

    const deleteOp: IdentityOperation = {
      version: 1,
      type: 'delete',
      previousOperationCID: rotationCID,
      createdAt: ts(T3),
    };
    const deletion = await signIdentityOperation({
      operation: deleteOp,
      signer: k2.signer,
      keyId: k2.keyId,
      identityDID: did,
    });
    const deletedLog = [...log, deletion.jwsToken];

    const credential = await createDFOSCredential({
      issuerDID: did,
      audienceDID: '*',
      att: [{ resource: 'chain:*', action: 'read' }],
      exp: unix(T3 + 60),
      iat: unix(T0),
      signer: k1.signer,
      keyId: k1.keyId,
    });

    // The resolver reports HEAD deletion state whatever basis it is asked for,
    // which is what makes deletion retroactive.
    const resolveIdentity = async (
      asked: string,
      basis?: string,
    ): Promise<VerifiedIdentity | undefined> => {
      if (asked !== did) return undefined;
      const head = await verifyIdentityChain({ didPrefix: 'did:dfos', log: deletedLog });
      const state = await verifyIdentityChain({
        didPrefix: 'did:dfos',
        log: deletedLog,
        ...(basis !== undefined ? { asOf: basis } : {}),
      });
      return { ...state, isDeleted: head.isDeleted };
    };

    await expect(
      verifyDFOSCredential(credential, { resolveIdentity, basis: ts(T1) }),
    ).rejects.toThrow(/issuer identity is deleted/);
    await expect(verifyDFOSCredential(credential, { resolveIdentity })).rejects.toThrow(
      /issuer identity is deleted/,
    );
  });
});
