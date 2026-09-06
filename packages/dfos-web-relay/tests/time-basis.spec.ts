/*

  THE SINGLE TIME BASIS AT THE RELAY (specs/PROTOCOL.md "Time basis",
  specs/RELAY.md "Ingest asks freshness; re-verification asks the basis").

  Ingest asks freshness: first admission of a NEW operation resolves its signer
  in head state. Re-verification asks the basis: replay and peer ingest of
  committed history resolve at each operation's own `createdAt`. A credential
  carried inline resolves at that basis in both modes; a credential presented at
  read time resolves at the head, because a presentation's basis is now.

  Twin: dfos-web-relay-go/time_basis_test.go — keep the two in lockstep.

*/

import {
  encodeEd25519Multikey,
  signContentOperation,
  signIdentityOperation,
  type ContentOperation,
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
import { describe, expect, it } from 'vitest';
import { hasPublicStandingAuth } from '../src/auth';
import { ingestOperations, resolveIdentityAsOf } from '../src/ingest';
import { MemoryRelayStore } from '../src/store';
import { chainKeyProof } from './key-proofs';

// -----------------------------------------------------------------------------
// fixtures — one rotation, on a fixed clock
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

/** Minutes before now, so every fixture op is in the past and none is future-bound. */
const ts = (minutesAgo: number) => new Date(Date.now() - minutesAgo * 60_000).toISOString();

const T0 = 120;
const T1 = 100;
const T_R = 60;
const T3 = 30;

/** An identity holding K1 from T0 that rotates to K2 at T_r. */
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
  const encoded = await dagCborCanonicalEncode(genesisOp);
  const { deriveChainIdentifier } = await import('@metalabel/dfos-protocol/chain');
  const did = deriveChainIdentifier(encoded.cid.bytes, 'did:dfos');

  const k2 = makeKey();
  const rotationOp: IdentityOperation = {
    version: 1,
    type: 'update',
    previousOperationCID: genesis.operationCID,
    authKeys: [k2.key],
    assertKeys: [k2.key],
    controllerKeys: [k2.key],
    createdAt: ts(T_R),
    keyProofs: [
      await chainKeyProof({
        privateKey: k2.keypair.privateKey,
        did,
        prevCID: genesis.operationCID,
      }),
    ],
  };
  const rotation = await signIdentityOperation({
    operation: rotationOp,
    signer: k1.signer,
    keyId: k1.keyId,
    identityDID: did,
  });

  return { did, k1, k2, genesis, rotation };
};

const contentGenesis = async (did: string, key: Key, title: string, minutesAgo: number) => {
  const document = await dagCborCanonicalEncode({ type: 'post', title });
  const op: ContentOperation = {
    version: 1,
    type: 'create',
    did,
    documentCID: document.cid.toString(),
    baseDocumentCID: null,
    createdAt: ts(minutesAgo),
    note: null,
  };
  return signContentOperation({ operation: op, signer: key.signer, kid: `${did}#${key.keyId}` });
};

// -----------------------------------------------------------------------------
// the as-of helper
// -----------------------------------------------------------------------------

describe('resolveIdentityAsOf', () => {
  it('answers the same key set from the shortcut and the re-walk branch', async () => {
    const store = new MemoryRelayStore();
    const { did, k1, k2, genesis, rotation } = await rotatingIdentity();
    await ingestOperations([genesis.jwsToken, rotation.jwsToken], store);

    // SHORTCUT: the stored chain's last operation is at or before the basis, so
    // head state IS the state as of the basis and no walk runs.
    const shortcut = await resolveIdentityAsOf(store, did, ts(T3));
    expect(shortcut?.authKeys.map((k) => k.id)).toEqual([k2.keyId]);

    // RE-WALK: the basis names a prefix, so the log is re-verified.
    const rewalk = await resolveIdentityAsOf(store, did, ts(T1));
    expect(rewalk?.authKeys.map((k) => k.id)).toEqual([k1.keyId]);

    // Both branches are driven from one chain, and both answer about the SAME
    // basis identically: the shortcut is the re-walk's answer whenever the head
    // is already at or before the basis.
    const shortcutAtHead = await resolveIdentityAsOf(store, did, ts(T_R));
    const rewalkAtHead = await resolveIdentityAsOf(store, did, ts(T_R - 1));
    expect(shortcutAtHead?.authKeys.map((k) => k.id)).toEqual(
      rewalkAtHead?.authKeys.map((k) => k.id),
    );

    // No basis is the head, which is the state as of now.
    const head = await resolveIdentityAsOf(store, did);
    expect(head?.authKeys.map((k) => k.id)).toEqual([k2.keyId]);
  });

  it('reports deletion from HEAD state at every basis', async () => {
    const store = new MemoryRelayStore();
    const { did, k2, genesis, rotation } = await rotatingIdentity();
    await ingestOperations([genesis.jwsToken, rotation.jwsToken], store);

    const rotationEncoded = await dagCborCanonicalEncode(
      (await import('@metalabel/dfos-protocol/crypto')).decodeJwsUnsafe(rotation.jwsToken)!.payload,
    );
    const deleteOp: IdentityOperation = {
      version: 1,
      type: 'delete',
      previousOperationCID: rotationEncoded.cid.toString(),
      createdAt: ts(T3),
    };
    const deletion = await signIdentityOperation({
      operation: deleteOp,
      signer: k2.signer,
      keyId: k2.keyId,
      identityDID: did,
    });
    expect((await ingestOperations([deletion.jwsToken], store))[0]!.status).toBe('new');

    // The as-of state at T1 predates the deletion, and still reports it: a
    // deleted issuer authorizes nothing at any point in history.
    const asOf = await resolveIdentityAsOf(store, did, ts(T1));
    expect(asOf?.isDeleted).toBe(true);
  });

  it('is a verdict, not a dependency miss, when the basis predates the genesis', async () => {
    const store = new MemoryRelayStore();
    const { did, genesis } = await rotatingIdentity();
    await ingestOperations([genesis.jwsToken], store);
    await expect(resolveIdentityAsOf(store, did, ts(T0 + 10))).rejects.toThrow(
      /identity has no state as of/,
    );
  });
});

// -----------------------------------------------------------------------------
// an issuer whose genesis is after the basis
// -----------------------------------------------------------------------------

describe('an issuer that did not exist at the basis', () => {
  it('rejects the operation permanently, never as a missing dependency', async () => {
    const store = new MemoryRelayStore();
    const creator = await rotatingIdentity();
    // The delegate's chain begins AFTER the write it is about to authorize.
    const delegateKey = makeKey();
    const delegateGenesisOp: IdentityOperation = {
      version: 1,
      type: 'create',
      authKeys: [delegateKey.key],
      assertKeys: [delegateKey.key],
      controllerKeys: [delegateKey.key],
      createdAt: ts(T3),
    };
    const delegateGenesis = await signIdentityOperation({
      operation: delegateGenesisOp,
      signer: delegateKey.signer,
      keyId: delegateKey.keyId,
    });
    const encoded = await dagCborCanonicalEncode(delegateGenesisOp);
    const { deriveChainIdentifier } = await import('@metalabel/dfos-protocol/chain');
    const delegateDID = deriveChainIdentifier(encoded.cid.bytes, 'did:dfos');

    const genesis = await contentGenesis(creator.did, creator.k1, 'genesis', T1 + 5);
    const seeded = await ingestOperations(
      [creator.genesis.jwsToken, delegateGenesis.jwsToken, genesis.jwsToken],
      store,
    );
    const contentId = seeded[2]!.chainId!;

    // A credential the DELEGATE issued, carried by an op dated before the
    // delegate's own genesis.
    const nowUnix = Math.floor(Date.now() / 1000);
    const credential = await createDFOSCredential({
      issuerDID: delegateDID,
      audienceDID: creator.did,
      att: [{ resource: `chain:${contentId}`, action: 'write' }],
      exp: nowUnix + 3600,
      iat: nowUnix - 7200,
      signer: delegateKey.signer,
      keyId: delegateKey.keyId,
    });
    const document = await dagCborCanonicalEncode({ type: 'post', title: 'too early' });
    const write = await signContentOperation({
      operation: {
        version: 1,
        type: 'update',
        did: delegateDID,
        previousOperationCID: genesis.operationCID,
        documentCID: document.cid.toString(),
        baseDocumentCID: null,
        createdAt: ts(T1),
        note: null,
        authorization: credential,
      },
      signer: delegateKey.signer,
      kid: `${delegateDID}#${delegateKey.keyId}`,
    });

    const result = (
      await ingestOperations([write.jwsToken], store, {
        admissionMode: 'historical',
      })
    )[0]!;
    expect(result.status).toBe('rejected');
    expect(result.error).toMatch(/identity has no state as of/);
    expect(result.dependencyMissing).not.toBe(true);
  });
});

// -----------------------------------------------------------------------------
// which key misses are verdicts
// -----------------------------------------------------------------------------

describe('a key miss is a verdict only when the stored chain runs past the basis', () => {
  it('buffers an operation whose identity dependency has not synced, and lands it once it does', async () => {
    const store = new MemoryRelayStore();
    const { did, k1, k2, genesis, rotation } = await rotatingIdentity();
    const early = await contentGenesis(did, k1, 'before the rotation', T1);
    expect((await ingestOperations([genesis.jwsToken, early.jwsToken], store))[0]!.status).toBe(
      'new',
    );

    // The rotation is NOT in this store yet, so the chain ends at the genesis
    // and head state has never held K2.
    const document = await dagCborCanonicalEncode({ type: 'post', title: 'signed by K2' });
    const late = await signContentOperation({
      operation: {
        version: 1,
        type: 'update',
        did,
        previousOperationCID: early.operationCID,
        documentCID: document.cid.toString(),
        baseDocumentCID: null,
        createdAt: ts(T3),
        note: null,
      },
      signer: k2.signer,
      kid: `${did}#${k2.keyId}`,
    });
    const buffered = (
      await ingestOperations([late.jwsToken], store, { admissionMode: 'historical' })
    )[0]!;
    expect(buffered.status).toBe('rejected');
    // RETRYABLE: the stored chain ends at or before the basis, so an operation
    // the basis names can still arrive. A verdict here DELETES the raw op.
    expect(buffered.dependencyMissing).toBe(true);
    expect(buffered.error).toMatch(/unknown key/);

    // The dependency arrives, and the same operation lands.
    expect((await ingestOperations([rotation.jwsToken], store))[0]!.status).toBe('new');
    expect(
      (await ingestOperations([late.jwsToken], store, { admissionMode: 'historical' }))[0]!.status,
    ).toBe('new');
  });

  it('is a verdict once an operation dated after the basis is stored', async () => {
    const store = new MemoryRelayStore();
    const { did, k1, k2, genesis, rotation } = await rotatingIdentity();
    const early = await contentGenesis(did, k1, 'before the rotation', T1);
    // Two batches, because first admission asks freshness: the early op is
    // authored while K1 is still the head, and only then does the rotation land.
    await ingestOperations([genesis.jwsToken, early.jwsToken], store);
    expect((await ingestOperations([rotation.jwsToken], store))[0]!.status).toBe('new');

    // A second rotation, dated AFTER the basis the next operation carries: the
    // stored chain now proves it holds every operation that basis names.
    const k3 = makeKey();
    const rotationEncoded = await dagCborCanonicalEncode(
      (await import('@metalabel/dfos-protocol/crypto')).decodeJwsUnsafe(rotation.jwsToken)!.payload,
    );
    const secondOp: IdentityOperation = {
      version: 1,
      type: 'update',
      previousOperationCID: rotationEncoded.cid.toString(),
      authKeys: [k3.key],
      assertKeys: [k3.key],
      controllerKeys: [k3.key],
      createdAt: ts(10),
      keyProofs: [
        await chainKeyProof({
          privateKey: k3.keypair.privateKey,
          did,
          prevCID: rotationEncoded.cid.toString(),
        }),
      ],
    };
    const second = await signIdentityOperation({
      operation: secondOp,
      signer: k2.signer,
      keyId: k2.keyId,
      identityDID: did,
    });
    expect((await ingestOperations([second.jwsToken], store))[0]!.status).toBe('new');

    // K1 was retired at T_r, and the basis sits between T_r and the second
    // rotation, so the as-of walk answers about a complete prefix.
    const document = await dagCborCanonicalEncode({ type: 'post', title: 'by a retired key' });
    const byRetiredKey = await signContentOperation({
      operation: {
        version: 1,
        type: 'update',
        did,
        previousOperationCID: early.operationCID,
        documentCID: document.cid.toString(),
        baseDocumentCID: null,
        createdAt: ts(20),
        note: null,
      },
      signer: k1.signer,
      kid: `${did}#${k1.keyId}`,
    });
    const verdict = (
      await ingestOperations([byRetiredKey.jwsToken], store, { admissionMode: 'historical' })
    )[0]!;
    expect(verdict.status).toBe('rejected');
    expect(verdict.error).toMatch(/unknown key/);
    expect(verdict.dependencyMissing).not.toBe(true);
  });
});

// -----------------------------------------------------------------------------
// peer-log ingest of a rotation and the content chain across it
// -----------------------------------------------------------------------------

describe('peer-log ingest of committed history across a rotation', () => {
  it('lands in the same state on the receiving relay', async () => {
    const origin = new MemoryRelayStore();
    const { did, k1, k2, genesis, rotation } = await rotatingIdentity();

    // Two batches, because first admission asks freshness: the early op is
    // authored while K1 is still the head, and only then does the rotation land.
    const early = await contentGenesis(did, k1, 'before the rotation', T1);
    const seeded = await ingestOperations([genesis.jwsToken, early.jwsToken], origin);
    expect(seeded.map((r) => r.status)).toEqual(['new', 'new']);
    expect((await ingestOperations([rotation.jwsToken], origin))[0]!.status).toBe('new');

    // A later op signed by the successor key, extending the same chain.
    const document = await dagCborCanonicalEncode({ type: 'post', title: 'after the rotation' });
    const late = await signContentOperation({
      operation: {
        version: 1,
        type: 'update',
        did,
        previousOperationCID: early.operationCID,
        documentCID: document.cid.toString(),
        baseDocumentCID: null,
        createdAt: ts(T3),
        note: null,
      },
      signer: k2.signer,
      kid: `${did}#${k2.keyId}`,
    });
    const lateResult = (await ingestOperations([late.jwsToken], origin))[0]!;
    expect(lateResult.status).toBe('new');
    const originChain = await origin.getContentChain(
      (await origin.getOperation(early.operationCID))!.chainId,
    );

    // The peer receives the same log in sequence order and re-verifies it at each
    // operation's own basis.
    const peer = new MemoryRelayStore();
    const synced = await ingestOperations(
      [genesis.jwsToken, early.jwsToken, rotation.jwsToken, late.jwsToken],
      peer,
      { admissionMode: 'historical' },
    );
    expect(synced.map((r) => r.status)).toEqual(['new', 'new', 'new', 'new']);

    const peerChain = await peer.getContentChain(originChain!.contentId);
    expect(peerChain?.state.headCID).toBe(originChain!.state.headCID);
    expect((await peer.getIdentityChain(did))?.state.authKeys.map((k) => k.id)).toEqual([k2.keyId]);
  });
});

// -----------------------------------------------------------------------------
// the read path
// -----------------------------------------------------------------------------

describe('a standing public credential is checked at the head', () => {
  it('grants before the rotation is ingested and stops granting after', async () => {
    const store = new MemoryRelayStore();
    const { did, k1, genesis, rotation } = await rotatingIdentity();
    const content = await contentGenesis(did, k1, 'public', T1);
    await ingestOperations([genesis.jwsToken, content.jwsToken], store);
    const contentId = (await store.getOperation(content.operationCID))!.chainId;

    const nowUnix = Math.floor(Date.now() / 1000);
    const credential = await createDFOSCredential({
      issuerDID: did,
      audienceDID: '*',
      att: [{ resource: `chain:${contentId}`, action: 'read' }],
      exp: nowUnix + 3600,
      iat: nowUnix - 3600,
      signer: k1.signer,
      keyId: k1.keyId,
    });
    expect((await ingestOperations([credential], store))[0]!.status).toBe('new');
    expect(await hasPublicStandingAuth(contentId, 'read', store)).toBe(true);

    // The rotation retires the issuing key. A read-time check runs at the head,
    // so the standing grant stops granting.
    expect((await ingestOperations([rotation.jwsToken], store))[0]!.status).toBe('new');
    expect(await hasPublicStandingAuth(contentId, 'read', store)).toBe(false);
  });
});
