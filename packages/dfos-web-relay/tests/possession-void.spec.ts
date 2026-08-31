/*

  POSSESSION PROOFS AT THE RELAY — WHAT VOID DOES AND DOES NOT CHANGE.

  A key-role membership is EFFECTIVE only if a possession proof admitted it.
  Everything else about the operation is unmoved: it is structurally valid, the
  relay sequences it, the CID stands, the log carries it.

  THAT NON-CHANGE IS THE POINT OF THIS FILE. A relay whose accept/reject verdict
  depended on possession evidence would be a relay that could disagree with
  another relay about whether an operation EXISTS — and two relays disagreeing
  about existence is the one divergence a gossip layer cannot heal. So the first
  test here is a regression test against ingest-reject creep, and it is
  deliberately about acceptance rather than resolution.

  The rest pin the surfaces the fold DOES move: the void key is absent from the
  effective arrays and named on `voidKeys`, it never becomes a verification
  method, and it never resolves a signature — while a key that WAS proved and
  later rotated out still does.

*/

import {
  encodeEd25519Multikey,
  signContentOperation,
  signIdentityOperation,
  type ContentOperation,
  type IdentityOperation,
  type MultikeyPublicKey,
} from '@metalabel/dfos-protocol/chain';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  decodeJwsUnsafe,
  generateId,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { describe, expect, it } from 'vitest';
import { identityToDidDocument } from '../src/did-document';
import { ingestOperations } from '../src/ingest';
import { createRelay } from '../src/relay';
import { MemoryRelayStore } from '../src/store';
import { chainKeyProof } from './key-proofs';

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

const ts = (offset = 0) => new Date(Date.now() + offset * 60_000).toISOString();

/** A genesis: exactly one key, in all three roles, signing itself. */
const genesis = async () => {
  const key = makeKey();
  const createOp: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [key.key],
    assertKeys: [key.key],
    controllerKeys: [key.key],
    createdAt: ts(),
  };
  const { jwsToken, operationCID } = await signIdentityOperation({
    operation: createOp,
    signer: key.signer,
    keyId: key.keyId,
  });
  const encoded = await dagCborCanonicalEncode(createOp);
  const { deriveChainIdentifier } = await import('@metalabel/dfos-protocol/chain');
  const did = deriveChainIdentifier(encoded.cid.bytes, 'did:dfos');
  return { key, did, jwsToken, operationCID };
};

/** One update, signed by `signedBy`, carrying whatever proofs it was given. */
const update = async (input: {
  did: string;
  prevCID: string;
  signedBy: Key;
  authKeys: MultikeyPublicKey[];
  assertKeys: MultikeyPublicKey[];
  controllerKeys: MultikeyPublicKey[];
  keyProofs?: string[];
  offset?: number;
}) => {
  const updateOp: IdentityOperation = {
    version: 1,
    type: 'update',
    previousOperationCID: input.prevCID,
    authKeys: input.authKeys,
    assertKeys: input.assertKeys,
    controllerKeys: input.controllerKeys,
    createdAt: ts(input.offset ?? 1),
    ...(input.keyProofs ? { keyProofs: input.keyProofs } : {}),
  };
  return signIdentityOperation({
    operation: updateOp,
    signer: input.signedBy.signer,
    keyId: input.signedBy.keyId,
    identityDID: input.did,
  });
};

/** A content genesis signed by `key` on behalf of `did`. */
const contentGenesis = async (did: string, key: Key, title: string, offset: number) => {
  const document = await dagCborCanonicalEncode({ type: 'post', title });
  const op: ContentOperation = {
    version: 1,
    type: 'create',
    did,
    documentCID: document.cid.toString(),
    baseDocumentCID: null,
    createdAt: ts(offset),
    note: null,
  };
  return signContentOperation({ operation: op, signer: key.signer, kid: `${did}#${key.keyId}` });
};

/**
 * A chain whose head declares `void` in the auth role with NO proof for it. The
 * genesis key stays in all three roles, so the chain keeps a working signer.
 */
const chainWithVoidKey = async (store: MemoryRelayStore) => {
  const root = await genesis();
  expect((await ingestOperations([root.jwsToken], store))[0]!.status).toBe('new');
  const voided = makeKey();
  const introduction = await update({
    did: root.did,
    prevCID: root.operationCID,
    signedBy: root.key,
    authKeys: [root.key.key, voided.key],
    assertKeys: [root.key.key],
    controllerKeys: [root.key.key],
  });
  return { root, voided, introduction };
};

// -----------------------------------------------------------------------------
// (1) NO INGEST-REJECT CREEP
// -----------------------------------------------------------------------------

describe('unproved introductions are sequenced, not refused', () => {
  it('accepts an update that introduces a key with no proof, and voids the membership', async () => {
    const store = new MemoryRelayStore();
    const { root, voided, introduction } = await chainWithVoidKey(store);

    // THE REGRESSION GUARD. Acceptance must not depend on possession evidence:
    // a relay that rejected here could disagree with another relay about whether
    // this operation exists at all, and existence is the one thing gossip cannot
    // reconcile. `voidKeys` exists precisely so this can be an acceptance.
    const [result] = await ingestOperations([introduction.jwsToken], store);
    expect(result!.status).toBe('new');
    expect(result!.error).toBeUndefined();
    expect(result!.kind).toBe('identity-op');
    expect(result!.chainId).toBe(root.did);
    expect(result!.cid).toBe(introduction.operationCID);

    // it is in the log, and it is the head
    const chain = (await store.getIdentityChain(root.did))!;
    expect(chain.headCID).toBe(introduction.operationCID);
    expect(chain.log.map((jws) => decodeJwsUnsafe(jws)?.header.cid)).toEqual([
      root.operationCID,
      introduction.operationCID,
    ]);
    expect(await store.getOperation(introduction.operationCID)).toBeDefined();

    // and the key it introduced is simply not there
    const state = chain.state;
    expect(state.authKeys.map((k) => k.id)).toEqual([root.key.keyId]);
    expect(state.assertKeys.map((k) => k.id)).toEqual([root.key.keyId]);
    expect(state.controllerKeys.map((k) => k.id)).toEqual([root.key.keyId]);

    // the chain still SAYS it, which is what makes the omission legible
    expect(state.declared?.authKeys.map((k) => k.id)).toEqual([root.key.keyId, voided.keyId]);
    expect(state.voidKeys).toEqual([
      { key: voided.key, role: 'auth', operationCID: introduction.operationCID },
    ]);
    // never proved, so never in has-ever-proved either
    expect(state.provedKeys?.authKeys.map((k) => k.id)).toEqual([root.key.keyId]);
  });

  it('rescues a void membership when a later operation carries a correctly-headed proof', async () => {
    const store = new MemoryRelayStore();
    const { root, voided, introduction } = await chainWithVoidKey(store);
    expect((await ingestOperations([introduction.jwsToken], store))[0]!.status).toBe('new');

    // Void is a state a chain can climb out of: the membership is introduced
    // AGAIN at the next operation, where a fresh envelope naming the CURRENT
    // head admits it.
    const rescue = await update({
      did: root.did,
      prevCID: introduction.operationCID,
      signedBy: root.key,
      authKeys: [root.key.key, voided.key],
      assertKeys: [root.key.key],
      controllerKeys: [root.key.key],
      keyProofs: [
        await chainKeyProof({
          privateKey: voided.keypair.privateKey,
          did: root.did,
          prevCID: introduction.operationCID,
          roles: ['auth'],
        }),
      ],
      offset: 2,
    });
    expect((await ingestOperations([rescue.jwsToken], store))[0]!.status).toBe('new');

    const state = (await store.getIdentityChain(root.did))!.state;
    expect(state.authKeys.map((k) => k.id)).toEqual([root.key.keyId, voided.keyId]);
    expect(state.voidKeys).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// (2) the surfaces the fold DOES move
// -----------------------------------------------------------------------------

describe('void keys never reach a resolution surface', () => {
  it('keeps a void key out of every DID Document verification relationship', async () => {
    const store = new MemoryRelayStore();
    const { root, voided, introduction } = await chainWithVoidKey(store);
    await ingestOperations([introduction.jwsToken], store);

    const doc = identityToDidDocument((await store.getIdentityChain(root.did))!.state);
    const genesisVm = `${root.did}#${root.key.keyId}`;
    const voidVm = `${root.did}#${voided.keyId}`;

    expect(doc.verificationMethod.map((vm) => vm.id)).toEqual([genesisVm]);
    expect(doc.authentication).toEqual([genesisVm]);
    expect(doc.assertionMethod).toEqual([genesisVm]);
    expect(doc.capabilityInvocation).toEqual([genesisVm]);
    expect(JSON.stringify(doc)).not.toContain(voidVm);
    expect(JSON.stringify(doc)).not.toContain(voided.key.publicKeyMultibase);
  });

  it('serves effective arrays plus the void list on the proof-plane identity route', async () => {
    const store = new MemoryRelayStore();
    const { root, voided, introduction } = await chainWithVoidKey(store);
    await ingestOperations([introduction.jwsToken], store);
    const relay = await createRelay({ store, authority: 'localhost' });

    const res = await relay.app.request(`http://localhost/proof/v1/identities/${root.did}`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      state: {
        authKeys: { id: string }[];
        voidKeys?: { key: { id: string }; role: string }[];
        provedKeys?: { authKeys: { id: string }[] };
      };
    };

    // backward-compatible: the arrays are still the arrays, and they are
    // EFFECTIVE, which is what a consumer resolving a key needs them to be
    expect(body.state.authKeys.map((k) => k.id)).toEqual([root.key.keyId]);
    // and the controller can SEE why their key is missing
    expect(body.state.voidKeys).toEqual([
      { key: voided.key, role: 'auth', operationCID: introduction.operationCID },
    ]);
    expect(body.state.provedKeys?.authKeys.map((k) => k.id)).toEqual([root.key.keyId]);
  });

  it('resolves a proved-then-rotated-out key historically, and a void key never', async () => {
    const store = new MemoryRelayStore();
    const root = await genesis();
    expect((await ingestOperations([root.jwsToken], store))[0]!.status).toBe('new');

    // content signed by the genesis key, which a rotation is about to retire
    const early = await contentGenesis(root.did, root.key, 'before the rotation', 1);
    expect((await ingestOperations([early.jwsToken], store))[0]!.status).toBe('new');

    const successor = makeKey();
    const rotation = await update({
      did: root.did,
      prevCID: root.operationCID,
      signedBy: root.key,
      authKeys: [successor.key],
      assertKeys: [successor.key],
      controllerKeys: [successor.key],
      keyProofs: [
        await chainKeyProof({
          privateKey: successor.keypair.privateKey,
          did: root.did,
          prevCID: root.operationCID,
        }),
      ],
      offset: 2,
    });
    expect((await ingestOperations([rotation.jwsToken], store))[0]!.status).toBe('new');

    // A key that was PROVED and later rotated out still resolves on the
    // historical path — that is what verifying long-lived artifacts across a
    // rotation means, and revocation, not rotation, is the invalidation.
    const late = await contentGenesis(root.did, root.key, 'after the rotation', 3);
    const [historical] = await ingestOperations([late.jwsToken], store, {
      admissionMode: 'historical',
    });
    expect(historical!.status).toBe('new');

    // A key nothing ever proved does not, even historically: it never spoke for
    // this identity, so there is nothing for its signature to have been.
    const voided = makeKey();
    const introduction = await update({
      did: root.did,
      prevCID: rotation.operationCID,
      signedBy: successor,
      authKeys: [successor.key, voided.key],
      assertKeys: [successor.key],
      controllerKeys: [successor.key],
      offset: 4,
    });
    expect((await ingestOperations([introduction.jwsToken], store))[0]!.status).toBe('new');

    const byVoidKey = await contentGenesis(root.did, voided, 'signed by a void key', 5);
    const [refused] = await ingestOperations([byVoidKey.jwsToken], store, {
      admissionMode: 'historical',
    });
    expect(refused!.status).toBe('rejected');
    expect(refused!.error).toContain(`unknown key ${voided.keyId}`);
  });
});
