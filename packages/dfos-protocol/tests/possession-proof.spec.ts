/*

  POSSESSION PROOFS ON THE IDENTITY CHAIN — the bimodal rule, and void semantics.

  The claim this file exists to hold: a key-role membership is EFFECTIVE only if
  possession admitted it, and everything else about the chain is unmoved. Every
  negative below produces a chain that VERIFIES — the operations are valid, the
  CIDs stand, a relay sequences them — and a key that does not resolve.

  Read the assertions in pairs. Each case checks `declared` still carries the
  membership, `voidKeys` names it, and the effective array does not. Those three
  together are the whole of "void": the chain said it, nobody proved it, no
  consumer sees it.

*/

import { describe, expect, it } from 'vitest';
import {
  signIdentityOperation,
  verifyIdentityChain,
  verifyIdentityExtensionFromTrustedState,
} from '../src/chain';
import type { IdentityOperation, MultikeyPublicKey, VerifiedIdentity } from '../src/chain';
import { encodeEd25519Multikey } from '../src/chain/multikey';
import { createNewEd25519Keypair, generateId, signPayloadEd25519 } from '../src/crypto';
import { KEY_ADD_JWS_TYP, serializeRoleSet, signKeyProof, type KeyRole } from '../src/key-proof';

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

const ts = (minute: number) =>
  new Date(Date.UTC(2026, 2, 7, 0, minute, 0, 0)).toISOString().replace(/\.\d{3}Z$/, '.000Z');

let nonces = 0;
/** One key-proof envelope, at one position. `roles` defaults to all three. */
const proofFor = async (input: {
  key: Key;
  did: string;
  prevCID: string;
  roles?: KeyRole[];
}): Promise<string> => {
  nonces += 1;
  const { proof } = await signKeyProof({
    typ: KEY_ADD_JWS_TYP,
    nonce: `nonce-possession-${nonces}`,
    audience: 'relay.example',
    did: input.did,
    roleSet: serializeRoleSet(input.roles ?? ['auth', 'assert', 'controller']),
    prevCID: input.prevCID,
    privateKey: input.key.keypair.privateKey,
  });
  return proof;
};

/** A single-key genesis and the state it verifies to. */
const genesis = async () => {
  const k = makeKey();
  const op: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [k.key],
    assertKeys: [k.key],
    controllerKeys: [k.key],
    createdAt: ts(0),
  };
  const { jwsToken, operationCID } = await signIdentityOperation({
    operation: op,
    signer: k.signer,
    keyId: k.keyId,
  });
  const state = await verifyIdentityChain({ didPrefix: 'did:dfos', log: [jwsToken] });
  return { key: k, op, jwsToken, operationCID, did: state.did, state };
};

/** Sign one update, signed by `signedBy`. */
const update = async (input: {
  did: string;
  prevCID: string;
  minute: number;
  signedBy: Key;
  authKeys: MultikeyPublicKey[];
  assertKeys: MultikeyPublicKey[];
  controllerKeys: MultikeyPublicKey[];
  keyProofs?: string[];
}) => {
  const op: IdentityOperation = {
    version: 1,
    type: 'update',
    previousOperationCID: input.prevCID,
    authKeys: input.authKeys,
    assertKeys: input.assertKeys,
    controllerKeys: input.controllerKeys,
    createdAt: ts(input.minute),
    ...(input.keyProofs ? { keyProofs: input.keyProofs } : {}),
  };
  const signed = await signIdentityOperation({
    operation: op,
    signer: input.signedBy.signer,
    keyId: input.signedBy.keyId,
    identityDID: input.did,
  });
  return { op, ...signed };
};

const roleArray = { auth: 'authKeys', assert: 'assertKeys', controller: 'controllerKeys' } as const;

/** Is (key, role) in effective state? */
const isEffective = (state: VerifiedIdentity, key: MultikeyPublicKey, role: KeyRole): boolean =>
  state[roleArray[role]].some((k) => k.id === key.id);

/** Is (key, role) in declared state? */
const isDeclared = (state: VerifiedIdentity, key: MultikeyPublicKey, role: KeyRole): boolean =>
  (state.declared?.[roleArray[role]] ?? []).some((k) => k.id === key.id);

/** Is (key, role) named on the void list? */
const isVoid = (state: VerifiedIdentity, key: MultikeyPublicKey, role: KeyRole): boolean =>
  (state.voidKeys ?? []).some((v) => v.key.id === key.id && v.role === role);

/**
 * The assertion every negative case makes: declared, void, and NOT effective —
 * on a chain that verified.
 */
const expectVoid = (state: VerifiedIdentity, key: MultikeyPublicKey, roles: KeyRole[]) => {
  for (const role of roles) {
    expect(isDeclared(state, key, role), `${role}: declared`).toBe(true);
    expect(isVoid(state, key, role), `${role}: void`).toBe(true);
    expect(isEffective(state, key, role), `${role}: NOT effective`).toBe(false);
  }
};

const expectProved = (state: VerifiedIdentity, key: MultikeyPublicKey, roles: KeyRole[]) => {
  for (const role of roles) {
    expect(isDeclared(state, key, role), `${role}: declared`).toBe(true);
    expect(isEffective(state, key, role), `${role}: effective`).toBe(true);
    expect(isVoid(state, key, role), `${role}: not void`).toBe(false);
  }
};

// -----------------------------------------------------------------------------

describe('possession proofs — the positive ceremony', () => {
  it('admits a rotation whose introduced key proves itself at the current head', async () => {
    const g = await genesis();
    const rotated = makeKey();
    const rot = await update({
      did: g.did,
      prevCID: g.operationCID,
      minute: 1,
      signedBy: g.key,
      authKeys: [rotated.key],
      assertKeys: [rotated.key],
      controllerKeys: [rotated.key],
      keyProofs: [await proofFor({ key: rotated, did: g.did, prevCID: g.operationCID })],
    });

    const state = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [g.jwsToken, rot.jwsToken],
    });
    expectProved(state, rotated.key, ['auth', 'assert', 'controller']);
    expect(state.voidKeys).toEqual([]);
    // The genesis key is gone from BOTH states — a removal is a removal.
    expect(isDeclared(state, g.key.key, 'controller')).toBe(false);
    expect(isEffective(state, g.key.key, 'controller')).toBe(false);
  });

  it('proves several roles with ONE envelope, and several keys with several', async () => {
    const g = await genesis();
    const a = makeKey();
    const b = makeKey();
    const op = await update({
      did: g.did,
      prevCID: g.operationCID,
      minute: 1,
      signedBy: g.key,
      // The genesis key stays a controller (a replay, no proof needed); `a` joins
      // all three roles on one envelope; `b` joins auth only.
      authKeys: [g.key.key, a.key, b.key],
      assertKeys: [g.key.key, a.key],
      controllerKeys: [g.key.key, a.key],
      keyProofs: [
        await proofFor({ key: a, did: g.did, prevCID: g.operationCID }),
        await proofFor({ key: b, did: g.did, prevCID: g.operationCID, roles: ['auth'] }),
      ],
    });
    const state = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [g.jwsToken, op.jwsToken],
    });
    expectProved(state, a.key, ['auth', 'assert', 'controller']);
    expectProved(state, b.key, ['auth']);
    expectProved(state, g.key.key, ['auth', 'assert', 'controller']);
    expect(state.voidKeys).toEqual([]);
  });

  it('does not replay proofs forward — a later update that only repeats keys carries none', async () => {
    const g = await genesis();
    const rotated = makeKey();
    const rot = await update({
      did: g.did,
      prevCID: g.operationCID,
      minute: 1,
      signedBy: g.key,
      authKeys: [rotated.key],
      assertKeys: [rotated.key],
      controllerKeys: [rotated.key],
      keyProofs: [await proofFor({ key: rotated, did: g.did, prevCID: g.operationCID })],
    });
    // A services-only edit: the same keys, no envelopes at all. Proved-ness is
    // INHERITED, which is what keeps proofs from accumulating in a chain.
    const later = await update({
      did: g.did,
      prevCID: rot.operationCID,
      minute: 2,
      signedBy: rotated,
      authKeys: [rotated.key],
      assertKeys: [rotated.key],
      controllerKeys: [rotated.key],
    });
    const state = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [g.jwsToken, rot.jwsToken, later.jwsToken],
    });
    expect('keyProofs' in later.op).toBe(false);
    expectProved(state, rotated.key, ['auth', 'assert', 'controller']);
    expect(state.voidKeys).toEqual([]);
  });
});

describe('possession proofs — void semantics', () => {
  it('voids an introduction with NO envelope, and leaves the chain valid', async () => {
    const g = await genesis();
    const added = makeKey();
    const op = await update({
      did: g.did,
      prevCID: g.operationCID,
      minute: 1,
      signedBy: g.key,
      authKeys: [g.key.key, added.key],
      assertKeys: [g.key.key],
      controllerKeys: [g.key.key],
    });
    // THE CHAIN VERIFIES. That is the door-3 claim: an unproved introduction is
    // not an invalid operation.
    const state = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [g.jwsToken, op.jwsToken],
    });
    expect(state.did).toBe(g.did);
    expectVoid(state, added.key, ['auth']);
    expect(state.voidKeys).toHaveLength(1);
    expect(state.voidKeys?.[0]?.operationCID).toBe(op.operationCID);
    // ...and the genesis key, proved by signing genesis, is untouched.
    expectProved(state, g.key.key, ['auth', 'assert', 'controller']);
  });

  it('voids an envelope bound to the WRONG head — the standing-consent case', async () => {
    const g = await genesis();
    const filler = await update({
      did: g.did,
      prevCID: g.operationCID,
      minute: 1,
      signedBy: g.key,
      authKeys: [g.key.key],
      assertKeys: [g.key.key],
      controllerKeys: [g.key.key],
    });
    const added = makeKey();
    // The envelope names GENESIS as its head; the operation carrying it builds
    // on `filler`. An envelope minted one operation ago is already dead.
    const stale = await proofFor({ key: added, did: g.did, prevCID: g.operationCID });
    const op = await update({
      did: g.did,
      prevCID: filler.operationCID,
      minute: 2,
      signedBy: g.key,
      authKeys: [g.key.key, added.key],
      assertKeys: [g.key.key],
      controllerKeys: [g.key.key],
      keyProofs: [stale],
    });
    const state = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [g.jwsToken, filler.jwsToken, op.jwsToken],
    });
    expectVoid(state, added.key, ['auth']);

    // The SAME key, the SAME operation position, with a correctly-headed
    // envelope: proved. So the refusal is the head binding and nothing else.
    const fresh = await update({
      did: g.did,
      prevCID: filler.operationCID,
      minute: 2,
      signedBy: g.key,
      authKeys: [g.key.key, added.key],
      assertKeys: [g.key.key],
      controllerKeys: [g.key.key],
      keyProofs: [await proofFor({ key: added, did: g.did, prevCID: filler.operationCID })],
    });
    const good = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [g.jwsToken, filler.jwsToken, fresh.jwsToken],
    });
    expectProved(good, added.key, ['auth']);
  });

  it('voids an envelope bound to ANOTHER chain', async () => {
    const g = await genesis();
    const other = await genesis();
    const added = makeKey();
    const op = await update({
      did: g.did,
      prevCID: g.operationCID,
      minute: 1,
      signedBy: g.key,
      authKeys: [g.key.key, added.key],
      assertKeys: [g.key.key],
      controllerKeys: [g.key.key],
      // Real key, real signature, right head shape — wrong identity.
      keyProofs: [await proofFor({ key: added, did: other.did, prevCID: g.operationCID })],
    });
    const state = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [g.jwsToken, op.jwsToken],
    });
    expectVoid(state, added.key, ['auth']);
  });

  it('voids only the roles the envelope does NOT cover', async () => {
    const g = await genesis();
    const added = makeKey();
    const op = await update({
      did: g.did,
      prevCID: g.operationCID,
      minute: 1,
      signedBy: g.key,
      authKeys: [g.key.key, added.key],
      assertKeys: [g.key.key, added.key],
      controllerKeys: [g.key.key, added.key],
      // Consent to auth alone. The other two memberships are declared with no
      // consent behind them.
      keyProofs: [
        await proofFor({ key: added, did: g.did, prevCID: g.operationCID, roles: ['auth'] }),
      ],
    });
    const state = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [g.jwsToken, op.jwsToken],
    });
    expectProved(state, added.key, ['auth']);
    expectVoid(state, added.key, ['assert', 'controller']);
  });

  it('voids a PROMOTION with no fresh envelope', async () => {
    const g = await genesis();
    const added = makeKey();
    // Step one: `added` joins auth, properly proved.
    const join = await update({
      did: g.did,
      prevCID: g.operationCID,
      minute: 1,
      signedBy: g.key,
      authKeys: [g.key.key, added.key],
      assertKeys: [g.key.key],
      controllerKeys: [g.key.key],
      keyProofs: [
        await proofFor({ key: added, did: g.did, prevCID: g.operationCID, roles: ['auth'] }),
      ],
    });
    // Step two: the controller quietly promotes it to controller. Holding auth is
    // not consent to hold control, so the promotion is its own introduction and
    // needs its own envelope.
    const promote = await update({
      did: g.did,
      prevCID: join.operationCID,
      minute: 2,
      signedBy: g.key,
      authKeys: [g.key.key, added.key],
      assertKeys: [g.key.key],
      controllerKeys: [g.key.key, added.key],
    });
    const state = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [g.jwsToken, join.jwsToken, promote.jwsToken],
    });
    expectProved(state, added.key, ['auth']);
    expectVoid(state, added.key, ['controller']);
  });

  it('voids a RE-ADD after removal, even with the envelope that worked the first time', async () => {
    const g = await genesis();
    const added = makeKey();
    const firstEnvelope = await proofFor({
      key: added,
      did: g.did,
      prevCID: g.operationCID,
      roles: ['auth'],
    });
    const join = await update({
      did: g.did,
      prevCID: g.operationCID,
      minute: 1,
      signedBy: g.key,
      authKeys: [g.key.key, added.key],
      assertKeys: [g.key.key],
      controllerKeys: [g.key.key],
      keyProofs: [firstEnvelope],
    });
    const remove = await update({
      did: g.did,
      prevCID: join.operationCID,
      minute: 2,
      signedBy: g.key,
      authKeys: [g.key.key],
      assertKeys: [g.key.key],
      controllerKeys: [g.key.key],
    });
    // The re-add REPLAYS the original envelope verbatim. It is a real signature
    // by the real key that really consented once — bound to a head two
    // operations back. Consent does not stand.
    const readd = await update({
      did: g.did,
      prevCID: remove.operationCID,
      minute: 3,
      signedBy: g.key,
      authKeys: [g.key.key, added.key],
      assertKeys: [g.key.key],
      controllerKeys: [g.key.key],
      keyProofs: [firstEnvelope],
    });
    const state = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [g.jwsToken, join.jwsToken, remove.jwsToken, readd.jwsToken],
    });
    expectVoid(state, added.key, ['auth']);
  });

  it('lets a chain climb back OUT of void with a correctly-headed envelope', async () => {
    const g = await genesis();
    const added = makeKey();
    const unproved = await update({
      did: g.did,
      prevCID: g.operationCID,
      minute: 1,
      signedBy: g.key,
      authKeys: [g.key.key, added.key],
      assertKeys: [g.key.key],
      controllerKeys: [g.key.key],
    });
    // The membership is still declared at the next operation, so it is still an
    // introduction there — and an envelope headed at THAT operation's parent
    // rescues it. Void is a state, not a mark.
    const rescue = await update({
      did: g.did,
      prevCID: unproved.operationCID,
      minute: 2,
      signedBy: g.key,
      authKeys: [g.key.key, added.key],
      assertKeys: [g.key.key],
      controllerKeys: [g.key.key],
      keyProofs: [
        await proofFor({
          key: added,
          did: g.did,
          prevCID: unproved.operationCID,
          roles: ['auth'],
        }),
      ],
    });
    const voided = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [g.jwsToken, unproved.jwsToken],
    });
    expectVoid(voided, added.key, ['auth']);
    const rescued = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [g.jwsToken, unproved.jwsToken, rescue.jwsToken],
    });
    expectProved(rescued, added.key, ['auth']);
  });
});

describe('possession proofs — has-ever-proved', () => {
  it('keeps a proved key forever and never admits a void one', async () => {
    // The `key=` reverse index and historical key resolution both read this, and
    // both are wrong under either of the two obvious shortcuts: reading current
    // effective state loses a rotated-out key that was genuinely proved, and
    // reading the raw log admits a key a stranger merely DECLARED.
    const g = await genesis();
    const rotated = makeKey();
    const neverProved = makeKey();

    const rot = await update({
      did: g.did,
      prevCID: g.operationCID,
      minute: 1,
      signedBy: g.key,
      // `rotated` is proved in; `neverProved` is declared with no envelope.
      authKeys: [rotated.key, neverProved.key],
      assertKeys: [rotated.key],
      controllerKeys: [rotated.key],
      keyProofs: [await proofFor({ key: rotated, did: g.did, prevCID: g.operationCID })],
    });
    // A second rotation drops BOTH of them and goes back to a key of its own.
    const third = makeKey();
    const rot2 = await update({
      did: g.did,
      prevCID: rot.operationCID,
      minute: 2,
      signedBy: rotated,
      authKeys: [third.key],
      assertKeys: [third.key],
      controllerKeys: [third.key],
      keyProofs: [await proofFor({ key: third, did: g.did, prevCID: rot.operationCID })],
    });

    const state = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [g.jwsToken, rot.jwsToken, rot2.jwsToken],
    });
    const proved = state.provedKeys ?? { authKeys: [], assertKeys: [], controllerKeys: [] };
    const provedAuthIds = proved.authKeys.map((k) => k.id);

    // Current effective state holds only the third key...
    expect(state.authKeys.map((k) => k.id)).toEqual([third.key.id]);
    // ...while has-ever-proved holds all three keys that were ever proved in.
    expect(provedAuthIds).toContain(g.key.key.id);
    expect(provedAuthIds).toContain(rotated.key.id);
    expect(provedAuthIds).toContain(third.key.id);
    // The declared-but-never-proved key is absent. A stranger cannot burn a key
    // by writing it into their own chain.
    expect(provedAuthIds).not.toContain(neverProved.key.id);
  });

  it('agrees between full replay and the O(1) extension verifier', async () => {
    const g = await genesis();
    const rotated = makeKey();
    const rot = await update({
      did: g.did,
      prevCID: g.operationCID,
      minute: 1,
      signedBy: g.key,
      authKeys: [rotated.key],
      assertKeys: [rotated.key],
      controllerKeys: [rotated.key],
      keyProofs: [await proofFor({ key: rotated, did: g.did, prevCID: g.operationCID })],
    });
    const replayed = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [g.jwsToken, rot.jwsToken],
    });
    const extended = await verifyIdentityExtensionFromTrustedState({
      currentState: g.state,
      headCID: g.operationCID,
      lastCreatedAt: g.op.createdAt,
      newOp: rot.jwsToken,
    });
    expect(extended.state.provedKeys).toEqual(replayed.provedKeys);
  });
});

describe('possession proofs — what proof status does NOT touch', () => {
  it('admits a signature from a VOID controller key — signer validity is declared-state', async () => {
    // The load-bearing separation. A relay must be able to decide whether an
    // operation is admissible without weighing possession evidence, or two
    // relays could disagree about whether an operation exists at all.
    const g = await genesis();
    const unproved = makeKey();
    const promote = await update({
      did: g.did,
      prevCID: g.operationCID,
      minute: 1,
      signedBy: g.key,
      authKeys: [g.key.key],
      assertKeys: [g.key.key],
      controllerKeys: [g.key.key, unproved.key],
    });
    const afterPromote = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [g.jwsToken, promote.jwsToken],
    });
    expectVoid(afterPromote, unproved.key, ['controller']);

    // ...and it signs the next operation anyway, because DECLARED state admits it.
    const next = await update({
      did: g.did,
      prevCID: promote.operationCID,
      minute: 2,
      signedBy: unproved,
      authKeys: [g.key.key],
      assertKeys: [g.key.key],
      controllerKeys: [g.key.key, unproved.key],
    });
    const state = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [g.jwsToken, promote.jwsToken, next.jwsToken],
    });
    expect(state.isDeleted).toBe(false);
    expectVoid(state, unproved.key, ['controller']);
    // The key signed a valid operation and still does not resolve. Both are true
    // at once, and that is the design.
    expect(isEffective(state, unproved.key, 'controller')).toBe(false);
  });

  it('carries both key states, and the void list, across delete and restore', async () => {
    const g = await genesis();
    const added = makeKey();
    const op = await update({
      did: g.did,
      prevCID: g.operationCID,
      minute: 1,
      signedBy: g.key,
      authKeys: [g.key.key, added.key],
      assertKeys: [g.key.key],
      controllerKeys: [g.key.key],
    });
    const del: IdentityOperation = {
      version: 1,
      type: 'delete',
      previousOperationCID: op.operationCID,
      createdAt: ts(2),
    };
    const signedDelete = await signIdentityOperation({
      operation: del,
      signer: g.key.signer,
      keyId: g.key.keyId,
      identityDID: g.did,
    });
    const res: IdentityOperation = {
      version: 1,
      type: 'restore',
      previousOperationCID: signedDelete.operationCID,
      createdAt: ts(3),
    };
    const signedRestore = await signIdentityOperation({
      operation: res,
      signer: g.key.signer,
      keyId: g.key.keyId,
      identityDID: g.did,
    });
    const state = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [g.jwsToken, op.jwsToken, signedDelete.jwsToken, signedRestore.jwsToken],
    });
    expect(state.isDeleted).toBe(false);
    expectVoid(state, added.key, ['auth']);
    expectProved(state, g.key.key, ['auth', 'assert', 'controller']);
  });
});

describe('possession proofs — carriage', () => {
  it('rejects keyProofs on create, delete and restore', async () => {
    const g = await genesis();
    const stray = await proofFor({ key: g.key, did: g.did, prevCID: g.operationCID });

    // create
    const k = makeKey();
    const badGenesis = await signIdentityOperation({
      operation: {
        version: 1,
        type: 'create',
        authKeys: [k.key],
        assertKeys: [k.key],
        controllerKeys: [k.key],
        createdAt: ts(0),
        keyProofs: [stray],
      } as unknown as IdentityOperation,
      signer: k.signer,
      keyId: k.keyId,
    });
    await expect(
      verifyIdentityChain({ didPrefix: 'did:dfos', log: [badGenesis.jwsToken] }),
    ).rejects.toThrow(/keyProofs is valid on update only/);

    // delete
    const badDelete = await signIdentityOperation({
      operation: {
        version: 1,
        type: 'delete',
        previousOperationCID: g.operationCID,
        createdAt: ts(1),
        keyProofs: [stray],
      } as unknown as IdentityOperation,
      signer: g.key.signer,
      keyId: g.key.keyId,
      identityDID: g.did,
    });
    await expect(
      verifyIdentityChain({ didPrefix: 'did:dfos', log: [g.jwsToken, badDelete.jwsToken] }),
    ).rejects.toThrow(/keyProofs is valid on update only/);

    // restore — which needs a real delete in front of it, since restore is only
    // ever valid immediately after one.
    const cleanDelete = await signIdentityOperation({
      operation: {
        version: 1,
        type: 'delete',
        previousOperationCID: g.operationCID,
        createdAt: ts(1),
      },
      signer: g.key.signer,
      keyId: g.key.keyId,
      identityDID: g.did,
    });
    const badRestore = await signIdentityOperation({
      operation: {
        version: 1,
        type: 'restore',
        previousOperationCID: cleanDelete.operationCID,
        createdAt: ts(2),
        keyProofs: [stray],
      } as unknown as IdentityOperation,
      signer: g.key.signer,
      keyId: g.key.keyId,
      identityDID: g.did,
    });
    await expect(
      verifyIdentityChain({
        didPrefix: 'did:dfos',
        log: [g.jwsToken, cleanDelete.jwsToken, badRestore.jwsToken],
      }),
    ).rejects.toThrow(/keyProofs is valid on update only/);
  });
});

describe('possession proofs — the O(1) extension verifier agrees with full replay', () => {
  it('produces the same effective state, declared state and void list', async () => {
    const g = await genesis();
    const proved = makeKey();
    const unproved = makeKey();
    const op = await update({
      did: g.did,
      prevCID: g.operationCID,
      minute: 1,
      signedBy: g.key,
      authKeys: [g.key.key, proved.key, unproved.key],
      assertKeys: [g.key.key],
      controllerKeys: [g.key.key],
      keyProofs: [
        await proofFor({ key: proved, did: g.did, prevCID: g.operationCID, roles: ['auth'] }),
      ],
    });

    const replayed = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [g.jwsToken, op.jwsToken],
    });
    const extended = await verifyIdentityExtensionFromTrustedState({
      currentState: g.state,
      headCID: g.operationCID,
      lastCreatedAt: g.op.createdAt,
      newOp: op.jwsToken,
    });

    expect(extended.operationCID).toBe(op.operationCID);
    expect(extended.state.authKeys).toEqual(replayed.authKeys);
    expect(extended.state.assertKeys).toEqual(replayed.assertKeys);
    expect(extended.state.controllerKeys).toEqual(replayed.controllerKeys);
    expect(extended.state.declared).toEqual(replayed.declared);
    expect(extended.state.voidKeys).toEqual(replayed.voidKeys);
    expectProved(extended.state, proved.key, ['auth']);
    expectVoid(extended.state, unproved.key, ['auth']);
  });

  it('rejects keyProofs on a delete extension', async () => {
    const g = await genesis();
    const stray = await proofFor({ key: g.key, did: g.did, prevCID: g.operationCID });
    const signed = await signIdentityOperation({
      operation: {
        version: 1,
        type: 'delete',
        previousOperationCID: g.operationCID,
        createdAt: ts(1),
        keyProofs: [stray],
      } as unknown as IdentityOperation,
      signer: g.key.signer,
      keyId: g.key.keyId,
      identityDID: g.did,
    });
    await expect(
      verifyIdentityExtensionFromTrustedState({
        currentState: g.state,
        headCID: g.operationCID,
        lastCreatedAt: g.op.createdAt,
        newOp: signed.jwsToken,
      }),
    ).rejects.toThrow(/keyProofs is valid on update only/);
  });
});
