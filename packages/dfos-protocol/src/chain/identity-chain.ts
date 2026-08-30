/*

  IDENTITY CHAIN

  JWS-based key chain operations for Ed25519/Multikey regime

  An identity chain is a self-sovereign signed linked list of key state
  commitments. The DID is derived from the genesis operation CID. Each
  operation is signed by a current controller key.

  TWO KEY STATES, AND WHY. A chain carries what its controller DECLARED and,
  separately, what possession actually PROVED. The two differ because a
  controller can write any key into any role — declaring a key is a claim about
  someone else's private material, and a claim is not a demonstration.

    - DECLARED state is structural: the full-state key arrays exactly as the
      operations spell them.
    - EFFECTIVE state is declared state minus every key-role membership no
      possession proof admitted.

  THE BIMODAL PROOF RULE, WITH NO THIRD CASE. Genesis declares exactly ONE key,
  in all three roles, and SIGNS ITSELF with it — that signature is the proof, and
  it covers all three roles. Every OTHER key-role membership in the chain's life
  is proved by an embedded KEY-PROOF envelope and by nothing else. There is no
  grandfathering, no operator attestation, and no "the controller vouched for it".

  AN UNPROVED INTRODUCTION VOIDS A MEMBERSHIP, NOT AN OPERATION. The operation is
  valid, the chain is valid, the CID stands and relays sequence it. The key is
  simply not in effective state for that role, and shows up on `voidKeys` so
  tooling can say so out loud. Voiding rather than rejecting is what keeps
  possession proofs off the ingest path: a relay that rejected unproved
  introductions would be a relay whose accept/reject verdict depends on evidence
  another relay might weigh differently, and two relays disagreeing about whether
  an operation exists is the one divergence a gossip layer cannot heal.

  SIGNER VALIDITY STAYS DECLARED-STATE-BASED, and this is load-bearing for the
  same reason. An operation's signer must be a controller key of the immediately
  prior DECLARED state. Gating signature admission on proof status would make
  chain VALIDITY — not just resolution — depend on the possession fold, and put
  the divergence back.

*/

import { createJws, dagCborCanonicalEncode, decodeJwsUnsafe, verifyJws } from '../crypto';
import {
  KEY_ADD_JWS_TYP,
  KEY_ROLES,
  unsafeKeyProofSubject,
  verifyChainKeyProof,
  type KeyRole,
} from '../key-proof';
import { deriveChainIdentifier } from './derivation';
import { decodeMultikey } from './multikey';
import {
  IdentityOperation,
  MAX_OPERATION_SIZE,
  type DeclaredKeyState,
  type MultikeyPublicKey,
  type ServiceEntry,
  type VerifiedIdentity,
  type VoidKeyMembership,
} from './schemas';
import type { Signer } from './schemas';
import { assertServicesWithinCap } from './services';

// -----------------------------------------------------------------------------
// the possession fold
// -----------------------------------------------------------------------------

/** The operation array each role's membership lives in. */
const ROLE_ARRAY = {
  auth: 'authKeys',
  assert: 'assertKeys',
  controller: 'controllerKeys',
} as const satisfies Record<KeyRole, keyof DeclaredKeyState>;

const emptyKeyState = (): DeclaredKeyState => ({
  authKeys: [],
  assertKeys: [],
  controllerKeys: [],
});

const keyStateOf = (op: {
  authKeys: MultikeyPublicKey[];
  assertKeys: MultikeyPublicKey[];
  controllerKeys: MultikeyPublicKey[];
}): DeclaredKeyState => ({
  authKeys: op.authKeys,
  assertKeys: op.assertKeys,
  controllerKeys: op.controllerKeys,
});

/** A key state where every declared membership is also effective. */
const fullyProved = (state: DeclaredKeyState): DeclaredKeyState => ({
  authKeys: [...state.authKeys],
  assertKeys: [...state.assertKeys],
  controllerKeys: [...state.controllerKeys],
});

/**
 * Fold one effective key state into a running HAS-EVER-PROVED union. Monotonic
 * and first-wins: a key id already in the union keeps the entry it went in with,
 * which is the same entry regardless, because key-material consistency is
 * enforced chain-wide.
 */
const unionProved = (into: DeclaredKeyState, next: DeclaredKeyState): DeclaredKeyState => {
  const merged = emptyKeyState();
  for (const role of KEY_ROLES) {
    const seen = new Map<string, MultikeyPublicKey>();
    for (const key of [...into[ROLE_ARRAY[role]], ...next[ROLE_ARRAY[role]]]) {
      if (!seen.has(key.id)) seen.set(key.id, key);
    }
    merged[ROLE_ARRAY[role]] = [...seen.values()];
  }
  return merged;
};

/**
 * The key-role memberships an operation's key proofs admit.
 *
 * AN INTRODUCTION IS A TRANSITION, NOT A PRESENCE. An operation introduces key K
 * to role R exactly when K is in the operation's R array and K was NOT in the
 * PRIOR EFFECTIVE R state. Two consequences follow, and both are the point:
 *
 *  - An ordinary update that replays keys already effective introduces nothing
 *    and needs no envelope. Full-state carriage moves key ARRAYS forward, never
 *    the evidence that admitted them, so proofs never accumulate in a chain.
 *  - Re-adding a removed key, or promoting an effective key into a role it did
 *    not hold, IS a fresh introduction and needs a FRESH envelope. An old
 *    envelope names an old `prevCID` and is dead against the current head, which
 *    is precisely how standing consent is foreclosed: there is no envelope a
 *    controller can bank against a future operation.
 *
 * Note that the prior state consulted is the EFFECTIVE one. A membership that
 * went void at operation N is therefore introduced AGAIN at N+1, where a
 * correctly-headed envelope can still rescue it — void is a state a chain can
 * climb out of, not a mark.
 */
const foldEffectiveKeyState = (input: {
  did: string;
  /** The operation's own full-state key arrays. */
  declared: DeclaredKeyState;
  /** Effective state as of the operation immediately before this one. */
  priorEffective: DeclaredKeyState;
  /** The operation's `previousOperationCID` — what an envelope must name. */
  previousOperationCID: string;
  /** This operation's CID, stamped onto any void membership it leaves behind. */
  operationCID: string;
  /** The envelopes this operation carries. */
  keyProofs: string[];
}): { effective: DeclaredKeyState; voidKeys: VoidKeyMembership[] } => {
  const carried = (role: KeyRole, key: MultikeyPublicKey): boolean =>
    input.priorEffective[ROLE_ARRAY[role]].some((prior) => prior.id === key.id);

  // The introductions, indexed by key MATERIAL. Material rather than key id
  // because an envelope binds a Multikey: two ids naming the same material are
  // the same key, and one envelope proves both.
  const introduced = new Map<string, { key: MultikeyPublicKey; roles: Set<KeyRole> }>();
  for (const role of KEY_ROLES) {
    for (const key of input.declared[ROLE_ARRAY[role]]) {
      if (carried(role, key)) continue;
      const entry = introduced.get(key.publicKeyMultibase) ?? { key, roles: new Set<KeyRole>() };
      entry.roles.add(role);
      introduced.set(key.publicKeyMultibase, entry);
    }
  }

  // Route each envelope to the candidate it NAMES and gate it there. The routing
  // hint is unverified (see `unsafeKeyProofSubject`); the gate immediately
  // re-checks it against the candidate's declared Multikey, so a forged hint only
  // reaches a candidate it then fails against.
  const proved = new Map<string, Set<KeyRole>>();
  for (const jws of input.keyProofs) {
    const subject = unsafeKeyProofSubject(jws);
    if (subject === null) continue;
    const candidate = introduced.get(subject);
    if (candidate === undefined) continue;
    for (const role of candidate.roles) {
      try {
        verifyChainKeyProof(jws, {
          expectedTyp: KEY_ADD_JWS_TYP,
          did: input.did,
          prevCID: input.previousOperationCID,
          publicKeyMultibase: candidate.key.publicKeyMultibase,
          role,
        });
      } catch {
        // Not proof of THIS membership. Never fatal: an envelope that fails here
        // is evidence that did not apply, not an invalid chain.
        continue;
      }
      const covered = proved.get(subject) ?? new Set<KeyRole>();
      covered.add(role);
      proved.set(subject, covered);
    }
  }

  const effective = emptyKeyState();
  const voidKeys: VoidKeyMembership[] = [];
  for (const role of KEY_ROLES) {
    for (const key of input.declared[ROLE_ARRAY[role]]) {
      if (carried(role, key) || proved.get(key.publicKeyMultibase)?.has(role) === true) {
        effective[ROLE_ARRAY[role]].push(key);
      } else {
        voidKeys.push({ key, role, operationCID: input.operationCID });
      }
    }
  }
  return { effective, voidKeys };
};

/**
 * THE SINGLE-KEY GENESIS RULE, structural. A genesis operation declares exactly
 * ONE key: one entry in each of the three arrays, and the same key in all three.
 *
 * This is a REJECT, not a void, and it is the only key rule in the chain that is.
 * Genesis is the one operation whose keys are proved by the operation's own
 * signature, and one signature demonstrates possession of exactly one key — so a
 * genesis declaring a second key would be declaring a membership that the bimodal
 * rule has no way to prove and no later operation can rescue, since nothing
 * precedes genesis to be a `prevCID`. Rather than mint a chain that is born with
 * a permanently void membership, the shape is refused outright. A second key
 * joins the ordinary way: an update, carrying an envelope.
 */
const assertSingleKeyGenesis = (op: {
  authKeys: MultikeyPublicKey[];
  assertKeys: MultikeyPublicKey[];
  controllerKeys: MultikeyPublicKey[];
}): void => {
  if (op.authKeys.length !== 1 || op.assertKeys.length !== 1 || op.controllerKeys.length !== 1) {
    throw new Error('create must declare exactly one key in each of auth, assert and controller');
  }
  const [auth, assert, controller] = [op.authKeys[0], op.assertKeys[0], op.controllerKeys[0]] as [
    MultikeyPublicKey,
    MultikeyPublicKey,
    MultikeyPublicKey,
  ];
  const same = (a: MultikeyPublicKey, b: MultikeyPublicKey): boolean =>
    a.id === b.id && a.type === b.type && a.publicKeyMultibase === b.publicKeyMultibase;
  if (!same(auth, assert) || !same(auth, controller)) {
    throw new Error('create must declare the SAME key in auth, assert and controller');
  }
};

/**
 * THE CARRIAGE GATE. `keyProofs` is valid on `update` and nowhere else — a
 * `create`, `delete` or `restore` carrying one is an INVALID operation.
 *
 * A rejection rather than a MUST-ignore, unlike every other unknown member on
 * these loose payloads, because a proof on one of those three operations is not
 * an unknown extension a later version might define: it is a claim in a position
 * where the bimodal rule already has an answer. On `create` the answer is the
 * genesis signature; on `delete` and `restore` there is nothing to introduce.
 * Ignoring it would let an operation carry evidence that reads as consequential
 * and is not.
 */
const assertKeyProofCarriage = (op: IdentityOperation): void => {
  if (op.type !== 'update' && 'keyProofs' in op) {
    throw new Error(`keyProofs is valid on update only, not on ${op.type}`);
  }
};

// -----------------------------------------------------------------------------
// signing
// -----------------------------------------------------------------------------

/**
 * Sign an identity operation as a JWS and derive the operation CID
 */
export const signIdentityOperation = async (input: {
  operation: IdentityOperation;
  signer: Signer;
  keyId: string;
  /** DID of the identity — omit for genesis (bare kid) */
  identityDID?: string;
}): Promise<{ jwsToken: string; operationCID: string }> => {
  const kid = input.identityDID ? `${input.identityDID}#${input.keyId}` : input.keyId;

  // derive CID first so it can be embedded in the signed header
  const encoded = await dagCborCanonicalEncode(input.operation);
  const operationCID = encoded.cid.toString();

  const jwsToken = await createJws({
    header: { alg: 'EdDSA', typ: 'did:dfos:identity-op', kid, cid: operationCID },
    payload: input.operation as unknown as Record<string, unknown>,
    sign: input.signer,
  });

  return { jwsToken, operationCID };
};

// -----------------------------------------------------------------------------
// verification
// -----------------------------------------------------------------------------

/**
 * Verify a log of JWS identity operations and derive the identity
 *
 * Walks the chain from genesis, verifying signatures and chain integrity, and
 * folds the possession proofs alongside. Returns the final verified identity
 * state: EFFECTIVE key arrays, with the declared arrays and the void memberships
 * beside them.
 */
export const verifyIdentityChain = async (input: {
  didPrefix: string;
  log: string[];
}): Promise<VerifiedIdentity> => {
  if (input.log.length === 0) throw new Error('log must have at least one operation');

  const state = {
    did: undefined as string | undefined,
    isDeleted: false,
    previousOperationCID: null as string | null,
    lastCreatedAt: null as string | null,
    /** What the chain SAYS — the arbiter of signer validity. */
    declared: emptyKeyState(),
    /** What possession PROVED — what consumers get. */
    effective: emptyKeyState(),
    /** Every membership possession has EVER proved. Monotonic. */
    provedKeys: emptyKeyState(),
    voidKeys: [] as VoidKeyMembership[],
    services: [] as ServiceEntry[],
    seenKeys: new Map<string, MultikeyPublicKey>(),
  };

  for (const [idx, jwsToken] of input.log.entries()) {
    // decode JWS
    const decoded = decodeJwsUnsafe(jwsToken);
    if (!decoded) throw new Error(`log[${idx}]: failed to decode JWS`);

    // parse payload
    const result = IdentityOperation.safeParse(decoded.payload);
    if (!result.success) {
      const messages = result.error.issues.map((e) => e.message).join(', ');
      throw new Error(`log[${idx}]: ${messages}`);
    }
    const op = result.data;

    // verify typ
    if (decoded.header.typ !== 'did:dfos:identity-op') {
      throw new Error(`log[${idx}]: invalid typ: ${decoded.header.typ}`);
    }

    // A deleted identity admits exactly one operation: restore. Conversely,
    // restore is invalid in every active position. Since nothing else may
    // follow delete, isDeleted also proves the immediate parent was delete.
    if (state.isDeleted && op.type !== 'restore') {
      throw new Error(`log[${idx}]: cannot modify a deleted identity`);
    }
    if (!state.isDeleted && op.type === 'restore') {
      throw new Error(`log[${idx}]: restore must immediately follow delete`);
    }

    // genesis must be create
    if (idx === 0 && op.type !== 'create') {
      throw new Error(`log[${idx}]: first operation must be create`);
    }
    if (idx > 0 && op.type === 'create') {
      throw new Error(`log[${idx}]: create can only be the first operation`);
    }

    // key proofs ride on update and nowhere else
    try {
      assertKeyProofCarriage(op);
    } catch (e) {
      throw new Error(`log[${idx}]: ${(e as Error).message}`);
    }

    // initialize key state from genesis
    if (op.type === 'create') {
      try {
        assertSingleKeyGenesis(op);
      } catch (e) {
        throw new Error(`log[${idx}]: ${(e as Error).message}`);
      }
      // Genesis declares one key and signs itself with it, so declared and
      // effective are the same set and there is nothing to void. Declared state
      // is assigned HERE, before the signature check below, because genesis is
      // the one operation whose signer is resolved against its own declaration.
      state.declared = keyStateOf(op);
      state.effective = fullyProved(state.declared);
      state.provedKeys = fullyProved(state.declared);
      state.services = op.services ?? [];
    }

    // chain integrity for non-genesis ops
    if (op.type !== 'create') {
      if (op.previousOperationCID !== state.previousOperationCID) {
        throw new Error(`log[${idx}]: previousCID is incorrect`);
      }
      if (!state.lastCreatedAt) throw new Error(`log[${idx}]: lastCreatedAt is not set`);
      if (op.createdAt <= state.lastCreatedAt) {
        throw new Error(`log[${idx}]: createdAt must be after last op`);
      }
    }

    // key consistency check — same key ID must always have same key material
    if (op.type === 'create' || op.type === 'update') {
      const incomingKeys = [...op.authKeys, ...op.assertKeys, ...op.controllerKeys];
      // DECLARED, not effective: key-material consistency is a property of what
      // the chain wrote, and a void key still may not change its material later.
      const currentKeys = [
        ...state.declared.authKeys,
        ...state.declared.assertKeys,
        ...state.declared.controllerKeys,
      ];
      for (const k of [...currentKeys, ...incomingKeys]) {
        const existing = state.seenKeys.get(k.id);
        if (!existing) {
          state.seenKeys.set(k.id, k);
        } else if (
          existing.publicKeyMultibase !== k.publicKeyMultibase ||
          existing.type !== k.type
        ) {
          throw new Error(`log[${idx}]: key ${k.id} type or public key inconsistency`);
        }
      }

      // duplicate key check within usage sections
      [op.authKeys, op.assertKeys, op.controllerKeys].forEach((keys) => {
        const set = new Set(keys.map((k) => k.id));
        if (set.size !== keys.length) {
          throw new Error(`log[${idx}]: cannot repeat key ids in same usage`);
        }
      });

      // enforce services byte cap (full-state services travel on create/update)
      if (op.services) {
        try {
          await assertServicesWithinCap(op.services);
        } catch (e) {
          throw new Error(`log[${idx}]: ${(e as Error).message}`);
        }
      }
    }

    // derive operation CID from payload
    const encoded = await dagCborCanonicalEncode(op);
    if (encoded.bytes.length > MAX_OPERATION_SIZE) {
      throw new Error(
        `log[${idx}]: operation exceeds max size: ${encoded.bytes.length} > ${MAX_OPERATION_SIZE}`,
      );
    }
    const operationCID = encoded.cid.toString();

    // verify cid header — must be present and match derived CID
    if (!decoded.header.cid) {
      throw new Error(`log[${idx}]: missing cid in protected header`);
    }
    if (decoded.header.cid !== operationCID) {
      throw new Error(`log[${idx}]: cid mismatch in protected header`);
    }

    // resolve signing key from kid
    const kid = decoded.header.kid;
    let signingKeyId: string;
    if (kid.includes('#')) {
      const hashIdx = kid.indexOf('#');
      signingKeyId = kid.substring(hashIdx + 1);
      if (idx === 0) {
        throw new Error(`log[${idx}]: genesis op kid must be bare key ID, got DID URL`);
      }
    } else {
      signingKeyId = kid;
      if (idx > 0) {
        throw new Error(`log[${idx}]: non-genesis op kid must be DID URL, got bare key ID`);
      }
    }

    // Find the controller key referenced by kid — in DECLARED state, on purpose.
    // Proof status does not gate signature admission: chain validity must not
    // depend on the possession fold, or two relays weighing evidence differently
    // would disagree about whether an operation exists. See the file header.
    const signingKey = state.declared.controllerKeys.find((k) => k.id === signingKeyId);
    if (!signingKey) {
      throw new Error(`log[${idx}]: kid references unknown key: ${signingKeyId}`);
    }

    // verify JWS signature
    const { keyBytes } = decodeMultikey(signingKey.publicKeyMultibase);
    try {
      verifyJws({ token: jwsToken, publicKey: keyBytes });
    } catch {
      throw new Error(`log[${idx}]: invalid signature`);
    }

    // derive DID from genesis CID
    if (state.did === undefined) {
      state.did = deriveChainIdentifier(encoded.cid.bytes, input.didPrefix);
    }
    const did = state.did;

    // verify DID in kid matches for non-genesis ops
    if (idx > 0 && kid.includes('#')) {
      const didFromKid = kid.substring(0, kid.indexOf('#'));
      if (didFromKid !== state.did) {
        throw new Error(`log[${idx}]: kid DID does not match identity DID`);
      }
    }

    // update state based on operation type
    state.previousOperationCID = operationCID;
    state.lastCreatedAt = op.createdAt;

    switch (op.type) {
      case 'create':
        // key state already initialized above
        break;
      case 'update': {
        if (op.controllerKeys.length === 0) {
          throw new Error(`log[${idx}]: update must have at least one controller key`);
        }
        // The possession fold runs against the state that held BEFORE this
        // operation, then declared state advances. Order matters: an
        // introduction is a transition out of the PRIOR effective state.
        const folded = foldEffectiveKeyState({
          did,
          declared: keyStateOf(op),
          priorEffective: state.effective,
          previousOperationCID: op.previousOperationCID,
          operationCID,
          keyProofs: op.keyProofs ?? [],
        });
        state.declared = keyStateOf(op);
        state.effective = folded.effective;
        state.provedKeys = unionProved(state.provedKeys, folded.effective);
        state.voidKeys = folded.voidKeys;
        // full-state: update replaces the entire services set (omit to clear)
        state.services = op.services ?? [];
        break;
      }
      case 'delete':
        state.isDeleted = true;
        break;
      case 'restore':
        state.isDeleted = false;
        break;
    }
  }

  if (!state.did) throw new Error('did is not set');

  return {
    did: state.did,
    isDeleted: state.isDeleted,
    // EFFECTIVE state is what a consumer gets. A void key never resolves.
    authKeys: state.effective.authKeys,
    assertKeys: state.effective.assertKeys,
    controllerKeys: state.effective.controllerKeys,
    services: state.services,
    declared: state.declared,
    voidKeys: state.voidKeys,
    provedKeys: state.provedKeys,
  };
};

// -----------------------------------------------------------------------------
// extension verification (O(1))
// -----------------------------------------------------------------------------

/**
 * Verify a single new operation against already-verified identity state
 *
 * The caller guarantees that `currentState` was produced by a correct prior
 * verification (full chain replay or a chain of trusted extensions from a
 * verified genesis). This function performs one signature verification and one
 * state transition — constant time regardless of chain length.
 *
 * Note: key-ID consistency across the full chain history is NOT checked here.
 * That invariant is established during genesis verification and maintained by
 * the protocol's key consistency rules. Periodic full re-verification can
 * audit this property.
 *
 * THE POSSESSION FOLD RUNS HERE TOO, and it needs both halves of the trusted
 * state: the EFFECTIVE arrays (to know what an introduction is a transition out
 * of) and the DECLARED arrays (to admit the signer). `currentState.declared`
 * carries the second. When it is absent — a hand-built state, or one produced
 * before this member existed — the effective arrays stand in for it, which is
 * exactly correct for any chain with no void memberships and is the only reading
 * available for a state that never recorded the difference.
 */
export const verifyIdentityExtensionFromTrustedState = async (input: {
  /** Previously verified identity state */
  currentState: VerifiedIdentity;
  /** CID of the most recent operation in the chain */
  headCID: string;
  /** createdAt timestamp of the most recent operation */
  lastCreatedAt: string;
  /** The new JWS operation to verify */
  newOp: string;
}): Promise<{
  state: VerifiedIdentity;
  operationCID: string;
  createdAt: string;
}> => {
  const { currentState, headCID, lastCreatedAt, newOp } = input;
  const priorEffective = keyStateOf(currentState);
  const priorDeclared = currentState.declared ?? priorEffective;
  // Absent has-ever-proved history reads as "what is effective now was proved" —
  // true for any chain that never voided a membership, and the only reading
  // available for a state that did not record the difference.
  const priorProved = currentState.provedKeys ?? priorEffective;

  // decode JWS
  const decoded = decodeJwsUnsafe(newOp);
  if (!decoded) throw new Error('failed to decode JWS');

  // parse payload
  const result = IdentityOperation.safeParse(decoded.payload);
  if (!result.success) {
    const messages = result.error.issues.map((e) => e.message).join(', ');
    throw new Error(messages);
  }
  const op = result.data;

  // key proofs ride on update and nowhere else
  assertKeyProofCarriage(op);

  // isDeleted proves that the trusted head is a delete: no other operation is
  // admitted after deletion. Restore is invalid against every active head.
  if (currentState.isDeleted && op.type !== 'restore') {
    throw new Error('cannot extend a deleted identity');
  }
  if (!currentState.isDeleted && op.type === 'restore') {
    throw new Error('restore must immediately follow delete');
  }

  // verify typ
  if (decoded.header.typ !== 'did:dfos:identity-op') {
    throw new Error(`invalid typ: ${decoded.header.typ}`);
  }

  // extensions must not be create
  if (op.type === 'create') {
    throw new Error('extension cannot be a create operation');
  }

  // chain integrity
  if (op.previousOperationCID !== headCID) {
    throw new Error('previousCID is incorrect');
  }
  if (op.createdAt <= lastCreatedAt) {
    throw new Error('createdAt must be after last op');
  }

  // derive operation CID
  const encoded = await dagCborCanonicalEncode(op);
  if (encoded.bytes.length > MAX_OPERATION_SIZE) {
    throw new Error(`operation exceeds max size: ${encoded.bytes.length} > ${MAX_OPERATION_SIZE}`);
  }
  const operationCID = encoded.cid.toString();

  // verify cid header
  if (!decoded.header.cid) throw new Error('missing cid in protected header');
  if (decoded.header.cid !== operationCID) throw new Error('cid mismatch in protected header');

  // resolve signing key from kid — must be a DID URL for non-genesis
  const kid = decoded.header.kid;
  if (!kid.includes('#')) {
    throw new Error('non-genesis op kid must be DID URL, got bare key ID');
  }
  const hashIdx = kid.indexOf('#');
  const signingKeyId = kid.substring(hashIdx + 1);
  const kidDid = kid.substring(0, hashIdx);

  if (kidDid !== currentState.did) {
    throw new Error('kid DID does not match identity DID');
  }

  // DECLARED state admits the signer — see the file header on why proof status
  // must not gate signature admission.
  const signingKey = priorDeclared.controllerKeys.find((k) => k.id === signingKeyId);
  if (!signingKey) {
    throw new Error(`kid references unknown key: ${signingKeyId}`);
  }

  // verify JWS signature
  const { keyBytes } = decodeMultikey(signingKey.publicKeyMultibase);
  try {
    verifyJws({ token: newOp, publicKey: keyBytes });
  } catch {
    throw new Error('invalid signature');
  }

  // key consistency — check for duplicate key IDs within usage sections
  if (op.type === 'update') {
    [op.authKeys, op.assertKeys, op.controllerKeys].forEach((keys) => {
      const set = new Set(keys.map((k) => k.id));
      if (set.size !== keys.length) {
        throw new Error('cannot repeat key ids in same usage');
      }
    });
    if (op.services) await assertServicesWithinCap(op.services);
  }

  // compute new state
  const newState: VerifiedIdentity = (() => {
    switch (op.type) {
      case 'update': {
        const declared = keyStateOf(op);
        const folded = foldEffectiveKeyState({
          did: currentState.did,
          declared,
          priorEffective,
          previousOperationCID: op.previousOperationCID,
          operationCID,
          keyProofs: op.keyProofs ?? [],
        });
        return {
          did: currentState.did,
          isDeleted: false,
          authKeys: folded.effective.authKeys,
          assertKeys: folded.effective.assertKeys,
          controllerKeys: folded.effective.controllerKeys,
          services: op.services ?? [],
          declared,
          voidKeys: folded.voidKeys,
          provedKeys: unionProved(priorProved, folded.effective),
        };
      }
      // delete and restore introduce nothing, so both key states — and the void
      // list — travel forward untouched.
      case 'delete':
        return {
          did: currentState.did,
          isDeleted: true,
          authKeys: currentState.authKeys,
          assertKeys: currentState.assertKeys,
          controllerKeys: currentState.controllerKeys,
          services: currentState.services,
          declared: priorDeclared,
          voidKeys: currentState.voidKeys ?? [],
          provedKeys: priorProved,
        };
      case 'restore':
        return {
          did: currentState.did,
          isDeleted: false,
          authKeys: currentState.authKeys,
          assertKeys: currentState.assertKeys,
          controllerKeys: currentState.controllerKeys,
          services: currentState.services,
          declared: priorDeclared,
          voidKeys: currentState.voidKeys ?? [],
          provedKeys: priorProved,
        };
    }
  })();

  return { state: newState, operationCID, createdAt: op.createdAt };
};
