/*

  IDENTITY CHAIN

  JWS-based key chain operations for Ed25519/Multikey regime

  An identity chain is a self-sovereign signed linked list of key state
  commitments. The DID is derived from the genesis operation CID. Each
  operation is signed by a current controller key.

*/

import { createJws, dagCborCanonicalEncode, decodeJwsUnsafe, verifyJws } from '../crypto';
import { deriveChainIdentifier } from './derivation';
import { decodeMultikey } from './multikey';
import { IdentityOperation, type MultikeyPublicKey, type VerifiedIdentity } from './schemas';
import type { Signer } from './schemas';

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
 * Walks the chain from genesis, verifying signatures and chain integrity.
 * Returns the final verified identity state.
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
    authKeys: [] as MultikeyPublicKey[],
    assertKeys: [] as MultikeyPublicKey[],
    controllerKeys: [] as MultikeyPublicKey[],
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

    // terminal state checks
    if (state.isDeleted) throw new Error(`log[${idx}]: cannot modify a deleted identity`);

    // genesis must be create
    if (idx === 0 && op.type !== 'create') {
      throw new Error(`log[${idx}]: first operation must be create`);
    }
    if (idx > 0 && op.type === 'create') {
      throw new Error(`log[${idx}]: create can only be the first operation`);
    }

    // initialize key state from genesis
    if (op.type === 'create') {
      if (op.controllerKeys.length === 0) {
        throw new Error(`log[${idx}]: create must have at least one controller key`);
      }
      state.authKeys = op.authKeys;
      state.assertKeys = op.assertKeys;
      state.controllerKeys = op.controllerKeys;
    }

    // chain integrity for non-genesis ops
    if (op.type === 'update' || op.type === 'delete') {
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
      const currentKeys = [...state.authKeys, ...state.assertKeys, ...state.controllerKeys];
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
    }

    // derive operation CID from payload
    const encoded = await dagCborCanonicalEncode(op);
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

    // find controller key referenced by kid
    const signingKey = state.controllerKeys.find((k) => k.id === signingKeyId);
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
      case 'update':
        if (op.controllerKeys.length === 0) {
          throw new Error(`log[${idx}]: update must have at least one controller key`);
        }
        state.authKeys = op.authKeys;
        state.assertKeys = op.assertKeys;
        state.controllerKeys = op.controllerKeys;
        break;
      case 'delete':
        state.isDeleted = true;
        break;
    }
  }

  if (!state.did) throw new Error('did is not set');

  return {
    did: state.did,
    isDeleted: state.isDeleted,
    authKeys: state.authKeys,
    assertKeys: state.assertKeys,
    controllerKeys: state.controllerKeys,
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

  if (currentState.isDeleted) {
    throw new Error('cannot extend a deleted identity');
  }

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

  // verify typ
  if (decoded.header.typ !== 'did:dfos:identity-op') {
    throw new Error(`invalid typ: ${decoded.header.typ}`);
  }

  // extensions must be update or delete
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

  const signingKey = currentState.controllerKeys.find((k) => k.id === signingKeyId);
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
  }

  // compute new state
  const newState: VerifiedIdentity =
    op.type === 'update'
      ? {
          did: currentState.did,
          isDeleted: false,
          authKeys: op.authKeys,
          assertKeys: op.assertKeys,
          controllerKeys: op.controllerKeys,
        }
      : {
          did: currentState.did,
          isDeleted: true,
          authKeys: currentState.authKeys,
          assertKeys: currentState.assertKeys,
          controllerKeys: currentState.controllerKeys,
        };

  return { state: newState, operationCID, createdAt: op.createdAt };
};
