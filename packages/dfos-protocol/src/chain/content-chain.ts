/*

  CONTENT CHAIN

  JWS-based document commitment chain for Ed25519/Multikey regime

  A content chain is a signed linked list of document commitments. Unlike an
  identity chain (which is self-sovereign), a content chain is signed by an
  external identity's keys. The protocol treats documents as opaque CIDs —
  document semantics (types, schemas, content) are application layer concerns.

*/

import { createJws, dagCborCanonicalEncode, decodeJwsUnsafe, verifyJws } from '../crypto';
import { deriveEntityId } from './derivation';
import { ContentOperation } from './schemas';
import type { Signer } from './schemas';

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

export interface VerifiedContentChain {
  /** Entity identifier — bare 22-char hash derived from genesis CID */
  entityId: string;
  /** CID of the genesis operation */
  genesisCID: string;
  /** CID of the most recent operation */
  headCID: string;
  /** Whether the chain has been terminated by a delete */
  isDeleted: boolean;
  /** The current documentCID (null if cleared or deleted) */
  currentDocumentCID: string | null;
  /** Number of operations in the chain */
  length: number;
}

// -----------------------------------------------------------------------------
// signing
// -----------------------------------------------------------------------------

/**
 * Sign a content chain operation as a JWS and derive the operation CID
 */
export const signContentOperation = async (input: {
  operation: ContentOperation;
  signer: Signer;
  /** kid for the JWS header — should be a DID URL: "did:dfos:xxx#key_yyy" */
  kid: string;
}): Promise<{ jwsToken: string; operationCID: string }> => {
  const jwsToken = await createJws({
    header: { alg: 'EdDSA', typ: 'did:dfos:content-op', kid: input.kid },
    payload: input.operation as unknown as Record<string, unknown>,
    sign: input.signer,
  });

  const encoded = await dagCborCanonicalEncode(input.operation);
  const operationCID = encoded.cid.toString();

  return { jwsToken, operationCID };
};

// -----------------------------------------------------------------------------
// verification
// -----------------------------------------------------------------------------

/**
 * Verify a content chain's structural integrity and signatures
 *
 * The caller provides a key resolver to look up public keys from kid values.
 * This keeps the content chain protocol independent of identity resolution.
 */
export const verifyContentChain = async (input: {
  log: string[];
  /** Resolve a kid (DID URL) to the raw Ed25519 public key bytes */
  resolveKey: (kid: string) => Promise<Uint8Array>;
}): Promise<VerifiedContentChain> => {
  if (input.log.length === 0) throw new Error('log must have at least one operation');

  const state = {
    entityId: null as string | null,
    genesisCID: null as string | null,
    headCID: null as string | null,
    isDeleted: false,
    currentDocumentCID: null as string | null,
    previousCID: null as string | null,
    lastCreatedAt: null as string | null,
  };

  for (const [idx, jwsToken] of input.log.entries()) {
    // decode JWS
    const decoded = decodeJwsUnsafe(jwsToken);
    if (!decoded) throw new Error(`log[${idx}]: failed to decode JWS`);

    // parse payload
    const result = ContentOperation.safeParse(decoded.payload);
    if (!result.success) {
      const messages = result.error.issues.map((e) => e.message).join(', ');
      throw new Error(`log[${idx}]: ${messages}`);
    }
    const op = result.data;

    // terminal state check
    if (state.isDeleted) throw new Error(`log[${idx}]: cannot extend a deleted chain`);

    // type sequence validation
    if (idx === 0 && op.type !== 'create') {
      throw new Error(`log[${idx}]: first operation must be create`);
    }
    if (idx > 0 && op.type === 'create') {
      throw new Error(`log[${idx}]: create can only be the first operation`);
    }

    // chain integrity for non-genesis ops
    if (op.type === 'update' || op.type === 'delete') {
      if (op.previousOperationCID !== state.previousCID) {
        throw new Error(`log[${idx}]: previousOperationCID is incorrect`);
      }
      if (!state.lastCreatedAt) throw new Error(`log[${idx}]: lastCreatedAt is not set`);
      if (op.createdAt <= state.lastCreatedAt) {
        throw new Error(`log[${idx}]: createdAt must be after last op`);
      }
    }

    // verify JWS signature via key resolver
    const kid = decoded.header.kid;
    const publicKey = await input.resolveKey(kid);
    try {
      verifyJws({ token: jwsToken, publicKey });
    } catch {
      throw new Error(`log[${idx}]: invalid signature`);
    }

    // derive operation CID
    const encoded = await dagCborCanonicalEncode(op);
    const operationCID = encoded.cid.toString();

    // update state
    if (idx === 0) {
      state.genesisCID = operationCID;
      state.entityId = deriveEntityId(encoded.cid.bytes);
    }
    state.headCID = operationCID;
    state.previousCID = operationCID;
    state.lastCreatedAt = op.createdAt;

    switch (op.type) {
      case 'create':
        state.currentDocumentCID = op.documentCID;
        break;
      case 'update':
        state.currentDocumentCID = op.documentCID;
        break;
      case 'delete':
        state.isDeleted = true;
        state.currentDocumentCID = null;
        break;
    }
  }

  return {
    entityId: state.entityId!,
    genesisCID: state.genesisCID!,
    headCID: state.headCID!,
    isDeleted: state.isDeleted,
    currentDocumentCID: state.currentDocumentCID,
    length: input.log.length,
  };
};
