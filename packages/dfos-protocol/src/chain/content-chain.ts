/*

  CONTENT CHAIN

  JWS-based document commitment chain for Ed25519/Multikey regime

  A content chain is a signed linked list of document commitments. Unlike an
  identity chain (which is self-sovereign), a content chain is signed by an
  external identity's keys. The protocol treats documents as opaque CIDs —
  document semantics (types, schemas, content) are application layer concerns.

  Authorization model:
  - The creator DID (signer of the genesis operation) owns the chain
  - The creator can sign subsequent operations directly (no credential needed)
  - Other DIDs require a DFOS credential in the operation's `authorization`
    field, with a delegation chain rooting at the creator DID

*/

import {
  decodeDFOSCredentialUnsafe,
  matchesResource,
  verifyDelegationChain,
  verifyDFOSCredential,
} from '../credentials';
import { createJws, dagCborCanonicalEncode, decodeJwsUnsafe, verifyJws } from '../crypto';
import { deriveContentId } from './derivation';
import { ContentOperation } from './schemas';
import type { Signer, VerifiedIdentity } from './schemas';

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

export interface VerifiedContentChain {
  /** Content identifier — bare 22-char hash derived from genesis CID */
  contentId: string;
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
  /** The DID that created the chain (signer of genesis operation) */
  creatorDID: string;
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
  // derive CID first so it can be embedded in the signed header
  const encoded = await dagCborCanonicalEncode(input.operation);
  const operationCID = encoded.cid.toString();

  const jwsToken = await createJws({
    header: { alg: 'EdDSA', typ: 'did:dfos:content-op', kid: input.kid, cid: operationCID },
    payload: input.operation as unknown as Record<string, unknown>,
    sign: input.signer,
  });

  return { jwsToken, operationCID };
};

// -----------------------------------------------------------------------------
// authorization verification (internal)
// -----------------------------------------------------------------------------

/**
 * Verify that a delegated content operation has a valid DFOS credential
 * authorizing the signer to write to this content chain.
 */
const verifyOperationAuthorization = async (input: {
  authorization: string;
  operationDID: string;
  creatorDID: string;
  contentId: string;
  createdAt: string;
  resolveIdentity: (did: string) => Promise<VerifiedIdentity | undefined>;
}): Promise<void> => {
  // decode to check typ before full verification
  const decoded = decodeDFOSCredentialUnsafe(input.authorization);
  if (!decoded) {
    throw new Error('failed to decode authorization credential');
  }
  if (decoded.header.typ !== 'did:dfos:credential') {
    throw new Error(`invalid authorization typ: ${decoded.header.typ}`);
  }

  // verify the credential signature + schema + expiry
  const opCreatedAtUnix = Math.floor(new Date(input.createdAt).getTime() / 1000);
  const credential = await verifyDFOSCredential(input.authorization, {
    resolveIdentity: input.resolveIdentity,
    now: opCreatedAtUnix,
  });

  // verify the delegation chain roots at the creator DID
  await verifyDelegationChain(credential, {
    resolveIdentity: input.resolveIdentity,
    rootDID: input.creatorDID,
    now: opCreatedAtUnix,
  });

  // verify the credential's audience matches the operation signer
  if (credential.aud !== '*' && credential.aud !== input.operationDID) {
    throw new Error(
      `credential audience ${credential.aud} does not match operation signer ${input.operationDID}`,
    );
  }

  // verify the credential covers write access to this content chain
  const covers = await matchesResource(credential.att, `chain:${input.contentId}`, 'write');
  if (!covers) {
    throw new Error(`credential does not cover write access to chain:${input.contentId}`);
  }
};

// -----------------------------------------------------------------------------
// verification
// -----------------------------------------------------------------------------

/**
 * Verify a content chain's structural integrity, signatures, and authorization
 *
 * The caller provides a key resolver to look up public keys from kid values.
 * This keeps the content chain protocol independent of identity resolution.
 *
 * Authorization rules:
 * - Genesis (create) operation: the signer is the chain creator, always authorized
 * - Subsequent operations signed by the creator DID: authorized (no credential needed)
 * - Subsequent operations signed by a different DID: must include an `authorization`
 *   field containing a valid DFOS credential with a delegation chain rooting at
 *   the creator DID
 */
export const verifyContentChain = async (input: {
  log: string[];
  /** Resolve a kid (DID URL) to the raw Ed25519 public key bytes */
  resolveKey: (kid: string) => Promise<Uint8Array>;
  /**
   * Enforce creator-sovereignty authorization. When true, non-creator signers
   * must include a DFOS credential in the operation's `authorization` field
   * with a delegation chain rooting at the creator DID.
   */
  enforceAuthorization?: boolean;
  /**
   * Resolve a DID to a VerifiedIdentity. Required when `enforceAuthorization`
   * is true, as credential verification needs identity resolution.
   */
  resolveIdentity?: (did: string) => Promise<VerifiedIdentity | undefined>;
}): Promise<VerifiedContentChain> => {
  if (input.log.length === 0) throw new Error('log must have at least one operation');

  if (input.enforceAuthorization && !input.resolveIdentity) {
    throw new Error('resolveIdentity is required when enforceAuthorization is true');
  }

  const state = {
    contentId: null as string | null,
    genesisCID: null as string | null,
    headCID: null as string | null,
    isDeleted: false,
    currentDocumentCID: null as string | null,
    previousCID: null as string | null,
    lastCreatedAt: null as string | null,
    creatorDID: null as string | null,
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

    // verify typ
    if (decoded.header.typ !== 'did:dfos:content-op') {
      throw new Error(`log[${idx}]: invalid typ: ${decoded.header.typ}`);
    }

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

    // verify kid DID matches payload did
    const kid = decoded.header.kid;
    const hashIdx = kid.indexOf('#');
    if (hashIdx < 0) throw new Error(`log[${idx}]: kid must be a DID URL`);
    const kidDid = kid.substring(0, hashIdx);
    if (kidDid !== op.did) {
      throw new Error(`log[${idx}]: kid DID does not match operation did`);
    }

    // verify JWS signature via key resolver
    const publicKey = await input.resolveKey(kid);
    try {
      verifyJws({ token: jwsToken, publicKey });
    } catch {
      throw new Error(`log[${idx}]: invalid signature`);
    }

    // --- authorization check ---
    if (idx === 0) {
      // genesis: signer is the creator, always authorized
      state.creatorDID = op.did;
    } else if (op.did !== state.creatorDID && input.enforceAuthorization) {
      // delegated operation: signer differs from creator, requires DFOS credential
      const authorization =
        op.type !== 'create' ? (op as { authorization?: string }).authorization : undefined;
      if (!authorization) {
        throw new Error(
          `log[${idx}]: signer ${op.did} is not the chain creator — authorization credential required`,
        );
      }

      try {
        await verifyOperationAuthorization({
          authorization,
          operationDID: op.did,
          creatorDID: state.creatorDID!,
          contentId: state.contentId!,
          createdAt: op.createdAt,
          resolveIdentity: input.resolveIdentity!,
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : 'unknown error';
        throw new Error(`log[${idx}]: authorization verification failed: ${message}`);
      }
    }

    // derive operation CID
    const encoded = await dagCborCanonicalEncode(op);
    const operationCID = encoded.cid.toString();

    // verify cid header — must be present and match derived CID
    if (!decoded.header.cid) {
      throw new Error(`log[${idx}]: missing cid in protected header`);
    }
    if (decoded.header.cid !== operationCID) {
      throw new Error(`log[${idx}]: cid mismatch in protected header`);
    }

    // update state
    if (idx === 0) {
      state.genesisCID = operationCID;
      state.contentId = deriveContentId(encoded.cid.bytes);
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
    contentId: state.contentId!,
    genesisCID: state.genesisCID!,
    headCID: state.headCID!,
    isDeleted: state.isDeleted,
    currentDocumentCID: state.currentDocumentCID,
    length: input.log.length,
    creatorDID: state.creatorDID!,
  };
};

// -----------------------------------------------------------------------------
// extension verification (O(1))
// -----------------------------------------------------------------------------

/**
 * Verify a single new content operation against already-verified chain state
 *
 * Same trust model as verifyIdentityExtensionFromTrustedState — the caller
 * guarantees `currentState` was correctly verified. One signature verification,
 * one key resolution, one state transition.
 */
export const verifyContentExtensionFromTrustedState = async (input: {
  /** Previously verified content chain state */
  currentState: VerifiedContentChain;
  /** createdAt timestamp of the most recent operation */
  lastCreatedAt: string;
  /** The new JWS operation to verify */
  newOp: string;
  /** Resolve a kid (DID URL) to the raw Ed25519 public key bytes */
  resolveKey: (kid: string) => Promise<Uint8Array>;
  /** Enforce creator-sovereignty authorization (see verifyContentChain) */
  enforceAuthorization?: boolean;
  /** Resolve a DID to a VerifiedIdentity. Required when enforceAuthorization is true. */
  resolveIdentity?: (did: string) => Promise<VerifiedIdentity | undefined>;
}): Promise<{
  state: VerifiedContentChain;
  operationCID: string;
  createdAt: string;
}> => {
  const { currentState, lastCreatedAt, newOp, resolveKey } = input;

  if (currentState.isDeleted) {
    throw new Error('cannot extend a deleted chain');
  }

  if (input.enforceAuthorization && !input.resolveIdentity) {
    throw new Error('resolveIdentity is required when enforceAuthorization is true');
  }

  // decode JWS
  const decoded = decodeJwsUnsafe(newOp);
  if (!decoded) throw new Error('failed to decode JWS');

  // parse payload
  const result = ContentOperation.safeParse(decoded.payload);
  if (!result.success) {
    const messages = result.error.issues.map((e) => e.message).join(', ');
    throw new Error(messages);
  }
  const op = result.data;

  // verify typ
  if (decoded.header.typ !== 'did:dfos:content-op') {
    throw new Error(`invalid typ: ${decoded.header.typ}`);
  }

  // extensions must be update or delete
  if (op.type === 'create') {
    throw new Error('extension cannot be a create operation');
  }

  // chain integrity — headCID is in VerifiedContentChain
  if (op.previousOperationCID !== currentState.headCID) {
    throw new Error('previousOperationCID is incorrect');
  }
  if (op.createdAt <= lastCreatedAt) {
    throw new Error('createdAt must be after last op');
  }

  // verify kid DID matches payload did
  const kid = decoded.header.kid;
  const hashIdx = kid.indexOf('#');
  if (hashIdx < 0) throw new Error('kid must be a DID URL');
  const kidDid = kid.substring(0, hashIdx);
  if (kidDid !== op.did) {
    throw new Error('kid DID does not match operation did');
  }

  // verify JWS signature via key resolver
  const publicKey = await resolveKey(kid);
  try {
    verifyJws({ token: newOp, publicKey });
  } catch {
    throw new Error('invalid signature');
  }

  // authorization check — delegated writes need a DFOS credential
  if (op.did !== currentState.creatorDID && input.enforceAuthorization) {
    const authorization = (op as { authorization?: string }).authorization;
    if (!authorization) {
      throw new Error(
        `signer ${op.did} is not the chain creator — authorization credential required`,
      );
    }

    try {
      await verifyOperationAuthorization({
        authorization,
        operationDID: op.did,
        creatorDID: currentState.creatorDID,
        contentId: currentState.contentId,
        createdAt: op.createdAt,
        resolveIdentity: input.resolveIdentity!,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'unknown error';
      throw new Error(`authorization verification failed: ${message}`);
    }
  }

  // derive operation CID
  const encoded = await dagCborCanonicalEncode(op);
  const operationCID = encoded.cid.toString();

  // verify cid header
  if (!decoded.header.cid) throw new Error('missing cid in protected header');
  if (decoded.header.cid !== operationCID) throw new Error('cid mismatch in protected header');

  // compute new state
  const newState: VerifiedContentChain = {
    contentId: currentState.contentId,
    genesisCID: currentState.genesisCID,
    headCID: operationCID,
    isDeleted: op.type === 'delete',
    currentDocumentCID: op.type === 'update' ? op.documentCID : null,
    length: currentState.length + 1,
    creatorDID: currentState.creatorDID,
  };

  return { state: newState, operationCID, createdAt: op.createdAt };
};
