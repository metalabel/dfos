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
  - Other DIDs require a DFOSContentWrite VC-JWT in the operation's
    `authorization` field, issued by the creator DID

*/

import { decodeCredentialUnsafe, VC_TYPE_CONTENT_WRITE, verifyCredential } from '../credentials';
import { createJws, dagCborCanonicalEncode, decodeJwsUnsafe, verifyJws } from '../crypto';
import { deriveContentId } from './derivation';
import { ContentOperation } from './schemas';
import type { Signer } from './schemas';

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
 *   field containing a valid DFOSContentWrite VC-JWT issued by the creator DID
 */
export const verifyContentChain = async (input: {
  log: string[];
  /** Resolve a kid (DID URL) to the raw Ed25519 public key bytes */
  resolveKey: (kid: string) => Promise<Uint8Array>;
  /**
   * Enforce creator-sovereignty authorization. When true, non-creator signers
   * must include a DFOSContentWrite VC-JWT in the operation's `authorization`
   * field. When false (default), any signer with a valid signature is accepted.
   *
   * Web relays should set this to true. Applications migrating to VC-based
   * authorization can enable this once all chains include authorization fields.
   */
  enforceAuthorization?: boolean;
}): Promise<VerifiedContentChain> => {
  if (input.log.length === 0) throw new Error('log must have at least one operation');

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
      // delegated operation: signer differs from creator, requires authorization VC
      const authorization =
        op.type !== 'create' ? (op as { authorization?: string }).authorization : undefined;
      if (!authorization) {
        throw new Error(
          `log[${idx}]: signer ${op.did} is not the chain creator — authorization VC required`,
        );
      }

      // extract the kid from the VC to resolve the creator's signing key
      const vcDecoded = decodeCredentialUnsafe(authorization);
      if (!vcDecoded) {
        throw new Error(`log[${idx}]: failed to decode authorization VC`);
      }
      const vcKid = vcDecoded.header.kid;
      if (!vcKid || !vcKid.includes('#')) {
        throw new Error(`log[${idx}]: authorization VC kid must be a DID URL`);
      }

      let creatorPublicKey: Uint8Array;
      try {
        creatorPublicKey = await input.resolveKey(vcKid);
      } catch {
        throw new Error(`log[${idx}]: cannot resolve creator key for authorization verification`);
      }

      // verify the authorization VC
      const opCreatedAtUnix = Math.floor(new Date(op.createdAt).getTime() / 1000);
      try {
        const credential = verifyCredential({
          token: authorization,
          publicKey: creatorPublicKey,
          subject: op.did,
          expectedType: VC_TYPE_CONTENT_WRITE,
          currentTime: opCreatedAtUnix,
        });

        // verify VC issuer is the chain creator
        if (credential.iss !== state.creatorDID) {
          throw new Error('VC issuer is not the chain creator');
        }

        // if VC is narrowed to a contentId, it must match this chain
        if (credential.contentId && credential.contentId !== state.contentId) {
          throw new Error(
            `VC contentId ${credential.contentId} does not match chain ${state.contentId}`,
          );
        }
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
