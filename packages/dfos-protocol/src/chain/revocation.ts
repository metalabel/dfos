/*

  REVOCATION

  Signed revocation artifact for DFOS credentials. Gossiped across the relay
  network like beacons. Permanent — no un-revoke, issue a new credential
  instead.

  Only the credential's issuer DID can revoke it. Relay maintains a revocation
  set per issuer and checks it during credential verification.

*/

import { createJws, dagCborCanonicalEncode, decodeJwsUnsafe, verifyJws } from '../crypto';
import { RevocationPayload } from './schemas';
import type { Signer } from './schemas';

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

export interface VerifiedRevocation {
  /** The issuer DID that revoked the credential */
  did: string;
  /** CID of the revoked credential */
  credentialCID: string;
  /** Timestamp of the revocation */
  createdAt: string;
  /** kid from the JWS header */
  signerKeyId: string;
  /** CID of the revocation artifact itself */
  revocationCID: string;
}

// -----------------------------------------------------------------------------
// signing
// -----------------------------------------------------------------------------

/**
 * Sign a revocation artifact as a JWS
 */
export const signRevocation = async (input: {
  issuerDID: string;
  credentialCID: string;
  signer: Signer;
  keyId: string;
}): Promise<{ jwsToken: string; revocationCID: string }> => {
  const kid = `${input.issuerDID}#${input.keyId}`;
  const now = new Date().toISOString().replace(/\d{3}Z$/, '000Z');

  const payload = {
    type: 'revocation' as const,
    did: input.issuerDID,
    credentialCID: input.credentialCID,
    createdAt: now,
  };

  const encoded = await dagCborCanonicalEncode(payload);
  const revocationCID = encoded.cid.toString();

  const jwsToken = await createJws({
    header: { alg: 'EdDSA', typ: 'did:dfos:revocation', kid, cid: revocationCID },
    payload: payload as unknown as Record<string, unknown>,
    sign: input.signer,
  });

  return { jwsToken, revocationCID };
};

// -----------------------------------------------------------------------------
// verification
// -----------------------------------------------------------------------------

/**
 * Verify a revocation JWS — signature, CID, payload schema, signer match
 */
export const verifyRevocation = async (input: {
  jwsToken: string;
  resolveKey: (kid: string) => Promise<Uint8Array>;
}): Promise<VerifiedRevocation> => {
  const decoded = decodeJwsUnsafe(input.jwsToken);
  if (!decoded) throw new Error('failed to decode revocation JWS');

  // parse payload
  const result = RevocationPayload.safeParse(decoded.payload);
  if (!result.success) {
    const messages = result.error.issues.map((e) => e.message).join(', ');
    throw new Error(`invalid revocation payload: ${messages}`);
  }
  const payload = result.data;

  // verify typ
  if (decoded.header.typ !== 'did:dfos:revocation') {
    throw new Error(`invalid revocation typ: ${decoded.header.typ}`);
  }

  // verify kid DID matches payload did (only the issuer can revoke)
  const kid = decoded.header.kid;
  const hashIdx = kid.indexOf('#');
  if (hashIdx < 0) throw new Error('revocation kid must be a DID URL');
  const kidDid = kid.substring(0, hashIdx);
  if (kidDid !== payload.did) {
    throw new Error('revocation kid DID does not match payload did');
  }

  // verify signature
  const publicKey = await input.resolveKey(kid);
  try {
    verifyJws({ token: input.jwsToken, publicKey });
  } catch {
    throw new Error('invalid revocation signature');
  }

  // verify CID
  const encoded = await dagCborCanonicalEncode(payload);
  const revocationCID = encoded.cid.toString();
  if (!decoded.header.cid) throw new Error('missing cid in revocation header');
  if (decoded.header.cid !== revocationCID) throw new Error('revocation cid mismatch');

  return {
    did: payload.did,
    credentialCID: payload.credentialCID,
    createdAt: payload.createdAt,
    signerKeyId: kid,
    revocationCID,
  };
};
