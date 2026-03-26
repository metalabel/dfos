/*

  COUNTERSIGNATURE

  Standalone witness attestation. A countersign is a signed statement
  that references a target operation by CID — "I, witness W, attest to
  operation X." It has its own CID, distinct from the target.

  Countersigns are stateless-verifiable: signature + CID integrity is
  sufficient. The relay adds semantic checks (target exists, witness !=
  author, dedup) at the ingestion layer.

  Composable with any CID-addressable operation: content ops, beacons,
  artifacts, identity ops, even other countersigns.

*/

import { createJws, dagCborCanonicalEncode, decodeJwsUnsafe, verifyJws } from '../crypto';
import { CountersignPayload } from './schemas';
import type { Signer } from './schemas';

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

export interface VerifiedCountersignature {
  /** CID of this countersign operation (distinct from the target) */
  countersignCID: string;
  /** The witness DID (payload.did — the DID that signed this attestation) */
  witnessDID: string;
  /** The CID being attested to */
  targetCID: string;
}

// -----------------------------------------------------------------------------
// signing
// -----------------------------------------------------------------------------

/**
 * Sign a countersignature attesting to a target operation by CID
 */
export const signCountersignature = async (input: {
  payload: CountersignPayload;
  signer: Signer;
  kid: string;
}): Promise<{ jwsToken: string; countersignCID: string }> => {
  const encoded = await dagCborCanonicalEncode(input.payload);
  const countersignCID = encoded.cid.toString();

  const jwsToken = await createJws({
    header: { alg: 'EdDSA', typ: 'did:dfos:countersign', kid: input.kid, cid: countersignCID },
    payload: input.payload as unknown as Record<string, unknown>,
    sign: input.signer,
  });

  return { jwsToken, countersignCID };
};

// -----------------------------------------------------------------------------
// verification
// -----------------------------------------------------------------------------

/**
 * Verify a countersignature JWS — stateless verification
 *
 * Checks: valid signature, CID integrity, payload schema. Does NOT check
 * whether the target exists or whether the witness differs from the target
 * author — those are relay-level semantic checks.
 */
export const verifyCountersignature = async (input: {
  jwsToken: string;
  resolveKey: (kid: string) => Promise<Uint8Array>;
}): Promise<VerifiedCountersignature> => {
  const decoded = decodeJwsUnsafe(input.jwsToken);
  if (!decoded) throw new Error('failed to decode countersignature JWS');

  // verify typ
  if (decoded.header.typ !== 'did:dfos:countersign') {
    throw new Error(`invalid countersignature typ: ${decoded.header.typ}`);
  }

  // parse payload
  const result = CountersignPayload.safeParse(decoded.payload);
  if (!result.success) {
    const messages = result.error.issues.map((e) => e.message).join(', ');
    throw new Error(`invalid countersignature payload: ${messages}`);
  }
  const payload = result.data;

  // verify kid DID matches payload did
  const kid = decoded.header.kid;
  const hashIdx = kid.indexOf('#');
  if (hashIdx < 0) throw new Error('countersignature kid must be a DID URL');
  const kidDid = kid.substring(0, hashIdx);
  if (kidDid !== payload.did) {
    throw new Error('countersignature kid DID does not match payload did');
  }

  // verify signature
  const publicKey = await input.resolveKey(kid);
  try {
    verifyJws({ token: input.jwsToken, publicKey });
  } catch {
    throw new Error('invalid countersignature signature');
  }

  // verify CID — use raw decoded payload to match artifact pattern
  const encoded = await dagCborCanonicalEncode(decoded.payload);
  const countersignCID = encoded.cid.toString();
  if (!decoded.header.cid) throw new Error('missing cid in countersignature header');
  if (decoded.header.cid !== countersignCID) throw new Error('countersignature cid mismatch');

  return {
    countersignCID,
    witnessDID: payload.did,
    targetCID: payload.targetCID,
  };
};
