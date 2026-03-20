/*

  COUNTERSIGNATURE

  Multiple valid JWS tokens for the same operation CID. The CID is derived
  from the payload which includes `did` (the author). Different signers
  produce different JWS tokens over the same payload.

  Author: kid DID matches payload did
  Witness: kid DID does NOT match payload did

*/

import { createJws, dagCborCanonicalEncode, decodeJwsUnsafe, verifyJws } from '../crypto';
import { BeaconPayload, ContentOperation } from './schemas';
import type { Signer } from './schemas';

// -----------------------------------------------------------------------------
// signing
// -----------------------------------------------------------------------------

/**
 * Sign an existing content operation as a countersignature (witness JWS)
 *
 * The witness signs the same payload as the author, producing a different
 * JWS token with their own kid. The CID is identical because the payload
 * is identical.
 */
export const signCountersignature = async (input: {
  /** The original operation payload (must include did of the author) */
  operationPayload: ContentOperation;
  /** Witness signer */
  signer: Signer;
  /** Witness kid — DID URL of the witness (must differ from payload.did) */
  kid: string;
}): Promise<{ jwsToken: string; operationCID: string }> => {
  const encoded = await dagCborCanonicalEncode(input.operationPayload);
  const operationCID = encoded.cid.toString();

  const jwsToken = await createJws({
    header: { alg: 'EdDSA', typ: 'did:dfos:content-op', kid: input.kid, cid: operationCID },
    payload: input.operationPayload as unknown as Record<string, unknown>,
    sign: input.signer,
  });

  return { jwsToken, operationCID };
};

// -----------------------------------------------------------------------------
// verification
// -----------------------------------------------------------------------------

export interface VerifiedCountersignature {
  operationCID: string;
  /** The DID that authored the operation (payload.did) */
  authorDID: string;
  /** The DID that witnessed the operation (kid DID) */
  witnessDID: string;
}

/**
 * Verify a countersignature JWS against an expected operation CID
 *
 * Checks: valid signature, CID matches, kid DID differs from payload did
 */
export const verifyCountersignature = async (input: {
  jwsToken: string;
  expectedCID: string;
  resolveKey: (kid: string) => Promise<Uint8Array>;
}): Promise<VerifiedCountersignature> => {
  const decoded = decodeJwsUnsafe(input.jwsToken);
  if (!decoded) throw new Error('failed to decode countersignature JWS');

  // verify typ
  if (decoded.header.typ !== 'did:dfos:content-op') {
    throw new Error(`invalid countersignature typ: ${decoded.header.typ}`);
  }

  // parse payload as content operation
  const result = ContentOperation.safeParse(decoded.payload);
  if (!result.success) {
    const messages = result.error.issues.map((e) => e.message).join(', ');
    throw new Error(`invalid operation payload: ${messages}`);
  }
  const op = result.data;

  // derive CID from payload and verify it matches expected
  const encoded = await dagCborCanonicalEncode(op);
  const operationCID = encoded.cid.toString();
  if (operationCID !== input.expectedCID) {
    throw new Error('countersignature CID does not match expected CID');
  }

  // verify CID in header matches
  if (decoded.header.cid !== operationCID) {
    throw new Error('countersignature header cid mismatch');
  }

  // verify signature
  const kid = decoded.header.kid;
  const publicKey = await input.resolveKey(kid);
  try {
    verifyJws({ token: input.jwsToken, publicKey });
  } catch {
    throw new Error('invalid countersignature');
  }

  // extract witness DID from kid
  const hashIdx = kid.indexOf('#');
  if (hashIdx < 0) throw new Error('countersignature kid must be a DID URL');
  const witnessDID = kid.substring(0, hashIdx);

  // witness DID must differ from author DID
  if (witnessDID === op.did) {
    throw new Error('countersignature kid DID must differ from operation did (not a witness)');
  }

  return {
    operationCID,
    authorDID: op.did,
    witnessDID,
  };
};

// -----------------------------------------------------------------------------
// beacon countersignature — verification
// -----------------------------------------------------------------------------

export interface VerifiedBeaconCountersignature {
  beaconCID: string;
  /** The DID that controls the beacon (payload.did) */
  controllerDID: string;
  /** The DID that witnessed the beacon (kid DID) */
  witnessDID: string;
}

/**
 * Verify a beacon countersignature JWS against an expected beacon CID
 *
 * Checks: valid signature, CID matches, kid DID differs from payload did
 */
export const verifyBeaconCountersignature = async (input: {
  jwsToken: string;
  expectedCID: string;
  resolveKey: (kid: string) => Promise<Uint8Array>;
}): Promise<VerifiedBeaconCountersignature> => {
  const decoded = decodeJwsUnsafe(input.jwsToken);
  if (!decoded) throw new Error('failed to decode beacon countersignature JWS');

  // verify typ
  if (decoded.header.typ !== 'did:dfos:beacon') {
    throw new Error(`invalid beacon countersignature typ: ${decoded.header.typ}`);
  }

  // parse payload as beacon
  const result = BeaconPayload.safeParse(decoded.payload);
  if (!result.success) {
    const messages = result.error.issues.map((e) => e.message).join(', ');
    throw new Error(`invalid beacon payload: ${messages}`);
  }
  const beacon = result.data;

  // derive CID from payload and verify it matches expected
  const encoded = await dagCborCanonicalEncode(beacon);
  const beaconCID = encoded.cid.toString();
  if (beaconCID !== input.expectedCID) {
    throw new Error('beacon countersignature CID does not match expected CID');
  }

  // verify CID in header matches
  if (decoded.header.cid !== beaconCID) {
    throw new Error('beacon countersignature header cid mismatch');
  }

  // verify signature
  const kid = decoded.header.kid;
  const publicKey = await input.resolveKey(kid);
  try {
    verifyJws({ token: input.jwsToken, publicKey });
  } catch {
    throw new Error('invalid beacon countersignature');
  }

  // extract witness DID from kid
  const hashIdx = kid.indexOf('#');
  if (hashIdx < 0) throw new Error('beacon countersignature kid must be a DID URL');
  const witnessDID = kid.substring(0, hashIdx);

  // witness DID must differ from controller DID
  if (witnessDID === beacon.did) {
    throw new Error('beacon countersignature kid DID must differ from beacon did (not a witness)');
  }

  return {
    beaconCID,
    controllerDID: beacon.did,
    witnessDID,
  };
};
