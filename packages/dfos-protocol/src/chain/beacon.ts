/*

  BEACON

  Floating signed manifest pointer announcement. Latest createdAt wins.
  Signed by identity controller key. No chain semantics — no backlink,
  no sequence number. Replace-on-newer.

*/

import { createJws, dagCborCanonicalEncode, decodeJwsUnsafe, verifyJws } from '../crypto';
import { BeaconPayload } from './schemas';
import type { Signer } from './schemas';

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

export interface VerifiedBeacon {
  did: string;
  manifestContentId: string;
  createdAt: string;
  signerKeyId: string;
  beaconCID: string;
}

// -----------------------------------------------------------------------------
// signing
// -----------------------------------------------------------------------------

/**
 * Sign a beacon announcement as a JWS
 */
export const signBeacon = async (input: {
  payload: BeaconPayload;
  signer: Signer;
  kid: string;
}): Promise<{ jwsToken: string; beaconCID: string }> => {
  const encoded = await dagCborCanonicalEncode(input.payload);
  const beaconCID = encoded.cid.toString();

  const jwsToken = await createJws({
    header: { alg: 'EdDSA', typ: 'did:dfos:beacon', kid: input.kid, cid: beaconCID },
    payload: input.payload as unknown as Record<string, unknown>,
    sign: input.signer,
  });

  return { jwsToken, beaconCID };
};

// -----------------------------------------------------------------------------
// verification
// -----------------------------------------------------------------------------

/** Max clock skew tolerance for beacon createdAt (5 minutes) */
const MAX_FUTURE_MS = 5 * 60 * 1000;

/**
 * Verify a beacon JWS — signature, CID, payload schema, clock skew
 */
export const verifyBeacon = async (input: {
  jwsToken: string;
  resolveKey: (kid: string) => Promise<Uint8Array>;
  /** Current time for clock skew check (defaults to Date.now()) */
  now?: number;
}): Promise<VerifiedBeacon> => {
  const decoded = decodeJwsUnsafe(input.jwsToken);
  if (!decoded) throw new Error('failed to decode beacon JWS');

  // parse payload
  const result = BeaconPayload.safeParse(decoded.payload);
  if (!result.success) {
    const messages = result.error.issues.map((e) => e.message).join(', ');
    throw new Error(`invalid beacon payload: ${messages}`);
  }
  const payload = result.data;

  // verify typ
  if (decoded.header.typ !== 'did:dfos:beacon') {
    throw new Error(`invalid beacon typ: ${decoded.header.typ}`);
  }

  // verify kid DID matches payload did
  const kid = decoded.header.kid;
  const hashIdx = kid.indexOf('#');
  if (hashIdx < 0) throw new Error('beacon kid must be a DID URL');
  const kidDid = kid.substring(0, hashIdx);
  if (kidDid !== payload.did) {
    throw new Error('beacon kid DID does not match payload did');
  }

  // verify signature
  const publicKey = await input.resolveKey(kid);
  try {
    verifyJws({ token: input.jwsToken, publicKey });
  } catch {
    throw new Error('invalid beacon signature');
  }

  // verify CID
  const encoded = await dagCborCanonicalEncode(payload);
  const beaconCID = encoded.cid.toString();
  if (!decoded.header.cid) throw new Error('missing cid in beacon header');
  if (decoded.header.cid !== beaconCID) throw new Error('beacon cid mismatch');

  // clock skew check
  const now = input.now ?? Date.now();
  const beaconTime = new Date(payload.createdAt).getTime();
  if (beaconTime > now + MAX_FUTURE_MS) {
    throw new Error('beacon createdAt is too far in the future');
  }

  return {
    did: payload.did,
    manifestContentId: payload.manifestContentId,
    createdAt: payload.createdAt,
    signerKeyId: kid,
    beaconCID,
  };
};
