/*

  AUTH

  Auth token and credential verification for relay request authentication

*/

import { verifyAuthToken, type VerifiedAuthToken } from '@metalabel/dfos-protocol/credentials';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { createCurrentKeyResolver } from './ingest';
import type { RelayStore } from './types';

/**
 * Authenticate a request using a DID-signed auth token
 *
 * Extracts the Bearer token from the Authorization header, resolves the
 * signing key from stored identity chains, and verifies the token against
 * the relay's DID as audience.
 *
 * Uses current-state key resolution only — rotated-out keys are rejected.
 *
 * Returns the verified auth token or null if authentication fails.
 */
export const authenticateRequest = async (
  authHeader: string | undefined,
  relayDID: string,
  store: RelayStore,
): Promise<VerifiedAuthToken | null> => {
  if (!authHeader) return null;
  if (!authHeader.startsWith('Bearer ')) return null;

  const token = authHeader.substring(7);
  if (!token) return null;

  // decode the JWT header to extract kid
  // auth tokens are JWTs (header.payload.sig) — same structure as JWS
  const decoded = decodeJwsUnsafe(token);
  if (!decoded) return null;

  const kid = decoded.header.kid;
  if (!kid || !kid.includes('#')) return null;

  const resolveKey = createCurrentKeyResolver(store);

  let publicKey: Uint8Array;
  try {
    publicKey = await resolveKey(kid);
  } catch {
    return null;
  }

  try {
    return verifyAuthToken({ token, publicKey, audience: relayDID });
  } catch {
    return null;
  }
};
