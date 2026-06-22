/*

  AUTH

  Auth token and credential verification for relay request authentication

*/

import {
  matchesResource,
  verifyAuthToken,
  verifyDelegationChain,
  verifyDFOSCredential,
  type VerifiedAuthToken,
  type VerifiedDFOSCredential,
} from '@metalabel/dfos-protocol/credentials';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { createCurrentKeyResolver, createHistoricalIdentityResolver } from './ingest';
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
/**
 * Default ceiling on a self-signed auth token's lifetime (exp-iat, seconds): 24h.
 * Auth tokens are ephemeral (the spec describes them as "minutes"); this bounds a
 * buggy/malicious signer minting an effectively-permanent bearer token. It
 * applies ONLY to auth tokens — DFOS credentials (read/write/standing) are
 * verified on a separate path (verifyContentAccess) and are unaffected. A value
 * <= 0 disables the ceiling.
 */
export const DEFAULT_MAX_AUTH_TOKEN_TTL_SECONDS = 86400;

export const authenticateRequest = async (
  authHeader: string | undefined,
  relayDID: string,
  store: RelayStore,
  maxAuthTokenTTLSeconds: number = DEFAULT_MAX_AUTH_TOKEN_TTL_SECONDS,
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
    const verified = verifyAuthToken({ token, publicKey, audience: relayDID });
    // enforce the auth-token lifetime ceiling (auth tokens only — credentials are
    // verified on a different path and never reach here).
    if (maxAuthTokenTTLSeconds > 0 && verified.exp - verified.iat > maxAuthTokenTTLSeconds) {
      return null;
    }
    return verified;
  } catch {
    return null;
  }
};

// -----------------------------------------------------------------------------
// content access verification
// -----------------------------------------------------------------------------

export interface AccessVerification {
  granted: boolean;
  source: 'public-credential' | 'request-credential' | 'creator' | 'none';
  credential?: VerifiedDFOSCredential;
}

/**
 * Check if a valid public standing credential exists for the given content.
 *
 * This is used at the route level to allow unauthenticated reads when public
 * credentials exist — matching the Go relay's `hasPublicStandingAuth`.
 */
export const hasPublicStandingAuth = async (
  contentId: string,
  action: 'read' | 'write',
  store: RelayStore,
): Promise<boolean> => {
  const resource = `chain:${contentId}`;
  const publicCreds = await store.getPublicCredentials(resource);
  if (publicCreds.length === 0) return false;

  const chain = await store.getContentChain(contentId);
  if (!chain) return false;

  const resolveIdentity = createHistoricalIdentityResolver(store);
  const isRevoked = async (issuerDID: string, credentialCID: string) =>
    store.isCredentialRevoked(issuerDID, credentialCID);

  for (const credJws of publicCreds) {
    try {
      const cred = await verifyDFOSCredential(credJws, { resolveIdentity });

      // check revocation
      const leafRevoked = await isRevoked(cred.iss, cred.credentialCID);
      if (leafRevoked) continue;

      // check resource + action match
      const covers = await matchesResource(cred.att, resource, action);
      if (!covers) continue;

      // verify delegation chain roots at creator
      await verifyDelegationChain(cred, {
        resolveIdentity,
        rootDID: chain.state.creatorDID,
        isRevoked,
      });

      return true;
    } catch {
      continue;
    }
  }

  return false;
};

/**
 * Derive the public (`aud:"*"`) credential JWS tokens that currently authorize
 * `read` on the given content chain — each re-verified live against the proof
 * plane (signature, expiry, revocation, delegation rooted at the creator)
 * through the same verifier the read path uses.
 *
 * This is the document gateway's enriched-resolve material: the proof node hands
 * the gateway the credentials themselves, not a pre-chewed "publicly readable"
 * boolean, so a split gateway or a zero-trust caller can independently
 * re-verify them. The result is sorted lexicographically so the field is
 * deterministic across relays and store backends (mirrors the Go relay's
 * `derivePublicGrants`).
 */
export const derivePublicGrants = async (
  contentId: string,
  creatorDID: string,
  store: RelayStore,
): Promise<string[]> => {
  const resource = `chain:${contentId}`;
  const publicCreds = await store.getPublicCredentials(resource);
  if (publicCreds.length === 0) return [];

  const resolveIdentity = createHistoricalIdentityResolver(store);
  const isRevoked = async (issuerDID: string, credentialCID: string) =>
    store.isCredentialRevoked(issuerDID, credentialCID);

  const grants: string[] = [];
  for (const credJws of publicCreds) {
    try {
      const cred = await verifyDFOSCredential(credJws, { resolveIdentity });
      if (await isRevoked(cred.iss, cred.credentialCID)) continue;
      if (!(await matchesResource(cred.att, resource, 'read'))) continue;
      await verifyDelegationChain(cred, { resolveIdentity, rootDID: creatorDID, isRevoked });
      grants.push(credJws);
    } catch {
      continue;
    }
  }

  grants.sort();
  return grants;
};

/**
 * Verify content access for a specific resource
 *
 * Checks in order:
 * 1. Is the requester the content creator? → granted
 * 2. Does a stored public credential cover this resource? → granted
 * 3. Does the per-request credential (Authorization header) cover this resource? → granted
 * 4. None → denied
 */
export const verifyContentAccess = async (options: {
  /** Per-request credential JWS (from X-Credential header) */
  credentialJWS?: string;
  /** The resource being accessed, e.g., "chain:<contentId>" */
  requestedResource: string;
  /** The action being requested */
  action: 'read' | 'write';
  store: RelayStore;
  /** The DID of the content chain creator (root authority) */
  creatorDID: string;
  /** From auth token — the DID making the request */
  requesterDID?: string;
}): Promise<AccessVerification> => {
  const { credentialJWS, requestedResource, action, store, creatorDID, requesterDID } = options;

  // 1. creator always has access
  if (requesterDID && requesterDID === creatorDID) {
    return { granted: true, source: 'creator' };
  }

  // shared helpers for credential verification
  const resolveIdentity = createHistoricalIdentityResolver(store);

  const isRevoked = async (issuerDID: string, credentialCID: string) =>
    store.isCredentialRevoked(issuerDID, credentialCID);

  // 2. check stored public credentials
  const publicCreds = await store.getPublicCredentials(requestedResource);
  for (const credJws of publicCreds) {
    try {
      const cred = await verifyDFOSCredential(credJws, { resolveIdentity });

      // check revocation (scoped to credential issuer)
      const leafRevoked = await isRevoked(cred.iss, cred.credentialCID);
      if (leafRevoked) continue;

      // check resource + action match
      const covers = await matchesResource(cred.att, requestedResource, action);
      if (!covers) continue;

      // verify delegation chain roots at creator (with revocation at every level)
      await verifyDelegationChain(cred, { resolveIdentity, rootDID: creatorDID, isRevoked });

      return { granted: true, source: 'public-credential' as const, credential: cred };
    } catch {
      continue; // invalid credential, skip
    }
  }

  // 3. check per-request credential
  if (credentialJWS) {
    try {
      const cred = await verifyDFOSCredential(credentialJWS, { resolveIdentity });

      // check revocation (scoped to credential issuer)
      const leafRevoked = await isRevoked(cred.iss, cred.credentialCID);
      if (leafRevoked) {
        return { granted: false, source: 'none' };
      }

      // verify delegation chain roots at creator (with revocation at every level)
      await verifyDelegationChain(cred, { resolveIdentity, rootDID: creatorDID, isRevoked });

      // audience verification for non-public credentials
      if (cred.aud !== '*') {
        if (!requesterDID || cred.aud !== requesterDID) {
          return { granted: false, source: 'none' };
        }
      }

      // check resource + action match
      const covers = await matchesResource(cred.att, requestedResource, action);
      if (!covers) {
        return { granted: false, source: 'none' };
      }

      return { granted: true, source: 'request-credential' as const, credential: cred };
    } catch {
      return { granted: false, source: 'none' };
    }
  }

  return { granted: false, source: 'none' };
};
