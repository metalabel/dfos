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

// -----------------------------------------------------------------------------
// content access verification
// -----------------------------------------------------------------------------

export interface AccessVerification {
  granted: boolean;
  source: 'public-credential' | 'request-credential' | 'creator' | 'none';
  credential?: VerifiedDFOSCredential;
}

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
  const resolveIdentity = async (did: string) => {
    const chain = await store.getIdentityChain(did);
    return chain?.state;
  };

  const isRevoked = async (issuerDID: string, credentialCID: string) =>
    store.isCredentialRevoked(issuerDID, credentialCID);

  // manifest lookup — resolves which contentIds a manifest indexes
  const manifestLookup = async (manifestContentId: string): Promise<string[]> => {
    const chain = await store.getContentChain(manifestContentId);
    if (!chain) return [];
    const docCID = chain.state.currentDocumentCID;
    if (!docCID) return [];
    const blob = await store.getBlob({ creatorDID: chain.state.creatorDID, documentCID: docCID });
    if (!blob) return [];
    try {
      const doc = JSON.parse(new TextDecoder().decode(blob)) as Record<string, unknown>;
      const entries = doc['entries'];
      if (!entries || typeof entries !== 'object') return [];
      // extract contentId references (22-char bare hashes, not DIDs or CIDs)
      return Object.values(entries as Record<string, unknown>).filter(
        (v): v is string =>
          typeof v === 'string' && !v.startsWith('did:') && !v.startsWith('bafyrei'),
      );
    } catch {
      return [];
    }
  };

  // 2. check stored public credentials
  const publicCreds = await store.getPublicCredentials(requestedResource);
  for (const credJws of publicCreds) {
    try {
      const cred = await verifyDFOSCredential(credJws, { resolveIdentity });

      // check revocation (scoped to credential issuer)
      const leafRevoked = await isRevoked(cred.iss, cred.credentialCID);
      if (leafRevoked) continue;

      // check resource + action match (with manifest transitive lookup)
      const covers = await matchesResource(cred.att, requestedResource, action, {
        manifestLookup,
      });
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

      // check resource + action match (with manifest transitive lookup)
      const covers = await matchesResource(cred.att, requestedResource, action, {
        manifestLookup,
      });
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
