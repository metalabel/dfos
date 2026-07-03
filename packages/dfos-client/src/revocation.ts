/*

  REVOCATION CHECKER

  The default `isRevoked` callback, wired to the relay `/revocations/v1`
  credential-status route (merged on main; served by every reference relay).

  Semantics are HONEST per the relay's own contract: a positive answer carries
  the self-proving revocation JWS (we re-check that the issuer DID matches before
  trusting the boolean); a negative answer means only "no relay we asked has
  ingested a revocation for this CID" — it is NOT proof of non-revocation. The
  client surfaces that gap as the `revocation` unverifiable trust axis, never as
  a false claim of proven-unrevoked.

*/

import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { REVOCATIONS_BASE_PATH } from '@metalabel/dfos-web-relay';
import type { RevChecker } from './types';

interface CredentialStatusBody {
  revoked?: boolean;
  revocation?: string;
}

/**
 * Build the default revocation checker over an ordered relay set. Returns true
 * only on a self-proving revocation whose issuer DID matches — a withholding or
 * unreachable relay yields false (honest), and the caller marks `revocation`
 * unverifiable.
 */
export const createRevocationChecker =
  (relays: string[], fetchImpl: typeof fetch): RevChecker =>
  async (issuerDID: string, credentialCID: string): Promise<boolean> => {
    for (const url of relays) {
      let body: CredentialStatusBody | null = null;
      try {
        const target = new URL(
          `${REVOCATIONS_BASE_PATH}/credential/${encodeURIComponent(credentialCID)}`,
          url,
        ).toString();
        const res = await fetchImpl(target);
        if (!res.ok) continue;
        body = (await res.json()) as CredentialStatusBody;
      } catch {
        continue;
      }
      if (!body?.revoked || !body.revocation) return false;
      // re-check the self-proving JWS: only the issuer can revoke, so the
      // revocation's payload `did` MUST match the issuer we're asking about.
      const decoded = decodeJwsUnsafe(body.revocation);
      const payloadDid = (decoded?.payload as Record<string, unknown> | undefined)?.['did'];
      if (payloadDid === issuerDID) return true;
      return false;
    }
    return false;
  };
