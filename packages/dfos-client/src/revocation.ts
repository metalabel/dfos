/*

  REVOCATION CHECKER

  The default `isRevoked` callback, wired to the relay `/revocations/v1`
  credential-status route (merged on main; served by every reference relay).

  Zero-trust: a relay's `revoked: true` boolean is never believed on its own.
  A positive answer must carry the self-proving revocation JWS, which is
  re-verified through the protocol's `verifyRevocation` (signature against the
  issuer's resolved key, CID integrity, kid-DID == payload did) AND must bind to
  exactly the (issuerDID, credentialCID) pair being asked about — a forged JWS
  or a real revocation replayed for a DIFFERENT credential proves nothing.

  Negative answers are HONEST per the relay's own contract: they mean only "no
  relay we asked has ingested a revocation for this CID" — NOT proof of
  non-revocation. ALL relays are consulted before answering false (any single
  relay can withhold), and the caller surfaces the residual gap as the
  `revocation` unverifiable trust axis.

*/

import { verifyRevocation } from '@metalabel/dfos-protocol/chain';
import { REVOCATIONS_BASE_PATH } from '@metalabel/dfos-web-relay/peer-client';
import { normalizeRelays } from './transport';
import type { RevChecker } from './types';

interface CredentialStatusBody {
  revoked?: boolean;
  revocation?: string;
}

/**
 * Build the default revocation checker over an ordered relay set.
 *
 * Returns true only for a revocation JWS that VERIFIES via the protocol
 * (`verifyRevocation`: signature, CID integrity, issuer-only rule) and whose
 * payload binds exactly the queried (issuerDID, credentialCID). Anything less —
 * unreachable relay, negative answer, forged or mismatched proof — moves on to
 * the next relay; false only after the full set has been consulted.
 */
export const createRevocationChecker = (
  relays: string[],
  fetchImpl: typeof fetch,
  resolveKey: (kid: string) => Promise<Uint8Array>,
): RevChecker => {
  const relaySet = normalizeRelays(relays);
  return async (issuerDID: string, credentialCID: string): Promise<boolean> => {
    for (const url of relaySet) {
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
      // negative answer — this relay hasn't seen a revocation; ask the rest
      if (!body?.revoked || !body.revocation) continue;

      // positive answer — believe only the proof, never the boolean
      try {
        const verified = await verifyRevocation({ jwsToken: body.revocation, resolveKey });
        if (verified.did === issuerDID && verified.credentialCID === credentialCID) {
          return true;
        }
        // verified JWS but for a different (issuer, credential) — a replay;
        // keep consulting the remaining relays
      } catch {
        // forged / garbage proof — ignore this relay's claim entirely
      }
    }
    return false;
  };
};
