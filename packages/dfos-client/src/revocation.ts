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
 *
 * When the caller supplies `asOfUnix` (the protocol does, on every cold fold, with
 * each operation's own `createdAt`), a verified revocation only counts if its own
 * signed `createdAt` is at or before that instant. This is what heals cold
 * verification of history: without it, revoking a credential today would make
 * every already-committed operation it ever authorized fail to verify tomorrow.
 */
export const createRevocationChecker = (
  relays: string[],
  fetchImpl: typeof fetch,
  resolveKey: (kid: string) => Promise<Uint8Array>,
): RevChecker => {
  const relaySet = normalizeRelays(relays);
  return async (issuerDID: string, credentialCID: string, asOfUnix?: number): Promise<boolean> => {
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
          // as-of gate: a revocation signed AFTER the instant being asked about
          // does not reach back to it. The boundary comes from the VERIFIED
          // payload, so a relay cannot move it by lying. An unparseable timestamp
          // on an otherwise-valid revocation falls back to the timeless answer —
          // the stricter direction, never a silent un-revoke.
          if (asOfUnix === undefined) return true;
          const revokedAtMs = new Date(verified.createdAt).getTime();
          if (!Number.isFinite(revokedAtMs) || Math.floor(revokedAtMs / 1000) <= asOfUnix) {
            return true;
          }
          // Revoked strictly AFTER asOfUnix — not revoked as of the queried
          // instant. Keep consulting the remaining relays rather than answering
          // false here: a store keeps one revocation per (issuer, credentialCID),
          // so a relay that ingested a DIFFERENT (earlier) revocation for the same
          // credential would answer with an earlier boundary that does bite.
          continue;
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
