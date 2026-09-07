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

import { parseProtocolTimestampUnix, verifyRevocation } from '@metalabel/dfos-protocol/chain';
import { REVOCATIONS_BASE_PATH } from '@metalabel/dfos-web-relay/peer-client';
import { normalizeRelays } from './transport';
import type { RevChecker } from './types';

interface CredentialStatusBody {
  revoked?: boolean;
  revocation?: string;
}

/** The one unavailable answer this checker gives, whatever made the status
 *  unobtainable. Callers branch on the throw, never on the text. */
const unavailable = (why: string): Error => new Error(`revocation status unavailable: ${why}`);

/**
 * The signing key behind a positive answer could not be produced.
 *
 * A forged proof and an unresolvable key both make `verifyRevocation` throw, and
 * they are opposite facts: the first is a relay lying, the second is this client
 * being unable to check. Only the resolver knows which, so the fact is captured
 * AT the resolver seam rather than guessed from a message downstream.
 */
class KeyUnresolvableError extends Error {}

/**
 * Build the default revocation checker over an ordered relay set.
 *
 * Returns true only for a revocation JWS that VERIFIES via the protocol
 * (`verifyRevocation`: signature, CID integrity, issuer-only rule) and whose
 * payload binds exactly the queried (issuerDID, credentialCID). Anything less —
 * unreachable relay, negative answer, forged or mismatched proof — moves on to
 * the next relay; false only after the full set has been consulted and at least
 * one relay answered with a parseable status body. Zero answers throws, and so
 * does a positive answer whose signing key this client could not resolve: a
 * dependency failure is never a negative status.
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
  resolveKey: (kid: string, basis?: string) => Promise<Uint8Array>,
): RevChecker => {
  const relaySet = normalizeRelays(relays);
  // the resolver seam, tagged: everything past it that throws is the PROOF
  // failing, everything here is this client failing to look
  const guardedResolveKey = async (kid: string, basis?: string): Promise<Uint8Array> => {
    try {
      return await resolveKey(kid, basis);
    } catch (err) {
      throw new KeyUnresolvableError(`could not resolve the revocation signing key ${kid}`, {
        cause: err,
      });
    }
  };
  return async (issuerDID: string, credentialCID: string, asOfUnix?: number): Promise<boolean> => {
    let answered = false;
    // a positive answer was served and this client could not check it. It is
    // neither believed nor discarded: the status is simply unobtainable.
    let unresolvable: KeyUnresolvableError | undefined;
    for (const url of relaySet) {
      let body: CredentialStatusBody | null = null;
      try {
        const target = new URL(
          `${REVOCATIONS_BASE_PATH}/credential/${encodeURIComponent(credentialCID)}`,
          url,
        ).toString();
        const res = await fetchImpl(target);
        // 501 is an explicit capability absence, not a negative revocation
        // answer. Exclude this relay exactly like an unreachable relay.
        if (res.status === 501) continue;
        if (!res.ok) continue;
        body = (await res.json()) as CredentialStatusBody;
        if (body === null || typeof body !== 'object' || typeof body.revoked !== 'boolean') {
          continue;
        }
        answered = true;
      } catch {
        continue;
      }
      // negative answer — this relay hasn't seen a revocation; ask the rest
      if (!body?.revoked || !body.revocation) continue;

      // positive answer — believe only the proof, never the boolean
      try {
        const verified = await verifyRevocation({
          jwsToken: body.revocation,
          resolveKey: guardedResolveKey,
        });
        if (verified.did === issuerDID && verified.credentialCID === credentialCID) {
          // as-of gate: a revocation signed AFTER the instant being asked about
          // does not reach back to it. The boundary comes from the VERIFIED
          // payload, so a relay cannot move it by lying, and it is read through the
          // protocol's canonical grammar rather than a lenient `new Date()` — an
          // off-grammar timestamp on an otherwise-valid revocation falls back to
          // the timeless answer, the stricter direction, never a silent un-revoke.
          // `asOfUnix <= 0` is timeless per the RevChecker contract.
          if (asOfUnix === undefined || asOfUnix <= 0) return true;
          const revokedAtUnix = parseProtocolTimestampUnix(verified.createdAt);
          if (revokedAtUnix === null || revokedAtUnix <= asOfUnix) return true;
          // Revoked strictly AFTER asOfUnix — not revoked as of the queried
          // instant. Keep consulting the remaining relays rather than answering
          // false here: a store keeps one revocation per (issuer, credentialCID),
          // so a relay that ingested a DIFFERENT (earlier) revocation for the same
          // credential would answer with an earlier boundary that does bite.
          continue;
        }
        // verified JWS but for a different (issuer, credential) — a replay;
        // keep consulting the remaining relays
      } catch (err) {
        // A KEY WE COULD NOT RESOLVE IS NOT A FORGERY. Relay A can serve an older
        // identity state than the one the genuine revocation was signed under, so
        // the proof is discarded here and `answered` (set by the other relays'
        // negative-shaped bodies) would then license `false` — a revoked
        // credential authorized because a lookup failed. Remember it and keep
        // consulting: a later relay may still prove the revocation outright.
        if (err instanceof KeyUnresolvableError) unresolvable = err;
        // anything else is a forged / garbage proof — ignore this relay's claim
      }
    }
    if (!answered) throw unavailable('no relay answered');
    // no relay proved a revocation, but one served a proof this client could not
    // check — the same unobtainable status the zero-answer path reports
    if (unresolvable) throw unavailable(unresolvable.message);
    return false;
  };
};
