/*

  CLIENT — one dfos-client per relay set

  A relay switch is a new client (the config is immutable by design), so this
  module memoizes on the relay set and rebuilds when it changes. The verified
  prefix cache lives in its own IndexedDB database, separate from the local
  index — the client owns what "verified" means; the index is just browsing.

*/

import { createClient, type Client } from '@metalabel/dfos-client';
import { indexedDbStore } from '@metalabel/dfos-client/store';
import { isDependencyMissing } from '@metalabel/dfos-protocol';
import { getQuorum, getRelays } from './relays';

/**
 * The message dfos-client's fan-out wraps a rejected candidate in
 * (`transport.ts`: "candidates existed but every one failed verification — that
 * is an error, not an absence"). Matched as a PREFIX because the original error
 * is appended, and the original is also carried as `cause`.
 */
const VERIFICATION_FAILURE = 'all candidate logs failed verification';

/** How far down a `cause` chain to look — mirrors the client's own unwrap. */
const CAUSE_DEPTH = 4;

/**
 * Did this throw mean "a relay ANSWERED, and what it served did not verify here"?
 *
 * The distinction the explorer cannot render honestly without: a chain read
 * fails either because nobody answered (a timeout, a network failure — the
 * question was never put) or because somebody answered with bytes that failed a
 * signature or CID check in this tab. Those are opposite statements, and the
 * client already separates them — it returns `unreachable` for the first and
 * THROWS the wrapper above for the second — so a caller that treats every throw
 * as silence prints the inverse of what happened.
 *
 * Never a substitute for `divergenceErrorFrom`: a divergence is its own typed
 * error and its own panel, and callers check it first. Pure, unit-tested.
 */
export const isVerificationFailure = (err: unknown): boolean => {
  // A DEPENDENCY MISS IS NOT AN ANSWER. The client marks a throw whose only
  // obstacle was an identity or key it could not resolve; the log itself was
  // never judged, so calling it "failed verification here" would print a
  // terminal red finding for a signer lookup that timed out.
  if (isDependencyMissing(err)) return false;
  let cursor = err;
  for (let depth = 0; depth < CAUSE_DEPTH && cursor instanceof Error; depth++) {
    if (cursor.message.startsWith(VERIFICATION_FAILURE)) return true;
    cursor = cursor.cause;
  }
  return false;
};

let cached: { key: string; client: Client } | null = null;

export const getClient = (): Client => {
  const relays = getRelays();
  const quorum = Math.min(getQuorum(), relays.length);
  const key = `${quorum}|${relays.join('|')}`;
  if (!cached || cached.key !== key) {
    cached = {
      key,
      client: createClient({ relays, quorum, store: indexedDbStore('dfos-explorer-client') }),
    };
  }
  return cached.client;
};

/**
 * Forget the verified prefix this browser pinned for ONE chain — the escape
 * hatch out of a divergence (components/diverged.tsx).
 *
 * NEVER CALLED WITHOUT A PERSON ASKING. The pin is what turns a rewritten
 * history into something a reader can see; a tab that dropped it on its own
 * would repair the symptom and destroy the evidence in the same move. So this
 * has exactly one caller, behind exactly one button.
 *
 * Local and narrow: one chain's cache entry, nothing on any relay, and nothing
 * in the local operation index (the sync page owns that reset). Returns whether
 * the cache was asked to forget.
 */
export const discardChainPin = (kind: 'identity' | 'content', id: string): Promise<boolean> =>
  getClient().discardCachedChain(kind, id);
