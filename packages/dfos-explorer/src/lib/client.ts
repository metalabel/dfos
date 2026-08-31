/*

  CLIENT — one dfos-client per relay set

  A relay switch is a new client (the config is immutable by design), so this
  module memoizes on the relay set and rebuilds when it changes. The verified
  prefix cache lives in its own IndexedDB database, separate from the local
  index — the client owns what "verified" means; the index is just browsing.

*/

import { createClient, type Client } from '@metalabel/dfos-client';
import { indexedDbStore } from '@metalabel/dfos-client/store';
import { getQuorum, getRelays } from './relays';

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
