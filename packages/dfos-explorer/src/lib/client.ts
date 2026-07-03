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
