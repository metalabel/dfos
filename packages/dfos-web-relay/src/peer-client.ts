/*

  HTTP PEER CLIENT

  Default PeerClient implementation using fetch. Maps semantic methods to
  HTTP calls against peer relay URLs. Returns null on any failure — the
  relay doesn't care WHY a peer couldn't answer.

  Also the entry module for the `./peer-client` subpath export: the lightweight,
  server-free surface for CLIENTS of a relay (fetch + paging + the route-prefix
  constants), with none of the relay server graph (hono, zod, stores) behind it.

*/

import { PROOF_BASE_PATH } from './types';
import type { PeerClient, PeerLogEntry } from './types';

// lightweight client-facing re-exports — everything a relay CONSUMER needs to
// speak the read routes, importable without pulling the relay server graph
export { PROOF_BASE_PATH } from './types';
export type { PeerClient, PeerLogEntry } from './types';
export { REVOCATIONS_BASE_PATH } from './revocations';

/**
 * Create an HTTP-based PeerClient.
 *
 * Each method makes a single HTTP request to the peer relay URL. On any
 * failure (network error, non-2xx response, invalid JSON), returns null
 * for read operations or silently fails for write operations.
 *
 * `options.fetch` injects the fetch implementation (timeouts, retries, tests);
 * defaults to `globalThis.fetch`.
 */
export const createHttpPeerClient = (options?: { fetch?: typeof fetch }): PeerClient => {
  const fetchImpl: typeof fetch = options?.fetch ?? ((input, init) => fetch(input, init));

  const fetchJSON = async (url: string): Promise<unknown | null> => {
    try {
      const res = await fetchImpl(url);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  };

  return {
    async getIdentityLog(peerUrl, did, params) {
      const url = new URL(`${PROOF_BASE_PATH}/identities/${encodeURIComponent(did)}/log`, peerUrl);
      if (params?.after) url.searchParams.set('after', params.after);
      if (params?.limit) url.searchParams.set('limit', String(params.limit));
      const data = (await fetchJSON(url.toString())) as {
        entries?: PeerLogEntry[];
        cursor?: string | null;
      } | null;
      if (!data?.entries) return null;
      return { entries: data.entries, cursor: data.cursor ?? null };
    },

    async getContentLog(peerUrl, contentId, params) {
      const url = new URL(
        `${PROOF_BASE_PATH}/content/${encodeURIComponent(contentId)}/log`,
        peerUrl,
      );
      if (params?.after) url.searchParams.set('after', params.after);
      if (params?.limit) url.searchParams.set('limit', String(params.limit));
      const data = (await fetchJSON(url.toString())) as {
        entries?: PeerLogEntry[];
        cursor?: string | null;
      } | null;
      if (!data?.entries) return null;
      return { entries: data.entries, cursor: data.cursor ?? null };
    },

    async getOperationLog(peerUrl, params) {
      const url = new URL(`${PROOF_BASE_PATH}/log`, peerUrl);
      if (params?.after) url.searchParams.set('after', params.after);
      if (params?.limit) url.searchParams.set('limit', String(params.limit));
      const data = (await fetchJSON(url.toString())) as {
        entries?: PeerLogEntry[];
        cursor?: string | null;
      } | null;
      if (!data?.entries) return null;
      return { entries: data.entries, cursor: data.cursor ?? null };
    },

    async submitOperations(peerUrl, operations) {
      try {
        const res = await fetchImpl(new URL(`${PROOF_BASE_PATH}/operations`, peerUrl).toString(), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ operations }),
        });
        // Check the status: a non-2xx (e.g. the receiver 400s an over-100 batch)
        // means the whole gossip push was dropped. Log it so a silent drop is
        // observable — sync remains the consistency backstop, hence no throw.
        if (!res.ok) {
          console.warn(
            `gossip submitOperations to ${peerUrl} returned ${res.status} (${operations.length} ops dropped)`,
          );
        }
      } catch {
        // network throw — fire-and-forget; sync is the consistency backstop
      }
    },
  };
};
