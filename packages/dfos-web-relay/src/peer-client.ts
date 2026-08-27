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

  return {
    async getIdentityLog(peerUrl, did, params) {
      const url = new URL(`${PROOF_BASE_PATH}/identities/${encodeURIComponent(did)}/log`, peerUrl);
      if (params?.after) url.searchParams.set('after', params.after);
      if (params?.limit) url.searchParams.set('limit', String(params.limit));
      let res: Response;
      try {
        res = await fetchImpl(url.toString());
      } catch {
        return null;
      }
      if (res.status === 400 && params?.after) return 'invalid-cursor';
      if (!res.ok) return null;
      let data: {
        entries?: PeerLogEntry[];
        next?: string | null;
        cursor?: string | null;
      };
      try {
        data = (await res.json()) as typeof data;
      } catch {
        return null;
      }
      if (!data?.entries) return null;
      // `cursor` fallback: pre-rename relays emit only the deprecated alias.
      return { entries: data.entries, next: data.next ?? data.cursor ?? null };
    },

    async getContentLog(peerUrl, contentId, params) {
      const url = new URL(
        `${PROOF_BASE_PATH}/content/${encodeURIComponent(contentId)}/log`,
        peerUrl,
      );
      if (params?.after) url.searchParams.set('after', params.after);
      if (params?.limit) url.searchParams.set('limit', String(params.limit));
      let res: Response;
      try {
        res = await fetchImpl(url.toString());
      } catch {
        return null;
      }
      if (res.status === 400 && params?.after) return 'invalid-cursor';
      if (!res.ok) return null;
      let data: {
        entries?: PeerLogEntry[];
        next?: string | null;
        cursor?: string | null;
      };
      try {
        data = (await res.json()) as typeof data;
      } catch {
        return null;
      }
      if (!data?.entries) return null;
      return { entries: data.entries, next: data.next ?? data.cursor ?? null };
    },

    async getOperationLog(peerUrl, params) {
      const url = new URL(`${PROOF_BASE_PATH}/log`, peerUrl);
      if (params?.after) url.searchParams.set('after', params.after);
      if (params?.limit) url.searchParams.set('limit', String(params.limit));
      let res: Response;
      try {
        res = await fetchImpl(url.toString());
      } catch {
        return null;
      }
      // A 400 with an `after` param is the peer rejecting our relay-local
      // cursor — distinguishable so the sync loop can reset instead of stall.
      if (res.status === 400 && params?.after) return 'invalid-cursor';
      if (!res.ok) return null;
      let data: { entries?: PeerLogEntry[]; next?: string | null; cursor?: string | null };
      try {
        data = (await res.json()) as typeof data;
      } catch {
        return null;
      }
      if (!data?.entries) return null;
      return { entries: data.entries, next: data.next ?? data.cursor ?? null };
    },

    async submitOperations(peerUrl, operations, options) {
      try {
        const url = new URL(`${PROOF_BASE_PATH}/operations`, peerUrl);
        // The body is serialized ONCE and both hashed and sent: an identity
        // proof binds `bodyHash`, so re-serializing for the wire would sign one
        // string and send another.
        const body = new TextEncoder().encode(JSON.stringify({ operations }));
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        // Gossip-out authenticates like any client: anonymously, or with an
        // identity proof signed by the relay's own DID. A signer that fails or
        // is absent leaves the push anonymous — a default-open peer admits it,
        // and sync is the consistency backstop either way.
        if (options?.signProof) {
          const proof = await options.signProof({
            method: 'POST',
            // `host`, never `hostname`: the authority carries the port when
            // there is one, and the peer compares it byte for byte against its
            // OWN configured authority.
            host: url.host,
            path: url.pathname + url.search,
            body,
          });
          if (proof) headers['Authorization'] = `DFOS ${proof}`;
        }
        const res = await fetchImpl(url.toString(), {
          method: 'POST',
          headers,
          body,
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
