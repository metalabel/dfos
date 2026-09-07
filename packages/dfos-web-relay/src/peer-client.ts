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
/**
 * Per-request timeout for every peer call this client makes.
 *
 * `fetch` has no default timeout, so a peer that accepts a connection and then
 * says nothing holds the caller forever. That matters most on READ-THROUGH,
 * which runs inside an unauthenticated GET for a chain nobody has to have heard
 * of: without this the request-side deadline can only be checked BETWEEN pages,
 * never during one, so a single unanswered page outlives every bound above it.
 * Matches the Go twin's `http.Client{Timeout: 30 * time.Second}`.
 */
export const PEER_REQUEST_TIMEOUT_MS = 30_000;

export const createHttpPeerClient = (options?: {
  fetch?: typeof fetch;
  /** Per-request timeout in milliseconds; 0 disables it. */
  timeoutMs?: number;
}): PeerClient => {
  const inner: typeof fetch = options?.fetch ?? ((input, init) => fetch(input, init));
  const timeoutMs = options?.timeoutMs ?? PEER_REQUEST_TIMEOUT_MS;
  // Threaded through every call site rather than left to each one to remember:
  // an unbounded peer read is exactly the kind of thing that gets added back by
  // the next method someone writes.
  const fetchImpl: typeof fetch = (input, init) =>
    timeoutMs > 0
      ? inner(input, { ...init, signal: init?.signal ?? AbortSignal.timeout(timeoutMs) })
      : inner(input, init);

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
