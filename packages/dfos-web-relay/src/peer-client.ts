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

/**
 * Byte cap on ONE peer log page. Matches the Go twin's `maxPeerLogPageBytes`.
 *
 * Read-through decodes a page inside an unauthenticated GET, and the op and
 * deadline budgets that bound read-through are only consulted AFTER the decode
 * has already returned — so the page itself has to be bounded here, or one
 * hostile response is unbounded work no later check can undo. The request
 * timeout bounds wall time, not memory.
 */
export const MAX_PEER_LOG_PAGE_BYTES = 16 << 20; // 16 MB

type PeerLogPage = { entries: PeerLogEntry[]; next: string | null };

/** Read a response body up to the cap; null past it, or on a read failure. */
const readBoundedBody = async (res: Response): Promise<string | null> => {
  const declared = Number(res.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_PEER_LOG_PAGE_BYTES) return null;
  try {
    if (!res.body) {
      const text = await res.text();
      return new TextEncoder().encode(text).length > MAX_PEER_LOG_PAGE_BYTES ? null : text;
    }
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > MAX_PEER_LOG_PAGE_BYTES) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
    const body = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.length;
    }
    return new TextDecoder().decode(body);
  } catch {
    return null;
  }
};

/**
 * One bounded page read, shared by all three log methods — an unbounded peer
 * read is exactly the kind of thing the next method someone writes adds back.
 *
 * `limit` is the page size this relay asked for: a peer that returns more
 * entries than were requested is answering a question nobody posed, so the page
 * is refused rather than drained (same rule as Go's `fetchLog`).
 */
const fetchLogPage = async (
  fetchImpl: typeof fetch,
  url: URL,
  params: { after?: string; limit?: number } | undefined,
): Promise<PeerLogPage | 'invalid-cursor' | null> => {
  if (params?.after) url.searchParams.set('after', params.after);
  if (params?.limit) url.searchParams.set('limit', String(params.limit));
  let res: Response;
  try {
    res = await fetchImpl(url.toString());
  } catch {
    return null;
  }
  // A 400 with an `after` param is the peer rejecting our relay-local cursor —
  // distinguishable so the sync loop can reset instead of stall.
  if (res.status === 400 && params?.after) return 'invalid-cursor';
  if (!res.ok) return null;
  const body = await readBoundedBody(res);
  if (body === null) return null;
  let data: { entries?: unknown; next?: string | null; cursor?: string | null };
  try {
    data = JSON.parse(body) as typeof data;
  } catch {
    return null;
  }
  if (!Array.isArray(data?.entries)) return null;
  if (params?.limit && params.limit > 0 && data.entries.length > params.limit) return null;
  // `cursor` fallback: pre-rename relays emit only the deprecated alias.
  return { entries: data.entries as PeerLogEntry[], next: data.next ?? data.cursor ?? null };
};

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
      return fetchLogPage(fetchImpl, url, params);
    },

    async getContentLog(peerUrl, contentId, params) {
      const url = new URL(
        `${PROOF_BASE_PATH}/content/${encodeURIComponent(contentId)}/log`,
        peerUrl,
      );
      return fetchLogPage(fetchImpl, url, params);
    },

    async getOperationLog(peerUrl, params) {
      const url = new URL(`${PROOF_BASE_PATH}/log`, peerUrl);
      return fetchLogPage(fetchImpl, url, params);
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
