/*

  HTTP PEER CLIENT

  Default PeerClient implementation using fetch. Maps semantic methods to
  HTTP calls against peer relay URLs. Returns null on any failure — the
  relay doesn't care WHY a peer couldn't answer.

*/

import type { PeerClient, PeerLogEntry } from './types';

/**
 * Create an HTTP-based PeerClient.
 *
 * Each method makes a single HTTP request to the peer relay URL. On any
 * failure (network error, non-2xx response, invalid JSON), returns null
 * for read operations or silently fails for write operations.
 */
export const createHttpPeerClient = (): PeerClient => {
  const fetchJSON = async (url: string): Promise<unknown | null> => {
    try {
      const res = await fetch(url);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  };

  return {
    async getIdentityLog(peerUrl, did, params) {
      const url = new URL(`/identities/${encodeURIComponent(did)}/log`, peerUrl);
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
      const url = new URL(`/content/${encodeURIComponent(contentId)}/log`, peerUrl);
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
      const url = new URL('/log', peerUrl);
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
        await fetch(new URL('/operations', peerUrl).toString(), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ operations }),
        });
      } catch {
        // fire-and-forget — sync is the consistency backstop
      }
    },
  };
};
