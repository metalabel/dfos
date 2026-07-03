/*

  TRANSPORT

  Fan-out orchestration over an injected PeerClient. This layer does NOT
  re-implement fetch or paging — each per-relay page fetch is delegated to the
  protocol's `createHttpPeerClient` (or an injected twin). What lives here is the
  read-only orchestration the peer client deliberately omits: draining a relay's
  full log across pages, fanning out to the ordered relay set, and deriving
  quorum agreement from distinct response digests.

*/

import type { PeerClient } from '@metalabel/dfos-web-relay';
import type { LogOp, Provenance, RelayResponse } from './types';

/** A single relay's paged log fetcher, already bound to the log kind + id. */
type PageFetcher = (
  url: string,
  params: { after?: string; limit: number },
) => Promise<{ entries: LogOp[]; cursor: string | null } | null>;

const PAGE_LIMIT = 1000;
const MAX_PAGES = 10_000; // hard stop against a pathological cursor loop

/**
 * FNV-1a over the ordered operation CIDs. Not cryptographic — a cheap, stable
 * fingerprint so two relays returning the same ops (in the same order) collapse
 * to one digest for quorum. The CIDs are themselves content-addressed, so this
 * is sufficient to detect divergence.
 */
export const digestOps = (ops: LogOp[]): string => {
  let h = 0x811c9dc5;
  const joined = ops.map((o) => o.cid).join('\n');
  for (let i = 0; i < joined.length; i++) {
    h ^= joined.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, '0');
};

/**
 * Drain a single relay's log from `after` to its tip, across pages. Returns
 * `null` only when the relay never answered (unreachable / 404) — a reachable
 * relay that is simply caught up (zero new ops after `after`) returns `[]`, so
 * "agreed, nothing newer" is distinguishable from "no answer".
 */
const drainRelay = async (
  fetchPage: PageFetcher,
  url: string,
  after: string | undefined,
): Promise<LogOp[] | null> => {
  const out: LogOp[] = [];
  let cursor = after;
  let answered = false;
  for (let page = 0; page < MAX_PAGES; page++) {
    const params = cursor ? { after: cursor, limit: PAGE_LIMIT } : { limit: PAGE_LIMIT };
    const res = await fetchPage(url, params);
    if (res === null) return answered ? out : null;
    answered = true;
    out.push(...res.entries);
    if (!res.cursor || res.entries.length === 0) break;
    cursor = res.cursor;
  }
  return out;
};

export interface FanOutResult {
  entries: LogOp[];
  provenance: Provenance;
}

/**
 * Fan a paged log read out across the ordered relay set and pick the answer that
 * `quorum` relays agree on (by distinct digest). With `quorum: 1` this is
 * first-wins with failover; with `quorum: N` the top digest must have ≥ N
 * responses for `agreed` to be true. On disagreement the top group's entries are
 * still returned with `agreed: false` — the caller reads provenance and decides.
 */
export const fanOutLog = async (
  fetchPage: PageFetcher,
  relays: string[],
  quorum: number,
  after: string | undefined,
): Promise<FanOutResult> => {
  const responses: RelayResponse[] = [];
  const byDigest = new Map<string, { url: string; entries: LogOp[] }>();

  for (const url of relays) {
    let entries: LogOp[] | null = null;
    try {
      entries = await drainRelay(fetchPage, url, after);
    } catch {
      entries = null;
    }
    if (entries === null) {
      responses.push({ url, ok: false, digest: '' });
      continue;
    }
    const digest = digestOps(entries);
    responses.push({ url, ok: true, digest });
    if (!byDigest.has(digest)) byDigest.set(digest, { url, entries });

    // early exit once quorum is provably met for this digest
    const count = responses.filter((r) => r.ok && r.digest === digest).length;
    if (count >= quorum) {
      return {
        entries,
        provenance: { answeredBy: url, responses, agreed: true, fromCache: false },
      };
    }
  }

  // no digest reached quorum — surface the most-agreed group, agreed: false
  let best: { url: string; entries: LogOp[]; count: number } | undefined;
  for (const [digest, group] of byDigest) {
    const count = responses.filter((r) => r.ok && r.digest === digest).length;
    if (!best || count > best.count) best = { ...group, count };
  }

  if (!best) {
    // every relay failed
    return {
      entries: [],
      provenance: {
        answeredBy: '',
        responses,
        agreed: false,
        fromCache: false,
      },
    };
  }

  return {
    entries: best.entries,
    provenance: { answeredBy: best.url, responses, agreed: false, fromCache: false },
  };
};

/** Bind the peer client's identity-log method into a PageFetcher. */
export const identityPager =
  (peerClient: PeerClient, did: string): PageFetcher =>
  (url, params) =>
    peerClient.getIdentityLog(url, did, params);

/** Bind the peer client's content-log method into a PageFetcher. */
export const contentPager =
  (peerClient: PeerClient, contentId: string): PageFetcher =>
  (url, params) =>
    peerClient.getContentLog(url, contentId, params);

/** Bind the peer client's global operation-log method into a PageFetcher. */
export const operationPager =
  (peerClient: PeerClient): PageFetcher =>
  (url, params) =>
    peerClient.getOperationLog(url, params);
