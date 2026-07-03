/*

  TRANSPORT

  Fan-out orchestration over an injected PeerClient. This layer does NOT
  re-implement fetch or paging — each per-relay page fetch is delegated to the
  relay package's `createHttpPeerClient` (or an injected twin). What lives here
  is the read-only orchestration the peer client deliberately omits: draining a
  relay's full log across pages, fanning out to the ordered relay set, deriving
  quorum agreement from distinct response digests, and failing over past
  candidates whose payload does not VERIFY (transport success is not trust —
  a reachable relay can still serve garbage).

*/

import type { PeerClient } from '@metalabel/dfos-web-relay/peer-client';
import type { LogOp, Provenance, RelayResponse } from './types';

/** A single relay's paged log fetcher, already bound to the log kind + id. */
type PageFetcher = (
  url: string,
  params: { after?: string; limit: number },
) => Promise<{ entries: LogOp[]; cursor: string | null } | null>;

const PAGE_LIMIT = 1000;
const MAX_PAGES = 10_000; // hard stop against a pathological cursor loop

/**
 * Normalize + dedupe a relay set: trim whitespace, strip trailing slashes,
 * drop duplicates (order-preserving). Prevents a single relay listed twice
 * (or with a cosmetic trailing slash) from satisfying a quorum by itself.
 */
export const normalizeRelays = (relays: string[]): string[] => {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of relays) {
    const url = raw.trim().replace(/\/+$/, '');
    if (url.length === 0 || seen.has(url)) continue;
    seen.add(url);
    out.push(url);
  }
  return out;
};

/**
 * FNV-1a over the ordered FULL JWS tokens. Not cryptographic — a cheap, stable
 * fingerprint so two relays returning identical answers collapse to one digest
 * for quorum. It must cover the whole token, not just the claimed CIDs: at
 * digest time nothing is verified yet, so a header CID is an unverified claim —
 * a forged token carrying an honest CID must land in a DIFFERENT group than the
 * honest token, or verification failover could never reach the honest copy.
 */
export const digestOps = (ops: LogOp[]): string => {
  let h = 0x811c9dc5;
  const joined = ops.map((o) => `${o.cid}\t${o.jwsToken}`).join('\n');
  for (let i = 0; i < joined.length; i++) {
    h ^= joined.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, '0');
};

/**
 * Drain a single relay's log from `after` to its tip, across pages —
 * ALL-OR-NOTHING. Returns `null` when the relay never answered (unreachable /
 * 404) AND when any later page fails: a partially-drained log must never be
 * mistaken for the relay's complete answer (it would digest as a plausible
 * truncated chain). A reachable relay that is simply caught up (zero new ops
 * after `after`) returns `[]`, so "nothing newer" stays distinguishable from
 * "no answer".
 */
const drainRelay = async (
  fetchPage: PageFetcher,
  url: string,
  after: string | undefined,
): Promise<LogOp[] | null> => {
  const out: LogOp[] = [];
  let cursor = after;
  for (let page = 0; page < MAX_PAGES; page++) {
    const params = cursor ? { after: cursor, limit: PAGE_LIMIT } : { limit: PAGE_LIMIT };
    const res = await fetchPage(url, params);
    if (res === null) return null; // any page failure voids the whole answer
    out.push(...res.entries);
    if (!res.cursor || res.entries.length === 0) break;
    cursor = res.cursor;
  }
  return out;
};

export interface FanOutResult<V> {
  /**
   * 'verified'    — some candidate log passed `verifyCandidate`; `value` holds it.
   * 'unreachable' — no relay answered at all (transport-level); caller may fall
   *                 back to cache.
   */
  outcome: 'verified' | 'unreachable';
  value?: V;
  entries: LogOp[];
  provenance: Provenance;
}

/**
 * Fan a paged log read out across the ordered relay set, group answers by
 * content digest, and return the first answer that both (a) reaches `quorum`
 * distinct-relay support and (b) passes `verifyCandidate`. Verification failure
 * marks the digest group bad and fails over to the next relay/candidate —
 * a reachable-but-lying relay never blocks a healthy one behind it.
 *
 * If no group reaches quorum, remaining unverified candidates are tried in
 * support order and returned with `agreed: false` — the caller reads provenance
 * and decides. Throws only when candidates existed but ALL failed verification.
 * Returns `outcome: 'unreachable'` when no relay answered at all.
 */
export const fanOutLog = async <V>(
  fetchPage: PageFetcher,
  relays: string[],
  quorum: number,
  after: string | undefined,
  verifyCandidate: (entries: LogOp[]) => Promise<V>,
): Promise<FanOutResult<V>> => {
  const responses: RelayResponse[] = [];
  const byDigest = new Map<string, { url: string; entries: LogOp[]; count: number }>();
  const badDigests = new Set<string>();
  let lastVerifyError: unknown;

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
    if (badDigests.has(digest)) continue; // known-bad payload — keep failing over

    const group = byDigest.get(digest) ?? { url, entries, count: 0 };
    group.count += 1;
    byDigest.set(digest, group);

    // once this digest reaches quorum, attempt verification; a pass is final,
    // a fail marks the group bad and the fan-out continues down the relay list
    if (group.count >= quorum) {
      try {
        const value = await verifyCandidate(group.entries);
        return {
          outcome: 'verified',
          value,
          entries: group.entries,
          provenance: { answeredBy: group.url, responses, agreed: true, fromCache: false },
        };
      } catch (err) {
        lastVerifyError = err;
        badDigests.add(digest);
      }
    }
  }

  // no digest reached quorum (or quorum winners all failed verification) —
  // try the remaining candidates in support order, surfacing agreed: false
  const remaining = [...byDigest.entries()]
    .filter(([digest]) => !badDigests.has(digest))
    .sort((a, b) => b[1].count - a[1].count);
  for (const [digest, group] of remaining) {
    try {
      const value = await verifyCandidate(group.entries);
      return {
        outcome: 'verified',
        value,
        entries: group.entries,
        provenance: { answeredBy: group.url, responses, agreed: false, fromCache: false },
      };
    } catch (err) {
      lastVerifyError = err;
      badDigests.add(digest);
    }
  }

  // candidates existed but every one failed verification — that is an error,
  // not an absence: surface it rather than pretending nothing answered
  if (lastVerifyError !== undefined) {
    const message = lastVerifyError instanceof Error ? lastVerifyError.message : 'unknown error';
    throw new Error(`all candidate logs failed verification: ${message}`);
  }

  // no relay answered at all
  return {
    outcome: 'unreachable',
    entries: [],
    provenance: { answeredBy: '', responses, agreed: false, fromCache: false },
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
