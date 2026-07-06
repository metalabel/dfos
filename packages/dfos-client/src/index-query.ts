/*

  INDEX QUERIES

  The client seam over the relay's optional `/index/v0` family — non-authoritative
  discovery hints (enumerate identities, filter content chains, reverse-look-up
  countersignatures by witness). A relay advertises support via `capabilities.index`
  in the well-known; when unsupported (or predating the family) the routes answer
  501 and this seam fails over to the next relay, exactly as the log/blob reads do.

  Nothing here verifies. Index rows are CLAIMS: every row carries the proof-plane
  pointers (`did` / `contentId` / `jwsToken`) a caller needs to re-derive the fact
  by fetching the chain and folding it through @metalabel/dfos-protocol. A caller
  that trusts a row without folding has skipped the verification the index cannot
  do for it — the same posture the revocation checker takes toward a `revoked`
  boolean.

*/

import { normalizeRelays } from './transport';
import type {
  CallOptions,
  IndexCapabilities,
  IndexContentPage,
  IndexCountersignaturesPage,
  IndexCredentialsPage,
  IndexIdentitiesPage,
} from './types';

// Mirrors the relay package's INDEX_BASE_PATH (packages/dfos-web-relay). Kept as
// a local constant so the client's index seam does not couple to a relay export
// that is not part of the client-facing `/peer-client` surface.
const INDEX_BASE_PATH = '/index/v0';

/** Append a query param when the value is present (skips undefined/empty). */
const setParam = (url: URL, key: string, value: string | number | boolean | undefined): void => {
  if (value === undefined) return;
  url.searchParams.set(key, String(value));
};

/**
 * Fetch a single index page from the first reachable, index-capable relay in the
 * set. A non-200 (501 = no index capability, 4xx = bad request, network throw)
 * fails over to the next relay; when no relay answers 200 the caller gets the
 * supplied `empty` page. Callers gate on `capabilities()` first, so the empty
 * fallback is the "every candidate declined" floor, not the common path.
 *
 * `throwOnDecline` flips the all-declined floor from empty-success to a throw. It
 * exists because `capabilities.index` is a SINGLE flag that does not imply every
 * `/index/v0` sub-route: a relay can advertise index yet 501 a newer route (e.g.
 * `/credentials`). Swallowing that into an empty page is indistinguishable from a
 * genuine 200-empty, so a caller that wants to fall back to a local source on
 * route-absence (rather than render a false-empty) opts into the throw. A genuine
 * 200-empty from a capable relay still returns normally — only the every-candidate-
 * declined floor throws.
 */
const fetchIndexPage = async <T>(
  relays: string[],
  fetchImpl: typeof fetch,
  build: (base: string) => URL,
  empty: T,
  throwOnDecline = false,
): Promise<T> => {
  for (const url of relays) {
    try {
      const res = await fetchImpl(build(url).toString());
      if (!res.ok) continue;
      return (await res.json()) as T;
    } catch {
      continue;
    }
  }
  if (throwOnDecline) throw new Error('no index-capable relay served the requested route');
  return empty;
};

/**
 * The index seam bound to an ordered relay set + the client's policy-wrapped
 * fetch. Returned methods accept a per-call `relays` override (CallOptions) the
 * same way the rest of the client does.
 */
export const createIndexQueries = (relays: string[], fetchImpl: typeof fetch) => {
  const relaysFor = (o?: CallOptions): string[] => normalizeRelays(o?.relays ?? relays);

  const indexIdentities = (
    params?: { hasPublicProfile?: boolean; after?: string; limit?: number },
    options?: CallOptions,
  ): Promise<IndexIdentitiesPage> =>
    fetchIndexPage(
      relaysFor(options),
      fetchImpl,
      (base) => {
        const url = new URL(`${INDEX_BASE_PATH}/identities`, base);
        setParam(url, 'hasPublicProfile', params?.hasPublicProfile);
        setParam(url, 'after', params?.after);
        setParam(url, 'limit', params?.limit);
        return url;
      },
      { identities: [], next: null },
    );

  const indexContent = (
    params?: {
      creator?: string;
      docSchema?: string;
      documentCID?: string;
      publicRead?: boolean;
      after?: string;
      limit?: number;
    },
    options?: CallOptions,
  ): Promise<IndexContentPage> =>
    fetchIndexPage(
      relaysFor(options),
      fetchImpl,
      (base) => {
        const url = new URL(`${INDEX_BASE_PATH}/content`, base);
        setParam(url, 'creator', params?.creator);
        setParam(url, 'docSchema', params?.docSchema);
        setParam(url, 'documentCID', params?.documentCID);
        setParam(url, 'publicRead', params?.publicRead);
        setParam(url, 'after', params?.after);
        setParam(url, 'limit', params?.limit);
        return url;
      },
      { content: [], next: null },
    );

  const indexCountersignatures = (
    witness: string,
    params?: { after?: string; limit?: number },
    options?: CallOptions,
  ): Promise<IndexCountersignaturesPage> =>
    fetchIndexPage(
      relaysFor(options),
      fetchImpl,
      (base) => {
        const url = new URL(`${INDEX_BASE_PATH}/countersignatures`, base);
        setParam(url, 'witness', witness);
        setParam(url, 'after', params?.after);
        setParam(url, 'limit', params?.limit);
        return url;
      },
      { witness, countersignatures: [], next: null },
    );

  const indexCredentials = (
    params?: { issuer?: string; resource?: string; after?: string; limit?: number },
    options?: CallOptions,
  ): Promise<IndexCredentialsPage> =>
    fetchIndexPage(
      relaysFor(options),
      fetchImpl,
      (base) => {
        const url = new URL(`${INDEX_BASE_PATH}/credentials`, base);
        setParam(url, 'issuer', params?.issuer);
        setParam(url, 'resource', params?.resource);
        setParam(url, 'after', params?.after);
        setParam(url, 'limit', params?.limit);
        return url;
      },
      { credentials: [], next: null },
      // route is newer than the `index` capability flag: throw on all-declined so a
      // relay that advertises index but predates /credentials makes the caller fall
      // back to its local fold instead of rendering a false-empty.
      true,
    );

  /**
   * Merged capability view across the relay set: a capability reads `true` when
   * ANY relay in the set advertises it, since the family is served with failover.
   * `index` is the one callers gate on before browsing the index instead of
   * falling back to full-log sync. An unreachable relay contributes nothing.
   */
  const capabilities = async (options?: CallOptions): Promise<IndexCapabilities> => {
    const merged: IndexCapabilities = { index: false };
    for (const url of relaysFor(options)) {
      try {
        const res = await fetchImpl(new URL('/.well-known/dfos-relay', url).toString());
        if (!res.ok) continue;
        const body = (await res.json()) as { capabilities?: Record<string, unknown> };
        if (body.capabilities?.['index'] === true) merged.index = true;
      } catch {
        continue;
      }
    }
    return merged;
  };

  return { indexIdentities, indexContent, indexCountersignatures, indexCredentials, capabilities };
};
