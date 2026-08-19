/*

  RAW INDEX ROUTES — the two /index/v0 families the client seam doesn't wrap

  `@metalabel/dfos-client` exposes identities / content / countersignatures /
  credentials. The relay also serves `/index/v0/operations` (a recency feed over
  the operation log) and `/index/v0/artifacts` (the last primitive that otherwise
  needed a full-log replay to enumerate). Both are NEWER than the
  `capabilities.index` flag — a single boolean that never implied any particular
  sub-route — so they are raw fetches here, with the same first-reachable-relay
  failover the client does.

  AN ALL-DECLINED SET THROWS, deliberately. A relay predating a route answers
  404/501, and folding that into `{ items: [] }` renders a false-empty
  indistinguishable from "this relay holds no artifacts". The throw surfaces as
  the pager's honest error, and the caller falls back to a source that is true
  (the forward log walk, the local corpus) instead of quietly showing nothing.
  This is the same reasoning `indexCredentials` encodes as `throwOnDecline`.

  THE THROW SAYS WHICH KIND OF FAILURE IT WAS. Only an every-relay 404/501 is a
  verdict about the ROUTE; a network throw, a 5xx, a timeout, or a 400 from a
  rejected cursor is transient and carries no such claim. The rejection is tagged
  ROUTE_ABSENT in the first case only, so a caller can permanently prefer another
  source where the route genuinely is not served, while a bad page or a
  hand-edited cursor stays retryable in place instead of hiding a working feed
  for the rest of the session.

  Rows are relay-asserted browsing metadata like every other index row: no JWS,
  no payload, no display-name projection. Open one to verify it.

*/

import {
  PAGE,
  ROUTE_ABSENT,
  routeAbsentFromStatuses,
  useIndexPageStack,
  type IndexPage,
} from './index-light';
import { getRelays } from './relays';

const INDEX_BASE_PATH = '/index/v0';

const TIMEOUT_MS = 10_000;

/** The recency orderings `/operations` and `/artifacts` share (see WEB-RELAY.md).
 *  `createdAt` is author-claimed; `ingestedAt` is this relay's acceptance time —
 *  browse chronology, never a consensus clock. */
export type IndexRecency = 'createdAt.desc' | 'ingestedAt.desc';

/** One row of `/index/v0/operations` — metadata only, no JWS. */
export interface IndexOperationRow {
  cid: string;
  kind: string;
  chainId: string;
  createdAt: string;
  ingestedAt: string;
}

/** One row of `/index/v0/artifacts`. `docSchema` is the inline document's
 *  `$schema` matched as an opaque string; the wire shape is nullable to preserve
 *  the index's honest-unknown convention, though an accepted artifact always
 *  carries its bytes (and so its `$schema`) inline. */
export interface IndexArtifactRow {
  cid: string;
  signerDID: string;
  createdAt: string;
  ingestedAt: string;
  docSchema: string | null;
}

/** Append a query param when the value is present — mirrors the client seam. */
const setParam = (url: URL, key: string, value: string | number | undefined): void => {
  if (value === undefined || value === '') return;
  url.searchParams.set(key, String(value));
};

/**
 * Fetch one index page from the first relay that answers 2xx. Every non-200
 * (404/501 = the relay predates this route, 400 = bad request, a network throw)
 * fails over to the next relay; when every candidate declines this THROWS — see
 * the header note on why an empty page would be a lie here.
 *
 * The per-relay statuses are kept (0 = network throw / abort) so the rejection
 * can carry the DURABLE route-absent verdict when — and only when — every relay
 * said 404/501.
 */
const fetchIndexPage = async <T>(
  route: string,
  params: Record<string, string | number | undefined>,
  relays: string[],
): Promise<T> => {
  const statuses: number[] = [];
  for (const relay of relays) {
    try {
      const url = new URL(`${INDEX_BASE_PATH}/${route}`, relay);
      for (const [key, value] of Object.entries(params)) setParam(url, key, value);
      const res = await fetch(url.toString(), {
        mode: 'cors',
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (!res.ok) {
        statuses.push(res.status);
        continue;
      }
      return (await res.json()) as T;
    } catch {
      statuses.push(0); // unreachable / aborted — no claim about the route
      continue;
    }
  }
  throw new Error(
    `no relay served /index/v0/${route}`,
    routeAbsentFromStatuses(statuses) ? { cause: ROUTE_ABSENT } : undefined,
  );
};

// -----------------------------------------------------------------------------
// pure row coercion — a relay's JSON is untrusted input like everything else
// -----------------------------------------------------------------------------

const str = (v: unknown): string => (typeof v === 'string' ? v : '');

/** Coerce an `/index/v0/operations` page body into rows, dropping anything without
 *  a cid (a row that names no operation is not addressable). Pure, unit-tested. */
export const toOperationRows = (body: unknown): IndexOperationRow[] => {
  const rows = (body as { operations?: unknown } | null)?.operations;
  if (!Array.isArray(rows)) return [];
  return rows.flatMap((row): IndexOperationRow[] => {
    const r = row as Record<string, unknown>;
    const cid = str(r['cid']);
    if (!cid) return [];
    return [
      {
        cid,
        kind: str(r['kind']),
        chainId: str(r['chainId']),
        createdAt: str(r['createdAt']),
        ingestedAt: str(r['ingestedAt']),
      },
    ];
  });
};

/** Coerce an `/index/v0/artifacts` page body into rows. `docSchema` stays null
 *  when the relay reports the honest unknown. Pure, unit-tested. */
export const toArtifactRows = (body: unknown): IndexArtifactRow[] => {
  const rows = (body as { artifacts?: unknown } | null)?.artifacts;
  if (!Array.isArray(rows)) return [];
  return rows.flatMap((row): IndexArtifactRow[] => {
    const r = row as Record<string, unknown>;
    const cid = str(r['cid']);
    if (!cid) return [];
    return [
      {
        cid,
        signerDID: str(r['signerDID']),
        createdAt: str(r['createdAt']),
        ingestedAt: str(r['ingestedAt']),
        docSchema: typeof r['docSchema'] === 'string' ? r['docSchema'] : null,
      },
    ];
  });
};

/** The page cursor a relay issued, or null when the enumeration is caught up.
 *  Pure, unit-tested. */
export const nextCursor = (body: unknown): string | null => {
  const next = (body as { next?: unknown } | null)?.next;
  return typeof next === 'string' && next.length > 0 ? next : null;
};

// -----------------------------------------------------------------------------
// page loaders
// -----------------------------------------------------------------------------

/** One page of the operation recency feed. Throws when no relay serves the route. */
export const fetchOperationsPage = async (params: {
  order: IndexRecency;
  kind?: string;
  after?: string;
  limit?: number;
}): Promise<{ items: IndexOperationRow[]; next: string | null }> => {
  const body = await fetchIndexPage<unknown>(
    'operations',
    {
      order: params.order,
      ...(params.kind ? { kind: params.kind } : {}),
      ...(params.after ? { after: params.after } : {}),
      limit: params.limit ?? PAGE,
    },
    getRelays(),
  );
  return { items: toOperationRows(body), next: nextCursor(body) };
};

/** One page of the artifact enumeration. Throws when no relay serves the route. */
export const fetchArtifactsPage = async (params: {
  order?: IndexRecency;
  signer?: string;
  docSchema?: string;
  after?: string;
  limit?: number;
}): Promise<{ items: IndexArtifactRow[]; next: string | null }> => {
  const body = await fetchIndexPage<unknown>(
    'artifacts',
    {
      ...(params.order ? { order: params.order } : {}),
      ...(params.signer ? { signer: params.signer } : {}),
      ...(params.docSchema ? { docSchema: params.docSchema } : {}),
      ...(params.after ? { after: params.after } : {}),
      limit: params.limit ?? PAGE,
    },
    getRelays(),
  );
  return { items: toArtifactRows(body), next: nextCursor(body) };
};

/**
 * Page the artifact index, newest-signed first by default. `cursor`/`onCursor`
 * carry the deep-linked page position exactly as the client-backed index hooks do.
 */
export const useIndexArtifacts = (
  enabled: boolean,
  opts: {
    order: IndexRecency | '';
    signer?: string;
    docSchema?: string;
    cursor?: string;
    onCursor?: (cursor: string) => void;
  },
): IndexPage<IndexArtifactRow> =>
  useIndexPageStack(
    enabled,
    `artifacts:${opts.order}:${opts.signer ?? ''}:${opts.docSchema ?? ''}`,
    opts.cursor ?? '',
    opts.onCursor,
    (after) =>
      fetchArtifactsPage({
        ...(opts.order ? { order: opts.order } : {}),
        ...(opts.signer ? { signer: opts.signer } : {}),
        ...(opts.docSchema ? { docSchema: opts.docSchema } : {}),
        ...(after ? { after } : {}),
      }),
  );
