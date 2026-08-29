/*

  RAW INDEX ROUTES — the /index/v0 reads that must FAIL LOUDLY

  `@metalabel/dfos-client` exposes identities / content / countersignatures /
  credentials. The relay also serves `/index/v0/operations` (a recency feed over
  the operation log) and `/index/v0/artifacts` (the last primitive that otherwise
  needed a full-log replay to enumerate). Both are NEWER than the
  `capabilities.index` flag — a single boolean that never implied any particular
  sub-route — so they are raw fetches here, with the same first-reachable-relay
  failover the client does.

  `/index/v0/content` and `/index/v0/countersignatures` are wrapped here TOO, for
  the second reason rather than the first. Their client-seam reads resolve an
  EMPTY PAGE when every relay declines, which is a face-value lie a caller cannot
  detect: indistinguishable from a served empty page, and — on a lane that PAGES
  — it lands in the success branch and clears the live cursor, presenting a
  truncated listing as a complete one. The actor ledger's Created, Contributed,
  and Witnessed lanes read through {@link fetchContentPage} and
  {@link fetchCountersignaturesPage} so an outage is an outage. (`indexCredentials`
  already sets `throwOnDecline`, so the Issued lane stays on the client seam.)

  `/index/v0/identities?key=` is wrapped here for BOTH reasons: the client seam's
  `indexIdentities` predates the `key=` filter and so cannot express the query at
  all, and it would resolve an all-declined set to an empty page — a false "no
  identity ever declared this key", which is the exact claim the key page must
  never make from an outage.

  THE TWO OPAQUE KEY FILTERS TAKE THEIR RELAY SET AS A PARAMETER, and it is not
  `getRelays()`. Every other route here fails over across the whole configured set
  and that is correct, because every other param is one a relay either honours or
  400s. `key=` and `signerKey=` are specified as opaque matches that never 400, so
  a relay predating either IGNORES it and answers 200 with an unfiltered page —
  and a failover that takes the first 2xx from ANY relay will happily take that
  one, whatever a probe said about some other relay. So those queries live in
  their own functions with a REQUIRED `relays`, carrying only the relays whose own
  probe cleared them (lib/index-light.ts). The gate is a parameter you cannot
  forget rather than a sentence in a doc comment.

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

import type {
  IndexContentRow,
  IndexCountersignatureRow,
  IndexIdentityRow,
  IndexOrder,
} from '@metalabel/dfos-client';
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

/**
 * One row of `/index/v0/credits` — the credit projection restated.
 *
 * Every field is ASSERTION-TIER: it says what a public head document claims, not
 * what is true. `position` is the entry's array index, and 0 is the primary
 * author. `hasClaim` is BYTE-PRESENCE of a claim token and nothing more — the
 * relay is deliberately not credit-claim aware, so a row can never tell you a
 * claim verifies. The four verification states (claimed / unclaimed / invalid /
 * unverifiable) are a client fold over the fetched document bytes, which is what
 * components/credits.tsx does when it has them.
 */
export interface IndexCreditRow {
  contentId: string;
  did: string;
  /** the entry's open-vocabulary role, or null when the entry declared none. */
  role: string | null;
  position: number;
  hasClaim: boolean;
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

/**
 * Coerce an `/index/v0/content` page body into rows, dropping anything without a
 * `contentId` (a row that names no chain is not addressable). The shape is the
 * client seam's `IndexContentRow` exactly, so every surface that already renders
 * one renders these unchanged.
 *
 * `publicRead` coerces to FALSE on anything that is not literally `true` — a
 * missing or malformed flag reads as gated, which is the direction that can only
 * cost a title, never leak one. `docSchema` / `currentDocumentCID` / `title` keep
 * the index's honest null. Pure, unit-tested.
 */
export const toContentRows = (body: unknown): IndexContentRow[] => {
  const rows = (body as { content?: unknown } | null)?.content;
  if (!Array.isArray(rows)) return [];
  return rows.flatMap((row): IndexContentRow[] => {
    const r = row as Record<string, unknown>;
    const contentId = str(r['contentId']);
    if (!contentId) return [];
    return [
      {
        contentId,
        genesisCID: str(r['genesisCID']),
        headCID: str(r['headCID']),
        creatorDID: str(r['creatorDID']),
        isDeleted: r['isDeleted'] === true,
        opCount: typeof r['opCount'] === 'number' ? r['opCount'] : 0,
        genesisAt: str(r['genesisAt']),
        headAt: str(r['headAt']),
        currentDocumentCID:
          typeof r['currentDocumentCID'] === 'string' ? r['currentDocumentCID'] : null,
        publicRead: r['publicRead'] === true,
        docSchema: typeof r['docSchema'] === 'string' ? r['docSchema'] : null,
        title: typeof r['title'] === 'string' ? r['title'] : null,
      },
    ];
  });
};

/**
 * Coerce an `/index/v0/identities` page body into rows, dropping anything without
 * a `did` (a row that names no identity is not addressable). The shape is the
 * client seam's `IndexIdentityRow` exactly, so every surface that already renders
 * one renders these unchanged.
 *
 * `profile` keeps the index's honest nulls all the way down: a relay withholds
 * the projected `name` of a non-public profile by spec, and coercing that to a
 * string would manufacture one. Pure, unit-tested.
 */
export const toIdentityRows = (body: unknown): IndexIdentityRow[] => {
  const rows = (body as { identities?: unknown } | null)?.identities;
  if (!Array.isArray(rows)) return [];
  return rows.flatMap((row): IndexIdentityRow[] => {
    const r = row as Record<string, unknown>;
    const did = str(r['did']);
    if (!did) return [];
    const p = r['profile'] as Record<string, unknown> | null | undefined;
    return [
      {
        did,
        headCID: str(r['headCID']),
        opCount: typeof r['opCount'] === 'number' ? r['opCount'] : 0,
        genesisAt: str(r['genesisAt']),
        headAt: str(r['headAt']),
        isDeleted: r['isDeleted'] === true,
        profile:
          p && typeof p === 'object'
            ? {
                anchor: str(p['anchor']),
                publicRead: p['publicRead'] === true,
                docSchema: typeof p['docSchema'] === 'string' ? p['docSchema'] : null,
                name: typeof p['name'] === 'string' ? p['name'] : null,
              }
            : null,
      },
    ];
  });
};

/**
 * Coerce an `/index/v0/countersignatures` page body into rows.
 *
 * A row is addressable when it names BOTH operations — the countersignature
 * (`cid`) and what it countersigned (`targetCID`) — so an entry missing either
 * is dropped; it could neither be linked nor folded. `relation` keeps the honest
 * null (an unrelated countersignature is ordinary, not an error).
 *
 * `jwsToken` is COERCED to the empty string rather than dropping the row, which
 * is the one judgment call in here. The token is a convenience the relay may
 * include; the surface that renders these rows links the two CIDs and folds the
 * proof by OPENING the op, never from this field. So a relay that withheld the
 * token withheld a shortcut, not the evidence — and dropping the row would let
 * that stinginess erase a countersignature that demonstrably exists, which is
 * the omission this whole module exists to refuse. Pure, unit-tested.
 */
export const toCountersignatureRows = (body: unknown): IndexCountersignatureRow[] => {
  const rows = (body as { countersignatures?: unknown } | null)?.countersignatures;
  if (!Array.isArray(rows)) return [];
  return rows.flatMap((row): IndexCountersignatureRow[] => {
    const r = row as Record<string, unknown>;
    const cid = str(r['cid']);
    const targetCID = str(r['targetCID']);
    if (!cid || !targetCID) return [];
    return [
      {
        cid,
        targetCID,
        relation: typeof r['relation'] === 'string' ? r['relation'] : null,
        jwsToken: str(r['jwsToken']),
      },
    ];
  });
};

/**
 * Coerce an `/index/v0/credits` page body into rows. A row needs both a
 * `contentId` and a `did` to mean anything — it names a credit OF someone ON
 * something — so an entry missing either is dropped rather than rendered as a
 * half-credit. `role` keeps the honest null (an unroled credit is ordinary, not
 * an error); `position` defaults to 0 only when the relay sent no number, which
 * would already be a malformed row. Pure, unit-tested.
 */
export const toCreditRows = (body: unknown): IndexCreditRow[] => {
  const rows = (body as { credits?: unknown } | null)?.credits;
  if (!Array.isArray(rows)) return [];
  return rows.flatMap((row): IndexCreditRow[] => {
    const r = row as Record<string, unknown>;
    const contentId = str(r['contentId']);
    const did = str(r['did']);
    if (!contentId || !did) return [];
    return [
      {
        contentId,
        did,
        role: typeof r['role'] === 'string' ? r['role'] : null,
        position: typeof r['position'] === 'number' ? r['position'] : 0,
        hasClaim: r['hasClaim'] === true,
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

/** One page of the operations index, against a caller-chosen relay set. */
const operationsPage = async (
  params: Record<string, string | number | undefined>,
  relays: string[],
): Promise<{ items: IndexOperationRow[]; next: string | null }> => {
  const body = await fetchIndexPage<unknown>('operations', params, relays);
  return { items: toOperationRows(body), next: nextCursor(body) };
};

/**
 * One page of the operation recency feed, across every configured relay. Throws
 * when no relay serves the route.
 *
 * Carries no opaque filter, so any index relay may answer it: `order` and `kind`
 * are validated params a relay either honours or 400s, never ones it can silently
 * ignore into a wrong page. The key-scoped filter is a different function for
 * exactly that reason — see {@link fetchSignerKeyOperationsPage}.
 */
export const fetchOperationsPage = async (params: {
  order: IndexRecency;
  kind?: string;
  after?: string;
  limit?: number;
}): Promise<{ items: IndexOperationRow[]; next: string | null }> =>
  operationsPage(
    {
      order: params.order,
      ...(params.kind ? { kind: params.kind } : {}),
      ...(params.after ? { after: params.after } : {}),
      limit: params.limit ?? PAGE,
    },
    getRelays(),
  );

/**
 * One page of the operations index narrowed to ONE SIGNING KEY. Throws when no
 * relay in `relays` serves the route.
 *
 * `signerKey` is the proof-tier actor filter — an exact multibase match against
 * the public key each row's signature verified against at ingest (WEB-RELAY.md,
 * Operations). It is passed VERBATIM: the relay matches it as opaque bytes, so
 * normalizing it here would silently ask a different question than the one pasted.
 *
 * `relays` IS REQUIRED, and it is not the configured set. A relay predating this
 * filter ignores it and answers with the UNFILTERED feed, so this query may only
 * be sent to relays whose own body probe said they honour it
 * (`useIndexSignerKeyFilterRelays` in ./index-light). Reading `getRelays()` here
 * is precisely the bug the split exists to make unwriteable: the failover takes
 * the first 2xx from ANY relay it is handed, so an unvetted relay in this list
 * ends up presenting the whole operation log as this key's signings. An empty
 * list asks nothing and throws, which is the honest degrade.
 */
export const fetchSignerKeyOperationsPage = async (params: {
  signerKey: string;
  relays: string[];
  order: IndexRecency;
  after?: string;
  limit?: number;
}): Promise<{ items: IndexOperationRow[]; next: string | null }> =>
  operationsPage(
    {
      order: params.order,
      signerKey: params.signerKey,
      ...(params.after ? { after: params.after } : {}),
      limit: params.limit ?? PAGE,
    },
    params.relays,
  );

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
 * One page of the content index on the ACTOR axis — `creator=` or `signer=`.
 * Throws when every relay declines, which is the whole reason this route is
 * mirrored here: the client seam would resolve an empty page instead, and a
 * paging caller would read that as "the enumeration ended" and drop its cursor.
 *
 * No `publicRead` filter is offered, deliberately. The actor lanes list every
 * chain on their axis and the index already answers them honestly (a gated row
 * carries `publicRead: false` and no projected title); a caller that wants the
 * public-only corpus surfaces is served by the client seam's paged hooks.
 */
export const fetchContentPage = async (params: {
  creator?: string;
  signer?: string;
  order?: IndexOrder;
  after?: string;
  limit?: number;
}): Promise<{ items: IndexContentRow[]; next: string | null }> => {
  const body = await fetchIndexPage<unknown>(
    'content',
    {
      ...(params.creator ? { creator: params.creator } : {}),
      ...(params.signer ? { signer: params.signer } : {}),
      ...(params.order ? { order: params.order } : {}),
      ...(params.after ? { after: params.after } : {}),
      limit: params.limit ?? PAGE,
    },
    getRelays(),
  );
  return { items: toContentRows(body), next: nextCursor(body) };
};

/**
 * One page of the countersignatures-by-witness reverse lookup. Throws when every
 * relay declines — same reason as {@link fetchContentPage}: the client seam
 * resolves `{ countersignatures: [], next: null }` there, which a paging caller
 * reads as "the enumeration ended" while dropping a live cursor.
 *
 * No `order=` is offered. `witness=` predates index iteration 2, so this lane
 * must keep working on a relay that would 400 an ordering param — and the probe
 * that would tell us otherwise gates a different set of surfaces.
 */
export const fetchCountersignaturesPage = async (params: {
  witness: string;
  relation?: string;
  after?: string;
  limit?: number;
}): Promise<{ items: IndexCountersignatureRow[]; next: string | null }> => {
  const body = await fetchIndexPage<unknown>(
    'countersignatures',
    {
      witness: params.witness,
      ...(params.relation ? { relation: params.relation } : {}),
      ...(params.after ? { after: params.after } : {}),
      limit: params.limit ?? PAGE,
    },
    getRelays(),
  );
  return { items: toCountersignatureRows(body), next: nextCursor(body) };
};

/**
 * One page of the has-ever-declared key reverse lookup —
 * `/index/v0/identities?key=`. Throws when every relay declines, which matters
 * more here than anywhere else in this module: an empty page from this route is
 * read as "no identity ever declared this key", and an outage must never be able
 * to say that.
 *
 * The value is passed VERBATIM. The relay matches it byte-for-byte against the
 * multibase strings in accepted operations' key arrays, so normalizing it here
 * would silently ask a different question than the one pasted.
 *
 * `relays` IS REQUIRED, and it is not the configured set — same reason as
 * {@link fetchSignerKeyOperationsPage}. `key=` is an opaque match a relay
 * predating it IGNORES, so only relays whose own body probe cleared them
 * (`useIndexKeyFilterRelays` in ./index-light) may be asked; the failover would
 * otherwise take an unvetted relay's unfiltered identity page and this surface
 * would print every identity on it as a declarer of the key.
 */
export const fetchIdentitiesByKeyPage = async (params: {
  key: string;
  relays: string[];
  after?: string;
  limit?: number;
}): Promise<{ items: IndexIdentityRow[]; next: string | null }> => {
  const body = await fetchIndexPage<unknown>(
    'identities',
    {
      key: params.key,
      ...(params.after ? { after: params.after } : {}),
      limit: params.limit ?? PAGE,
    },
    params.relays,
  );
  return { items: toIdentityRows(body), next: nextCursor(body) };
};

/**
 * Page the identities that have ever declared one public key.
 *
 * `enabled` carries TWO gates, not one: a relay index must exist, and `relays`
 * must be non-empty — the subset whose own probe said they honour `key=`
 * (`useIndexKeyFilterRelays` in ./index-light). The set is also part of the
 * resetKey: a query bound to different relays is a different query, and a cursor
 * minted against the old one means nothing to it.
 *
 * No `order=` is offered. `key=` and the ordered enumeration are independent
 * filters, and this lane wants the route's plain lexical `did` cursor — the one
 * ordering every index-capable relay serves.
 */
export const useIndexIdentitiesByKey = (
  enabled: boolean,
  key: string,
  relays: string[],
  opts?: { cursor?: string; onCursor?: (cursor: string) => void },
): IndexPage<IndexIdentityRow> =>
  useIndexPageStack(
    enabled,
    `identities-by-key:${key}:${relays.join(',')}`,
    opts?.cursor ?? '',
    opts?.onCursor,
    (after) => fetchIdentitiesByKeyPage({ key, relays, ...(after ? { after } : {}) }),
  );

/** One page of the credit projection. Throws when no relay serves the route. */
export const fetchCreditsPage = async (params: {
  did?: string;
  contentId?: string;
  role?: string;
  after?: string;
  limit?: number;
}): Promise<{ items: IndexCreditRow[]; next: string | null }> => {
  const body = await fetchIndexPage<unknown>(
    'credits',
    {
      ...(params.did ? { did: params.did } : {}),
      ...(params.contentId ? { contentId: params.contentId } : {}),
      ...(params.role ? { role: params.role } : {}),
      ...(params.after ? { after: params.after } : {}),
      limit: params.limit ?? PAGE,
    },
    getRelays(),
  );
  return { items: toCreditRows(body), next: nextCursor(body) };
};

/**
 * Page the credit projection — `did=` for "which public works credit this
 * identity", `contentId=` for "who this public document says made it". Rows come
 * back in `(contentId, position)` order, and the cursor is opaque in every mode
 * because the natural key is composite; it is passed back verbatim.
 *
 * A single chain's set may be REPLACED wholesale between pages when its head is
 * revised, so an in-flight enumeration can miss a row that changed underneath it.
 * That is the route's stated contract, not a bug to paper over: the complete
 * answer for one chain is a fresh `contentId=` page, or the document itself.
 */
export const useIndexCredits = (
  enabled: boolean,
  opts: {
    did?: string;
    contentId?: string;
    role?: string;
    cursor?: string;
    onCursor?: (cursor: string) => void;
  },
): IndexPage<IndexCreditRow> =>
  useIndexPageStack(
    enabled,
    `credits:${opts.did ?? ''}:${opts.contentId ?? ''}:${opts.role ?? ''}`,
    opts.cursor ?? '',
    opts.onCursor,
    (after) =>
      fetchCreditsPage({
        ...(opts.did ? { did: opts.did } : {}),
        ...(opts.contentId ? { contentId: opts.contentId } : {}),
        ...(opts.role ? { role: opts.role } : {}),
        ...(after ? { after } : {}),
      }),
  );

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
