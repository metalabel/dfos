/*

  INDEX BROWSE — the primary enumeration path, straight off a relay's /index/v0

  When a relay advertises capabilities.index, the explorer ALWAYS enumerates
  browse and home from the relay's index projections — instantly, and even after
  a full deep sync. These rows are relay-asserted discovery hints — ATTRIBUTED,
  never authority — and the verify-queue promotes the visible ones to VERIFIED by
  folding their chains in the tab (the fold wins over the hint). The local index
  is the verified-overlay + offline cache + audit corpus, NOT the enumeration
  source: the live index is always fresher than a past sync.

  A relay WITHOUT the capability yields `false` here and every surface falls back
  to browsing the LOCAL index (which needs a full-log sync first) — byte-for-byte
  the pre-index behavior.

  Full-corpus deep sync stays as the AUDIT posture: it folds every operation
  locally and so can detect a relay index's omissions (a light client cannot). It
  no longer gates enumeration — it is an explicit "audit completeness" action.

  Enumeration is intrinsically incomplete under "completeness is outside the
  proof": these loaders page on demand (load-more), and any name search filters
  the LOADED rows only — the relay has no search, and this never pretends
  otherwise.

*/

import type { IndexContentRow, IndexIdentityRow, IndexOrder } from '@metalabel/dfos-client';
import { useEffect, useRef, useState } from 'preact/hooks';
import { getClient } from './client';
import { getRelays } from './relays';

/** Per-page size for the index loaders — one page is the initial browse, and
 *  "load more" pulls the next page on demand (no silent whole-corpus cap). */
const PAGE = 200;

/**
 * Whether any configured relay advertises the index capability. `null` while the
 * well-known is still being read (callers hold today's behavior until it settles),
 * then a stable boolean. When true, browse/home enumerate from /index/v0 always;
 * when false, they fall back to the local synced index. Recomputed on mount — a
 * relay switch re-navigates.
 */
export const useIndexCapable = (): boolean | null => {
  const [capable, setCapable] = useState<boolean | null>(null);
  useEffect(() => {
    let dead = false;
    void getClient()
      .capabilities()
      .then((c) => {
        if (!dead) setCapable(c.index);
      })
      .catch(() => {
        if (!dead) setCapable(false);
      });
    return () => {
      dead = true;
    };
  }, []);
  return capable;
};

// -----------------------------------------------------------------------------
// ITERATION-2 FEATURE DETECTION — does the SERVING relay honour the index
// `order=` param (and therefore also `signer=`, shipped in the same release)?
//
// A relay predating index iteration 2 silently IGNORES both: it returns LEXICAL
// rows under a recency label ("newest active"/"newest first") and an UNFILTERED
// content page under "contributed" (signer= ignored → every chain, minus the
// client-side creator-subtraction = fabricated "contributions"). Both are lies
// the explorer must not present. The spec REQUIRES a 400 for an unknown `order=`
// value, so ONE probe cleanly separates an iteration-2 relay (400) from an older
// one that ignores the param (200) — feature detection, never a version sniff.
//
// Gate ONLY the ordered/signer surfaces on this. `nameContains`, `creator`,
// `witness`, and `issuer` predate iteration 2 and MUST NOT be gated.
// -----------------------------------------------------------------------------

const PROBE_ORDER = '__dfos_iter2_probe__';
// Must EXCEED the dfos-client per-request timeout (10s default): the probe may
// never mark a relay indeterminate that the query failover would still wait
// for, or the gate and the queries can disagree on which relay answers — and a
// slow pre-iteration-2 first relay would serve ordered/signer requests the
// probe cleared against a faster later relay.
const PROBE_TIMEOUT_MS = 12_000;

/** Interpret one relay's probe response STATUS: 400 → it validates `order=` (an
 *  iteration-2 relay), 2xx → it ignores the param (pre-iteration-2), anything
 *  else (501 no index / 5xx / unreachable = 0) → indeterminate, defer to the next
 *  relay. Pure, unit-tested. */
export const iter2FromProbeStatus = (status: number): boolean | null =>
  status === 400 ? true : status >= 200 && status < 300 ? false : null;

/** Decide iteration-2 support from the ordered per-relay probe statuses: the
 *  first DEFINITIVE relay wins (mirrors query failover, which serves from the
 *  first reachable index relay); all-indeterminate → unsupported. The default is
 *  deliberately the SAFE one — degrade rather than risk presenting fabricated
 *  ordered/signer rows. Pure, unit-tested. */
export const decideIter2 = (statuses: number[]): boolean => {
  for (const status of statuses) {
    const verdict = iter2FromProbeStatus(status);
    if (verdict !== null) return verdict;
  }
  return false;
};

/** One relay's probe status — the `order=` value is deliberately invalid, so an
 *  iteration-2 relay answers 400 and an older one 200. Network/abort → 0. */
const probeRelayStatus = async (base: string): Promise<number> => {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), PROBE_TIMEOUT_MS);
  try {
    const url = new URL(`/index/v0/identities?order=${PROBE_ORDER}&limit=1`, base);
    return (await fetch(url.toString(), { signal: ctrl.signal })).status;
  } catch {
    return 0; // unreachable / aborted — indeterminate
  } finally {
    clearTimeout(timer);
  }
};

// probe once per relay set, shared across every mount for the session (a relay
// switch re-navigates, and the set key changes anyway, so this never goes stale)
const iter2Cache = new Map<string, Promise<boolean>>();

const probeIter2Support = (relays: string[]): Promise<boolean> => {
  const key = relays.join('|');
  let cached = iter2Cache.get(key);
  if (!cached) {
    cached = Promise.all(relays.map(probeRelayStatus)).then(decideIter2);
    iter2Cache.set(key, cached);
  }
  return cached;
};

/**
 * Whether the serving relay supports index iteration 2 (`order=` + `signer=`).
 * `null` while the probe is in flight — callers hold the DEGRADED (pre-iteration-2)
 * view until it settles, so an older relay never flashes ordered/signer rows the
 * gate would then have to retract — then a stable boolean. Same module-cached,
 * once-per-session idiom as {@link useIndexCapable}.
 */
export const useIndexIter2 = (): boolean | null => {
  const [supported, setSupported] = useState<boolean | null>(null);
  useEffect(() => {
    let dead = false;
    void probeIter2Support(getRelays())
      .then((v) => {
        if (!dead) setSupported(v);
      })
      .catch(() => {
        if (!dead) setSupported(false);
      });
    return () => {
      dead = true;
    };
  }, []);
  return supported;
};

export interface IndexLoad<T> {
  rows: T[];
  loading: boolean;
  /** the relay index has a next page — `loadMore` will pull it. */
  hasMore: boolean;
  /** pull the next page and append it (no-op while loading or exhausted). */
  loadMore: () => void;
  /** the INITIAL index load REJECTED (relay unreachable / index errored) — this
   *  is distinct from a successful but genuinely-empty page (rows [], error
   *  false). Consumers use it to fall back to the local corpus / show an honest
   *  error instead of a false "the index returned nothing". */
  error: boolean;
  /** re-run the initial load — a retry after an error, or a refresh from head. */
  retry: () => void;
}

/** What a browse surface should render given the index capability + whether the
 *  index load errored + whether a local synced corpus exists. Pure so it unit-
 *  tests without a DOM: `index` = live index rows; `index-unavailable` = index
 *  errored and no local fallback (honest error + retry); `index-fell-back` =
 *  index errored but a local corpus exists (show local, note the fallback);
 *  `local` = no index-capable relay (the pre-index path: checking / sync / local). */
export type IndexBrowseMode = 'index' | 'index-unavailable' | 'index-fell-back' | 'local';

export const indexBrowseMode = (
  indexed: boolean | null,
  indexError: boolean,
  localHasRows: boolean,
): IndexBrowseMode => {
  if (indexed === true && !indexError) return 'index';
  if (indexed === true && indexError) return localHasRows ? 'index-fell-back' : 'index-unavailable';
  return 'local';
};

/** The render state of an index-sourced list: rows win; else honest error over
 *  loading over empty — so an errored or settled-empty list never shows a
 *  permanent "loading…". Pure, unit-tested. */
export type IndexListState = 'rows' | 'error' | 'loading' | 'empty';

export const indexListState = (loading: boolean, error: boolean, count: number): IndexListState => {
  if (count > 0) return 'rows';
  if (error) return 'error';
  if (loading) return 'loading';
  return 'empty';
};

/**
 * Whether a credential surface should read from the live relay index or fall back to
 * the local fold. `capabilities.index` is a SINGLE flag — it does not imply the
 * `/index/v0/credentials` sub-route exists (a relay can advertise index yet predate
 * that route). So the index credential lane is authoritative only when the relay is
 * index-capable AND the route did not error; on error we degrade to the local scan
 * rather than render a false-empty panel. Pure so both views test it without a DOM.
 */
export const indexCredSource = (indexed: boolean | null, indexError: boolean): boolean =>
  indexed === true && !indexError;

/**
 * Generic cursor pager over an index projection. Loads the first page when
 * enabled, exposes `loadMore` to append the next page via the relay's `next`
 * cursor. `resetKey` bumps to reload from scratch (e.g. a filter toggle).
 *
 * A `run` id invalidates in-flight loads across a reset/unmount so a slow first
 * page can't clobber a fresh one; `busy` guards against overlapping fetches.
 */
const useIndexPager = <T>(
  enabled: boolean,
  resetKey: string,
  fetchPage: (after?: string) => Promise<{ items: T[]; next: string | null }>,
): IndexLoad<T> => {
  const [rows, setRows] = useState<T[]>([]);
  const [loading, setLoading] = useState(false);
  const [next, setNext] = useState<string | undefined>(undefined);
  const [hasMore, setHasMore] = useState(false);
  const [error, setError] = useState(false);
  const [reloadTick, setReloadTick] = useState(0);
  const runRef = useRef(0);
  const busyRef = useRef(false);
  // hold the latest fetch closure without making it an effect dependency
  const fetchRef = useRef(fetchPage);
  fetchRef.current = fetchPage;

  const loadPage = (after: string | undefined, run: number, reset: boolean): void => {
    if (busyRef.current) return;
    busyRef.current = true;
    setLoading(true);
    void fetchRef
      .current(after)
      .then((page) => {
        if (run !== runRef.current) return; // superseded by a reset/unmount
        setError(false); // reachable — a genuinely-empty page is NOT an error
        setRows((prev) => (reset ? page.items : [...prev, ...page.items]));
        setNext(page.next ?? undefined);
        setHasMore(!!page.next);
      })
      .catch(() => {
        if (run !== runRef.current) return;
        // only the INITIAL load flags error — a failed load-more leaves the rows
        // already shown intact (and its own button handles the retry affordance)
        if (reset) {
          setError(true);
          setRows([]);
          setNext(undefined);
          setHasMore(false);
        }
      })
      .finally(() => {
        busyRef.current = false;
        if (run === runRef.current) setLoading(false);
      });
  };

  useEffect(() => {
    if (!enabled) {
      setRows([]);
      setNext(undefined);
      setHasMore(false);
      setError(false);
      return;
    }
    const run = ++runRef.current;
    setRows([]);
    setNext(undefined);
    setHasMore(false);
    setError(false);
    loadPage(undefined, run, true);
    return () => {
      runRef.current += 1; // invalidate any in-flight load on dep change / unmount
    };
    // fetchPage is read via fetchRef so it is intentionally not a dependency
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, resetKey, reloadTick]);

  const loadMore = (): void => {
    if (!enabled || !hasMore || loading || busyRef.current) return;
    loadPage(next, runRef.current, false);
  };

  // retry re-runs the INITIAL load via the effect (a failed first page leaves
  // hasMore false, so loadMore can't recover it — reloadTick can).
  const retry = (): void => setReloadTick((t) => t + 1);

  return { rows, loading, hasMore, loadMore, error, retry };
};

/** Options common to the index list hooks — a server-side `nameContains` substring
 *  (identities only) and a time `order`. Both bump the pager's resetKey, so changing
 *  either re-pages from the relay and the loaded rows always reflect the live query. */
export interface IndexListOpts {
  nameContains?: string;
  order?: IndexOrder;
}

/** Page the identity index (optionally public-profile-only) with load-more. A
 *  `nameContains` substring is applied SERVER-SIDE (the relay filters over the
 *  projected profile name before paginating — amber/non-authoritative), and an
 *  `order` selects recently-arrived / recently-active enumeration. Both re-page
 *  from the relay when changed. */
export const useIndexIdentities = (
  enabled: boolean,
  publicOnly: boolean,
  opts?: IndexListOpts,
): IndexLoad<IndexIdentityRow> =>
  useIndexPager(
    enabled,
    `identities:${publicOnly}:${opts?.nameContains ?? ''}:${opts?.order ?? ''}`,
    (after) =>
      getClient()
        .indexIdentities({
          ...(publicOnly ? { hasPublicProfile: true } : {}),
          ...(opts?.nameContains ? { nameContains: opts.nameContains } : {}),
          ...(opts?.order ? { order: opts.order } : {}),
          ...(after ? { after } : {}),
          limit: PAGE,
        })
        .then((p) => ({ items: p.identities, next: p.next })),
  );

/** Page the content index (optionally public-read-only), optionally narrowed to a
 *  single `$schema` and/or a `creator` / `signer` DID server-side, in the lexical
 *  default or a time `order`. Every filter bumps the resetKey, so changing one
 *  re-pages from the relay and the loaded rows always reflect the live query. In
 *  ordered mode the relay's `next` is an opaque token, passed back verbatim. */
export const useIndexContent = (
  enabled: boolean,
  publicOnly: boolean,
  opts?: { docSchema?: string; creator?: string; signer?: string; order?: IndexOrder },
): IndexLoad<IndexContentRow> =>
  useIndexPager(
    enabled,
    `content:${publicOnly}:${opts?.docSchema ?? ''}:${opts?.creator ?? ''}:${opts?.signer ?? ''}:${opts?.order ?? ''}`,
    (after) =>
      getClient()
        .indexContent({
          ...(publicOnly ? { publicRead: true } : {}),
          ...(opts?.docSchema ? { docSchema: opts.docSchema } : {}),
          ...(opts?.creator ? { creator: opts.creator } : {}),
          ...(opts?.signer ? { signer: opts.signer } : {}),
          ...(opts?.order ? { order: opts.order } : {}),
          ...(after ? { after } : {}),
          limit: PAGE,
        })
        .then((p) => ({ items: p.content, next: p.next })),
  );
