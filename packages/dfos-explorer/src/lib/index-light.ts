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
  proof": these loaders serve ONE PAGE AT A TIME off the relay's keyset cursor.
  Name search is the relay's own `nameContains` filter, applied server-side
  before pagination — never a client-side pass over already-loaded rows.

*/

import type { IndexContentRow, IndexIdentityRow, IndexOrder } from '@metalabel/dfos-client';
import { useEffect, useRef, useState } from 'preact/hooks';
import { getClient } from './client';
import { getRelays } from './relays';

/** Per-page size for every index surface — small enough to read, paged with a
 *  real prev/next off the relay's `next` cursor (no whole-corpus scroll). */
export const PAGE = 25;

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

/** One relay's status for a probe path. Network/abort → 0 (indeterminate). */
const probeRelayStatus = async (base: string, path: string): Promise<number> => {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), PROBE_TIMEOUT_MS);
  try {
    return (await fetch(new URL(path, base).toString(), { signal: ctrl.signal })).status;
  } catch {
    return 0; // unreachable / aborted — indeterminate
  } finally {
    clearTimeout(timer);
  }
};

// probe once per (feature, relay set), shared across every mount for the session
// (a relay switch re-navigates, and the set key changes anyway, so this never
// goes stale)
const probeCache = new Map<string, Promise<boolean>>();

const probeSupport = (feature: string, path: string, relays: string[]): Promise<boolean> => {
  const key = `${feature}|${relays.join('|')}`;
  let cached = probeCache.get(key);
  if (!cached) {
    cached = Promise.all(relays.map((base) => probeRelayStatus(base, path))).then(decideIter2);
    probeCache.set(key, cached);
  }
  return cached;
};

/** The shared "probe once, hold the degraded view until it settles" hook behind
 *  both feature gates below. `null` while in flight; a rejection reads as
 *  unsupported, which is always the safe direction. */
const useProbe = (feature: string, path: string): boolean | null => {
  const [supported, setSupported] = useState<boolean | null>(null);
  useEffect(() => {
    let dead = false;
    void probeSupport(feature, path, getRelays())
      .then((v) => {
        if (!dead) setSupported(v);
      })
      .catch(() => {
        if (!dead) setSupported(false);
      });
    return () => {
      dead = true;
    };
  }, [feature, path]);
  return supported;
};

/**
 * Whether the serving relay supports index iteration 2 (`order=` + `signer=`).
 * `null` while the probe is in flight — callers hold the DEGRADED (pre-iteration-2)
 * view until it settles, so an older relay never flashes ordered/signer rows the
 * gate would then have to retract — then a stable boolean. Same module-cached,
 * once-per-session idiom as {@link useIndexCapable}.
 */
export const useIndexIter2 = (): boolean | null =>
  useProbe('iter2', `/index/v0/identities?order=${PROBE_ORDER}&limit=1`);

// -----------------------------------------------------------------------------
// TITLE-SEARCH FEATURE DETECTION — does the SERVING relay honour `titleContains=`?
//
// Same failure shape as `order=`, and worse in consequence: a relay predating the
// filter IGNORES it and returns an UNFILTERED page of content chains, which a
// search surface would then present as "chains whose title matches". Every row of
// that page is a fabricated hit.
//
// The spec gives a clean separator. `titleContains` is implicitly public-only, so
// combining it with `publicRead=false` is a REQUIRED 400 ("invalid filter
// combination") on a relay that implements it — while a relay that ignores the
// param sees a plain `publicRead=false` query and answers 200. One probe, same
// 400-validates / 200-ignores verdict the `order=` probe reads, so it shares the
// pure deciders above.
// -----------------------------------------------------------------------------

/**
 * Whether the serving relay honours `titleContains=` on the content index.
 * `null` while the probe is in flight — a search surface says "checking" rather
 * than running a query whose results it could not stand behind.
 */
export const useIndexTitleSearch = (): boolean | null =>
  useProbe('titleContains', '/index/v0/content?titleContains=__dfos_probe__&publicRead=false');

export interface IndexPage<T> {
  /** the rows of the CURRENT page only — paging replaces them, never appends. */
  rows: T[];
  loading: boolean;
  /** the index load REJECTED (relay unreachable / index errored) — this is
   *  distinct from a successful but genuinely-empty page (rows [], error false).
   *  Consumers use it to fall back to the local corpus / show an honest error
   *  instead of a false "the index returned nothing". */
  error: boolean;
  /** the cursor that produced this page ('' = the first page) — the deep-link key. */
  cursor: string;
  /** the relay issued a `next` — a further page exists. */
  hasNext: boolean;
  /** this page was reached by paging forward, so `prev` can pop back to it. A
   *  DEEP-LINKED page has no history to pop: it reports false here and true on
   *  `offFirst`, which is the honest difference (we know we're not at the start,
   *  we just don't know the cursor of the page before this one). */
  hasPrev: boolean;
  /** not the first page — `first` re-enters the enumeration from the top. */
  offFirst: boolean;
  next: () => void;
  prev: () => void;
  first: () => void;
  /** re-run the current page — a retry after an error. */
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
 * Generic KEYSET PAGER over an index projection: one page at a time, forward via
 * the relay's opaque `next` cursor and backward via a stack of the cursors already
 * visited (a keyset index serves no "page N-1" — the only honest back is the one
 * you walked in on). `resetKey` bumps to re-enter the enumeration from the top
 * (e.g. a filter toggle).
 *
 * `cursor` is the position as the URL states it, and the URL WINS. It seeds the
 * stack on mount (restoring a deep link) and is also watched: a change this pager
 * did not itself write — the header link back to a bare `#/documents`, a hand-edited
 * hash, a same-route link while the component stays mounted — re-enters at that
 * position, so the page shown can never disagree with the address bar. An
 * externally supplied position carries no walk history, so it resets the stack.
 *
 * A `run` id invalidates in-flight loads across a page change/unmount so a slow
 * page can't clobber a fresher one; `busy` guards against overlapping fetches.
 */
export const useIndexPageStack = <T>(
  enabled: boolean,
  resetKey: string,
  cursorParam: string,
  onCursor: ((cursor: string) => void) | undefined,
  fetchPage: (after?: string) => Promise<{ items: T[]; next: string | null }>,
): IndexPage<T> => {
  // the cursors walked to reach here; the last is the CURRENT page ('' = first)
  const [stack, setStack] = useState<string[]>(() => [cursorParam]);
  const [rows, setRows] = useState<T[]>([]);
  const [loading, setLoading] = useState(false);
  const [next, setNext] = useState<string>('');
  const [error, setError] = useState(false);
  const [reloadTick, setReloadTick] = useState(0);
  const runRef = useRef(0);
  const busyRef = useRef(false);
  const resetKeyRef = useRef(resetKey);
  // the last cursor THIS pager put in the URL — so its own write echoing back
  // through the hash is not mistaken for someone else moving the position
  const writtenRef = useRef(cursorParam);
  // hold the latest fetch closure without making it an effect dependency
  const fetchRef = useRef(fetchPage);
  fetchRef.current = fetchPage;
  const onCursorRef = useRef(onCursor);
  onCursorRef.current = onCursor;

  const cursor = stack[stack.length - 1] ?? '';

  /** Move to a new position and tell the URL about it. */
  const setPosition = (nextStack: string[]): void => {
    const at = nextStack[nextStack.length - 1] ?? '';
    writtenRef.current = at;
    setStack(nextStack);
    onCursorRef.current?.(at);
  };

  // a filter change re-enters the enumeration from the top — a cursor minted
  // against the old query means nothing to the new one. Guarded on an actual
  // CHANGE so a deep-linked first mount keeps its restored cursor.
  useEffect(() => {
    if (resetKeyRef.current === resetKey) return;
    resetKeyRef.current = resetKey;
    setPosition(['']);
    // setPosition is stable enough for this guarded one-shot
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resetKey]);

  // the URL moved and it wasn't us — adopt it. Without this the address bar and
  // the rendered page silently disagree (clearing `?after=` via the header link
  // leaves the old deep page on screen under a first-page URL).
  useEffect(() => {
    if (cursorParam === writtenRef.current) return;
    writtenRef.current = cursorParam;
    setStack([cursorParam]); // no walk history for a position we didn't walk to
  }, [cursorParam]);

  useEffect(() => {
    if (!enabled) {
      setRows([]);
      setNext('');
      setError(false);
      return;
    }
    const run = ++runRef.current;
    setLoading(true);
    busyRef.current = true;
    void fetchRef
      .current(cursor || undefined)
      .then((page) => {
        if (run !== runRef.current) return; // superseded by a page change/unmount
        setError(false); // reachable — a genuinely-empty page is NOT an error
        setRows(page.items);
        setNext(page.next ?? '');
      })
      .catch(() => {
        if (run !== runRef.current) return;
        setError(true);
        setRows([]);
        setNext('');
      })
      .finally(() => {
        busyRef.current = false;
        if (run === runRef.current) setLoading(false);
      });
    return () => {
      runRef.current += 1; // invalidate any in-flight load on dep change / unmount
    };
    // fetchPage is read via fetchRef so it is intentionally not a dependency
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, resetKey, cursor, reloadTick]);

  const go = (nextStack: string[]): void => {
    if (loading || busyRef.current) return;
    setPosition(nextStack);
  };

  return {
    rows,
    loading,
    error,
    cursor,
    hasNext: !!next,
    hasPrev: stack.length > 1,
    offFirst: cursor !== '',
    next: () => {
      if (next) go([...stack, next]);
    },
    prev: () => {
      if (stack.length > 1) go(stack.slice(0, -1));
    },
    first: () => {
      if (cursor !== '') go(['']);
    },
    retry: () => setReloadTick((t) => t + 1),
  };
};

/** Options common to the index list hooks — a server-side `nameContains` substring
 *  (identities only) and a time `order`. Both bump the pager's resetKey, so changing
 *  either re-enters the enumeration and the shown page always reflects the live query. */
export interface IndexListOpts {
  nameContains?: string;
  order?: IndexOrder;
}

/** Page the identity index (optionally public-profile-only). A `nameContains`
 *  substring is applied SERVER-SIDE (the relay filters over the projected profile
 *  name before paginating — amber/non-authoritative), and an `order` selects
 *  recently-arrived / recently-active enumeration. Both re-enter the enumeration
 *  when changed. `cursor`/`onCursor` carry the deep-linked page position. */
export const useIndexIdentities = (
  enabled: boolean,
  publicOnly: boolean,
  opts?: IndexListOpts & { cursor?: string; onCursor?: (cursor: string) => void },
): IndexPage<IndexIdentityRow> =>
  useIndexPageStack(
    enabled,
    `identities:${publicOnly}:${opts?.nameContains ?? ''}:${opts?.order ?? ''}`,
    opts?.cursor ?? '',
    opts?.onCursor,
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
 *  single `$schema` and/or a `creator` / `signer` DID server-side, or to a
 *  `titleContains` substring over projected titles, in the lexical default or a
 *  time `order`. Every filter bumps the resetKey, so changing one re-enters the
 *  enumeration and the shown page always reflects the live query. In ordered mode
 *  the relay's `next` is an opaque token, passed back verbatim.
 *
 *  `titleContains` is public-only by construction (the relay restricts the query
 *  to `publicRead=true` rows and 400s an explicit `publicRead=false`), and it must
 *  only be passed to a relay that honours it — see {@link useIndexTitleSearch}. */
export const useIndexContent = (
  enabled: boolean,
  publicOnly: boolean,
  opts?: {
    docSchema?: string;
    creator?: string;
    signer?: string;
    titleContains?: string;
    order?: IndexOrder;
    cursor?: string;
    onCursor?: (cursor: string) => void;
  },
): IndexPage<IndexContentRow> =>
  useIndexPageStack(
    enabled,
    `content:${publicOnly}:${opts?.docSchema ?? ''}:${opts?.creator ?? ''}:${opts?.signer ?? ''}:${opts?.titleContains ?? ''}:${opts?.order ?? ''}`,
    opts?.cursor ?? '',
    opts?.onCursor,
    (after) =>
      getClient()
        .indexContent({
          ...(publicOnly ? { publicRead: true } : {}),
          ...(opts?.docSchema ? { docSchema: opts.docSchema } : {}),
          ...(opts?.creator ? { creator: opts.creator } : {}),
          ...(opts?.signer ? { signer: opts.signer } : {}),
          ...(opts?.titleContains ? { titleContains: opts.titleContains } : {}),
          ...(opts?.order ? { order: opts.order } : {}),
          ...(after ? { after } : {}),
          limit: PAGE,
        })
        .then((p) => ({ items: p.content, next: p.next })),
  );
