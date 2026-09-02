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
import { PAGE_ROWS } from './paging';
import { getRelays } from './relays';

/** Per-page size for every index surface — small enough to read, paged with a
 *  real prev/next off the relay's `next` cursor (no whole-corpus scroll). Held
 *  equal to lib/paging.ts's `PAGE_ROWS` so a keyset-paged table and a
 *  client-paged one are the same height. */
export const PAGE = PAGE_ROWS;

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
const probeCache = new Map<string, Promise<unknown>>();

/** Memoize one feature's verdict for one relay set. The verdict shape is the
 *  feature's own — a boolean for the status-probed gates, the SUPPORTED RELAY
 *  SUBSET for the body-probed ones — so this is generic over it; the feature name
 *  and the relay set together key the cache, and a feature always answers in one
 *  shape. */
const probeOnce = <T>(feature: string, relays: string[], run: () => Promise<T>): Promise<T> => {
  const key = `${feature}|${relays.join('|')}`;
  let cached = probeCache.get(key) as Promise<T> | undefined;
  if (!cached) {
    cached = run();
    probeCache.set(key, cached);
  }
  return cached;
};

/** The STATUS-shaped probe: ask every relay in parallel, read the verdict off the
 *  ordered statuses (400 validates / 2xx ignores). */
const probeSupport = (path: string, relays: string[]): Promise<boolean> =>
  Promise.all(relays.map((base) => probeRelayStatus(base, path))).then(decideIter2);

/** The shared "probe once, hold the degraded view until it settles" hook behind
 *  every feature gate below. `null` while in flight; a rejection reads as
 *  unsupported, which is always the safe direction. `run` is read through a ref so
 *  a caller may pass a fresh closure — the FEATURE keys the cache, not the
 *  closure's identity. */
const useProbe = (feature: string, run: (relays: string[]) => Promise<boolean>): boolean | null => {
  const [supported, setSupported] = useState<boolean | null>(null);
  const runRef = useRef(run);
  runRef.current = run;
  useEffect(() => {
    let dead = false;
    const relays = getRelays();
    void probeOnce(feature, relays, () => runRef.current(relays))
      .then((v) => {
        if (!dead) setSupported(v);
      })
      .catch(() => {
        if (!dead) setSupported(false);
      });
    return () => {
      dead = true;
    };
    // `run` is read via runRef so it is intentionally not a dependency
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [feature]);
  return supported;
};

/**
 * {@link useProbe} for a feature whose verdict is a RELAY SUBSET rather than one
 * boolean — the two opaque key filters, whose queries must be bound to the
 * relays that actually passed the probe (see the body-probe section below).
 * `null` while in flight; a rejection reads as the EMPTY set, which is the same
 * safe direction a `false` is for the boolean gates: nothing is asked at all.
 */
const useRelayProbe = (
  feature: string,
  run: (relays: string[]) => Promise<string[]>,
): string[] | null => {
  const [supported, setSupported] = useState<string[] | null>(null);
  const runRef = useRef(run);
  runRef.current = run;
  useEffect(() => {
    let dead = false;
    const relays = getRelays();
    void probeOnce(feature, relays, () => runRef.current(relays))
      .then((v) => {
        if (!dead) setSupported(v);
      })
      .catch(() => {
        if (!dead) setSupported([]);
      });
    return () => {
      dead = true;
    };
    // `run` is read via runRef so it is intentionally not a dependency
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [feature]);
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
  useProbe('iter2', (relays) =>
    probeSupport(`/index/v0/identities?order=${PROBE_ORDER}&limit=1`, relays),
  );

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
  useProbe('titleContains', (relays) =>
    probeSupport('/index/v0/content?titleContains=__dfos_probe__&publicRead=false', relays),
  );

// -----------------------------------------------------------------------------
// BODY-PROBED FILTER DETECTION — the two OPAQUE key filters: `key=` on the
// identity index (has-ever-proved) and `signerKey=` on the operations index
// (what this key signed).
//
// Same failure shape as `order=` and `titleContains=`, and these two are the
// worst of the family: a relay predating either filter IGNORES the param and
// answers with an UNFILTERED page — every identity on the relay presented as one
// that proved this key, or every operation on the relay presented as one this
// key signed. Both are fabricated claims about key custody, on the surface where
// that claim matters most.
//
// The 400-based separator the other two probes use is UNAVAILABLE here, and
// deliberately so: WEB-RELAY.md specifies both as OPAQUE matches — a string no
// operation ever declared simply matches nothing, "no format validation and no
// 400". There is no invalid value to provoke a rejection with. So these probes
// read the BODY instead of the status: query a sentinel nothing can match, and
//
//   rows came back  → the relay ignored the param        → UNSUPPORTED
//   zero rows       → the relay applied it (or is empty)  → supported
//   non-2xx         → indeterminate, defer to the next relay
//
// The empty-corpus case reads as "supported" and is harmless: a relay holding
// nothing answers a real query with nothing either way, so the page states a true
// absence rather than inventing rows.
//
// THE VERDICT IS PER-RELAY, AND THE QUERY IS BOUND TO IT. This is the whole
// difference between these two gates and the status-probed ones above. A single
// collapsed boolean ("some relay supports it") is not a safe gate here, because
// the query paths fail over relay by relay and serve the FIRST 2xx from ANY
// configured relay: probe A as supported, have A be down at query time, and the
// query lands on old relay B, which ignores the param and answers with the
// unfiltered page — the exact fabrication above, reached through a gate that said
// yes. So the probe keeps each relay's own verdict, and the filtered queries run
// ONLY against relays whose OWN probe was definitive-supported. An INDETERMINATE
// relay is excluded rather than trusted: it made no claim, and asking it is the
// one thing we cannot take back. An empty supported set means the filter is
// unsupported here and the lane says so — never a query against an unvetted relay.
// -----------------------------------------------------------------------------

/**
 * The probe value, shared by BOTH key filters: a syntactically REAL multikey —
 * `z` + base58btc of `[0xed, 0x01] ++
 * sha256('dfos-explorer:index-key-filter-probe:v1')` — so a relay sees a
 * well-formed key rather than something it might one day reject, and one whose 32
 * bytes are a published hash rather than a generated public key.
 *
 * That construction answers both questions at once. Having no private half
 * anyone could hold, no chain can ever have PROVED it and nothing can ever have
 * signed with it — so it matches nothing on `key=` and nothing on `signerKey=`.
 * The unclaimability is the whole point: a chain could DECLARE this key, and
 * under has-ever-proved that would still index nothing.
 * One sentinel, because it is the same unclaimable value in both places.
 */
export const KEY_PROBE_MULTIBASE = 'z6MkoR9B2ETntZELcPzFTTMnbfhz3pHumPyJi5oEzQvC2WbE';

/** Interpret one relay's body-shaped filter probe: rows back means the param was
 *  IGNORED (the relay predates it), a served empty page means it was applied, and
 *  a non-2xx / a throw (`status` 0) is indeterminate — defer to the next relay.
 *  `rows` is only meaningful on a 2xx. Pure, unit-tested. */
export const bodyFilterFromProbe = (status: number, rows: number): boolean | null =>
  status >= 200 && status < 300 ? rows === 0 : null;

/** One relay's body-probe outcome for a filter param, carrying WHICH relay it was
 *  about — the binding the queries need. */
export interface BodyFilterProbe {
  relay: string;
  status: number;
  rows: number;
}

/** The relays a filtered query may honestly be sent to: those whose OWN probe was
 *  definitive-SUPPORTED. An indeterminate relay (unreachable, 5xx, no such route)
 *  is excluded, not deferred to — it made no claim, and the query fails over to
 *  whatever answers, so a relay we could not vet must never be in the set. Order
 *  is preserved so failover still walks the configured preference. Pure,
 *  unit-tested. */
export const supportedBodyFilterRelays = (probes: readonly BodyFilterProbe[]): string[] =>
  probes.filter((p) => bodyFilterFromProbe(p.status, p.rows) === true).map((p) => p.relay);

/** The UI gate derived from a supported-relay set: `null` while the probe is in
 *  flight, else whether any relay can be asked at all. Pure, unit-tested. */
export const bodyFilterSupported = (relays: string[] | null): boolean | null =>
  relays === null ? null : relays.length > 0;

/** One relay's body-probe outcome for a filter param. A network throw / abort
 *  reports status 0 (indeterminate), as does a body that isn't a readable page of
 *  `rowsKey` — a 2xx we cannot parse is no verdict about the filter. */
const probeRelayBodyFilter = async (
  relay: string,
  path: string,
  rowsKey: string,
): Promise<BodyFilterProbe> => {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), PROBE_TIMEOUT_MS);
  try {
    const res = await fetch(new URL(path, relay).toString(), { signal: ctrl.signal });
    if (!res.ok) return { relay, status: res.status, rows: 0 };
    const body = (await res.json()) as Record<string, unknown>;
    const rows = body[rowsKey];
    if (!Array.isArray(rows)) return { relay, status: 0, rows: 0 };
    return { relay, status: res.status, rows: rows.length };
  } catch {
    return { relay, status: 0, rows: 0 }; // unreachable / aborted / unparseable
  } finally {
    clearTimeout(timer);
  }
};

/** The BODY-shaped probe: ask every relay in parallel, keep each relay's own
 *  verdict, and return the subset that passed. */
const probeBodyFilterRelays = (
  path: string,
  rowsKey: string,
  relays: string[],
): Promise<string[]> =>
  Promise.all(relays.map((relay) => probeRelayBodyFilter(relay, path, rowsKey))).then(
    supportedBodyFilterRelays,
  );

/**
 * The relays that honour `key=` on the identity index — the ONLY relays the
 * has-ever-proved lookup may be sent to. `null` while the probe is in flight
 * (the key page says it is checking rather than running a query whose rows it
 * could not stand behind), then a stable set; `[]` is "no relay here answers this
 * question". Same module-cached, once-per-session idiom as the gates above.
 */
export const useIndexKeyFilterRelays = (): string[] | null =>
  useRelayProbe('key', (relays) =>
    probeBodyFilterRelays(
      `/index/v0/identities?key=${encodeURIComponent(KEY_PROBE_MULTIBASE)}&limit=1`,
      'identities',
      relays,
    ),
  );

/**
 * The relays that honour `signerKey=` on the operations index — the proof-tier
 * "what has this key signed" filter. `null` while the probe is in flight, then a
 * stable set.
 *
 * A relay that does not serve `/index/v0/operations` at all answers 404/501,
 * which is indeterminate here and simply leaves it out of the set — the same safe
 * direction, reached without a second probe.
 */
export const useIndexSignerKeyFilterRelays = (): string[] | null =>
  useRelayProbe('signerKey', (relays) =>
    probeBodyFilterRelays(
      `/index/v0/operations?signerKey=${encodeURIComponent(KEY_PROBE_MULTIBASE)}&limit=1`,
      'operations',
      relays,
    ),
  );

// -----------------------------------------------------------------------------
// CORPUS PROBE — does the serving relay hold any NON-PUBLIC content at all?
//
// Not feature detection. The three probes above ask what a relay can DO; this one
// asks what it HOLDS, and it exists for a different reason: a control that cannot
// change what is on screen must not be on screen. A relay whose whole corpus is
// public answers `publicRead=false` and `no filter` with the same rows, so a
// "public only" toggle over that corpus is a promise the page cannot keep — flip
// it, watch nothing move, and the honest thing the explorer says everywhere else
// about gated chains reads as decoration.
//
// This is the shape `browseDocuments` already uses on the local path, where the
// "show N gated" control renders only when `gatedCount > 0`. The relay's own
// answer decides whether the affordance exists, so ONE static bundle stays honest
// against a public-only relay and against a relay full of dark rows.
//
//   rows came back  → non-public rows exist here → the toggle can do something
//   zero rows       → nothing for it to reveal    → don't offer it
//   non-2xx         → indeterminate               → defer to the next relay
//
// A relay predating the `publicRead` filter IGNORES it and answers with its whole
// corpus, which reads here as "rows exist" — the toggle renders and behaves
// exactly as it does today. That is the right direction for this gate: an unknown
// relay keeps the control rather than having it silently withdrawn.
// -----------------------------------------------------------------------------

/** Interpret one relay's non-public-content probe: rows back means the relay
 *  holds content it does not serve publicly (or ignored the filter, same
 *  direction), zero rows means it holds none, and a non-2xx / throw (`status` 0)
 *  is no verdict at all. Pure, unit-tested. */
export const gatedContentFromProbe = (status: number, rows: number): boolean | null =>
  status >= 200 && status < 300 ? rows > 0 : null;

/** Whether a public-only control is worth rendering against the configured relay
 *  set. ANY relay definitively reporting non-public rows decides it — the feeds
 *  fail over across the whole set, so a row on any of them can reach the screen.
 *  Failing that, a definitive empty from any relay hides the control, and an
 *  ALL-INDETERMINATE set keeps it: we never looked, so nothing is withdrawn on
 *  the strength of not having looked. Pure, unit-tested. */
export const decideGatedContentPresent = (probes: readonly BodyFilterProbe[]): boolean => {
  let answered = false;
  for (const probe of probes) {
    const verdict = gatedContentFromProbe(probe.status, probe.rows);
    if (verdict === true) return true;
    if (verdict === false) answered = true;
  }
  return !answered;
};

/**
 * Whether any configured relay holds content it does not serve publicly — the
 * gate on the posts feed's "public only" control. `null` while the probe is in
 * flight (the control is withheld rather than flashed and retracted), then a
 * stable boolean. Same module-cached, once-per-session idiom as the gates above.
 *
 * This says nothing about whether such rows would be READABLE. A non-public row
 * enumerated here still renders with no title (the display-name circuit breaker
 * nulls it), which is the whole point of showing it: existence without content.
 */
export const useIndexGatedContent = (): boolean | null =>
  useProbe('gatedContent', (relays) =>
    Promise.all(
      relays.map((relay) =>
        probeRelayBodyFilter(relay, '/index/v0/content?publicRead=false&limit=1', 'content'),
      ),
    ).then(decideGatedContentPresent),
  );

export interface IndexPage<T> {
  /** the rows of the CURRENT page only — paging replaces them, never appends. */
  rows: T[];
  loading: boolean;
  /** the index load REJECTED (relay unreachable / index errored) — this is
   *  distinct from a successful but genuinely-empty page (rows [], error false).
   *  Consumers use it to fall back to the local corpus / show an honest error
   *  instead of a false "the index returned nothing". */
  error: boolean;
  /** the load failed DURABLY — every configured relay answered 404/501 for this
   *  route, so a retry cannot help and a caller may prefer another source for the
   *  session. A TRANSIENT failure (unreachable, 5xx, a rejected cursor) reports
   *  `error` without this and stays retryable in place. See ROUTE_ABSENT. */
  routeAbsent: boolean;
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
 * {@link indexListState} with the CAPABILITY PROBE folded in. A list is only
 * enabled once `capabilities.index` has settled, and a disabled pager holds
 * `loading: false` — so a surface that reads the raw state while `indexed` is
 * still null settles on `empty` and announces "the relay returned no rows"
 * before a single request has gone out. While the probe is in flight nothing has
 * been asked, and the honest render is LOADING. Pure, unit-tested.
 */
export const indexListStateFor = (
  indexed: boolean | null,
  loading: boolean,
  error: boolean,
  count: number,
): IndexListState => indexListState(loading || indexed === null, error, count);

// -----------------------------------------------------------------------------
// FAILURE DURABILITY — "the route isn't there" vs "that didn't work just now"
//
// An index sub-route newer than the `capabilities.index` flag can fail two ways,
// and treating them alike is a real bug in both directions. Every relay
// answering 404/501 is DURABLE: the route is not served, retrying changes
// nothing, and a caller may prefer another source for the rest of the session. A
// network throw, a 5xx, a timeout, or a 400 from a rejected cursor is TRANSIENT
// and says nothing about whether the route exists — latching on one of those
// would let a single bad page (or a hand-edited cursor) hide a working feed.
// -----------------------------------------------------------------------------

/** `cause` marker on a rejection meaning every relay answered "no such route". */
export const ROUTE_ABSENT = 'dfos:index-route-absent';

/** Whether a rejection carried the durable route-absent verdict. */
export const isRouteAbsent = (error: unknown): boolean =>
  error instanceof Error && error.cause === ROUTE_ABSENT;

/**
 * Whether per-relay outcomes amount to the durable verdict: EVERY relay answered
 * 404 or 501. A 0 (network throw / abort), a 5xx, or a 400 anywhere in the set
 * makes the whole failure transient — one relay being unreachable is not evidence
 * about what the others serve. An empty set is no verdict: nothing was asked.
 * Pure, unit-tested.
 */
export const routeAbsentFromStatuses = (statuses: number[]): boolean =>
  statuses.length > 0 && statuses.every((status) => status === 404 || status === 501);

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
  const [routeAbsent, setRouteAbsent] = useState(false);
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
      setRouteAbsent(false);
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
        setRouteAbsent(false);
        setRows(page.items);
        setNext(page.next ?? '');
      })
      .catch((e: unknown) => {
        if (run !== runRef.current) return;
        setError(true);
        // only the every-relay-404/501 verdict is durable; everything else stays
        // retryable in place rather than condemning the route (see ROUTE_ABSENT)
        setRouteAbsent(isRouteAbsent(e));
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
    routeAbsent,
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
