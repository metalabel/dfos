/*

  CONTENT → VERIFIED LABEL — the app-wide row rendering for every contentId

  A contentId is a hash. Wherever one appears outside an already-labelled index
  row, this module resolves its current document and derives the same title or
  snippet every other surface uses (lib/doc-label.ts). It is the content sibling
  of did-profiles.ts: a module-level cache + bounded worker pump, a persisted TTL
  cache for positives, and an index point lookup standing in while proof lands.

  THE DISPLAY HAS THREE BEATS. A chip begins as the short contentId, promotes to
  the relay index's projected public title in the ATTRIBUTED amber tier when that
  one-round-trip hint arrives, then promotes again to a VERIFIED label derived
  from the anonymously fetched document bytes. `projectedTitle` owns the public-
  read honesty rule, so a title the relay does not mark public never reaches the
  screen even as a temporary projection.

  EVERY SURFACE THAT NAMES A CONTENT CHAIN RUNS THOSE THREE BEATS — the chip, and
  equally the index-row tables (browse, search, the post feed, the actor ledger,
  credited-on) through `useIndexRowLabel`, which reads the amber beat straight off
  the row it already holds instead of spending a point lookup on it. There is no
  fourth kind of label and no surface that stops at beat two.

  THE INTEGRITY GATE IS ABSOLUTE: `client.document(contentId)` folds the content
  chain, anonymously fetches its current document, and re-hashes those bytes to
  the documentCID the chain commits to. A label renders verified only when that
  re-hash succeeds. Gated, absent, mismatched, non-JSON, or unreachable bytes
  yield NOTHING and the contentId renders bare; a relay cannot write a label by
  serving different bytes under a committed chain.

  Label PRECEDENCE lives only in doc-label.ts. This module supplies its verified
  document and discards the `id` fallback so the chip owns bare-id rendering.

  Caching: verified labels persist to localStorage with a 1h TTL (documents can
  change as their chains advance), bounded so a wide corpus cannot grow the key.
  NEGATIVE verdicts stay in memory for the session only — persisting "no label"
  across a transient relay failure would silently blank a real title or snippet.

*/

import { useEffect, useState } from 'preact/hooks';
import { getClient } from './client';
import { cacheIsFresh, trimCache } from './did-profiles';
import { deriveDocLabel, type DocLabel } from './doc-label';
import { projectedTitle, useIndexContentRow } from './index-point';
import { subscribeRelays } from './relays';

/** How long a resolved label is trusted before the chain is re-resolved. */
export const LABEL_TTL_MS = 60 * 60 * 1000;

/** Cap on persisted labels — a wide browse must not grow the key unbounded. */
const CACHE_MAX = 400;

/** In-flight resolves at once — the same politeness budget did-profiles and
 *  index-point give their row hydrators. */
const CONCURRENCY = 4;

const LS_KEY = 'dfos.explorer.contentLabels';

/** One persisted positive: text, quoted flag, label kind, and resolve time. */
interface CachedLabel {
  t: string;
  q: boolean;
  k: 'title' | 'snippet';
  at: number;
}

// -----------------------------------------------------------------------------
// pure part (unit-tested)
// -----------------------------------------------------------------------------

/**
 * The verified label verdict for one resolved document. `integrity` is the
 * client's bytes→committed-documentCID re-hash: false means the relay served
 * something OTHER than what the chain commits to, which is never a label.
 * An integral document with no derivable text is `null` — the chip renders its
 * bare contentId and the in-memory verdict prevents repeated session fetches.
 */
export const verifiedContentLabel = (
  contentId: string,
  decoded: unknown,
  integrity: boolean,
): DocLabel | null => {
  if (!integrity || typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) {
    return null;
  }
  const label = deriveDocLabel({
    contentId,
    doc: decoded as Record<string, unknown>,
  });
  return label.kind === 'id' ? null : label;
};

// -----------------------------------------------------------------------------
// localStorage cache
// -----------------------------------------------------------------------------

const readStore = (): Record<string, CachedLabel> => {
  try {
    const raw = globalThis.localStorage?.getItem(LS_KEY);
    if (!raw) return {};
    const parsed: unknown = JSON.parse(raw);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, CachedLabel>)
      : {};
  } catch {
    return {}; // storage unavailable / corrupt — resolve from the network
  }
};

const writeStore = (entries: Record<string, CachedLabel>): void => {
  try {
    globalThis.localStorage?.setItem(LS_KEY, JSON.stringify(trimCache(entries, CACHE_MAX)));
  } catch {
    // storage unavailable / quota — the in-memory cache still holds the session
  }
};

// -----------------------------------------------------------------------------
// resolver — module cache + waiter/pump, the did-profiles.ts idiom
// -----------------------------------------------------------------------------

/** contentId → verified label, or null once it resolved to "none". */
const cache = new Map<string, DocLabel | null>();
const waiters = new Map<string, Set<() => void>>();
const queue: string[] = [];
let active = 0;

// A negative verdict is relay-circumstantial — "these relays yielded no label" —
// so a relay-set change drops it and the next mount re-resolves. Positives are
// bound to the chain by math and survive the switch.
subscribeRelays(() => {
  for (const [id, label] of cache) if (label === null) cache.delete(id);
});

const notify = (contentId: string): void => {
  for (const fn of waiters.get(contentId) ?? []) fn();
};

const remember = (contentId: string, label: DocLabel | null): void => {
  cache.set(contentId, label);
  // only POSITIVES persist — see the header note on negative caching
  if (label && label.kind !== 'id') {
    const entries = readStore();
    entries[contentId] = {
      t: label.text,
      q: label.quoted,
      k: label.kind,
      at: Date.now(),
    };
    writeStore(entries);
  }
  notify(contentId);
};

const resolveOne = async (contentId: string): Promise<void> => {
  try {
    const doc = await getClient().document(contentId);
    remember(contentId, verifiedContentLabel(contentId, doc.value.decoded, doc.value.integrity));
  } catch {
    // gated bytes, no current document, unresolvable chain, or an unreachable
    // relay — the id renders bare either way. In-memory only, so a reload retries.
    cache.set(contentId, null);
    notify(contentId);
  }
};

const pump = (): void => {
  while (active < CONCURRENCY && queue.length > 0) {
    const contentId = queue.shift()!;
    active += 1;
    void resolveOne(contentId).finally(() => {
      active -= 1;
      pump();
    });
  }
};

/** Hydrate the memory cache from a fresh persisted entry, if one exists. */
const hydrate = (contentId: string): boolean => {
  const entry = readStore()[contentId];
  if (!entry || !cacheIsFresh(entry.at, Date.now(), LABEL_TTL_MS)) return false;
  cache.set(contentId, { text: entry.t, quoted: entry.q, kind: entry.k });
  return true;
};

const enqueue = (contentId: string): void => {
  if (cache.has(contentId) || queue.includes(contentId)) return;
  if (hydrate(contentId)) {
    notify(contentId);
    return;
  }
  queue.push(contentId);
  pump();
};

/** pending = not resolved yet · resolved = a verified label · none = no label
 *  (or unreachable) — the contentId renders bare. */
export type ContentLabelState = 'pending' | 'resolved' | 'none';

/** Which tier the returned `label` came from: `verified` = derived from bytes
 *  bound to the chain in this tab · `attributed` = a public relay projection
 *  standing in until the verified answer lands. Meaningless when `label` is null. */
export type ContentLabelTier = 'attributed' | 'verified';

/**
 * Resolve a contentId to its verified document label, hydrating in place as the
 * result lands. `need` gates the work. Returns the attributed floor — `pending`
 * — until the resolve settles, with a public projected title standing in when
 * the relay index supplies one.
 *
 * `projected` is that same amber beat handed in by a caller who ALREADY holds
 * the relay's row (a browse, search, or feed table does — the projection came
 * down with the page). Supplying it, INCLUDING as `''` for "the relay projects
 * no title here", suppresses the point lookup a bare chip has to spend a round
 * trip on: a page of rows would otherwise mean a page of extra index requests
 * for answers the page already received. The caller owns the public-read
 * honesty rule for what
 * it passes; {@link useIndexRowLabel} applies it.
 */
export const useContentLabel = (
  contentId: string,
  need = true,
  projected?: string,
): { label: DocLabel | null; state: ContentLabelState; tier: ContentLabelTier } => {
  const [label, setLabel] = useState<DocLabel | null>(() => cache.get(contentId) ?? null);
  const [state, setState] = useState<ContentLabelState>(() =>
    cache.has(contentId) ? (cache.get(contentId) ? 'resolved' : 'none') : 'pending',
  );

  useEffect(() => {
    if (!need || !contentId) return;
    if (!cache.has(contentId)) {
      setLabel(null);
      setState('pending');
    }
    const read = (): void => {
      if (!cache.has(contentId)) return;
      const hit = cache.get(contentId) ?? null;
      setLabel(hit);
      setState(hit ? 'resolved' : 'none');
    };
    read();
    let set = waiters.get(contentId);
    if (!set) {
      set = new Set();
      waiters.set(contentId, set);
    }
    set.add(read);
    enqueue(contentId);
    read();
    return () => {
      set.delete(read);
    };
  }, [contentId, need]);

  // AMBER PRELUDE — one round trip against the index's point lookup while the
  // verified document resolve above is still running, skipped entirely when the
  // caller already handed the projection in. Dropped the instant the verified
  // answer lands (or resolves to "no label"), so a projection never outlives the
  // proof it was standing in for.
  const row = useIndexContentRow(contentId, need && state === 'pending' && projected === undefined);
  const amber = (projected ?? projectedTitle(row)).trim();
  if (state === 'pending' && !label && amber) {
    return {
      label: { text: amber, quoted: false, kind: 'title' },
      state,
      tier: 'attributed',
    };
  }

  return { label, state, tier: 'verified' };
};

/** The relay index's projection of one content row — exactly the fields a browse,
 *  search, feed, or ledger row already holds when the page lands. */
export interface IndexRowProjection {
  contentId: string;
  title: string | null;
  publicRead: boolean;
}

/**
 * THE PUBLIC-READ HONESTY RULE for a projected title, in one place. Only a title
 * the relay marks `publicRead` is safe to render: an unupgraded relay may still
 * project one for a non-public chain, and it must never reach the screen — not
 * even as a temporary amber beat. Pure, unit-tested.
 */
export const rowProjection = (row: IndexRowProjection): string =>
  row.publicRead ? (row.title ?? '').trim() : '';

/**
 * THE SAME RULE FOR THE VERIFIED BEAT — a non-public row shows NO resolved label,
 * whatever the resolver managed to hand back.
 *
 * `need` already stops the resolver from fetching for a gated row, but
 * {@link useContentLabel} seeds its state from the module cache regardless: a
 * chain resolved earlier in this same SPA session, while the index still called
 * it public, would render its remembered title here. That breaks the bare-pill
 * posture on exactly the surfaces built to hold it — the actor ledger, and home's
 * include-gated mode whose own copy promises the titles are never rendered.
 *
 * When the row and the cache disagree, this suppresses. The index hint may well
 * be the lagging half (a chain just made public reads gated for a moment), and
 * withholding a legitimate title for that moment costs a name; rendering a title
 * for a chain the relay currently marks non-public cannot be taken back. Pure,
 * unit-tested.
 */
export const visibleRowLabel = (
  row: IndexRowProjection,
  resolved: DocLabel | null,
): DocLabel | null => (row.publicRead ? resolved : null);

/**
 * The label for one relay-index content row, running the SAME THREE BEATS as
 * ContentChip: the short contentId, promoted to the relay's projected public
 * title in the amber attributed tier, promoted again to a VERIFIED label derived
 * from bytes this tab re-hashed to the chain's committed document CID.
 *
 * It used to stop at beat two. An untitled public post — the relay index projects
 * `title` only for a post/v1 that has one — was labelled by fetching the document
 * bytes RAW and rendering an excerpt of them amber, with no integrity check at
 * all: a snippet a relay could write by serving whatever it liked under a
 * committed chain. That path is gone. The verified resolve fetches the same bytes
 * through the integrity gate and yields the same excerpt (quoted) as PROOF, and a
 * row the gate rejects falls back to the short id rather than to a relay's prose.
 *
 * `seen` gates the verified resolve on the row having actually been looked at —
 * the caller derives it from the verify status, which flips as the row scrolls
 * into view, so a 300-row corpus never folds 300 chains. The amber beat needs no
 * gate: it came down with the page. A chain the relay marks non-public is never
 * resolved either — its bytes are gated by definition, so the request could only
 * ever spend a round trip to learn what the row already says.
 *
 * NOT resolving is not the same as not SHOWING, which is why both beats pass
 * through a gate here: the projected title through {@link rowProjection} and the
 * resolved one through {@link visibleRowLabel}. The session cache can answer for
 * a chain nobody re-asked about, so "we never fetched this" was never enough to
 * keep a gated row bare.
 */
export const useIndexRowLabel = (
  row: IndexRowProjection,
  seen: boolean,
): { label: DocLabel; tier: ContentLabelTier } => {
  const projected = rowProjection(row);
  const { label, tier } = useContentLabel(row.contentId, seen && row.publicRead, projected);
  return {
    label: visibleRowLabel(row, label) ?? deriveDocLabel({ contentId: row.contentId }),
    tier,
  };
};
