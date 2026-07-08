/*

  DOC LABEL — one standardized name for a content chain, everywhere

  Home recent-activity, the document browser, and the identity actor-ledger all
  render a row per content chain. They diverged on what to SHOW for it: a
  projected title here, a bare id there, nothing for an untitled post. This is
  the single derivation they now share.

  The label convention (identical on every surface):
    - has a title            → the title, plain (reads as a name)
    - post/v1, no title      → a quoted body snippet ("So today I di…")
    - profile/v1             → the profile name, else a quoted description snippet
    - unknown / unresolvable → the short contentId (the pre-existing fallback)
  A short `$schema` badge (post/v1, profile/v1) sits alongside it.

  A relay's index projects `title` ONLY for a post/v1 with a non-empty title;
  everything else needs the document bytes. Those are fetched LAZILY and
  concurrency-capped through `useDocSnippet` (the local index already carries
  projected title/snippet — see sync-projections.ts — so the local paths pass
  them straight in and never fetch). The bytes are relay-served and UNVERIFIED,
  so a snippet stays in the same attributed (amber) tier as a projected title —
  the detail page is the proof, exactly as with `name`/`title`.

*/

import { useEffect, useState } from 'preact/hooks';
import { short } from './format';
import { fetchBlobRaw } from './relay-raw';
import { getRelays } from './relays';

/** How many characters of a body/description snippet to show before ellipsis. */
export const SNIPPET_MAX = 48;

export interface DocLabel {
  /** the display string (already truncated; NOT pre-quoted). */
  text: string;
  /** true for a body/description snippet — render it quoted, attributed-amber. */
  quoted: boolean;
  /** title = a name/title (plain), snippet = quoted excerpt, id = fallback contentId. */
  kind: 'title' | 'snippet' | 'id';
}

const clean = (v: unknown): string => (typeof v === 'string' ? v.trim() : '');

/** Collapse whitespace/newlines to a single space and truncate — a plain-text
 *  strip (no markdown rendering), so a multi-paragraph body reads as one line. */
export const snippet = (text: string, max = SNIPPET_MAX): string => {
  const flat = text.replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max).trimEnd()}…` : flat;
};

/** Derive a label from a projected title/snippet (local index) and/or lazily
 *  resolved document bytes (relay index). Pure — the fetch lives in the hook. */
export const deriveDocLabel = (input: {
  title?: string | null | undefined;
  snippet?: string | null | undefined;
  docSchema?: string | null | undefined;
  contentId: string;
  doc?: Record<string, unknown> | null | undefined;
}): DocLabel => {
  const title = clean(input.title);
  if (title) return { text: title, quoted: false, kind: 'title' };

  // a pre-projected snippet (local rollup) — already stripped, just truncate
  const projected = clean(input.snippet);
  if (projected) return { text: snippet(projected), quoted: true, kind: 'snippet' };

  // lazily-resolved bytes (relay-index path): title/name plain, else a quoted excerpt
  const doc = input.doc;
  if (doc) {
    const schema = clean(doc['$schema']) || clean(input.docSchema);
    if (schema.endsWith('/profile/v1')) {
      const name = clean(doc['name']);
      if (name) return { text: name, quoted: false, kind: 'title' };
      const desc = clean(doc['description']);
      if (desc) return { text: snippet(desc), quoted: true, kind: 'snippet' };
    } else {
      const t = clean(doc['title']);
      if (t) return { text: t, quoted: false, kind: 'title' };
      const body = clean(doc['body']);
      if (body) return { text: snippet(body), quoted: true, kind: 'snippet' };
    }
  }

  return { text: short(input.contentId, 14, 5), quoted: false, kind: 'id' };
};

// -----------------------------------------------------------------------------
// lazy, concurrency-capped document-bytes resolver for untitled index rows
//
// verify-queue folds a row's CHAIN (signatures/CIDs/op-count) but never fetches
// the document bytes, so a body/description snippet needs its own fetch. It is
// bounded (a wide corpus never fans out) and memoized module-wide (a row seen on
// two surfaces fetches once). Triggered by visibility via the `active` flag the
// caller derives from the row's verify status — no second IntersectionObserver.
// -----------------------------------------------------------------------------

const CONCURRENCY = 6;

/** contentId → parsed doc (or null once resolved to gated/absent/non-JSON). */
const cache = new Map<string, Record<string, unknown> | null>();
const waiters = new Map<string, Set<() => void>>();
const queue: string[] = [];
let active = 0;

const notify = (id: string): void => {
  for (const fn of waiters.get(id) ?? []) fn();
};

const resolveOne = async (id: string): Promise<void> => {
  try {
    const blob = await fetchBlobRaw(id, getRelays());
    if (!blob.bytes) {
      // status 0 = no relay answered (transient/unreachable) — do NOT negative-
      // cache, so a later mount retries. A real HTTP verdict (401/403 gated, 404
      // absent) is durable — cache null so a known-empty chain isn't refetched.
      if (blob.status !== 0) cache.set(id, null);
      return;
    }
    const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: false }).decode(blob.bytes));
    cache.set(
      id,
      typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
        ? (parsed as Record<string, unknown>)
        : null,
    );
  } catch {
    cache.set(id, null); // gated / absent / non-JSON — no snippet, fall back to id
  } finally {
    notify(id);
  }
};

const pump = (): void => {
  while (active < CONCURRENCY && queue.length > 0) {
    const id = queue.shift()!;
    active += 1;
    void resolveOne(id).finally(() => {
      active -= 1;
      pump();
    });
  }
};

const enqueueSnippet = (id: string): void => {
  if (cache.has(id) || queue.includes(id)) return;
  queue.push(id);
  pump();
};

/**
 * Resolve a content chain's document bytes for snippet derivation — lazily and
 * only when needed. `active` gates the fetch on visibility (the caller passes a
 * flag derived from the row's verify status, which flips the moment the row
 * scrolls into view). Returns the parsed doc, or null until/unless it resolves.
 */
export const useDocSnippet = (
  contentId: string,
  need: boolean,
): Record<string, unknown> | null => {
  const [doc, setDoc] = useState<Record<string, unknown> | null>(
    () => cache.get(contentId) ?? null,
  );
  useEffect(() => {
    if (!need) return;
    if (cache.has(contentId)) {
      setDoc(cache.get(contentId) ?? null);
      return;
    }
    const read = (): void => setDoc(cache.get(contentId) ?? null);
    let set = waiters.get(contentId);
    if (!set) {
      set = new Set();
      waiters.set(contentId, set);
    }
    set.add(read);
    enqueueSnippet(contentId);
    return () => {
      set.delete(read);
    };
  }, [contentId, need]);
  return doc;
};
