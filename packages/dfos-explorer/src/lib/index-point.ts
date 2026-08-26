/*

  INDEX POINT LOOKUPS — one identifier in, at most one row out

  The index families answer "the row FOR this did / this contentId" directly
  (`/index/v0/identities?did=`, `/index/v0/content?contentId=`), which is what a
  detail surface actually wants. Before those filters existed the only way to
  reach one row through the index was to walk the enumeration until it appeared —
  a cache dance over pages nobody wanted, unbounded on a large corpus.

  THE RESULT IS ALWAYS KEY-MATCHED, and that is load-bearing rather than
  defensive. A relay predating these filters IGNORES the unknown param and
  returns an ordinary first page — every row of it about some other identifier.
  Handing that page's first row back as "the row for X" would be the relay
  writing an answer to a question it never understood. So the matchers below keep
  only a row whose own key equals the one asked for; anything else resolves to
  nothing and the caller stays on the path it already had. That makes these
  lookups safe on every relay with no capability probe.

  What a `null` means is therefore narrow: "no row came back for this key here",
  never "this identifier does not exist". Absence is not proof of absence in the
  index (a relay can be behind, partitioned, or withholding), and on a relay that
  ignores the filter it means only that the id was not on the page served. Every
  caller uses this as an AMBER prelude — an instant relay-asserted projection —
  while the proof plane resolves the same thing for real underneath.

  Caching mirrors did-profiles.ts: a module map plus a waiter/pump so the same id
  requested from several rows resolves once. Nothing persists — these are hints
  with no integrity binding, and a stale hint is worse than a second fetch.

  THE CACHE IS SCOPED TO THE RELAY SET, which a bare id would not be. Unlike a
  verified profile — bound to its chain by math, and therefore true no matter who
  served it — every row here is RELAY-ASSERTED, so an answer from one set says
  nothing about another. The cached NULL is the sharper edge: "no row came back"
  is exactly what a relay predating these filters produces, and remembering it
  under a bare id would mean that adding a capable relay never re-resolves
  anything. Folding the set into the key makes a relay switch re-ask by
  construction (the key changes, so the hook's effect re-runs), and the maps are
  cleared on the same event to keep them from accumulating dead sets.

*/

import type { IndexContentRow, IndexIdentityRow } from '@metalabel/dfos-client';
import { useEffect, useState } from 'preact/hooks';
import { getClient } from './client';
import { getRelays, subscribeRelays } from './relays';

/** In-flight point lookups at once — the same politeness budget did-profiles
 *  and content-labels give their row hydrators. */
const CONCURRENCY = 4;

// -----------------------------------------------------------------------------
// pure parts (unit-tested)
// -----------------------------------------------------------------------------

/** The identity row that is actually ABOUT `did`, or null. See the header note:
 *  a relay that ignores `did=` serves an unrelated page, and no row of it is an
 *  answer. Pure. */
export const rowForDid = (rows: IndexIdentityRow[], did: string): IndexIdentityRow | null =>
  rows.find((row) => row.did === did) ?? null;

/** The content row that is actually ABOUT `contentId`, or null. Same reasoning
 *  as {@link rowForDid}. Pure. */
export const rowForContentId = (
  rows: IndexContentRow[],
  contentId: string,
): IndexContentRow | null => rows.find((row) => row.contentId === contentId) ?? null;

/**
 * The projected public profile name an identity row is allowed to display, or ''.
 * HONEST DEGRADATION, identical to the browse rows: only a name the relay marks
 * `publicRead` ever reaches the screen — an unupgraded relay may still project a
 * non-public one. Pure.
 *
 * A WHITESPACE-ONLY PROJECTION IS NOTHING. The verified path already treats a
 * blank name as no name (did-profiles.ts: "a nameless profile resolves to
 * none"), so leaving the projection untrimmed would let a relay replace a short,
 * readable identifier with an empty amber span that clicks nowhere the eye can
 * see — and then have it "promote" to the id it should have shown all along.
 */
export const projectedName = (row: IndexIdentityRow | null): string =>
  row?.profile?.publicRead ? (row.profile.name ?? '').trim() : '';

/**
 * The projected title a content row is allowed to display, or ''. Same two rules
 * as {@link projectedName}: a non-public chain never surfaces its title, and a
 * whitespace-only title is not a title. Pure.
 */
export const projectedTitle = (row: IndexContentRow | null): string =>
  row?.publicRead ? (row.title ?? '').trim() : '';

// -----------------------------------------------------------------------------
// resolver — module cache + waiter/pump, the did-profiles.ts idiom
// -----------------------------------------------------------------------------

/** One cache per family, keyed by `${relaySet}|${family}:${id}` — see the header
 *  note on why a bare id would be wrong. The value is the matched row, or null
 *  once resolved to "nothing came back for this key, on these relays". */
const identityCache = new Map<string, IndexIdentityRow | null>();
const contentCache = new Map<string, IndexContentRow | null>();
const waiters = new Map<string, Set<() => void>>();
const queue: { key: string; run: () => Promise<void> }[] = [];
let active = 0;

/** The configured relay set, as a cache-scoping key. */
const relaySetKey = (): string => getRelays().join('|');

// A relay change invalidates every hint in flight and at rest. The keys already
// carry the set, so this is purely about not accumulating dead ones; the hooks
// re-ask because their key changed, not because of this.
subscribeRelays(() => {
  identityCache.clear();
  contentCache.clear();
});

/** Track the relay set so a change re-keys (and so re-runs) every point lookup. */
const useRelaySetKey = (): string => {
  const [key, setKey] = useState(relaySetKey);
  useEffect(() => subscribeRelays(() => setKey(relaySetKey())), []);
  return key;
};

const notify = (key: string): void => {
  for (const fn of waiters.get(key) ?? []) fn();
};

const pump = (): void => {
  while (active < CONCURRENCY && queue.length > 0) {
    const job = queue.shift()!;
    active += 1;
    void job.run().finally(() => {
      active -= 1;
      notify(job.key);
      pump();
    });
  }
};

const enqueue = (key: string, run: () => Promise<void>): void => {
  if (queue.some((job) => job.key === key)) return;
  queue.push({ key, run });
  pump();
};

const resolveIdentity = async (key: string, did: string): Promise<void> => {
  try {
    const page = await getClient().indexIdentities({ did, limit: 1 });
    identityCache.set(key, rowForDid(page.identities, did));
  } catch {
    // unreachable / declined — NOT a verdict. Leave the cache empty so a later
    // mount retries rather than remembering a network blip as "no row".
  }
};

const resolveContent = async (key: string, contentId: string): Promise<void> => {
  try {
    const page = await getClient().indexContent({ contentId, limit: 1 });
    contentCache.set(key, rowForContentId(page.content, contentId));
  } catch {
    // see resolveIdentity — a failed fetch records nothing.
  }
};

const useCachedRow = <T>(
  cache: Map<string, T | null>,
  id: string,
  need: boolean,
  key: string,
  run: (key: string) => Promise<void>,
): T | null => {
  const [row, setRow] = useState<T | null>(() => cache.get(key) ?? null);
  useEffect(() => {
    if (!need || !id) return;
    const read = (): void => setRow(cache.get(key) ?? null);
    read();
    if (cache.has(key)) return;
    let set = waiters.get(key);
    if (!set) {
      set = new Set();
      waiters.set(key, set);
    }
    set.add(read);
    enqueue(key, () => run(key));
    return () => {
      set.delete(read);
    };
    // cache/run are stable per (relay set, family, id), which `key` names
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, need]);
  return row;
};

/**
 * The relay index's row for one DID, hydrating in place. `need` gates the fetch
 * so a surface that already has the answer never asks. Returns null until (and
 * unless) a key-matched row lands, and re-asks when the relay set changes.
 */
export const useIndexIdentityRow = (did: string, need = true): IndexIdentityRow | null => {
  const key = `${useRelaySetKey()}|identity:${did}`;
  return useCachedRow(identityCache, did, need, key, (k) => resolveIdentity(k, did));
};

/** The relay index's row for one contentId. Same contract as
 *  {@link useIndexIdentityRow}. */
export const useIndexContentRow = (contentId: string, need = true): IndexContentRow | null => {
  const key = `${useRelaySetKey()}|content:${contentId}`;
  return useCachedRow(contentCache, contentId, need, key, (k) => resolveContent(k, contentId));
};
