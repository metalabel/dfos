/*

  DID → PUBLIC PROFILE — the app-wide default rendering for every DID

  Tables of DIDs are hash soup. Most identities on the network publish a public
  profile, so every row that renders a DID resolves it to that profile's NAME and
  hydrates in place (see components/did-chip.tsx). This module is the resolver
  behind that: a module-level cache + a bounded worker pump, the same idiom as
  doc-label.ts's snippet resolver.

  THE PRIVACY INVARIANT IS ABSOLUTE: only a PUBLIC profile ever yields a name.
  Resolution runs entirely through the proof plane —

    client.identity(did)      the identity chain, FOLDED AND VERIFIED in the tab
    profileAnchorOf(services) the controller-signed ContentAnchor for the profile
    client.document(anchor)   an ANONYMOUS blob fetch + a re-hash to the
                              committed documentCID (`integrity`)

  — so a name renders only when (a) the anchor is signed by the identity itself,
  (b) the bytes were served to an unauthenticated fetch, which IS what public-read
  means empirically, and (c) those exact bytes hash to the CID the chain commits
  to. A gated, absent, mismatched, or unreachable profile yields NOTHING and the
  DID renders bare. This is strictly stronger than the relay index's projected
  `name` (attributed): here the bytes are bound to the chain by math.

  Avatar bytes are deliberately NOT rendered in row contexts — the MediaObject is
  carried here so a detail surface can gate it through the existing verified-bytes
  Avatar (components/profile.tsx), which is the one place image bytes render.

  Caching: verified profiles persist to localStorage with a 1h TTL (names drift
  when a profile chain is updated), bounded so the corpus can't grow the key.
  NEGATIVE verdicts stay in memory for the session only — persisting "no public
  profile" across a transient relay failure would silently blank real names.

*/

import { useEffect, useState } from 'preact/hooks';
import { getClient } from './client';
import { parseMediaObject, type MediaObject } from './media';
import { isProfileContent, profileAnchorOf } from './profile';

export interface DidProfile {
  did: string;
  /** the public profile's name — never empty (a nameless profile resolves to none). */
  name: string;
  description: string;
  /** the profile's avatar Media, for a surface that gates bytes on the cid rehash. */
  avatar: MediaObject | null;
}

/** pending = not resolved yet · resolved = a public profile · none = no public
 *  profile (or unreachable) — the DID renders bare. */
export type DidProfileState = 'pending' | 'resolved' | 'none';

/** How long a resolved profile is trusted from cache before re-resolving. */
export const PROFILE_TTL_MS = 60 * 60 * 1000;

/** Cap on persisted profiles — a wide browse must not grow the key unbounded. */
const CACHE_MAX = 400;

/** In-flight resolves at once — mirrors doc-label's snippet pump so the two
 *  lazy row-hydrators stay equally polite to relays. */
const CONCURRENCY = 4;

const LS_KEY = 'dfos.explorer.didProfiles';

/** One persisted entry: name, description, ms-epoch of the resolve. */
interface CachedProfile {
  n: string;
  d: string;
  at: number;
}

// -----------------------------------------------------------------------------
// pure parts (unit-tested)
// -----------------------------------------------------------------------------

/**
 * The public-profile verdict for one resolved document. `integrity` is the
 * client's bytes→committed-documentCID re-hash: false means the relay served
 * something OTHER than what the chain commits to, which is never a name.
 * A profile with no name is `null` — a chip has nothing to show.
 */
export const publicProfileOf = (
  did: string,
  decoded: unknown,
  integrity: boolean,
): DidProfile | null => {
  if (!integrity || !isProfileContent(decoded)) return null;
  const name = typeof decoded.name === 'string' ? decoded.name.trim() : '';
  if (!name) return null;
  const description = typeof decoded.description === 'string' ? decoded.description.trim() : '';
  return { did, name, description, avatar: parseMediaObject(decoded.avatar) };
};

/** A cached profile is trusted until its TTL elapses (a profile chain can be
 *  updated, so a name is never cached forever). Clock skew reads as stale. */
export const cacheIsFresh = (at: number, now: number, ttlMs = PROFILE_TTL_MS): boolean =>
  now >= at && now - at < ttlMs;

/** Keep the `max` most recently resolved entries — oldest resolves fall off. */
export const trimCache = (
  entries: Record<string, CachedProfile>,
  max = CACHE_MAX,
): Record<string, CachedProfile> => {
  const keys = Object.keys(entries);
  if (keys.length <= max) return entries;
  const kept = keys.sort((a, b) => (entries[b]?.at ?? 0) - (entries[a]?.at ?? 0)).slice(0, max);
  const out: Record<string, CachedProfile> = {};
  for (const k of kept) {
    const v = entries[k];
    if (v) out[k] = v;
  }
  return out;
};

// -----------------------------------------------------------------------------
// localStorage cache
// -----------------------------------------------------------------------------

const readStore = (): Record<string, CachedProfile> => {
  try {
    const raw = globalThis.localStorage?.getItem(LS_KEY);
    if (!raw) return {};
    const parsed: unknown = JSON.parse(raw);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, CachedProfile>)
      : {};
  } catch {
    return {}; // storage unavailable / corrupt — resolve from the network
  }
};

const writeStore = (entries: Record<string, CachedProfile>): void => {
  try {
    globalThis.localStorage?.setItem(LS_KEY, JSON.stringify(trimCache(entries)));
  } catch {
    // storage unavailable / quota — the in-memory cache still holds the session
  }
};

// -----------------------------------------------------------------------------
// resolver — module cache + waiter/pump, the doc-label.ts idiom
// -----------------------------------------------------------------------------

/** did → resolved public profile, or null once it resolved to "none". */
const cache = new Map<string, DidProfile | null>();
const waiters = new Map<string, Set<() => void>>();
const queue: string[] = [];
let active = 0;

const notify = (did: string): void => {
  for (const fn of waiters.get(did) ?? []) fn();
};

const remember = (did: string, profile: DidProfile | null): void => {
  cache.set(did, profile);
  // only POSITIVES persist — see the header note on negative caching
  if (profile) {
    const entries = readStore();
    entries[did] = { n: profile.name, d: profile.description, at: Date.now() };
    writeStore(entries);
  }
  notify(did);
};

const resolveOne = async (did: string): Promise<void> => {
  try {
    const client = getClient();
    // beat 1 — the identity chain, folded and verified in the tab, for its
    // controller-signed profile anchor
    const identity = await client.identity(did);
    const anchor = profileAnchorOf(identity.value.services);
    if (!anchor) {
      remember(did, null);
      return;
    }
    // beat 2 — an ANONYMOUS document fetch; `integrity` is the re-hash to the
    // committed documentCID. Gated bytes throw (no relay serves them) → none.
    const doc = await client.document(anchor);
    remember(did, publicProfileOf(did, doc.value.decoded, doc.value.integrity));
  } catch {
    // no public profile, unresolvable identity, or an unreachable relay — the
    // DID renders bare either way. In-memory only, so a reload retries.
    cache.set(did, null);
    notify(did);
  }
};

const pump = (): void => {
  while (active < CONCURRENCY && queue.length > 0) {
    const did = queue.shift()!;
    active += 1;
    void resolveOne(did).finally(() => {
      active -= 1;
      pump();
    });
  }
};

/** Hydrate the memory cache from a fresh persisted entry, if one exists. */
const hydrate = (did: string): boolean => {
  const entry = readStore()[did];
  if (!entry || !cacheIsFresh(entry.at, Date.now())) return false;
  cache.set(did, { did, name: entry.n, description: entry.d, avatar: null });
  return true;
};

const enqueue = (did: string): void => {
  if (cache.has(did) || queue.includes(did)) return;
  if (hydrate(did)) return;
  queue.push(did);
  pump();
};

/**
 * Resolve a DID to its public profile, hydrating in place as the result lands.
 * `need` gates the work so a chip can hold off (an already-named row needs no
 * resolve). Returns the attributed floor — `pending` — until the resolve settles.
 */
export const useDidProfile = (
  did: string,
  need = true,
): { profile: DidProfile | null; state: DidProfileState } => {
  const [profile, setProfile] = useState<DidProfile | null>(() => cache.get(did) ?? null);
  const [state, setState] = useState<DidProfileState>(() =>
    cache.has(did) ? (cache.get(did) ? 'resolved' : 'none') : 'pending',
  );

  useEffect(() => {
    if (!need || !did) return;
    const read = (): void => {
      if (!cache.has(did)) return;
      const hit = cache.get(did) ?? null;
      setProfile(hit);
      setState(hit ? 'resolved' : 'none');
    };
    read();
    let set = waiters.get(did);
    if (!set) {
      set = new Set();
      waiters.set(did, set);
    }
    set.add(read);
    enqueue(did);
    read();
    return () => {
      set.delete(read);
    };
  }, [did, need]);

  return { profile, state };
};
