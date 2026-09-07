/*

  DID → PUBLIC PROFILE — the app-wide default rendering for every DID

  Tables of DIDs are hash soup. Most identities on the network publish a public
  profile, so every row that renders a DID resolves it to that profile's NAME and
  hydrates in place (see components/did-chip.tsx). This module is the resolver
  behind that: a module-level cache + a bounded worker pump, the same idiom as
  content-labels.ts's verified-label resolver.

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

  THAT RIGOUR COSTS THREE ROUND TRIPS, which is a long time for a table of DIDs
  to sit as hash soup. So the hook also runs the relay index's POINT LOOKUP
  (`/index/v0/identities?did=` — lib/index-point.ts) alongside it, which answers
  "what does this DID call itself" in ONE request. That answer is a relay
  projection, so it renders in the ATTRIBUTED tier (amber) and is replaced the
  moment the verified name lands — the same attributed→verified promotion every
  index-light row makes. The point lookup never relaxes the invariant above: the
  index withholds a non-public profile's name by spec, and the projection is
  additionally checked to be public here before it can render.

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
import { projectedName, useIndexIdentityRow } from './index-point';
import { parseMediaObject, type MediaObject } from './media';
import { isProfileContent, profileAnchorOf } from './profile';
import { subscribeRelays } from './relays';

export interface DidProfile {
  did: string;
  /** the public profile's name — never empty (a nameless profile resolves to none). */
  name: string;
  description: string;
  /** the profile's avatar Media, for a surface that gates bytes on the cid rehash. */
  avatar: MediaObject | null;
}

/**
 * pending = not resolved yet · resolved = a public profile · none = the identity
 * resolved and there is no public profile to show · unavailable = the question
 * could not be asked at all.
 *
 * THE LAST TWO ARE NOT THE SAME SENTENCE. "No public profile" is a finding about
 * an identity; an unreachable relay is a finding about the network, and printing
 * the first over the second is the explorer asserting something it never
 * observed. A row renders them differently (components/index-light.tsx).
 */
export type DidProfileState = 'pending' | 'resolved' | 'none' | 'unavailable';

/**
 * A settled resolve: the public profile, `null` for "there is none", or
 * `'unavailable'` for "we could not look". The third value is the whole point —
 * see {@link DidProfileState}.
 */
export type ProfileVerdict = DidProfile | null | 'unavailable';

/** How long a resolved profile is trusted from cache before re-resolving. */
export const PROFILE_TTL_MS = 60 * 60 * 1000;

/** Cap on persisted profiles — a wide browse must not grow the key unbounded. */
const CACHE_MAX = 400;

/** In-flight resolves at once — mirrors content-labels' pump so the two lazy
 *  row-hydrators stay equally polite to relays. */
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
export const trimCache = <T extends { at: number }>(
  entries: Record<string, T>,
  max = CACHE_MAX,
): Record<string, T> => {
  const keys = Object.keys(entries);
  if (keys.length <= max) return entries;
  const kept = keys.sort((a, b) => (entries[b]?.at ?? 0) - (entries[a]?.at ?? 0)).slice(0, max);
  const out: Record<string, T> = {};
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
// resolver — module cache + waiter/pump, the content-labels.ts idiom
// -----------------------------------------------------------------------------

/** did → resolved public profile, `null` for "none", `'unavailable'` for "could
 *  not look". */
const cache = new Map<string, ProfileVerdict>();
const waiters = new Map<string, Set<() => void>>();
const queue: string[] = [];
let active = 0;

const notify = (did: string): void => {
  for (const fn of waiters.get(did) ?? []) fn();
};

const remember = (did: string, profile: ProfileVerdict): void => {
  cache.set(did, profile);
  // only POSITIVES persist — see the header note on negative caching
  if (profile && profile !== 'unavailable') {
    const entries = readStore();
    entries[did] = { n: profile.name, d: profile.description, at: Date.now() };
    writeStore(entries);
  }
  notify(did);
};

/** The two round trips the resolve needs, structurally — so the verdict split
 *  below is unit-testable without a browser or a relay. `getClient()` satisfies
 *  it as it stands. */
export interface ProfileSource {
  identity(did: string): Promise<{ value: { services: { type: string; [k: string]: unknown }[] } }>;
  document(anchor: string): Promise<{ value: { decoded?: unknown; integrity: boolean } }>;
}

/**
 * Resolve one DID to a verdict, with the two beats caught SEPARATELY because
 * they answer different questions.
 *
 * Beat 1 throwing means the identity chain itself did not resolve — an
 * unreachable relay, a divergence, a chain nobody serves. Nothing was learned
 * about whether a public profile exists, so the verdict is `'unavailable'`.
 *
 * Beat 2 throwing means the chain resolved, named an anchor, and no relay served
 * those bytes to an unauthenticated read. That is what "not a PUBLIC profile"
 * means empirically (see the header's privacy invariant), so it stays `null` —
 * the same verdict as an anchor that resolved to something that is not a profile.
 *
 * Pure of module state, unit-tested.
 */
export const resolveProfileVerdict = async (
  did: string,
  client: ProfileSource,
): Promise<ProfileVerdict> => {
  let identity: Awaited<ReturnType<ProfileSource['identity']>>;
  try {
    // beat 1 — the identity chain, folded and verified in the tab, for its
    // controller-signed profile anchor
    identity = await client.identity(did);
  } catch {
    return 'unavailable';
  }
  const anchor = profileAnchorOf(identity.value.services);
  if (!anchor) return null;
  try {
    // beat 2 — an ANONYMOUS document fetch; `integrity` is the re-hash to the
    // committed documentCID. Gated bytes throw (no relay serves them) → none.
    const doc = await client.document(anchor);
    return publicProfileOf(did, doc.value.decoded, doc.value.integrity);
  } catch {
    return null;
  }
};

const resolveOne = async (did: string): Promise<void> => {
  // in-memory only either way, so a reload retries
  remember(did, await resolveProfileVerdict(did, getClient()));
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

// A negative verdict is relay-circumstantial — "these relays yielded no profile"
// — so a relay-set change drops it and asks again, the content-labels.ts idiom.
// Positives are bound to the chain by math and survive the switch. Registered
// once, for the module's life: this resolver is a session singleton.
subscribeRelays(() => {
  for (const [did, profile] of cache) {
    if (profile !== null && profile !== 'unavailable') continue;
    cache.delete(did);
    // a row still on screen re-asks the NEW relay set rather than keeping a
    // verdict the old one produced; one nobody is watching just falls out
    if (waiters.get(did)?.size) enqueue(did);
    notify(did);
  }
});

/** Which tier the returned `profile` came from: `verified` = bound to the chain
 *  by math in this tab (see the header note) · `attributed` = the relay index's
 *  projection, standing in until the verified answer lands. Meaningless when
 *  `profile` is null. */
export type DidProfileTier = 'attributed' | 'verified';

/** The cache entry as a renderable profile — a verdict that is not one is null. */
const profileOf = (verdict: ProfileVerdict | undefined): DidProfile | null =>
  verdict && verdict !== 'unavailable' ? verdict : null;

/** The cache entry as a display state. A missing entry is the pending floor. */
const stateOf = (did: string): DidProfileState => {
  if (!cache.has(did)) return 'pending';
  const hit = cache.get(did);
  if (hit === 'unavailable') return 'unavailable';
  return hit ? 'resolved' : 'none';
};

/**
 * Resolve a DID to its public profile, hydrating in place as the result lands.
 * `need` gates the work so a chip can hold off (an already-named row needs no
 * resolve). Returns the attributed floor — `pending` — until the resolve settles,
 * with the relay index's projected name standing in meanwhile (tier `attributed`).
 *
 * `projected` is that same amber beat handed in by a caller who ALREADY holds the
 * relay's identity row — a browse or search page received it with the page.
 * Supplying it, INCLUDING as `''` for "the relay projects no public name here",
 * suppresses the point lookup a bare chip has to spend a round trip on. The
 * caller owns the public-read honesty rule for what it passes (`projectedName`
 * in lib/index-point.ts is that rule).
 */
export const useDidProfile = (
  did: string,
  need = true,
  projected?: string,
): { profile: DidProfile | null; state: DidProfileState; tier: DidProfileTier } => {
  const [profile, setProfile] = useState<DidProfile | null>(() => profileOf(cache.get(did)));
  const [state, setState] = useState<DidProfileState>(() => stateOf(did));

  useEffect(() => {
    if (!need || !did) return;
    if (!cache.has(did)) {
      setProfile(null);
      setState('pending');
    }
    const read = (): void => {
      // a dropped entry (the relay-set clear above) returns the row to the
      // pending floor rather than leaving the old relay set's verdict on screen
      setProfile(profileOf(cache.get(did)));
      setState(stateOf(did));
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

  // AMBER PRELUDE — one round trip against the index's point lookup while the
  // three-beat verified resolve above is still running, skipped entirely when the
  // caller already handed the projection in. Dropped the instant the verified
  // answer lands (or resolves to "no public profile"), so a projection never
  // outlives the proof it was standing in for.
  const indexRow = useIndexIdentityRow(did, need && state === 'pending' && projected === undefined);
  const amber = (projected ?? projectedName(indexRow)).trim();
  if (state === 'pending' && !profile && amber) {
    return {
      profile: { did, name: amber, description: '', avatar: null },
      state,
      tier: 'attributed',
    };
  }

  return { profile, state, tier: 'verified' };
};
