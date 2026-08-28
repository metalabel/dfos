/*

  KEY STANDING — what one identity's chain says about one key, right now

  The relay's `key=` filter is a HAS-EVER-DECLARED reverse lookup by design
  (WEB-RELAY.md): an identity matches when any accepted operation of its chain
  ever carried the key, whether or not a later update rotated it out. That is the
  right index — a holder recovering from a restored key holds exactly the keys
  that were rotated away — and it is also a claim that goes stale in the reader's
  head. "This key controls these five identities" is not what a match means.

  So every matched row is labelled with the key's CURRENT standing, folded from
  that identity's own chain rather than from the index row:

    current   — the head state still carries the key, in these classes
    rotated   — the chain verifies and its head no longer carries the key
    deleted   — the chain verifies and the identity is deactivated
    unchecked — the chain did not resolve here, so we do not know

  The fourth is the point. `unchecked` is never folded into `rotated`: one is an
  observation, the other is our own failure to make one, and the difference is
  the whole invalid-vs-unverifiable discipline. A row whose chain we could not
  read says so and stays a row — the index's claim that this identity once
  declared the key is untouched by our inability to check what it does now.

  Matching is BYTE-FOR-BYTE on the multibase string, the same comparison the
  relay's filter makes. A key is its encoding here; no normalization, no decode.

  The resolver below is the module-cache + bounded-pump idiom of
  lib/did-profiles.ts and lib/content-labels.ts, so a page of rows folds a few
  chains at a time instead of firing one resolve per row at once.

*/

import type { VerifiedIdentity } from '@metalabel/dfos-protocol/chain';
import { useEffect, useState } from 'preact/hooks';
import { getClient } from './client';

/** The three key arrays an identity operation declares. Ordered as the identity
 *  view's key panel orders them, so both surfaces read the same. */
export type KeyClass = 'auth' | 'assert' | 'controller';

/** The head state a standing is folded from: the verified identity's key arrays,
 *  flattened to multibase strings, plus its terminal deletion state. */
export interface HeadKeys {
  isDeleted: boolean;
  auth: string[];
  assert: string[];
  controller: string[];
}

export type KeyStanding =
  | { kind: 'current'; classes: KeyClass[] }
  | { kind: 'rotated' }
  /** `classes` records which head arrays still carry the key — empty when it was
   *  rotated out before the deletion. Deactivation is the headline either way. */
  | { kind: 'deleted'; classes: KeyClass[] }
  | { kind: 'unchecked'; reason: string };

// -----------------------------------------------------------------------------
// pure parts (unit-tested)
// -----------------------------------------------------------------------------

/** Flatten a verified identity's head state to the shape the fold reads. */
export const headKeysOf = (identity: VerifiedIdentity): HeadKeys => ({
  isDeleted: identity.isDeleted,
  auth: identity.authKeys.map((k) => k.publicKeyMultibase),
  assert: identity.assertKeys.map((k) => k.publicKeyMultibase),
  controller: identity.controllerKeys.map((k) => k.publicKeyMultibase),
});

/** Which head arrays carry this exact multibase string, in panel order. */
export const classesOf = (multibase: string, head: HeadKeys): KeyClass[] => {
  const classes: KeyClass[] = [];
  if (head.auth.includes(multibase)) classes.push('auth');
  if (head.assert.includes(multibase)) classes.push('assert');
  if (head.controller.includes(multibase)) classes.push('controller');
  return classes;
};

/**
 * One matched identity's standing for one key. `head` is null when the chain did
 * not resolve or did not verify here — which yields `unchecked`, never a guess in
 * either direction. Pure, unit-tested.
 */
export const keyStanding = (
  multibase: string,
  head: HeadKeys | null,
  reason = 'the chain did not resolve here',
): KeyStanding => {
  if (head === null) return { kind: 'unchecked', reason };
  const classes = classesOf(multibase, head);
  if (head.isDeleted) return { kind: 'deleted', classes };
  return classes.length > 0 ? { kind: 'current', classes } : { kind: 'rotated' };
};

// -----------------------------------------------------------------------------
// resolver — module cache + waiter/pump (the did-profiles.ts idiom)
// -----------------------------------------------------------------------------

/** What one chain resolved to: its head keys, or the reason we have none. */
type ChainResult = { head: HeadKeys } | { head: null; reason: string };

/** In-flight identity folds at once — matches the other lazy row-hydrators so the
 *  page stays equally polite to relays. */
const CONCURRENCY = 4;

const cache = new Map<string, ChainResult>();
const waiters = new Map<string, Set<() => void>>();
const queue: string[] = [];
let active = 0;

const notify = (did: string): void => {
  for (const fn of waiters.get(did) ?? []) fn();
};

const resolveOne = async (did: string): Promise<void> => {
  try {
    const resolved = await getClient().identity(did);
    cache.set(did, { head: headKeysOf(resolved.value) });
  } catch (e) {
    // no relay served this chain, or it failed verification here. COULD NOT
    // CHECK — in memory only, so a reload retries rather than latching a failure.
    cache.set(did, { head: null, reason: e instanceof Error ? e.message : String(e) });
  }
  notify(did);
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

const enqueue = (did: string): void => {
  if (cache.has(did) || queue.includes(did)) return;
  queue.push(did);
  pump();
};

/**
 * The key's standing on one identity, folded from that identity's chain in this
 * tab. `null` while the fold is in flight — the row renders immediately and the
 * label lands after, so a page of matches never waits on its chains.
 */
export const useKeyStanding = (did: string, multibase: string): KeyStanding | null => {
  const [result, setResult] = useState<ChainResult | null>(() => cache.get(did) ?? null);

  useEffect(() => {
    if (!did) return;
    if (!cache.has(did)) setResult(null);
    const read = (): void => {
      const hit = cache.get(did);
      if (hit) setResult(hit);
    };
    read();
    let set = waiters.get(did);
    if (!set) {
      set = new Set();
      waiters.set(did, set);
    }
    set.add(read);
    enqueue(did);
    return () => {
      set.delete(read);
    };
  }, [did]);

  if (result === null) return null;
  return keyStanding(multibase, result.head, result.head === null ? result.reason : undefined);
};
