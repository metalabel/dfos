/*

  KEY STANDING — what one identity's chain says about one key, right now

  The relay's `key=` filter is a HAS-EVER-PROVED reverse lookup by design
  (WEB-RELAY.md, KEY-PROOF.md): an identity matches when any accepted operation
  of its chain ever admitted the key — named it in a role AND carried the key's
  own proof of possession for that role. Whether a later update rotated it out
  makes no difference. That is the right index — a holder recovering from a
  restored key holds exactly the keys that were rotated away — and it is also a
  claim that goes stale in the reader's head. "This key controls these five
  identities" is not what a match means.

  PROVED, NOT MERELY NAMED, and the difference is the reason this index exists in
  this shape. Anyone can write anyone else's public key into their own chain — a
  public key is public. Only the key itself can sign the KEY-PROOF envelope that
  consents to join a chain in a role at a position. A named-but-unproved
  membership is VOID: the operation is valid and the relay serves it, but the
  membership is absent from the chain's effective key state, it never resolves,
  and it never enters this index. If the index counted mere declarations, writing
  a stranger's key into your own chain would burn it in every future ceremony
  that consults this oracle before signing.

  So every matched row is labelled with the key's CURRENT standing, folded from
  that identity's own chain rather than from the index row:

    current   — the head's effective state carries the key, in these classes
    void      — the head DECLARES the key and no proof admitted it, so it is not
                in effective state (see below)
    rotated   — the chain verifies and its head neither carries nor names the key
    deleted   — the chain verifies and the identity is deactivated
    unchecked — the chain did not resolve here, so we do not know

  VOID IS NOT ROTATED, and folding it into `rotated` was the fold's one lie. A
  row is here because the key was proved into this chain at some point; a head
  that names the key again without a proof (or that proved it into one role and
  named it into two) is not a chain that rotated the key away, it is a chain
  whose controller wrote a membership that does not work. `rotated out` would
  tell that controller the opposite of what happened, and this explorer is one of
  the few surfaces that can tell them at all.

  `unchecked` is never folded into `rotated` either: one is an observation, the
  other is our own failure to make one, and the difference is the whole
  invalid-vs-unverifiable discipline. A row whose chain we could not read says so
  and stays a row — the index's claim that this identity once proved the key is
  untouched by our inability to check what it does now.

  Matching is BYTE-FOR-BYTE on the multibase string, the same comparison the
  relay's filter makes. A key is its encoding here; no normalization, no decode.

  The resolver below is the module-cache + bounded-pump idiom of
  lib/did-profiles.ts and lib/content-labels.ts, so a page of rows folds a few
  chains at a time instead of firing one resolve per row at once.

*/

import type { VerifiedIdentity } from '@metalabel/dfos-protocol/chain';
import { useEffect, useState } from 'preact/hooks';
import { getClient } from './client';

/** The three roles a key can hold on an identity. Ordered as the identity view's
 *  key panel orders them, so both surfaces read the same. Byte-identical to the
 *  protocol's `KeyRole`, which is what `voidKeys` entries carry. */
export type KeyClass = 'auth' | 'assert' | 'controller';

/** The head state a standing is folded from: the verified identity's EFFECTIVE
 *  key arrays, flattened to multibase strings, its declared-but-unproved
 *  memberships, and its terminal deletion state. */
export interface HeadKeys {
  isDeleted: boolean;
  auth: string[];
  assert: string[];
  controller: string[];
  /** Memberships the head declares that no key proof admitted, flattened to
   *  (key, role) pairs. Empty on a fully-proved chain — and empty, necessarily,
   *  on a state that predates the member (an older relay's assertion, a cached
   *  fold), which reads as "nothing void here" rather than as an unknown. That
   *  under-reports; it never invents a void membership. */
  voids: { key: string; role: KeyClass }[];
}

export type KeyStanding =
  /** In effective state. `voidClasses` names the roles the same head declares
   *  this key into WITHOUT a proof — a key proved into auth and named into
   *  assert is current and incomplete at the same time, and one chip cannot say
   *  both. Usually empty. */
  | { kind: 'current'; classes: KeyClass[]; voidClasses: KeyClass[] }
  /** The head names this key, in these roles, and no proof admitted any of them.
   *  Not in effective state: it resolves nowhere and signs nothing here. */
  | { kind: 'void'; classes: KeyClass[] }
  | { kind: 'rotated' }
  /** `classes` records which head arrays still carry the key — empty when it was
   *  rotated out before the deletion. Deactivation is the headline either way. */
  | { kind: 'deleted'; classes: KeyClass[] }
  | { kind: 'unchecked'; reason: string };

// -----------------------------------------------------------------------------
// pure parts (unit-tested)
// -----------------------------------------------------------------------------

/** Flatten a verified identity's head state to the shape the fold reads. The
 *  three arrays are EFFECTIVE state; `voidKeys` is the declared half that no
 *  proof admitted, and it is optional on the type, so an absent member flattens
 *  to no void memberships. */
export const headKeysOf = (identity: VerifiedIdentity): HeadKeys => ({
  isDeleted: identity.isDeleted,
  auth: identity.authKeys.map((k) => k.publicKeyMultibase),
  assert: identity.assertKeys.map((k) => k.publicKeyMultibase),
  controller: identity.controllerKeys.map((k) => k.publicKeyMultibase),
  voids: (identity.voidKeys ?? []).map((v) => ({
    key: v.key.publicKeyMultibase,
    role: v.role as KeyClass,
  })),
});

/** Which head arrays carry this exact multibase string, in panel order. */
export const classesOf = (multibase: string, head: HeadKeys): KeyClass[] => {
  const classes: KeyClass[] = [];
  if (head.auth.includes(multibase)) classes.push('auth');
  if (head.assert.includes(multibase)) classes.push('assert');
  if (head.controller.includes(multibase)) classes.push('controller');
  return classes;
};

/** The roles the head DECLARES this key into with no proof admitting it, in the
 *  same panel order. Deduplicated: one void membership per (key, role). */
export const voidClassesOf = (multibase: string, head: HeadKeys): KeyClass[] => {
  const named = new Set(head.voids.filter((v) => v.key === multibase).map((v) => v.role));
  return (['auth', 'assert', 'controller'] as const).filter((role) => named.has(role));
};

/**
 * One matched identity's standing for one key. `head` is null when the chain did
 * not resolve or did not verify here — which yields `unchecked`, never a guess in
 * either direction.
 *
 * Branch order is the honesty order. Deletion outranks everything: a deactivated
 * chain's key state is moot whatever its shape. Then effective membership, which
 * is the only state in which the key actually works — carrying its void roles
 * along so a partly-proved key is not rounded to fully-proved. Then void, which
 * must never be reported as `rotated`: the head names the key, so nothing rotated
 * it away. `rotated` is left for the true case — the head neither carries the key
 * nor names it. Pure, unit-tested.
 */
export const keyStanding = (
  multibase: string,
  head: HeadKeys | null,
  reason = 'the chain did not resolve here',
): KeyStanding => {
  if (head === null) return { kind: 'unchecked', reason };
  const classes = classesOf(multibase, head);
  if (head.isDeleted) return { kind: 'deleted', classes };
  const voidClasses = voidClassesOf(multibase, head);
  if (classes.length > 0) return { kind: 'current', classes, voidClasses };
  if (voidClasses.length > 0) return { kind: 'void', classes: voidClasses };
  return { kind: 'rotated' };
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
