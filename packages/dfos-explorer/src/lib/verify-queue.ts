/*

  VERIFY QUEUE — sparse, viewport-priority proof-plane folds for index-light rows

  Index-light rows (browse.tsx / home.tsx populated from /index/v0) render
  instantly as ATTRIBUTED: relay-asserted discovery hints, unverified. This queue
  promotes them to VERIFIED the same way a detail page does — it fetches the one
  chain via dfos-client (client.identity/content + client.log, which fold and
  re-check every signature and CID in the tab), lands the verified ops in the
  local index via jitIndexChain, and records what the fold learned so a row can
  reconcile any field the relay's hint got wrong (the fold wins).

  It is SPARSE and VIEWPORT-PRIORITY: rows enqueue themselves only as they scroll
  into view, so a 1000-row corpus never triggers 1000 folds — only what the eye
  reaches. Work drains through a bounded worker pool (CONCURRENCY mirrors
  sync-projections' pool) so a relay is never hammered. Each chain is folded at
  most once — an already-verified/errored chain is a no-op on re-enqueue.

  Verdicts are DURABLE: a successful fold is persisted (db `verify` store, keyed
  by `${kind}:${chainId}`), so a reload trusts a prior fold and shows the row
  green WITHOUT re-folding — re-folding only when the relay's hint opCount exceeds
  the recorded one (verdictIsFresh). Failures are never persisted (transient).

  A FAILURE IS NOT ONE THING, and the row says which it was. A divergence (a
  relay serving a rewritten history) is a typed error with its own panel; a log
  that ANSWERED and failed a signature or CID check here is a statement about
  what was served; a timeout is a failure to look. The first two are terminal and
  red, the third is amber and RETRYABLE — and a relay-set change clears all of
  them, because every one of them was a verdict about a relay set the reader has
  since changed.

*/

import { divergenceErrorFrom } from '@metalabel/dfos-client';
import { useEffect, useState } from 'preact/hooks';
import { getClient, isVerificationFailure } from './client';
import type { VerifyVerdict } from './db';
import { getDb } from './db-instance';
import { subscribeRelays } from './relays';
import { currentDbGeneration, jitIndexChain, writeIfCurrent } from './sync-store';

/** The chain kinds a browse row can carry — the only two that fold as a history. */
export type VerifyKind = 'identity' | 'content';

/**
 * attributed = relay hint, unverified · verifying = fold in flight · verified =
 * folded + re-checked in the tab · diverged = the relays serve a history that
 * contradicts the verified prefix this tab pinned · unverified = a relay
 * answered and its log failed verification here · error = the fold could not be
 * made at all (a timeout, an unreachable relay), which is not a finding about
 * the chain and is the one failure a re-enqueue retries.
 */
export type VerifyStatus =
  | 'attributed'
  | 'verifying'
  | 'verified'
  | 'diverged'
  | 'unverified'
  | 'error';

/** What the fold learned that a row should reconcile to — the fold wins over the
 *  index hint. Both fields are order-independent (branch-inclusive log length,
 *  terminal deletion state) so they need no head selection to be correct. */
export interface VerifiedFacts {
  isDeleted: boolean;
  opCount: number;
}

export interface VerifyRecord {
  status: VerifyStatus;
  facts?: VerifiedFacts;
  error?: string;
}

/** In-flight resolves at once — mirrors sync-projections' bounded pool so the two
 *  background verifiers stay equally polite to relays. */
const CONCURRENCY = 8;

const key = (kind: VerifyKind, chainId: string): string => `${kind}:${chainId}`;

/**
 * A durable verdict is fresh enough to trust WITHOUT re-folding when its folded
 * opCount is at least the relay index's current hint. opCount is branch-inclusive
 * and monotonic, so a hint ABOVE the recorded count means a newer op the verdict
 * predates — re-fold. No hint (undefined) → trust the durable verdict.
 *
 * DELIBERATE THREAT-MODEL CHOICE (not an oversight): freshness is keyed on the
 * op COUNT (+ isDeleted), NOT the head CID. A relay could in principle serve a
 * DIFFERENT branch with the SAME opCount and this would reuse the prior verdict
 * without a re-fold. That's accepted, and matches the existing in-session stale
 * check (also opCount-based — non-regression), because: (a) the fold that PRODUCED
 * the verdict already re-checked every signature and CID, so a fabricated chain
 * never becomes a verdict in the first place; (b) opCount is branch-inclusive and
 * only grows, so real new activity always trips a re-fold; (c) this drives a
 * browse-row hint, and the detail page is always the rigorous, head-bound proof.
 * A head-CID-bound verdict would be strictly stronger — a candidate hardening, not
 * a bug — if browse rows ever become a verification input.
 */
export const verdictIsFresh = (verdictOpCount: number, hintOpCount?: number): boolean =>
  hintOpCount === undefined || verdictOpCount >= hintOpCount;

/**
 * Which failure a throw from the fold is. The order is the order of specificity:
 * a divergence is a typed error the client raises against a prefix this tab
 * pinned; a verification failure is a relay having ANSWERED with a log that did
 * not check out; everything left is a failure to look, which says nothing about
 * the chain and is the only one a re-enqueue retries. Pure, unit-tested.
 */
export const failureStatus = (err: unknown): VerifyStatus => {
  if (divergenceErrorFrom(err)) return 'diverged';
  if (isVerificationFailure(err)) return 'unverified';
  return 'error';
};

/** Best-effort read of a durable verdict — never throws (persistence is an
 *  optimization; a miss just means we fold). */
const loadVerdict = async (k: string): Promise<VerifyVerdict | undefined> => {
  try {
    return await (await getDb()).getVerify(k);
  } catch {
    return undefined;
  }
};

/** Best-effort persist of a fold verdict so a reload trusts it without a fold.
 *  Fenced on the wipe generation captured when the fold began: a verdict landing
 *  after a reset would leave the emptied store asserting a chain was verified,
 *  with none of the ops that verdict was folded from. */
const persistVerdict = async (
  k: string,
  facts: VerifiedFacts,
  generation: number,
): Promise<void> => {
  try {
    const db = await getDb();
    await writeIfCurrent(generation, async () => {
      await db.putVerify({
        key: k,
        opCount: facts.opCount,
        isDeleted: facts.isDeleted,
        verifiedAt: Date.now(),
      });
    });
  } catch {
    // durable verdicts are an optimization, never a correctness requirement
  }
};

const records = new Map<string, VerifyRecord>();
const queue: { kind: VerifyKind; chainId: string; hintOpCount?: number }[] = [];
let active = 0;

type Listener = () => void;
const listeners = new Set<Listener>();
const emit = (): void => {
  for (const fn of listeners) fn();
};

const setRecord = (k: string, rec: VerifyRecord): void => {
  records.set(k, rec);
  emit();
};

/** Hydrate-then-fold one chain: trust a fresh durable verdict without a network
 *  fold, else fold through dfos-client, land it in the local index, record the
 *  verified facts, and persist them. A throw is classified into one of the three
 *  failure states (NOT persisted — a failure is transient). */
const run = async (kind: VerifyKind, chainId: string, hintOpCount?: number): Promise<void> => {
  const k = key(kind, chainId);
  // the fold below is a network round trip; a reset can land inside it. Both
  // writes this job makes are fenced on the store as it stands NOW, so neither
  // repopulates an index the user has since cleared (lib/sync-store.ts).
  const generation = currentDbGeneration();
  try {
    // durable verdict first: a prior fold recorded at an opCount >= the relay's
    // current hint is trusted with NO network fold — the ops are already local,
    // only the verdict was ephemeral. Reload shows the row green instantly.
    const durable = await loadVerdict(k);
    if (durable && verdictIsFresh(durable.opCount, hintOpCount)) {
      setRecord(k, {
        status: 'verified',
        facts: { isDeleted: durable.isDeleted, opCount: durable.opCount },
      });
      return;
    }
    const client = getClient();
    // client.identity/content re-fold the whole chain in the tab; client.log
    // returns the same verified op log we hand to jitIndexChain (fire-and-forget
    // best-effort local indexing, exactly as the detail views do).
    if (kind === 'identity') {
      const [res, log] = await Promise.all([
        client.identity(chainId),
        client.log('identity', chainId),
      ]);
      void jitIndexChain(chainId, 'identity-op', log.value, generation);
      const facts: VerifiedFacts = { isDeleted: res.value.isDeleted, opCount: log.value.length };
      setRecord(k, { status: 'verified', facts });
      void persistVerdict(k, facts, generation);
    } else {
      const [res, log] = await Promise.all([
        client.content(chainId),
        client.log('content', chainId),
      ]);
      void jitIndexChain(chainId, 'content-op', log.value, generation);
      const facts: VerifiedFacts = {
        isDeleted: res.value.chain.isDeleted,
        opCount: log.value.length,
      };
      setRecord(k, { status: 'verified', facts });
      void persistVerdict(k, facts, generation);
    }
  } catch (e) {
    setRecord(k, {
      status: failureStatus(e),
      error: e instanceof Error ? e.message : String(e),
    });
  } finally {
    active -= 1;
    pump();
  }
};

// Every failure verdict here is a verdict about a RELAY SET — "these relays did
// not answer", "these relays served a log that did not check out" — so changing
// the set retires it and the next enqueue asks again. Verified records survive:
// they are bound to the chain by math, not to the relays that served it. An
// in-flight 'verifying' record is left alone rather than cleared, so a relay
// switch never starts a second fold for a chain already folding.
subscribeRelays(() => {
  let dropped = false;
  for (const [k, rec] of records) {
    if (rec.status === 'verified' || rec.status === 'verifying') continue;
    records.delete(k);
    dropped = true;
  }
  if (dropped) emit();
});

const pump = (): void => {
  while (active < CONCURRENCY && queue.length > 0) {
    const job = queue.shift()!;
    active += 1;
    void run(job.kind, job.chainId, job.hintOpCount);
  }
};

/**
 * Enqueue a row for verification. Idempotent: a chain already verifying, verified,
 * diverged, or unverified is never re-folded — with two escapes:
 *
 *   1. a verified record whose folded opCount is LOWER than the relay hint's is
 *      stale (opCount is branch-inclusive, so any new op raises it), and letting
 *      stale fold facts win over a fresher hint would display old data labeled
 *      "verified". Such a row re-folds.
 *   2. an `error` record is a failure to LOOK, not a finding — it says nothing
 *      about the chain, so it must not be terminal for the session. A re-enqueue
 *      (the row scrolling back into view, or a relay-set change having cleared
 *      the map) tries again. `diverged` and `unverified` are findings and stay.
 *
 * First enqueue flips the row to 'verifying' so the badge shows progress
 * immediately, even before a worker slot frees up.
 */
export const enqueueVerify = (kind: VerifyKind, chainId: string, hintOpCount?: number): void => {
  const k = key(kind, chainId);
  const existing = records.get(k);
  if (existing) {
    const stale =
      existing.status === 'verified' &&
      existing.facts !== undefined &&
      typeof hintOpCount === 'number' &&
      hintOpCount > existing.facts.opCount;
    const retryable = existing.status === 'error';
    if (!stale && !retryable) return; // already folded / in flight — no-op
  }
  setRecord(k, { status: 'verifying' });
  queue.push({ kind, chainId, ...(hintOpCount !== undefined ? { hintOpCount } : {}) });
  pump();
};

/** Read a row's verification record, re-rendering when it changes. Returns the
 *  attributed floor until the row has been enqueued. */
export const useVerifyStatus = (kind: VerifyKind, chainId: string): VerifyRecord => {
  const k = key(kind, chainId);
  const [rec, setRec] = useState<VerifyRecord>(() => records.get(k) ?? { status: 'attributed' });
  useEffect(() => {
    const read = (): void => setRec(records.get(k) ?? { status: 'attributed' });
    read();
    listeners.add(read);
    return () => {
      listeners.delete(read);
    };
  }, [k]);
  return rec;
};
