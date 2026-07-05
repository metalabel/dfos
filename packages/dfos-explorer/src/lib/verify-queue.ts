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

*/

import { useEffect, useState } from 'preact/hooks';
import { getClient } from './client';
import { jitIndexChain } from './sync-store';

/** The chain kinds a browse row can carry — the only two that fold as a history. */
export type VerifyKind = 'identity' | 'content';

/** attributed = relay hint, unverified · verifying = fold in flight · verified =
 *  folded + re-checked in the tab · error = the fold failed or contradicted. */
export type VerifyStatus = 'attributed' | 'verifying' | 'verified' | 'error';

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

const records = new Map<string, VerifyRecord>();
const queue: { kind: VerifyKind; chainId: string }[] = [];
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

/** Fold one chain through dfos-client, land it in the local index, and record the
 *  verified facts. A throw (unreachable, tampered, contradiction) → status error. */
const run = async (kind: VerifyKind, chainId: string): Promise<void> => {
  const k = key(kind, chainId);
  try {
    const client = getClient();
    // client.identity/content re-fold the whole chain in the tab; client.log
    // returns the same verified op log we hand to jitIndexChain (fire-and-forget
    // best-effort local indexing, exactly as the detail views do).
    if (kind === 'identity') {
      const [res, log] = await Promise.all([
        client.identity(chainId),
        client.log('identity', chainId),
      ]);
      void jitIndexChain(chainId, 'identity-op', log.value);
      setRecord(k, {
        status: 'verified',
        facts: { isDeleted: res.value.isDeleted, opCount: log.value.length },
      });
    } else {
      const [res, log] = await Promise.all([
        client.content(chainId),
        client.log('content', chainId),
      ]);
      void jitIndexChain(chainId, 'content-op', log.value);
      setRecord(k, {
        status: 'verified',
        facts: { isDeleted: res.value.chain.isDeleted, opCount: log.value.length },
      });
    }
  } catch (e) {
    setRecord(k, { status: 'error', error: e instanceof Error ? e.message : String(e) });
  } finally {
    active -= 1;
    pump();
  }
};

const pump = (): void => {
  while (active < CONCURRENCY && queue.length > 0) {
    const job = queue.shift()!;
    active += 1;
    void run(job.kind, job.chainId);
  }
};

/**
 * Enqueue a row for verification. Idempotent: a chain already verifying, verified,
 * or errored is never re-folded — with one escape: a verified record whose folded
 * opCount is LOWER than the relay hint's is stale (opCount is branch-inclusive, so
 * any new op raises it), and letting stale fold facts win over a fresher hint would
 * display old data labeled "verified". Such a row re-folds. First enqueue flips the
 * row to 'verifying' so the badge shows progress immediately, even before a worker
 * slot frees up.
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
    if (!stale) return; // already folded / in flight — no-op
  }
  setRecord(k, { status: 'verifying' });
  queue.push({ kind, chainId });
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
