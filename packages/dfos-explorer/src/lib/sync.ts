/*

  SYNC ENGINE — full global log → local index

  Pages a relay's /log through the client's globalLog seam and lands every
  operation in the local IndexedDB index, maintaining the per-chain rollup
  incrementally. Resumable via the per-relay cursor. The pool is a union across
  relays — CIDs are content-addressed, so re-seeing an op is an idempotent put.

  Everything recorded here is relay-asserted browsing metadata. Verification
  happens later, at fold time, from the stored JWS tokens themselves.

*/

import type { Client } from '@metalabel/dfos-client';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { isOpKind, type ChainRollup, type ExplorerDb, type ExplorerOp } from './db';

export interface SyncProgress {
  relay: string;
  /** ops pulled from this relay so far (across all runs) */
  count: number;
  /** ops added this run */
  added: number;
  /** rollup size after this page */
  chains: number;
}

export interface SyncOptions {
  db: ExplorerDb;
  client: Client;
  relay: string;
  onProgress?: (p: SyncProgress) => void;
  signal?: AbortSignal;
}

/**
 * The relay's /log entries carry `kind` and `chainId` beyond the typed LogOp
 * floor (the peer-client passes the parsed JSON through untouched). Routing
 * hints only — never a verification input.
 */
interface AnnotatedLogOp {
  cid: string;
  jwsToken: string;
  kind?: unknown;
  chainId?: unknown;
}

export const syncFromRelay = async (options: SyncOptions): Promise<{ added: number }> => {
  const { db, client, relay, onProgress, signal } = options;

  const state = await db.getCursor(relay);
  let cursor = state?.cursor ?? null;
  let count = state?.count ?? 0;
  let added = 0;

  // preload the rollups once so per-page merges need no reads; counts are
  // incremented only for ops that were not already present (union across relays)
  const rollups = new Map<string, ChainRollup>();
  for (const chain of await db.allChains()) rollups.set(chain.chainId, chain);

  while (!signal?.aborted) {
    const page = await client.globalLog(cursor ?? undefined, { relays: [relay] });
    if (!page.provenance.answeredBy) throw new Error(`relay unreachable: ${relay}`);
    if (page.entries.length === 0) break;

    const known = await db.knownOps(page.entries.map((e) => e.cid));
    const ops: ExplorerOp[] = [];
    const touched = new Map<string, ChainRollup>();
    for (const entry of page.entries as AnnotatedLogOp[]) {
      const kind = isOpKind(entry.kind) ? entry.kind : 'artifact';
      const chainId = typeof entry.chainId === 'string' ? entry.chainId : '';
      if (!entry.cid || !entry.jwsToken || !chainId) continue;

      let type = '';
      let createdAt = '';
      let kid = '';
      const decoded = decodeJwsUnsafe(entry.jwsToken);
      if (decoded) {
        if (typeof decoded.payload['type'] === 'string') type = decoded.payload['type'];
        if (typeof decoded.payload['createdAt'] === 'string')
          createdAt = decoded.payload['createdAt'];
        if (typeof decoded.header.kid === 'string') kid = decoded.header.kid;
      }

      ops.push({
        cid: entry.cid,
        jwsToken: entry.jwsToken,
        kind,
        chainId,
        type,
        createdAt,
        kid,
        seq: count,
      });
      count += 1;

      if (!known.has(entry.cid)) {
        const rollup = rollups.get(chainId) ?? {
          chainId,
          kind,
          opCount: 0,
          firstCreatedAt: createdAt,
          lastCreatedAt: '',
          headCid: '',
        };
        rollup.opCount += 1;
        rollup.kind = kind;
        if (!rollup.firstCreatedAt || (createdAt && createdAt < rollup.firstCreatedAt))
          rollup.firstCreatedAt = createdAt;
        if (createdAt >= rollup.lastCreatedAt) {
          rollup.lastCreatedAt = createdAt;
          rollup.headCid = entry.cid;
        }
        rollups.set(chainId, rollup);
        touched.set(chainId, rollup);
        added += 1;
      }
    }

    await db.putBatch(ops, [...touched.values()]);
    cursor = page.cursor;
    await db.setCursor({ relay, cursor, count, updatedAt: new Date().toISOString() });
    onProgress?.({ relay, count, added, chains: rollups.size });
    if (!cursor) break;
  }

  return { added };
};

/** Sync every relay in order; failures are per-relay, not fatal to the run. */
export const syncAll = async (
  options: Omit<SyncOptions, 'relay'> & { relays: string[] },
): Promise<{ added: number; errors: { relay: string; error: string }[] }> => {
  let added = 0;
  const errors: { relay: string; error: string }[] = [];
  for (const relay of options.relays) {
    if (options.signal?.aborted) break;
    try {
      const result = await syncFromRelay({ ...options, relay });
      added += result.added;
    } catch (e) {
      errors.push({ relay, error: e instanceof Error ? e.message : String(e) });
    }
  }
  return { added, errors };
};
