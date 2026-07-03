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
import { isOpKind, type ChainRollup, type ExplorerDb, type ExplorerOp, type OpKind } from './db';

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

/** Page size for full-log sync — big pages, few roundtrips (relay caps at 1000). */
const SYNC_PAGE_LIMIT = 500;

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
    const page = await client.globalLog(cursor ?? undefined, {
      relays: [relay],
      limit: SYNC_PAGE_LIMIT,
    });
    if (!page.provenance.answeredBy) throw new Error(`relay unreachable: ${relay}`);
    if (page.entries.length === 0) break;

    const known = await db.knownOps(page.entries.map((e) => e.cid));
    const ops: ExplorerOp[] = [];
    const touched = new Map<string, ChainRollup>();
    for (const entry of page.entries) {
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

// -----------------------------------------------------------------------------
// JIT indexing — fold a single chain's ops into the local index on demand
//
// When you navigate straight to a chain (no full sync yet), the detail view has
// already fetched + VERIFIED the op log via the client. Landing those ops in the
// index makes the chain browsable immediately and lets a later full sync skip
// them. The rollup is recomputed from the stored ops (not incrementally merged)
// so it is always exact regardless of overlap with a prior sync.
// -----------------------------------------------------------------------------

const decodeOpMeta = (jwsToken: string): { type: string; createdAt: string; kid: string } => {
  let type = '';
  let createdAt = '';
  let kid = '';
  const decoded = decodeJwsUnsafe(jwsToken);
  if (decoded) {
    if (typeof decoded.payload['type'] === 'string') type = decoded.payload['type'];
    if (typeof decoded.payload['createdAt'] === 'string') createdAt = decoded.payload['createdAt'];
    if (typeof decoded.header.kid === 'string') kid = decoded.header.kid;
  }
  return { type, createdAt, kid };
};

const rollupFrom = (chainId: string, kind: OpKind, ops: ExplorerOp[]): ChainRollup => {
  const rollup: ChainRollup = {
    chainId,
    kind,
    opCount: ops.length,
    firstCreatedAt: '',
    lastCreatedAt: '',
    headCid: '',
  };
  for (const op of ops) {
    if (!rollup.firstCreatedAt || (op.createdAt && op.createdAt < rollup.firstCreatedAt))
      rollup.firstCreatedAt = op.createdAt;
    if (op.createdAt >= rollup.lastCreatedAt) {
      rollup.lastCreatedAt = op.createdAt;
      rollup.headCid = op.cid;
    }
  }
  return rollup;
};

/**
 * Land a single chain's ops into the local index (idempotent by CID) and
 * recompute its rollup. `ops` are the verified log entries the detail view
 * already holds. Returns how many were newly added.
 */
export const indexChainOps = async (
  db: ExplorerDb,
  chainId: string,
  kind: OpKind,
  ops: { cid: string; jwsToken: string }[],
): Promise<{ added: number }> => {
  const usable = ops.filter((o) => o.cid && o.jwsToken);
  if (!chainId || usable.length === 0) return { added: 0 };

  const known = await db.knownOps(usable.map((o) => o.cid));
  const rows: ExplorerOp[] = usable.map((o, i) => {
    const meta = decodeOpMeta(o.jwsToken);
    return { cid: o.cid, jwsToken: o.jwsToken, kind, chainId, seq: i, ...meta };
  });
  await db.putBatch(rows, []);

  // recompute the rollup from the authoritative stored set (exact, not merged)
  const stored = await db.chainOps(chainId, kind);
  await db.putBatch([], [rollupFrom(chainId, kind, stored)]);

  const added = usable.filter((o) => !known.has(o.cid)).length;
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
