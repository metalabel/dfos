/*

  LOCAL INDEX — normalized IndexedDB store

  The explorer's local database: one row per operation (content-addressed by
  CID, so the pool unions cleanly across relays), a derived per-chain rollup,
  and a per-relay sync cursor. Chains fold OFFLINE from this store; nothing in
  here is a verification input — folds re-check every signature and CID.

  Stores:
    ops    (keyPath cid)      source of truth. idx: chainId, kind, createdAt
    chains (keyPath chainId)  derived rollup / materialized view. idx: kind, lastCreatedAt, opCount
    sync   (keyPath relay)    per-relay forward cursor

*/

/** Every operation kind the relay log can carry. */
export type OpKind =
  | 'identity-op'
  | 'content-op'
  | 'artifact'
  | 'countersign'
  | 'revocation'
  | 'credential';

export const OP_KINDS: readonly OpKind[] = [
  'identity-op',
  'content-op',
  'artifact',
  'countersign',
  'revocation',
  'credential',
];

export const isOpKind = (v: unknown): v is OpKind => OP_KINDS.includes(v as OpKind);

/**
 * Kinds that form a linked HISTORY under one chainId (identity / content), so a
 * per-chain rollup is the meaningful unit. Everything else is a standalone OP
 * that chains under some other primitive's chainId — most importantly a
 * `credential` chains under its ISSUER DID, colliding with that identity's
 * chain. Counting those by rollup-kind under-counts them (last-writer-wins on
 * the shared chainId); they must be counted from the `ops` store instead.
 */
export const CHAIN_KINDS: readonly OpKind[] = ['identity-op', 'content-op'];

/** One operation row. `kind`/`chainId` are relay-asserted routing hints. */
export interface ExplorerOp {
  cid: string;
  jwsToken: string;
  kind: OpKind;
  chainId: string;
  /** payload.type when decodable ('create' | 'update' | 'delete' | …) */
  type: string;
  /** payload.createdAt — fixed-width grammar, lexicographically chronological */
  createdAt: string;
  /** header.kid when present ('' for genesis ops) */
  kid: string;
  /** arrival index — stable sort tiebreak only */
  seq: number;
}

/** Derived per-chain rollup — a browsing index, recomputed incrementally on sync. */
export interface ChainRollup {
  chainId: string;
  kind: OpKind;
  opCount: number;
  firstCreatedAt: string;
  lastCreatedAt: string;
  headCid: string;
}

/** Per-relay sync cursor. `count` doubles as the next arrival seq. */
export interface SyncCursor {
  relay: string;
  cursor: string | null;
  count: number;
  updatedAt: string;
}

export interface ChainsQuery {
  sort: 'recent' | 'ops';
  kind?: OpKind | undefined;
  limit: number;
}

export interface ExplorerDb {
  putBatch(ops: ExplorerOp[], rollups: ChainRollup[]): Promise<void>;
  getOp(cid: string): Promise<ExplorerOp | undefined>;
  /** Which of these CIDs are already stored — one transaction, batched. */
  knownOps(cids: string[]): Promise<Set<string>>;
  /** A chain's ops sorted createdAt asc, seq asc. MUST pass `kind` for identity
   *  chains — credentials issued by a DID share that DID's chainId. */
  chainOps(chainId: string, kind?: OpKind): Promise<ExplorerOp[]>;
  getChain(chainId: string): Promise<ChainRollup | undefined>;
  allChains(): Promise<ChainRollup[]>;
  /** Ops of a single kind, newest first — the browsable list for op-primitives
   *  (credentials, artifacts) that don't surface as their own chain rollup. */
  opsOfKind(kind: OpKind, limit: number): Promise<ExplorerOp[]>;
  /**
   * counts.byKind is per-primitive: CHAIN counts for identity/content, OP counts
   * for credential/artifact/etc. (see CHAIN_KINDS) — so a credential colliding
   * with its issuer's identity chain is still counted.
   */
  counts(): Promise<{ ops: number; chains: number; byKind: Partial<Record<OpKind, number>> }>;
  chainsQuery(q: ChainsQuery): Promise<ChainRollup[]>;
  getCursor(relay: string): Promise<SyncCursor | undefined>;
  setCursor(cursor: SyncCursor): Promise<void>;
  wipe(): Promise<void>;
  close(): void;
}

const DB_VERSION = 2;

// scan ceiling for filtered index-cursor queries — keeps worst case bounded
const MAX_SCAN = 8000;

const req = <T>(r: IDBRequest<T>): Promise<T> =>
  new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error ?? new Error('indexeddb request failed'));
  });

const done = (t: IDBTransaction): Promise<void> =>
  new Promise((resolve, reject) => {
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error ?? new Error('indexeddb transaction failed'));
    t.onabort = () => reject(t.error ?? new Error('indexeddb transaction aborted'));
  });

/**
 * Origin storage usage (bytes) via the StorageManager estimate — dominated by
 * this app's IndexedDB. `null` when the API is unavailable (older/locked-down
 * browsers). It's an estimate the browser rounds for privacy, not an exact
 * byte count, so it's surfaced as "~N MB".
 */
export const estimateStorageBytes = async (): Promise<number | null> => {
  try {
    const est = await globalThis.navigator?.storage?.estimate?.();
    return typeof est?.usage === 'number' ? est.usage : null;
  } catch {
    return null;
  }
};

export const openExplorerDb = async (
  name = 'dfos-explorer',
  factory?: IDBFactory,
): Promise<ExplorerDb> => {
  const idb = factory ?? globalThis.indexedDB;
  if (!idb) throw new Error('openExplorerDb requires an IndexedDB environment');

  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const open = idb.open(name, DB_VERSION);
    open.onupgradeneeded = () => {
      const d = open.result;
      // schema changed since the spike (cursor shape, seq semantics) — the
      // local index is a disposable cache, so upgrades rebuild from scratch
      for (const store of Array.from(d.objectStoreNames)) d.deleteObjectStore(store);
      const ops = d.createObjectStore('ops', { keyPath: 'cid' });
      ops.createIndex('chainId', 'chainId');
      ops.createIndex('kind', 'kind');
      ops.createIndex('createdAt', 'createdAt');
      const chains = d.createObjectStore('chains', { keyPath: 'chainId' });
      chains.createIndex('kind', 'kind');
      chains.createIndex('lastCreatedAt', 'lastCreatedAt');
      chains.createIndex('opCount', 'opCount');
      d.createObjectStore('sync', { keyPath: 'relay' });
    };
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error ?? new Error('indexeddb open failed'));
  });

  const putBatch = async (ops: ExplorerOp[], rollups: ChainRollup[]): Promise<void> => {
    const t = db.transaction(['ops', 'chains'], 'readwrite');
    const opsStore = t.objectStore('ops');
    const chainsStore = t.objectStore('chains');
    for (const op of ops) opsStore.put(op);
    for (const rollup of rollups) chainsStore.put(rollup);
    await done(t);
  };

  const getOp = async (cid: string): Promise<ExplorerOp | undefined> =>
    (await req(db.transaction('ops').objectStore('ops').get(cid))) as ExplorerOp | undefined;

  const knownOps = async (cids: string[]): Promise<Set<string>> => {
    const store = db.transaction('ops').objectStore('ops');
    const hits = await Promise.all(cids.map((cid) => req(store.getKey(cid))));
    const out = new Set<string>();
    hits.forEach((hit, i) => {
      const cid = cids[i];
      if (hit !== undefined && cid) out.add(cid);
    });
    return out;
  };

  const chainOps = async (chainId: string, kind?: OpKind): Promise<ExplorerOp[]> => {
    const rows = (await req(
      db.transaction('ops').objectStore('ops').index('chainId').getAll(chainId),
    )) as ExplorerOp[];
    const filtered = kind ? rows.filter((r) => r.kind === kind) : rows;
    filtered.sort(
      (a, b) =>
        (a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0) || a.seq - b.seq,
    );
    return filtered;
  };

  const getChain = async (chainId: string): Promise<ChainRollup | undefined> =>
    (await req(db.transaction('chains').objectStore('chains').get(chainId))) as
      | ChainRollup
      | undefined;

  const allChains = async (): Promise<ChainRollup[]> =>
    (await req(db.transaction('chains').objectStore('chains').getAll())) as ChainRollup[];

  const counts = async (): Promise<{
    ops: number;
    chains: number;
    byKind: Partial<Record<OpKind, number>>;
  }> => {
    const t = db.transaction(['ops', 'chains']);
    const opsStore = t.objectStore('ops');
    const chainsStore = t.objectStore('chains');
    const opsCount = req(opsStore.count());
    const chainsCount = req(chainsStore.count());
    const byKind: Partial<Record<OpKind, number>> = {};
    // per-primitive: chain-forming kinds counted as CHAINS, everything else
    // (credentials, artifacts…) counted as OPS from the ops store, so a
    // credential sharing its issuer's chainId is never swallowed by the rollup
    const kindCounts = await Promise.all(
      OP_KINDS.map((k) =>
        CHAIN_KINDS.includes(k)
          ? req(chainsStore.index('kind').count(k))
          : req(opsStore.index('kind').count(k)),
      ),
    );
    OP_KINDS.forEach((k, i) => {
      const n = kindCounts[i];
      if (n) byKind[k] = n;
    });
    return { ops: await opsCount, chains: await chainsCount, byKind };
  };

  const opsOfKind = async (kind: OpKind, limit: number): Promise<ExplorerOp[]> => {
    const rows = (await req(
      db.transaction('ops').objectStore('ops').index('kind').getAll(kind),
    )) as ExplorerOp[];
    rows.sort(
      (a, b) =>
        (a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : 0) || b.seq - a.seq,
    );
    return rows.slice(0, limit);
  };

  const chainsQuery = (q: ChainsQuery): Promise<ChainRollup[]> => {
    const store = db.transaction('chains').objectStore('chains');
    const index = q.sort === 'ops' ? store.index('opCount') : store.index('lastCreatedAt');
    const out: ChainRollup[] = [];
    let scanned = 0;
    return new Promise((resolve, reject) => {
      const cursorReq = index.openCursor(null, 'prev');
      cursorReq.onsuccess = () => {
        const cursor = cursorReq.result;
        if (!cursor || out.length >= q.limit || scanned >= MAX_SCAN) return resolve(out);
        scanned += 1;
        const row = cursor.value as ChainRollup;
        if (!q.kind || row.kind === q.kind) out.push(row);
        cursor.continue();
      };
      cursorReq.onerror = () => reject(cursorReq.error ?? new Error('chains query failed'));
    });
  };

  const getCursor = async (relay: string): Promise<SyncCursor | undefined> =>
    (await req(db.transaction('sync').objectStore('sync').get(relay))) as SyncCursor | undefined;

  const setCursor = async (cursor: SyncCursor): Promise<void> => {
    const t = db.transaction('sync', 'readwrite');
    t.objectStore('sync').put(cursor);
    await done(t);
  };

  const wipe = async (): Promise<void> => {
    const t = db.transaction(['ops', 'chains', 'sync'], 'readwrite');
    t.objectStore('ops').clear();
    t.objectStore('chains').clear();
    t.objectStore('sync').clear();
    await done(t);
  };

  return {
    putBatch,
    getOp,
    knownOps,
    chainOps,
    getChain,
    allChains,
    opsOfKind,
    counts,
    chainsQuery,
    getCursor,
    setCursor,
    wipe,
    close: () => db.close(),
  };
};
