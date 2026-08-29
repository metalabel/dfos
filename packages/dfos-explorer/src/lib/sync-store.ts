/*

  SYNC STORE — the global, nav-resilient sync engine

  Sync used to live in the LocalIndex component, so it died the moment you
  navigated away and could never drive a header/home indicator. This lifts it to
  a module singleton (observable, like relays.ts): one sync runs at a time, its
  progress is broadcast to every subscriber, and it survives route changes —
  tapping an index row mid-sync keeps the pull going in the background.

  Progress is deliberately INDETERMINATE. globalLog is cursor-paged with no known
  total, and "completeness is outside the proof" is the whole ethos — so the UI
  shows a live op/chain count and an animated pulse, never a fabricated percent.

  Everything synced is relay-asserted browsing metadata. Verification happens
  later, at fold time, on the detail pages.

*/

import { useEffect, useState } from 'preact/hooks';
import { getClient } from './client';
import type { OpKind } from './db';
import { getDb } from './db-instance';
import { clearDivergenceReport } from './divergence-store';
import { fmtCount, short } from './format';
import { getRelays } from './relays';
import { getAutoSyncMinutes } from './settings';
import { indexChainOps, syncAll, type SyncProgress } from './sync';
import { resolvePublicProjections } from './sync-projections';

// 'syncing' = Phase 1 (log paging); 'resolving' = Phase 2 (public projections).
export type SyncPhase = 'idle' | 'syncing' | 'resolving' | 'done' | 'error';

export interface SyncState {
  phase: SyncPhase;
  /** relay currently being paged (short host), '' when idle */
  relay: string;
  /** ops seen on the current relay this run */
  ops: number;
  /** rollup chain count after the latest page */
  chains: number;
  /** new ops added across the run */
  added: number;
  /** human status line */
  status: string;
  /** last error message, '' when none */
  error: string;
  /** ms epoch the current/last run started (0 = never) — via Date.now on a click */
  startedAt: number;
  /** ms epoch the last run finished successfully (0 = never) */
  lastSyncAt: number;
  /** how it was kicked off — surfaced so the indicator can read 'auto' quietly */
  trigger: 'manual' | 'auto' | null;
  /** Phase-2: content chains resolved this run */
  resolved: number;
  /** Phase-2: of those, resolved to a public integrity-checked document */
  publicDocs: number;
  /** bumped on any local-db mutation (sync page, wipe, JIT write) so every
   *  subscriber re-reads counts — the single "the index changed" signal */
  dbEpoch: number;
}

const LS_LAST_SYNC = 'dfos.explorer.lastSyncAt';

const loadLastSync = (): number => {
  try {
    const raw = globalThis.localStorage?.getItem(LS_LAST_SYNC);
    const n = raw ? Number(raw) : 0;
    return Number.isFinite(n) ? n : 0;
  } catch {
    return 0;
  }
};

let state: SyncState = {
  phase: 'idle',
  relay: '',
  ops: 0,
  chains: 0,
  added: 0,
  status: '',
  error: '',
  startedAt: 0,
  lastSyncAt: loadLastSync(),
  trigger: null,
  resolved: 0,
  publicDocs: 0,
  dbEpoch: 0,
};

type Listener = (s: SyncState) => void;
const listeners = new Set<Listener>();

const emit = (): void => {
  const snapshot = state;
  for (const fn of listeners) fn(snapshot);
};

const set = (patch: Partial<SyncState>): void => {
  state = { ...state, ...patch };
  emit();
};

export const getSyncState = (): SyncState => state;

/** Signal that the local index changed (wipe, JIT single-chain write, …) so
 *  every subscriber re-reads its counts. Sync progress bumps this on its own. */
export const markDbChanged = (): void => set({ dbEpoch: state.dbEpoch + 1 });

// -----------------------------------------------------------------------------
// THE WIPE GENERATION — a write fence for fire-and-forget writers
//
// A reset WIPES the store, and several writers here are fire-and-forget:
// jitIndexChain runs off a detail view's fold, and the verify queue persists a
// verdict after a network round trip. Either can be in flight when the wipe
// lands, and a write that resolves afterwards repopulates a store the UI has
// already reported as cleared — with, in the worst case, exactly the dropped
// history a reset exists to forget. `resetLocalIndex` refusing while a full sync
// holds the controller does nothing about these: they take no controller.
//
// So a background writer captures the generation BEFORE its awaits and hands it
// to {@link writeIfCurrent}, which drops the write when a wipe has happened since.
//
// THIS IS NOT `dbEpoch`, deliberately. dbEpoch bumps on ANY local mutation — every
// sync page, every JIT add — so fencing on it would make one background write
// cancel another's, silently losing legitimate rows. The fence's question is
// narrower and is the only one that matters: was the store I read my handle for
// DESTROYED under me? Only a wipe answers yes.
//
// It is advisory in the strict sense — nothing stops a write already inside an
// IndexedDB transaction — but it closes the window that actually happens: the
// seconds between "this work started" and "its rows would land".
// -----------------------------------------------------------------------------

let wipeGeneration = 0;

/** The wipe generation as it stands right now. A fire-and-forget writer reads
 *  this before it starts and hands it back to {@link writeIfCurrent}. */
export const currentDbGeneration = (): number => wipeGeneration;

/**
 * Run a local-index write only if the store has not been wiped since
 * `generation` was read. Returns whether the write ran, so a caller can tell
 * "wrote nothing" from "did not write".
 */
export const writeIfCurrent = async (
  generation: number,
  write: () => Promise<void>,
): Promise<boolean> => {
  if (generation !== wipeGeneration) return false;
  await write();
  return true;
};

export const subscribeSync = (fn: Listener): (() => void) => {
  listeners.add(fn);
  return () => listeners.delete(fn);
};

let controller: AbortController | null = null;

export const isSyncing = (): boolean => state.phase === 'syncing';

/**
 * Kick a full-log sync. Idempotent while one is running (returns the in-flight
 * promise). Progress paints are throttled by the caller-free store itself.
 */
export const startSync = async (trigger: 'manual' | 'auto' = 'manual'): Promise<void> => {
  if (controller) return; // one at a time — a second click is a no-op
  const relays = getRelays();
  controller = new AbortController();
  const signal = controller.signal;
  set({
    phase: 'syncing',
    relay: '',
    ops: 0,
    chains: 0,
    added: 0,
    resolved: 0,
    publicDocs: 0,
    error: '',
    status: 'starting…',
    startedAt: Date.now(),
    trigger,
  });

  try {
    const db = await getDb();
    const result = await syncAll({
      db,
      client: getClient(),
      relays,
      signal,
      onProgress: (p: SyncProgress) => {
        set({
          relay: short(p.relay.replace(/^https?:\/\//, ''), 22, 0),
          ops: p.count,
          chains: p.chains,
          added: p.added,
          status: `${fmtCount(p.count)} ops · ${fmtCount(p.chains)} chains`,
          dbEpoch: state.dbEpoch + 1,
        });
      },
    });

    // aborted during Phase 1 — leave what landed, do NOT auto-continue Phase 2
    if (signal.aborted) {
      set({ phase: 'idle', status: 'stopped' });
      return;
    }

    // Phase 2 (decision C): auto-continue into public-projection resolution
    const proj = await runProjections(db, relays, signal);

    // aborted mid-Phase-2 — resolvePublicProjections breaks its loop and returns
    // partial tallies rather than throwing, so re-check before claiming "done"
    // (else we'd persist a false lastSyncAt and hide the interrupted resolution)
    if (signal.aborted) {
      set({ phase: 'idle', status: 'stopped' });
      return;
    }

    // a run that ADDED operations changed the mirror the standing divergence
    // verdict was about — the ops it sampled were not these — so retire it rather
    // than let the home banner keep printing an answer to the old question. A run
    // that added nothing left the corpus exactly as the verdict found it.
    if (result.added > 0) clearDivergenceReport();

    const now = Date.now();
    persistLastSync(now);
    const projLine = proj ? ` · ${fmtCount(proj.publicDocs)} public docs` : '';
    set({
      phase: 'done',
      lastSyncAt: now,
      status: result.errors.length
        ? `done · ${result.errors.length} relay error(s): ${result.errors
            .map((e) => e.error)
            .join('; ')}`
        : `done · +${fmtCount(result.added)} new ops${projLine}`,
      error: result.errors.length ? result.errors.map((e) => e.error).join('; ') : '',
    });
  } catch (e) {
    if (signal.aborted) {
      set({ phase: 'idle', status: 'stopped' });
    } else {
      const msg = e instanceof Error ? e.message : String(e);
      set({ phase: 'error', error: msg, status: `sync failed: ${msg}` });
    }
  } finally {
    controller = null;
  }
};

/**
 * Phase 2 — resolve public projections. Sets `phase: 'resolving'` and streams
 * progress; returns the tallies (or null if aborted before it began). Shared by
 * the auto-continue path and the standalone `startProjections` re-run.
 */
const runProjections = async (
  db: Awaited<ReturnType<typeof getDb>>,
  relays: string[],
  signal: AbortSignal,
): Promise<{ publicDocs: number; attributed: number } | null> => {
  if (signal.aborted) return null;
  set({ phase: 'resolving', resolved: 0, publicDocs: 0, status: 'resolving public projections…' });
  const proj = await resolvePublicProjections({
    db,
    relays,
    signal,
    onProgress: (p) => {
      set({
        resolved: p.resolved,
        publicDocs: p.publicDocs,
        status: `resolving ${fmtCount(p.resolved)}/${fmtCount(p.total)} chains · ${fmtCount(
          p.publicDocs,
        )} public`,
        dbEpoch: state.dbEpoch + 1,
      });
    },
  });
  return proj;
};

/**
 * Run ONLY Phase 2, resuming from where prior resolutions left off (chains whose
 * head hasn't drifted are skipped). Separately abortable from a full sync — the
 * op log stays as it is; this only fills in the browse projections.
 */
export const startProjections = async (): Promise<void> => {
  if (controller) return;
  const relays = getRelays();
  controller = new AbortController();
  const signal = controller.signal;
  set({ startedAt: Date.now(), trigger: 'manual', error: '' });
  try {
    const db = await getDb();
    await runProjections(db, relays, signal);
    set({
      phase: signal.aborted ? 'idle' : 'done',
      status: signal.aborted ? 'stopped' : `done · resolved projections`,
    });
  } catch (e) {
    if (signal.aborted) {
      set({ phase: 'idle', status: 'stopped' });
    } else {
      const msg = e instanceof Error ? e.message : String(e);
      set({ phase: 'error', error: msg, status: `resolve failed: ${msg}` });
    }
  } finally {
    controller = null;
  }
};

export const stopSync = (): void => {
  controller?.abort();
};

/** True while Phase 2 (public projections) is resolving. */
export const isResolving = (): boolean => state.phase === 'resolving';

/**
 * Just-in-time index a single chain the detail view already fetched + verified.
 * Best-effort and fire-and-forget: a failure here never blocks the view (the
 * page renders from the client fold regardless). On any real add it signals the
 * index changed so the local-index panel and home hero re-read their counts.
 *
 * FENCED ON THE WIPE GENERATION. The caller's fold is a network round trip and a
 * reset can land inside it, so `generation` is the generation as it stood when
 * that work BEGAN — the caller reads {@link currentDbGeneration} before its
 * awaits and passes it here. When it is omitted the generation is read at entry,
 * which still covers this function's own awaits (the db open, the write itself).
 * A fenced-out write is dropped silently: the rows are a cache of a fold the view
 * already has, and they land again on the next visit.
 */
export const jitIndexChain = async (
  chainId: string,
  kind: OpKind,
  ops: { cid: string; jwsToken: string }[],
  generation: number = currentDbGeneration(),
): Promise<void> => {
  try {
    const db = await getDb();
    await writeIfCurrent(generation, async () => {
      const { added } = await indexChainOps(db, chainId, kind, ops);
      if (added > 0) markDbChanged();
    });
  } catch {
    // indexing is an optimization, never a correctness requirement
  }
};

const persistLastSync = (ms: number): void => {
  try {
    globalThis.localStorage?.setItem(LS_LAST_SYNC, String(ms));
  } catch {
    // storage unavailable — in-memory value still drives this session
  }
};

/**
 * Clear the local index and everything derived from it, so the next sync starts
 * from nothing. LOCAL ONLY — nothing is submitted, deleted, or retracted on any
 * relay; this drops a cache.
 *
 * Why it has to exist: the index is append-only by design (a relay must not be
 * able to make you forget what it served you), so a relay that DROPS operations
 * leaves the tab holding history no relay carries any more — and the local
 * figures, which are preferred precisely because they are locally counted, then
 * describe a corpus that isn't there. Resetting is the only way back.
 *
 * Refuses while a run is in flight rather than wiping under it — the caller
 * stops the sync first (the reset control is disabled until then). That refusal
 * only covers the FULL SYNC, which is the one writer holding the controller; the
 * fire-and-forget writers (JIT chain indexing, verdict persistence) take no
 * controller and are fenced instead — the generation bumps HERE, before the wipe,
 * so any write already under way is dropped rather than landing behind it.
 *
 * `lastSyncAt` is cleared alongside the store, not merely zeroed in memory: a
 * surviving timestamp would tell auto-sync the emptied index is fresh and it
 * would never rebuild (same reasoning as the db upgrade path in db.ts).
 */
export const resetLocalIndex = async (): Promise<boolean> => {
  if (controller) return false;
  // bump BEFORE the wipe: a writer whose rows would land after this point is
  // writing into a store that is already, as far as the user is concerned, gone
  wipeGeneration += 1;
  const db = await getDb();
  await db.wipe();
  try {
    globalThis.localStorage?.removeItem(LS_LAST_SYNC);
  } catch {
    // storage unavailable — the in-memory reset below still holds this session
  }
  set({
    phase: 'idle',
    relay: '',
    ops: 0,
    chains: 0,
    added: 0,
    resolved: 0,
    publicDocs: 0,
    status: 'local data cleared',
    error: '',
    startedAt: 0,
    lastSyncAt: 0,
    trigger: null,
    dbEpoch: state.dbEpoch + 1,
  });
  return true;
};

// -----------------------------------------------------------------------------
// auto-sync — a single heartbeat that fires a background sync when the index
// is older than the configured cadence. A 30s tick keeps it simple: setting
// changes, load-time staleness, and post-run rescheduling all fall out of the
// same due-check, no timer juggling.
// -----------------------------------------------------------------------------

const HEARTBEAT_MS = 30_000;

/** ms epoch the next auto-sync is due, or 0 when auto-sync is off. */
export const nextAutoSyncAt = (): number => {
  const minutes = getAutoSyncMinutes();
  if (minutes <= 0) return 0;
  const base = state.lastSyncAt || 0;
  return base + minutes * 60_000;
};

const autoTick = (): void => {
  const minutes = getAutoSyncMinutes();
  // skip while EITHER phase runs — a full sync holds the controller across Phase
  // 2, but guarding on the phase directly avoids relying on that as the only lock
  if (minutes <= 0 || isSyncing() || isResolving()) return;
  const due = state.lastSyncAt === 0 || Date.now() >= state.lastSyncAt + minutes * 60_000;
  if (due) void startSync('auto');
};

let heartbeat: ReturnType<typeof setInterval> | null = null;

/** Start the auto-sync heartbeat (idempotent). Returns a stop fn. */
export const startAutoSyncScheduler = (): (() => void) => {
  if (heartbeat === null) {
    heartbeat = setInterval(autoTick, HEARTBEAT_MS);
  }
  return () => {
    if (heartbeat !== null) {
      clearInterval(heartbeat);
      heartbeat = null;
    }
  };
};

/** Subscribe a component to the live sync state. */
export const useSyncState = (): SyncState => {
  const [snap, setSnap] = useState<SyncState>(getSyncState);
  useEffect(() => {
    setSnap(getSyncState());
    return subscribeSync(setSnap);
  }, []);
  return snap;
};
