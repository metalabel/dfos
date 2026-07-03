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
import { getDb } from './db-instance';
import { fmtCount, short } from './format';
import { getRelays } from './relays';
import { syncAll, type SyncProgress } from './sync';

export type SyncPhase = 'idle' | 'syncing' | 'done' | 'error';

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
  set({
    phase: 'syncing',
    relay: '',
    ops: 0,
    chains: 0,
    added: 0,
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
      signal: controller.signal,
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
    const now = Date.now();
    persistLastSync(now);
    set({
      phase: 'done',
      lastSyncAt: now,
      status: result.errors.length
        ? `done · ${result.errors.length} relay error(s): ${result.errors
            .map((e) => e.error)
            .join('; ')}`
        : `done · +${fmtCount(result.added)} new ops`,
      error: result.errors.length ? result.errors.map((e) => e.error).join('; ') : '',
    });
  } catch (e) {
    if (controller?.signal.aborted) {
      set({ phase: 'idle', status: 'stopped' });
    } else {
      const msg = e instanceof Error ? e.message : String(e);
      set({ phase: 'error', error: msg, status: `sync failed: ${msg}` });
    }
  } finally {
    controller = null;
  }
};

export const stopSync = (): void => {
  controller?.abort();
};

const persistLastSync = (ms: number): void => {
  try {
    globalThis.localStorage?.setItem(LS_LAST_SYNC, String(ms));
  } catch {
    // storage unavailable — in-memory value still drives this session
  }
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
