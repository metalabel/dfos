/*

  SETTINGS — small user preferences, localStorage-backed, observable

  Currently just the auto-sync interval. Kept separate from relays.ts because
  these are UI ergonomics, not the trust-relevant relay/quorum parameters.

*/

const AUTO_SYNC_KEY = 'dfos.explorer.autoSyncMinutes';

/** Allowed auto-sync cadences in minutes; 0 = off. */
export const AUTO_SYNC_OPTIONS = [0, 5, 15, 30, 60] as const;
export type AutoSyncMinutes = (typeof AUTO_SYNC_OPTIONS)[number];

type Listener = () => void;
const listeners = new Set<Listener>();

const storage = (): Storage | undefined => {
  try {
    return globalThis.localStorage;
  } catch {
    return undefined;
  }
};

const isValid = (n: number): n is AutoSyncMinutes =>
  (AUTO_SYNC_OPTIONS as readonly number[]).includes(n);

export const getAutoSyncMinutes = (): AutoSyncMinutes => {
  try {
    const raw = storage()?.getItem(AUTO_SYNC_KEY);
    const n = raw ? Number(raw) : 0;
    if (isValid(n)) return n;
  } catch {
    // fall through to default
  }
  return 0;
};

export const setAutoSyncMinutes = (n: number): void => {
  const value: AutoSyncMinutes = isValid(n) ? n : 0;
  try {
    storage()?.setItem(AUTO_SYNC_KEY, String(value));
  } catch {
    // storage unavailable — in-memory listeners still fire for this session
  }
  for (const fn of listeners) fn();
};

export const subscribeSettings = (fn: Listener): (() => void) => {
  listeners.add(fn);
  return () => listeners.delete(fn);
};
