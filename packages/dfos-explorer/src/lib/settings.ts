/*

  SETTINGS — small user preferences, localStorage-backed, observable

  The auto-sync interval, the public-only feed filter, and whether the home
  intro has been dismissed. Kept separate from relays.ts because these are UI
  ergonomics, not the trust-relevant relay/quorum parameters.

*/

const AUTO_SYNC_KEY = 'dfos.explorer.autoSyncMinutes';
const PUBLIC_ONLY_KEY = 'dfos.explorer.publicOnly';
const INTRO_DISMISSED_KEY = 'dfos.explorer.introDismissed';

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

/**
 * Whether content feeds hide gated (non-public-read) rows. Defaults to ON —
 * public-only is what a stranger's explorer should show first, and a gated row
 * carries no readable title to show anyway. A `pub` hash param overrides this
 * per-link; the toggle writes both.
 */
export const getPublicOnly = (): boolean => {
  try {
    return storage()?.getItem(PUBLIC_ONLY_KEY) !== '0';
  } catch {
    return true;
  }
};

export const setPublicOnly = (on: boolean): void => {
  try {
    storage()?.setItem(PUBLIC_ONLY_KEY, on ? '1' : '0');
  } catch {
    // storage unavailable — the hash param still carries it for this view
  }
  for (const fn of listeners) fn();
};

/**
 * Whether the home intro has been dismissed. One-way: it defaults to false, the
 * dismiss writes true, and nothing writes it back — a dismissed intro is gone.
 * Storage that throws (private windows) reads as NOT dismissed, so the intro
 * renders and the dismiss still works for the session.
 */
export const getIntroDismissed = (): boolean => {
  try {
    return storage()?.getItem(INTRO_DISMISSED_KEY) === '1';
  } catch {
    return false;
  }
};

export const dismissIntro = (): void => {
  try {
    storage()?.setItem(INTRO_DISMISSED_KEY, '1');
  } catch {
    // storage unavailable — the component's own state still hides it this session
  }
  for (const fn of listeners) fn();
};

export const subscribeSettings = (fn: Listener): (() => void) => {
  listeners.add(fn);
  return () => listeners.delete(fn);
};
