/*

  RELAY SET — localStorage-backed, observable

  The relay list is a user parameter, not an authority: the client fans reads
  across the whole set and the UI reports which relay answered and whether the
  set agreed. Seeding relay.dfos.com is a pragmatic default with one-click
  removal (the default-relay tension is real — keep it honest, keep it visible).

*/

const LS_KEY = 'dfos.explorer.relays';

export const DEFAULT_RELAYS = ['https://relay.dfos.com'];

type Listener = () => void;

const listeners = new Set<Listener>();

const storage = (): Storage | undefined => {
  try {
    return globalThis.localStorage;
  } catch {
    return undefined;
  }
};

const load = (): string[] => {
  try {
    const raw = storage()?.getItem(LS_KEY);
    if (!raw) return [...DEFAULT_RELAYS];
    const parsed: unknown = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.length > 0 && parsed.every((v) => typeof v === 'string'))
      return parsed;
  } catch {
    // fall through to default
  }
  return [...DEFAULT_RELAYS];
};

let relays: string[] = load();

const persist = (): void => {
  try {
    storage()?.setItem(LS_KEY, JSON.stringify(relays));
  } catch {
    // storage unavailable — in-memory set still works for the session
  }
  for (const fn of listeners) fn();
};

/** Normalize user input to an origin-ish base URL, or null when unusable. */
export const normalizeRelayUrl = (raw: string): string | null => {
  let value = raw.trim();
  if (!value) return null;
  if (!/^https?:\/\//i.test(value)) value = `https://${value}`;
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    return `${url.origin}${url.pathname.replace(/\/+$/, '')}`;
  } catch {
    return null;
  }
};

export const getRelays = (): string[] => [...relays];

export const addRelay = (raw: string): string | null => {
  const url = normalizeRelayUrl(raw);
  if (!url) return null;
  if (!relays.includes(url)) {
    relays = [...relays, url];
    persist();
  }
  return url;
};

export const removeRelay = (url: string): void => {
  if (!relays.includes(url)) return;
  relays = relays.filter((r) => r !== url);
  if (relays.length === 0) relays = [...DEFAULT_RELAYS];
  persist();
};

export const subscribeRelays = (fn: Listener): (() => void) => {
  listeners.add(fn);
  return () => listeners.delete(fn);
};
