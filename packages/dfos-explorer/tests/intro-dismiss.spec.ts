/**
 * Home intro dismissal — the persistence contract behind the banner.
 *
 * The banner's whole promise is that dismissing it is permanent: a return visit
 * must not re-show it. That promise lives in two pure-ish functions, so it is
 * testable without a renderer. The private-window case matters just as much —
 * storage that THROWS must read as "not dismissed" and must not throw out of
 * the dismiss, or the banner takes the page down with it.
 */

import { afterEach, describe, expect, it } from 'vitest';
import { dismissIntro, getIntroDismissed } from '../src/lib/settings';

/** Install a localStorage stand-in for this test (node has none). */
const install = (store: Storage | undefined): void => {
  Object.defineProperty(globalThis, 'localStorage', {
    value: store,
    configurable: true,
    writable: true,
  });
};

const memoryStorage = (): Storage => {
  const map = new Map<string, string>();
  return {
    get length() {
      return map.size;
    },
    clear: () => map.clear(),
    getItem: (k: string) => map.get(k) ?? null,
    key: (i: number) => [...map.keys()][i] ?? null,
    removeItem: (k: string) => void map.delete(k),
    setItem: (k: string, v: string) => void map.set(k, v),
  } as Storage;
};

/** A private-window-ish storage: every access throws. */
const hostileStorage = (): Storage =>
  ({
    getItem: () => {
      throw new Error('storage disabled');
    },
    setItem: () => {
      throw new Error('storage disabled');
    },
  }) as unknown as Storage;

afterEach(() => {
  install(undefined);
});

describe('home intro dismissal', () => {
  it('is not dismissed by default', () => {
    install(memoryStorage());
    expect(getIntroDismissed()).toBe(false);
  });

  it('persists the dismissal across reads', () => {
    install(memoryStorage());
    dismissIntro();
    expect(getIntroDismissed()).toBe(true);
    // and stays dismissed — nothing re-shows it
    expect(getIntroDismissed()).toBe(true);
  });

  it('reads a foreign value as not dismissed', () => {
    const store = memoryStorage();
    store.setItem('dfos.explorer.introDismissed', 'yes');
    install(store);
    expect(getIntroDismissed()).toBe(false);
  });

  it('reads not-dismissed with no storage at all', () => {
    install(undefined);
    expect(getIntroDismissed()).toBe(false);
    expect(() => dismissIntro()).not.toThrow();
  });

  it('survives storage that throws', () => {
    install(hostileStorage());
    expect(getIntroDismissed()).toBe(false);
    expect(() => dismissIntro()).not.toThrow();
  });
});
