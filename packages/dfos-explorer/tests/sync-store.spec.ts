import { describe, expect, it } from 'vitest';
import { getSyncState, isSyncing, markDbChanged, subscribeSync } from '../src/lib/sync-store';

describe('sync-store observable', () => {
  it('starts idle and not syncing', () => {
    expect(getSyncState().phase).toBe('idle');
    expect(isSyncing()).toBe(false);
  });

  it('markDbChanged bumps dbEpoch and notifies subscribers', () => {
    const before = getSyncState().dbEpoch;
    let seen = -1;
    const unsub = subscribeSync((s) => {
      seen = s.dbEpoch;
    });
    markDbChanged();
    expect(getSyncState().dbEpoch).toBe(before + 1);
    expect(seen).toBe(before + 1);
    unsub();
  });

  it('stops notifying after unsubscribe', () => {
    let calls = 0;
    const unsub = subscribeSync(() => {
      calls += 1;
    });
    markDbChanged();
    expect(calls).toBe(1);
    unsub();
    markDbChanged();
    expect(calls).toBe(1);
  });
});
