import { describe, expect, it } from 'vitest';
import { verdictIsFresh } from '../src/lib/verify-queue';

describe('verify-queue durable-verdict freshness', () => {
  it('trusts a durable verdict when the index gives no opCount hint', () => {
    expect(verdictIsFresh(5)).toBe(true);
  });

  it('trusts a verdict whose opCount meets or exceeds the hint (no re-fold)', () => {
    expect(verdictIsFresh(5, 5)).toBe(true);
    expect(verdictIsFresh(6, 5)).toBe(true);
  });

  it('re-folds when the hint opCount exceeds the recorded verdict (stale)', () => {
    // opCount is branch-inclusive and monotonic, so a higher hint means a newer
    // op the persisted verdict predates — trusting it would show stale "verified"
    expect(verdictIsFresh(4, 5)).toBe(false);
  });
});
