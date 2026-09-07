import { DivergenceError } from '@metalabel/dfos-client';
import { describe, expect, it } from 'vitest';
import { isVerificationFailure } from '../src/lib/client';
import { failureStatus, verdictIsFresh } from '../src/lib/verify-queue';

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

// M43 / M64: one `catch` used to fold three different events into one red badge
// — a rewritten history, a log that failed its checks, and a timeout — and none
// of them could be retried in that session.
describe('failureStatus — a failed fold is not one thing', () => {
  const divergence = (): DivergenceError =>
    new DivergenceError({
      chainType: 'content',
      chainId: 'ct7kkfz7ehzvv6fzvate9rz2874nc3e',
      cachedHeadCID: 'bafy-cached',
      liveHeadCID: 'bafy-live',
    });

  it('a divergence is its own terminal state, not a generic error', () => {
    expect(failureStatus(divergence())).toBe('diverged');
    // and it survives the client's own wrapping, cause chain and all
    expect(failureStatus(new Error('fold failed', { cause: divergence() }))).toBe('diverged');
  });

  it('a relay that answered with an unverifiable log is `unverified`', () => {
    expect(failureStatus(new Error('all candidate logs failed verification: bad signature'))).toBe(
      'unverified',
    );
  });

  it('anything else is a failure to LOOK — amber, and retryable', () => {
    expect(failureStatus(new Error('fetch failed'))).toBe('error');
    expect(failureStatus(new Error('content not found on any relay: ct7kk'))).toBe('error');
    expect(failureStatus('a string nobody threw as an Error')).toBe('error');
  });
});

// the guard identity.tsx uses to keep `chain-unverified` out of the
// "no relay answered" arm — the same question, asked at the other site
describe('isVerificationFailure', () => {
  it('recognises the client’s wrapper, directly and through a cause chain', () => {
    const inner = new Error('all candidate logs failed verification: cid mismatch');
    expect(isVerificationFailure(inner)).toBe(true);
    expect(isVerificationFailure(new Error('resolve failed', { cause: inner }))).toBe(true);
  });

  it('is false for a transport miss, which is the opposite statement', () => {
    expect(isVerificationFailure(new Error('content not found on any relay: ct7kk'))).toBe(false);
    expect(isVerificationFailure(undefined)).toBe(false);
  });
});
