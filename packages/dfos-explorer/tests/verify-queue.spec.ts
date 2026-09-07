import { DivergenceError, type LogOp } from '@metalabel/dfos-client';
import { markDependencyMissing } from '@metalabel/dfos-protocol';
import { createJws } from '@metalabel/dfos-protocol/crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { observeOnVisible } from '../src/components/index-light';
import { isVerificationFailure } from '../src/lib/client';
import { failureStatus, oldestOpAtOf, verdictIsFresh } from '../src/lib/verify-queue';

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

  // A signer identity that timed out is a failure to look, not a finding about
  // the log — it used to arrive wrapped as "failed verification" and stick the
  // row on terminal red, so scrolling back never retried it.
  it('a dependency miss is retryable `error`, never terminal `unverified`', () => {
    const miss = markDependencyMissing(
      new Error('candidate log verification could not complete: unknown identity: did:dfos:x'),
    );
    expect(failureStatus(miss)).toBe('error');
  });

  it('the marker beats the message: a marked wrapper is still not a verdict', () => {
    const marked = markDependencyMissing(
      new Error('all candidate logs failed verification: unknown identity'),
    );
    expect(isVerificationFailure(marked)).toBe(false);
    expect(failureStatus(marked)).toBe('error');
  });
});

describe('oldestOpAtOf — the oldest op a fold actually covered', () => {
  const opAt = async (createdAt: string): Promise<LogOp> => {
    const jwsToken = await createJws({
      header: { alg: 'EdDSA', typ: 'did:dfos:identity', kid: 'did:dfos:x#k', cid: 'bafy' },
      payload: { createdAt },
      sign: async () => new Uint8Array(64),
    });
    return { cid: 'bafy', jwsToken };
  };

  it('is the minimum createdAt across the log', async () => {
    const log = [await opAt('2025-01-01T00:00:00.000Z'), await opAt('2024-01-01T00:00:00.000Z')];
    expect(oldestOpAtOf(log)).toBe('2024-01-01T00:00:00.000Z');
  });

  it('is empty for a log nothing decodes from', () => {
    expect(oldestOpAtOf([{ cid: 'x', jwsToken: 'not.a.jws' }])).toBe('');
    expect(oldestOpAtOf([])).toBe('');
  });
});

// the retryable `error` state is only reachable if the viewport trigger is still
// watching: the observer used to detach on the first intersection, which left a
// row that failed for want of an answer stuck until it remounted.
describe('observeOnVisible — the trigger re-arms on every entry', () => {
  afterEach(() => vi.unstubAllGlobals());

  /** A stand-in IntersectionObserver whose entries the test drives by hand. */
  const stubObserver = (): { enter: () => void; leave: () => void; disconnects: () => number } => {
    let fire: ((entries: { isIntersecting: boolean }[]) => void) | null = null;
    let disconnects = 0;
    vi.stubGlobal(
      'IntersectionObserver',
      class {
        constructor(cb: (entries: { isIntersecting: boolean }[]) => void) {
          fire = cb;
        }
        observe(): void {}
        disconnect(): void {
          disconnects += 1;
        }
      },
    );
    return {
      enter: () => fire?.([{ isIntersecting: true }]),
      leave: () => fire?.([{ isIntersecting: false }]),
      disconnects: () => disconnects,
    };
  };

  it('calls back on each entry, so a scroll away and back re-enqueues', () => {
    const io = stubObserver();
    let calls = 0;
    const stop = observeOnVisible({} as Element, () => {
      calls += 1;
    });
    io.enter();
    expect(calls).toBe(1);
    // still on screen: IntersectionObserver reports TRANSITIONS, so a row that
    // failed and stayed put does not spin
    io.enter();
    expect(calls).toBe(2);
    io.leave();
    expect(calls).toBe(2);
    io.enter();
    expect(calls).toBe(3);
    stop();
    expect(io.disconnects()).toBe(1);
  });

  it('ignores a report that the element is not intersecting', () => {
    const io = stubObserver();
    let calls = 0;
    observeOnVisible({} as Element, () => {
      calls += 1;
    });
    io.leave();
    expect(calls).toBe(0);
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
