import { DivergenceError, type Client, type LogOp } from '@metalabel/dfos-client';
import { markDependencyMissing } from '@metalabel/dfos-protocol';
import { createJws } from '@metalabel/dfos-protocol/crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { observeOnVisible } from '../src/components/index-light';
import { isVerificationFailure } from '../src/lib/client';
import {
  durableVerdictReusable,
  failureStatus,
  oldestOpAtOf,
  verdictIsFresh,
} from '../src/lib/verify-queue';

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

// A durable verdict pins what was immutable when it was folded. Credential
// authority is not: an issuer can be deleted, and a revocation dated at or
// before a delegated op can arrive later. Reuse needs every half.
describe('durableVerdictReusable — fresh, authorized, nothing dropped, same count', () => {
  const CONTENT = 'ct7kkfz7ehzvv6fzvate9rz2874nc3e';
  type Summary = Awaited<ReturnType<Client['recheckContentAuthority']>>;
  const recheckAnswering = (answer: () => Promise<Summary>) => {
    const recheckContentAuthority = vi.fn(answer);
    return { client: { recheckContentAuthority }, recheckContentAuthority };
  };
  const clean =
    (opCount: number, isDeleted = false) =>
    async (): Promise<Summary> => ({ opCount, isDeleted, rejected: [] });

  it('reuses a fresh content verdict whose cached chain still holds it', async () => {
    const { client, recheckContentAuthority } = recheckAnswering(clean(3));
    expect(
      await durableVerdictReusable({
        client,
        kind: 'content',
        chainId: CONTENT,
        verdictOpCount: 3,
        verdictIsDeleted: false,
        hintOpCount: 3,
      }),
    ).toBe(true);
    expect(recheckContentAuthority).toHaveBeenCalledWith(CONTENT);
  });

  it('re-folds when the recheck fails (issuer deleted, or a backdated revocation)', async () => {
    const { client } = recheckAnswering(async () => {
      throw new Error('log[1]: authorization verification failed: issuer is deleted');
    });
    expect(
      await durableVerdictReusable({
        client,
        kind: 'content',
        chainId: CONTENT,
        verdictOpCount: 3,
        verdictIsDeleted: false,
      }),
    ).toBe(false);
  });

  it('re-folds when the client holds no cached chain to recheck', async () => {
    const { client } = recheckAnswering(async () => undefined);
    expect(
      await durableVerdictReusable({
        client,
        kind: 'content',
        chainId: CONTENT,
        verdictOpCount: 3,
        verdictIsDeleted: false,
      }),
    ).toBe(false);
  });

  // Codex scenario (i): the verdict recorded a delegated DELETE (isDeleted:
  // true, two ops). A revocation dated before the delete then dropped it from
  // the client's cached chain on a later read. The recheck over the cached
  // lineage passes (genesis alone), and the relay's branch-inclusive hint still
  // says two, so only the cached rejection tells the verdict is stale.
  it('re-folds when the cached chain dropped an op the verdict counted', async () => {
    const { client } = recheckAnswering(async () => ({
      opCount: 1,
      isDeleted: false,
      rejected: [{ cid: 'bafy-delete', reason: 'authorization verification failed: revoked' }],
    }));
    expect(
      await durableVerdictReusable({
        client,
        kind: 'content',
        chainId: CONTENT,
        verdictOpCount: 2,
        verdictIsDeleted: false,
        hintOpCount: 2,
      }),
    ).toBe(false);
  });

  // The verdict recorded a delegated DELETE (two ops, isDeleted). The delete's
  // credential is then revoked with a date before it, and a creator sibling
  // lands. Under the client's monotone union the surviving count only drops
  // when authority is withdrawn, and here it comes back to two (genesis plus
  // the sibling) with nothing rejected once relays stop serving the delete.
  // Count and rejections both look clean; only the deletion state differs.
  it('re-folds when the cached deletion state differs from the verdict', async () => {
    const { client } = recheckAnswering(clean(2, false));
    expect(
      await durableVerdictReusable({
        client,
        kind: 'content',
        chainId: CONTENT,
        verdictOpCount: 2,
        verdictIsDeleted: true,
        hintOpCount: 2,
      }),
    ).toBe(false);
  });

  it('re-folds when the cached surviving count differs from the verdict count', async () => {
    const { client } = recheckAnswering(clean(4));
    expect(
      await durableVerdictReusable({
        client,
        kind: 'content',
        chainId: CONTENT,
        verdictOpCount: 3,
        verdictIsDeleted: false,
      }),
    ).toBe(false);
  });

  // Codex scenario (ii): the verdict was made while a delegated op was dropped
  // (issuer deleted), so it counted one surviving op. The issuer is restored.
  // The relay's hint is branch-inclusive (two) and already exceeds the recorded
  // surviving count, so freshness alone forces the re-fold.
  it('a stale op count re-folds without asking for a recheck', async () => {
    const { client, recheckContentAuthority } = recheckAnswering(clean(2));
    expect(
      await durableVerdictReusable({
        client,
        kind: 'content',
        chainId: CONTENT,
        verdictOpCount: 1,
        verdictIsDeleted: false,
        hintOpCount: 2,
      }),
    ).toBe(false);
    expect(recheckContentAuthority).not.toHaveBeenCalled();
  });

  it('an identity verdict carries no delegated authority and needs no recheck', async () => {
    const { client, recheckContentAuthority } = recheckAnswering(async () => undefined);
    expect(
      await durableVerdictReusable({
        client,
        kind: 'identity',
        chainId: 'did:dfos:x',
        verdictOpCount: 1,
        verdictIsDeleted: false,
      }),
    ).toBe(true);
    expect(recheckContentAuthority).not.toHaveBeenCalled();
  });
});
