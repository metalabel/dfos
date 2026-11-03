/*

  VERIFY TRUST — an answer the client would not vouch for is not a verdict

  Offline, with a credential's revocation status unobtainable, dfos-client
  returns the cached chain with `trust.ok: false` instead of throwing. The
  queue must read that as "could not verify, try again": not verified, never
  persisted, and retried on the next enqueue — the same path a dependency miss
  takes.

  The collaborators are mocked the way verify-scope.spec.ts mocks them.

*/

import { afterEach, describe, expect, it, vi } from 'vitest';
import type { VerifyVerdict } from '../src/lib/db';

const puts: VerifyVerdict[] = [];
let contentCalls = 0;

const untrusted = { ok: false, unverifiable: ['tip', 'revocation'] };

vi.mock('../src/lib/client', () => ({
  getClient: () => ({
    content: async () => {
      contentCalls += 1;
      return {
        value: { chain: { isDeleted: false }, rejected: [] },
        trust: untrusted,
      };
    },
    log: async () => ({ value: [], trust: untrusted }),
    recheckContentAuthority: async () => undefined,
  }),
  isVerificationFailure: () => false,
}));

vi.mock('../src/lib/db-instance', () => ({
  getDb: async () => ({
    getVerify: async () => undefined,
    putVerify: async (v: VerifyVerdict) => {
      puts.push(v);
    },
  }),
}));

vi.mock('../src/lib/sync-store', () => ({
  currentDbGeneration: () => 0,
  jitIndexChain: () => undefined,
  writeIfCurrent: async (_generation: number, fn: () => Promise<void>) => {
    await fn();
  },
}));

const { enqueueVerify, peekVerifyRecord } = await import('../src/lib/verify-queue');

const CONTENT = 'ct7kkfz7ehzvv6fzvate9rz2874nc3e';

describe('a trust.ok: false fold is not a verdict', () => {
  afterEach(() => {
    puts.length = 0;
  });

  it('is neither shown nor persisted as verified, and stays retryable', async () => {
    enqueueVerify('content', CONTENT);
    await vi.waitFor(() => expect(peekVerifyRecord('content', CONTENT)?.status).toBe('error'));
    expect(puts).toHaveLength(0);

    // `error` is the retryable state: a re-enqueue folds again
    const before = contentCalls;
    enqueueVerify('content', CONTENT);
    await vi.waitFor(() => expect(contentCalls).toBe(before + 1));
    await vi.waitFor(() => expect(peekVerifyRecord('content', CONTENT)?.status).toBe('error'));
    expect(puts).toHaveLength(0);
  });
});
