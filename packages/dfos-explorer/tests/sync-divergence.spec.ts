/**
 * A SYNC THAT ADDED OPERATIONS RETIRES THE STANDING DIVERGENCE VERDICT.
 *
 * The verdict is a spot-check of the local mirror against the relays. A sync that
 * pulled in new operations changed that mirror — the ops the check sampled were
 * not these — so the old `aligned`/`diverged` is an answer about a corpus that no
 * longer exists, and the home banner would keep printing it. A run that added
 * nothing left the corpus exactly as the check found it, and its verdict stands.
 *
 * The sync engine itself is mocked here: what is under test is the store's
 * bookkeeping at the end of a run, not the paging.
 */

import { IDBFactory } from 'fake-indexeddb';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

let added = 0;

vi.mock('../src/lib/client', () => ({ getClient: () => ({}) }));
vi.mock('../src/lib/sync', () => ({
  syncAll: () => Promise.resolve({ added, errors: [] }),
  indexChainOps: () => Promise.resolve({ added: 0 }),
}));
vi.mock('../src/lib/sync-projections', () => ({
  resolvePublicProjections: () => Promise.resolve({ publicDocs: 0, attributed: 0 }),
}));

const chain = (chainId: string) => ({
  chainId,
  kind: 'content-op' as const,
  opCount: 1,
  firstCreatedAt: '2026-01-01',
  lastCreatedAt: '2026-01-01',
  headCid: `head-${chainId}`,
});

let originalFetch: typeof fetch;

beforeAll(() => {
  (globalThis as { indexedDB?: IDBFactory }).indexedDB = new IDBFactory();
  originalFetch = globalThis.fetch;
  // every relay still serves every sampled op, so a check reads `aligned`
  globalThis.fetch = ((input: RequestInfo | URL) => {
    const url = String(input);
    const cid = decodeURIComponent(url.slice(url.lastIndexOf('/') + 1));
    return Promise.resolve({
      status: 200,
      json: () => Promise.resolve({ cid, jwsToken: 'eyJ…' }),
    } as Response);
  }) as typeof fetch;
});

afterAll(() => {
  globalThis.fetch = originalFetch;
});

beforeEach(async () => {
  const { getDb } = await import('../src/lib/db-instance');
  const db = await getDb();
  await db.wipe();
  await db.putBatch([], [chain('a')]);
});

describe('startSync — the standing verdict after a run', () => {
  it('retires it when the run ADDED operations', async () => {
    const { getDivergenceReport, runDivergenceCheck } = await import('../src/lib/divergence-store');
    const { startSync } = await import('../src/lib/sync-store');
    await runDivergenceCheck();
    expect(getDivergenceReport()?.verdict).toBe('aligned');

    added = 4;
    await startSync('manual');
    expect(getDivergenceReport()).toBeNull();
  });

  it('leaves it standing when the run added nothing', async () => {
    const { getDivergenceReport, runDivergenceCheck } = await import('../src/lib/divergence-store');
    const { startSync } = await import('../src/lib/sync-store');
    await runDivergenceCheck();
    expect(getDivergenceReport()?.verdict).toBe('aligned');

    added = 0;
    await startSync('manual');
    expect(getDivergenceReport()?.verdict).toBe('aligned');
  });
});
