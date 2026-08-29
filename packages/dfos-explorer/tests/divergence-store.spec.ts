/**
 * THE STANDING VERDICT ONLY STANDS WHILE ITS QUESTION DOES.
 *
 * divergence-store holds one session verdict so two surfaces can read it without
 * a probe volley each. That is right until the question changes underneath it —
 * and the verdict answers "does the local mirror still describe THE RELAYS'
 * corpus?", which names two moving things. A relay added or removed makes "the
 * relays" a different set; a sync that adds operations makes the mirror a
 * different mirror. Either way the old `aligned`/`diverged` is an answer to a
 * question nobody asked, and the home banner keeps printing it.
 *
 * The reset case was already handled by the caller (views/sync.tsx). These are
 * the other two.
 */

import { IDBFactory } from 'fake-indexeddb';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

beforeAll(() => {
  (globalThis as { indexedDB?: IDBFactory }).indexedDB = new IDBFactory();
});

const chain = (chainId: string, firstCreatedAt: string) => ({
  chainId,
  kind: 'content-op' as const,
  opCount: 1,
  firstCreatedAt,
  lastCreatedAt: firstCreatedAt,
  headCid: `head-${chainId}`,
});

/** Every relay serves every sampled op back, so a check reads `aligned`. */
const servingFetch = (): typeof fetch =>
  ((input: RequestInfo | URL) => {
    const url = String(input);
    const cid = decodeURIComponent(url.slice(url.lastIndexOf('/') + 1));
    return Promise.resolve({
      status: 200,
      json: () => Promise.resolve({ cid, jwsToken: 'eyJ…' }),
    } as Response);
  }) as typeof fetch;

let originalFetch: typeof fetch;

beforeEach(async () => {
  originalFetch = globalThis.fetch;
  globalThis.fetch = servingFetch();
  const { getDb } = await import('../src/lib/db-instance');
  const db = await getDb();
  await db.wipe();
  await db.putBatch([], [chain('a', '2026-01-01'), chain('b', '2026-02-01')]);
});

afterEach(async () => {
  globalThis.fetch = originalFetch;
  const { getRelays, removeRelay, DEFAULT_RELAYS } = await import('../src/lib/relays');
  for (const relay of getRelays()) {
    if (!DEFAULT_RELAYS.includes(relay)) removeRelay(relay);
  }
});

describe('divergence-store — invalidation', () => {
  it('a standing verdict survives an unrelated read', async () => {
    const { ensureDivergenceCheck, getDivergenceReport, runDivergenceCheck } =
      await import('../src/lib/divergence-store');
    expect((await runDivergenceCheck())?.verdict).toBe('aligned');
    expect(getDivergenceReport()?.verdict).toBe('aligned');
    // the second caller gets the standing verdict and issues no requests
    expect((await ensureDivergenceCheck())?.verdict).toBe('aligned');
  });

  it('a relay ADDED retires the verdict — it was about different relays', async () => {
    const { getDivergenceReport, runDivergenceCheck } = await import('../src/lib/divergence-store');
    const { addRelay } = await import('../src/lib/relays');
    await runDivergenceCheck();
    expect(getDivergenceReport()).not.toBeNull();
    addRelay('https://another-relay.example');
    // the new relay may hold a quite different corpus; nothing has been checked
    // against it, so there is no verdict to show
    expect(getDivergenceReport()).toBeNull();
  });

  it('a relay REMOVED retires it too', async () => {
    const { getDivergenceReport, runDivergenceCheck } = await import('../src/lib/divergence-store');
    const { addRelay, removeRelay } = await import('../src/lib/relays');
    addRelay('https://another-relay.example');
    await runDivergenceCheck();
    expect(getDivergenceReport()).not.toBeNull();
    removeRelay('https://another-relay.example');
    expect(getDivergenceReport()).toBeNull();
  });

  it('a quorum change is not a relay-set change and leaves the verdict alone', async () => {
    // relays.ts notifies the same listeners on a quorum change; the verdict is
    // about which relays were asked, not how many must agree
    const { getDivergenceReport, runDivergenceCheck } = await import('../src/lib/divergence-store');
    const { getQuorum, setQuorum } = await import('../src/lib/relays');
    await runDivergenceCheck();
    setQuorum(getQuorum() + 1);
    expect(getDivergenceReport()?.verdict).toBe('aligned');
  });

  it('re-checking after the set changed files a verdict about the NEW set', async () => {
    const { getDivergenceReport, runDivergenceCheck } = await import('../src/lib/divergence-store');
    const { addRelay } = await import('../src/lib/relays');
    await runDivergenceCheck();
    addRelay('https://another-relay.example');
    expect(getDivergenceReport()).toBeNull();
    await runDivergenceCheck();
    expect(getDivergenceReport()?.verdict).toBe('aligned');
    // …and it is not retired again by a set that has not moved since
    const { getQuorum, setQuorum } = await import('../src/lib/relays');
    setQuorum(getQuorum());
    expect(getDivergenceReport()).not.toBeNull();
  });
});
