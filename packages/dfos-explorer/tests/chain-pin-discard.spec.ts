/**
 * THE ESCAPE HATCH'S DURABLE HALF.
 *
 * The pin that strands a browser lives in IndexedDB, not in memory — that is
 * exactly why the stranding survives a reload and why clearing site data was the
 * only fix. So the discard has to work against the store the explorer actually
 * configures (`indexedDbStore`), not just the in-process Map the client package
 * tests against.
 *
 * Three properties, and all three are what make the hatch safe to put behind one
 * button: it removes the chain it names, it removes ONLY that chain, and asking
 * twice (or asking about a chain that was never pinned) is not an error.
 */

import { indexedDbStore } from '@metalabel/dfos-client/store';
import { IDBFactory } from 'fake-indexeddb';
import { beforeEach, describe, expect, it } from 'vitest';

beforeEach(() => {
  // a fresh factory per test — a pin left behind by one case must not decide another
  (globalThis as { indexedDB?: IDBFactory }).indexedDB = new IDBFactory();
});

const PINNED = { log: ['eyJ…'], headCID: 'bafy-head', lastCreatedAt: '2026-08-30T00:00:00.000Z' };

describe('indexedDbStore per-chain discard', () => {
  it('forgets the named chain and leaves every other pin standing', async () => {
    const store = indexedDbStore('dfos-explorer-client-test');
    await store.set('identity:did:dfos:stranded', PINNED);
    await store.set('identity:did:dfos:fine', PINNED);
    await store.set('content:did:dfos:fine/1', PINNED);

    await store.delete!('identity:did:dfos:stranded');

    expect(await store.get('identity:did:dfos:stranded')).toBe(undefined);
    expect(await store.get('identity:did:dfos:fine')).toEqual(PINNED);
    expect(await store.get('content:did:dfos:fine/1')).toEqual(PINNED);
  });

  it('is idempotent, and absent chains are already in the requested state', async () => {
    const store = indexedDbStore('dfos-explorer-client-test');
    await store.set('content:did:dfos:abc/1', PINNED);

    await expect(store.delete!('content:did:dfos:abc/1')).resolves.toBe(undefined);
    await expect(store.delete!('content:did:dfos:abc/1')).resolves.toBe(undefined);
    await expect(store.delete!('identity:did:dfos:never-pinned')).resolves.toBe(undefined);
    expect(await store.get('content:did:dfos:abc/1')).toBe(undefined);
  });

  it('leaves the store writable, so the next fold can pin the new history', async () => {
    const store = indexedDbStore('dfos-explorer-client-test');
    await store.set('identity:did:dfos:rewritten', PINNED);
    await store.delete!('identity:did:dfos:rewritten');

    const refolded = { ...PINNED, headCID: 'bafy-rewritten-head' };
    await store.set('identity:did:dfos:rewritten', refolded);
    expect(await store.get('identity:did:dfos:rewritten')).toEqual(refolded);
  });
});
