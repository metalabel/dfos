/**
 * THE RESET FENCE — a wipe the background writers cannot undo.
 *
 * `resetLocalIndex` refuses while a full sync holds the controller, which covers
 * the one writer that takes a controller and nothing else. The fire-and-forget
 * writers — jitIndexChain off a detail view's fold, the verify queue's verdict
 * persistence — are in flight across network round trips and take no lock, so a
 * write issued before the wipe can resolve after it and repopulate a store the UI
 * has already reported as cleared. Including, in the worst case, exactly the
 * dropped-history operations a reset exists to forget.
 *
 * So each of those captures the WIPE GENERATION when its work begins and hands it
 * back at write time. These tests are that contract, from both sides: a stale
 * generation writes nothing, and an ordinary concurrent write does not count as a
 * fence break (which is why the fence is not `dbEpoch` — that bumps on every sync
 * page and every JIT add, and fencing on it would make background writers cancel
 * each other).
 */

import { IDBFactory } from 'fake-indexeddb';
import { beforeAll, describe, expect, it } from 'vitest';

// the shared db handle opens against the global factory — install one before
// anything in the store is touched
beforeAll(() => {
  (globalThis as { indexedDB?: IDBFactory }).indexedDB = new IDBFactory();
});

const b64url = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
const op = (cid: string, createdAt: string) => ({
  cid,
  jwsToken: `${b64url({ typ: 'did:dfos:identity', kid: 'did:dfos:aaa#key1' })}.${b64url({
    type: 'create',
    createdAt,
  })}.sig`,
});

const OPS = [op('bafy-a1', '2026-01-01T00:00:00.000Z'), op('bafy-a2', '2026-01-02T00:00:00.000Z')];

describe('writeIfCurrent — the fence itself', () => {
  it('runs the write while the generation still stands', async () => {
    const { currentDbGeneration, writeIfCurrent } = await import('../src/lib/sync-store');
    let ran = false;
    const ok = await writeIfCurrent(currentDbGeneration(), async () => {
      ran = true;
    });
    expect(ok).toBe(true);
    expect(ran).toBe(true);
  });

  it('drops the write once the generation has moved', async () => {
    const { currentDbGeneration, resetLocalIndex, writeIfCurrent } =
      await import('../src/lib/sync-store');
    const stale = currentDbGeneration();
    await resetLocalIndex();
    let ran = false;
    const ok = await writeIfCurrent(stale, async () => {
      ran = true;
    });
    expect(ok).toBe(false);
    expect(ran).toBe(false);
  });

  it('an ordinary local write is NOT a fence break', async () => {
    // dbEpoch bumps on every sync page and every JIT add. If the fence read that,
    // one background write landing would cancel another's — legitimate rows lost.
    const { currentDbGeneration, markDbChanged, writeIfCurrent } =
      await import('../src/lib/sync-store');
    const generation = currentDbGeneration();
    markDbChanged();
    expect(await writeIfCurrent(generation, async () => {})).toBe(true);
  });
});

describe('jitIndexChain — a write started before a reset does not repopulate it', () => {
  it('lands rows when no reset intervened', async () => {
    const { currentDbGeneration, jitIndexChain, resetLocalIndex } =
      await import('../src/lib/sync-store');
    const { getDb } = await import('../src/lib/db-instance');
    await resetLocalIndex();
    await jitIndexChain('did:dfos:aaa', 'identity-op', OPS, currentDbGeneration());
    expect((await (await getDb()).counts()).ops).toBe(2);
  });

  it('drops a write whose fold began before the wipe', async () => {
    const { currentDbGeneration, jitIndexChain, resetLocalIndex } =
      await import('../src/lib/sync-store');
    const { getDb } = await import('../src/lib/db-instance');
    // the detail view's fold starts here — a network round trip is now in flight
    const generation = currentDbGeneration();
    // …and the user clears the local index while it is out
    expect(await resetLocalIndex()).toBe(true);
    expect((await (await getDb()).counts()).ops).toBe(0);
    // …and the fold finally resolves and tries to land its ops
    await jitIndexChain('did:dfos:aaa', 'identity-op', OPS, generation);
    // the store the UI just called cleared is still cleared
    expect((await (await getDb()).counts()).ops).toBe(0);
    expect(await (await getDb()).getChain('did:dfos:aaa')).toBeUndefined();
  });
});
