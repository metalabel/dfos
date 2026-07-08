import { IDBFactory } from 'fake-indexeddb';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { openExplorerDb, type ChainRollup, type ExplorerOp } from '../src/lib/db';
import { getDb } from '../src/lib/db-instance';

const op = (partial: Partial<ExplorerOp> & { cid: string }): ExplorerOp => ({
  jwsToken: 'x.y.z',
  kind: 'identity-op',
  chainId: 'did:dfos:aaa',
  type: 'create',
  createdAt: '2026-01-01T00:00:00.000Z',
  kid: '',
  seq: 0,
  ...partial,
});

const rollup = (partial: Partial<ChainRollup> & { chainId: string }): ChainRollup => ({
  kind: 'identity-op',
  opCount: 1,
  firstCreatedAt: '2026-01-01T00:00:00.000Z',
  lastCreatedAt: '2026-01-01T00:00:00.000Z',
  headCid: 'bafy-head',
  ...partial,
});

const freshDb = () => openExplorerDb('test', new IDBFactory());

describe('explorer db', () => {
  it('stores and retrieves ops by cid', async () => {
    const db = await freshDb();
    await db.putBatch([op({ cid: 'bafy1' })], []);
    expect((await db.getOp('bafy1'))?.cid).toBe('bafy1');
    expect(await db.getOp('bafy-missing')).toBeUndefined();
  });

  it('knownOps reports stored cids as a set', async () => {
    const db = await freshDb();
    await db.putBatch([op({ cid: 'bafy1' }), op({ cid: 'bafy2' })], []);
    const known = await db.knownOps(['bafy1', 'bafy2', 'bafy3']);
    expect(known).toEqual(new Set(['bafy1', 'bafy2']));
  });

  it('chainOps sorts by createdAt then seq and filters by kind', async () => {
    const db = await freshDb();
    await db.putBatch(
      [
        op({ cid: 'c', createdAt: '2026-01-03T00:00:00.000Z', seq: 2 }),
        op({ cid: 'a', createdAt: '2026-01-01T00:00:00.000Z', seq: 0 }),
        op({ cid: 'b', createdAt: '2026-01-01T00:00:00.000Z', seq: 1 }),
        // a credential issued by the same DID shares the chainId — must be filterable
        op({ cid: 'cred', kind: 'credential', createdAt: '2026-01-02T00:00:00.000Z', seq: 3 }),
      ],
      [],
    );
    const identityOps = await db.chainOps('did:dfos:aaa', 'identity-op');
    expect(identityOps.map((o) => o.cid)).toEqual(['a', 'b', 'c']);
    const all = await db.chainOps('did:dfos:aaa');
    expect(all).toHaveLength(4);
  });

  it('counts ops and chains by kind', async () => {
    const db = await freshDb();
    await db.putBatch(
      [op({ cid: 'x' }), op({ cid: 'y', kind: 'content-op', chainId: 'content1' })],
      [rollup({ chainId: 'did:dfos:aaa' }), rollup({ chainId: 'content1', kind: 'content-op' })],
    );
    const counts = await db.counts();
    expect(counts.ops).toBe(2);
    expect(counts.chains).toBe(2);
    expect(counts.byKind['identity-op']).toBe(1);
    expect(counts.byKind['content-op']).toBe(1);
  });

  it('chainsQuery sorts recent / most-ops and filters by kind', async () => {
    const db = await freshDb();
    await db.putBatch(
      [],
      [
        rollup({ chainId: 'old', opCount: 9, lastCreatedAt: '2026-01-01T00:00:00.000Z' }),
        rollup({ chainId: 'new', opCount: 1, lastCreatedAt: '2026-02-01T00:00:00.000Z' }),
        rollup({
          chainId: 'content1',
          kind: 'content-op',
          opCount: 5,
          lastCreatedAt: '2026-01-15T00:00:00.000Z',
        }),
      ],
    );
    const recent = await db.chainsQuery({ sort: 'recent', limit: 10 });
    expect(recent.rows[0]?.chainId).toBe('new');
    expect(recent.truncated).toBe(false);
    const byOps = await db.chainsQuery({ sort: 'ops', limit: 10 });
    expect(byOps.rows[0]?.chainId).toBe('old');
    const contentOnly = await db.chainsQuery({ sort: 'recent', kind: 'content-op', limit: 10 });
    expect(contentOnly.rows.map((c) => c.chainId)).toEqual(['content1']);
    const limited = await db.chainsQuery({ sort: 'recent', limit: 2 });
    expect(limited.rows).toHaveLength(2);
    // hitting the limit is ordinary pagination, not a truncated scan
    expect(limited.truncated).toBe(false);
  });

  it('round-trips Phase-2 projection fields on a rollup', async () => {
    const db = await freshDb();
    await db.putBatch(
      [],
      [
        rollup({
          chainId: 'content-profile',
          kind: 'content-op',
          docSchema: 'https://schemas.dfos.com/profile/v1',
          publicRead: true,
          resolvedHead: 'bafy-head',
        }),
        rollup({
          chainId: 'did:dfos:named',
          kind: 'identity-op',
          name: 'Alice',
          nameLower: 'alice',
          publicRead: true,
        }),
      ],
    );
    const doc = await db.getChain('content-profile');
    expect(doc?.docSchema).toBe('https://schemas.dfos.com/profile/v1');
    expect(doc?.resolvedHead).toBe('bafy-head');
    const id = await db.getChain('did:dfos:named');
    expect(id?.name).toBe('Alice');
  });

  it('browseIdentities filters by resolved name and substring search', async () => {
    const db = await freshDb();
    await db.putBatch(
      [],
      [
        rollup({ chainId: 'did:dfos:a', name: 'Alice', nameLower: 'alice', publicRead: true }),
        rollup({
          chainId: 'did:dfos:b',
          name: 'Bob Loblaw',
          nameLower: 'bob loblaw',
          publicRead: true,
        }),
        // no resolved profile — hidden unless includeGated
        rollup({ chainId: 'did:dfos:c' }),
      ],
    );
    const all = await db.browseIdentities({ limit: 10 });
    expect(all.publicCount).toBe(2);
    expect(all.gatedCount).toBe(1);
    expect(all.rows.map((r) => r.chainId)).toEqual(['did:dfos:a', 'did:dfos:b']); // name-sorted

    const search = await db.browseIdentities({ query: 'lob', limit: 10 });
    expect(search.rows.map((r) => r.name)).toEqual(['Bob Loblaw']);
    expect(search.matched).toBe(1);

    const gated = await db.browseIdentities({ includeGated: true, limit: 10 });
    expect(gated.rows).toHaveLength(3);
  });

  it('browseDocuments partitions public / gated / unresolved', async () => {
    const db = await freshDb();
    await db.putBatch(
      [],
      [
        rollup({
          chainId: 'pub',
          kind: 'content-op',
          docSchema: 'https://schemas.dfos.com/profile/v1',
          publicRead: true,
          resolvedHead: 'h1',
          lastCreatedAt: '2026-02-01T00:00:00.000Z',
        }),
        // resolved but gated (no schema, publicRead false)
        rollup({ chainId: 'gated', kind: 'content-op', publicRead: false, resolvedHead: 'h2' }),
        // never resolved
        rollup({ chainId: 'pending', kind: 'content-op' }),
      ],
    );
    const pub = await db.browseDocuments({ limit: 10 });
    expect(pub.publicCount).toBe(1);
    expect(pub.gatedCount).toBe(1);
    expect(pub.unresolvedCount).toBe(1);
    expect(pub.rows.map((r) => r.chainId)).toEqual(['pub']);

    const withGated = await db.browseDocuments({ includeGated: true, limit: 10 });
    expect(withGated.rows.map((r) => r.chainId).sort()).toEqual(['gated', 'pub']);

    const bySchema = await db.browseDocuments({
      schema: 'https://schemas.dfos.com/profile/v1',
      limit: 10,
    });
    expect(bySchema.rows.map((r) => r.chainId)).toEqual(['pub']);
  });

  it('browseDocuments joins the attributed profile name via profileSource', async () => {
    const db = await freshDb();
    await db.putBatch(
      [],
      [
        rollup({
          chainId: 'profile-chain',
          kind: 'content-op',
          docSchema: 'https://schemas.dfos.com/profile/v1',
          publicRead: true,
          resolvedHead: 'h1',
        }),
        // the identity whose profile lives on profile-chain — carries the name
        rollup({
          chainId: 'did:dfos:alice',
          kind: 'identity-op',
          name: 'Alice',
          nameLower: 'alice',
          profileSource: 'profile-chain',
        }),
      ],
    );
    const res = await db.browseDocuments({ limit: 10 });
    expect(res.names['profile-chain']).toBe('Alice');
    // a content chain with no attributing identity gets no title
    expect(res.names['unknown']).toBeUndefined();
  });

  it('tracks per-relay cursors and wipes everything', async () => {
    const db = await freshDb();
    await db.setCursor({
      relay: 'https://r1',
      cursor: 'abc',
      count: 42,
      updatedAt: '2026-01-01T00:00:00.000Z',
    });
    expect((await db.getCursor('https://r1'))?.count).toBe(42);
    expect(await db.getCursor('https://r2')).toBeUndefined();

    await db.putBatch([op({ cid: 'bafy1' })], [rollup({ chainId: 'did:dfos:aaa' })]);
    await db.putVerify({
      key: 'identity:did:dfos:aaa',
      opCount: 3,
      isDeleted: false,
      verifiedAt: 1,
    });
    await db.wipe();
    expect(await db.getOp('bafy1')).toBeUndefined();
    expect(await db.getCursor('https://r1')).toBeUndefined();
    expect(await db.getVerify('identity:did:dfos:aaa')).toBeUndefined();
    expect((await db.counts()).chains).toBe(0);
  });

  it('persists and retrieves durable verify verdicts by key', async () => {
    const db = await freshDb();
    expect(await db.getVerify('identity:did:dfos:zzz')).toBeUndefined();
    await db.putVerify({
      key: 'identity:did:dfos:zzz',
      opCount: 7,
      isDeleted: true,
      verifiedAt: 1700000000000,
    });
    const v = await db.getVerify('identity:did:dfos:zzz');
    expect(v?.opCount).toBe(7);
    expect(v?.isDeleted).toBe(true);
    // put is an upsert — a fresher fold overwrites in place
    await db.putVerify({
      key: 'identity:did:dfos:zzz',
      opCount: 9,
      isDeleted: false,
      verifiedAt: 1700000000001,
    });
    expect((await db.getVerify('identity:did:dfos:zzz'))?.opCount).toBe(9);
  });

  it('sets onversionchange to close so this connection yields to a future upgrade', async () => {
    // Behavioral proof of the recurrence guard: with the open connection yielding
    // (onversionchange → close), a higher-version open from another "tab" must NOT
    // block — it upgrades and succeeds. Without the handler the live connection
    // would hold the old version and this open would fire `blocked` (the PR #194
    // bug), which the test would catch below.
    const factory = new IDBFactory();
    const db = await openExplorerDb('versionchange-test', factory);
    const outcome = await new Promise<'success' | 'blocked' | 'error'>((resolve) => {
      const req = factory.open('versionchange-test', 999);
      req.onupgradeneeded = () => {
        // a no-op upgrade — reaching here already means we were not blocked
      };
      req.onsuccess = () => {
        req.result.close();
        resolve('success');
      };
      req.onblocked = () => resolve('blocked');
      req.onerror = () => resolve('error');
    });
    expect(outcome).toBe('success');
    db.close();
  });

  it('counts credentials from OPS even when they collide with an identity chainId', async () => {
    const db = await freshDb();
    // one issuer DID hosts an identity chain AND 3 credential ops that chain
    // under the same chainId — the rollup collapses to a single kind, but the
    // credential count must still reflect all 3 ops
    await db.putBatch(
      [
        op({ cid: 'id1', kind: 'identity-op', chainId: 'did:dfos:iss' }),
        op({ cid: 'id2', kind: 'identity-op', chainId: 'did:dfos:iss', type: 'update' }),
        op({ cid: 'cr1', kind: 'credential', chainId: 'did:dfos:iss' }),
        op({ cid: 'cr2', kind: 'credential', chainId: 'did:dfos:iss' }),
        op({ cid: 'cr3', kind: 'credential', chainId: 'did:dfos:iss' }),
      ],
      // the rollup for the shared chainId (last-writer-wins) lands as identity
      [rollup({ chainId: 'did:dfos:iss', kind: 'identity-op', opCount: 5 })],
    );

    const counts = await db.counts();
    expect(counts.byKind['identity-op']).toBe(1); // one identity CHAIN
    expect(counts.byKind['credential']).toBe(3); // three credential OPS, not collapsed
    expect(counts.chains).toBe(1);
    expect(counts.ops).toBe(5);

    const grants = await db.opsOfKind('credential', 300);
    expect(grants.map((g) => g.cid).sort()).toEqual(['cr1', 'cr2', 'cr3']);
  });
});

// -----------------------------------------------------------------------------
// open-path guards (PR #194 regression): a version bump can't upgrade while
// another same-origin tab holds an older-version connection — indexedDB.open
// fires `blocked` and never settles. openExplorerDb must ALWAYS settle so
// getDb() (and the verify queue behind it) can never hang for the tab's lifetime.
//
// A hand-driven fake IDBFactory lets us fire `blocked`/`success` on demand and
// drive the grace/safety timers with fake timers — deterministic, and it doesn't
// depend on fake-indexeddb's internal blocked-event scheduling. These constants
// mirror BLOCKED_GRACE_MS / OPEN_TIMEOUT_MS in db.ts (module-private there).
// -----------------------------------------------------------------------------

const BLOCKED_GRACE_MS = 3_000;
const OPEN_TIMEOUT_MS = 15_000;

interface FakeOpenRequest {
  onblocked: (() => void) | null;
  onupgradeneeded: ((event: { oldVersion: number }) => void) | null;
  onsuccess: (() => void) | null;
  onerror: (() => void) | null;
  result: unknown;
  error: unknown;
}

/** A minimal IDBFactory whose single open request is driven by the test. */
const fakeFactory = (): { factory: IDBFactory; request: FakeOpenRequest } => {
  const request: FakeOpenRequest = {
    onblocked: null,
    onupgradeneeded: null,
    onsuccess: null,
    onerror: null,
    result: null,
    error: null,
  };
  const factory = { open: () => request } as unknown as IDBFactory;
  return { factory, request };
};

/** A stand-in IDBDatabase — the wrapper only touches close()/onversionchange
 *  unless a data method is called (none are in these open-path tests). */
const fakeDb = (): { onversionchange: (() => void) | null; close: () => void; closed: boolean } => {
  const db = {
    onversionchange: null as (() => void) | null,
    closed: false,
    close(): void {
      db.closed = true;
    },
  };
  return db;
};

describe('openExplorerDb open-path guards', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('rejects after the grace when another tab blocks the upgrade', async () => {
    vi.useFakeTimers();
    const { factory, request } = fakeFactory();
    const p = openExplorerDb('blocked-grace', factory);
    // attach the rejection handler up front so the pending timer-driven reject
    // never surfaces as an unhandled rejection while we advance the clock.
    const rejected = expect(p).rejects.toThrow(/blocking a local index upgrade/);
    // openExplorerDb runs its open() + handler wiring synchronously before the
    // first await, so the request is armed immediately.
    request.onblocked?.();
    // still pending just before the grace elapses…
    await vi.advanceTimersByTimeAsync(BLOCKED_GRACE_MS - 1);
    // …then rejects once it does
    await vi.advanceTimersByTimeAsync(2);
    await rejected;
  });

  it('rejects on the overall safety timeout if the open never settles', async () => {
    vi.useFakeTimers();
    const { factory } = fakeFactory();
    const p = openExplorerDb('safety-timeout', factory);
    const rejected = expect(p).rejects.toThrow(/timed out/);
    // no blocked/success/error ever fires — the safety net must still settle it
    await vi.advanceTimersByTimeAsync(OPEN_TIMEOUT_MS + 1);
    await rejected;
  });

  it('resolves if a blocked open unblocks within the grace (success cancels the reject)', async () => {
    vi.useFakeTimers();
    const { factory, request } = fakeFactory();
    const db = fakeDb();
    const p = openExplorerDb('blocked-then-success', factory);
    request.onblocked?.();
    // the blocking tab closes partway through the grace and the open succeeds
    await vi.advanceTimersByTimeAsync(BLOCKED_GRACE_MS - 500);
    request.result = db;
    request.onsuccess?.();
    await expect(p).resolves.toBeDefined();
    // the grace reject was cancelled — advancing past it must not throw late
    await vi.advanceTimersByTimeAsync(OPEN_TIMEOUT_MS + 1);
    // onversionchange installed, and firing it closes the connection
    expect(typeof db.onversionchange).toBe('function');
    db.onversionchange?.();
    expect(db.closed).toBe(true);
  });

  it('closes a late success that arrives after the open already rejected', async () => {
    vi.useFakeTimers();
    const { factory, request } = fakeFactory();
    const db = fakeDb();
    const p = openExplorerDb('late-success', factory);
    const rejected = expect(p).rejects.toThrow(/blocking a local index upgrade/);
    request.onblocked?.();
    await vi.advanceTimersByTimeAsync(BLOCKED_GRACE_MS + 1);
    await rejected;
    // the blocking tab finally closes and the open belatedly succeeds — the now
    // orphaned connection must be closed, not leaked open for the tab's lifetime,
    // and it must NOT get a versionchange handler (it's already discarded).
    expect(db.closed).toBe(false);
    request.result = db;
    request.onsuccess?.();
    expect(db.closed).toBe(true);
    expect(db.onversionchange).toBeNull();
  });

  it('invokes onClosed when the connection yields to a version upgrade', async () => {
    vi.useFakeTimers();
    const { factory, request } = fakeFactory();
    const db = fakeDb();
    let closedSignals = 0;
    const p = openExplorerDb('on-closed', factory, () => {
      closedSignals += 1;
    });
    request.result = db;
    request.onsuccess?.();
    await expect(p).resolves.toBeDefined();
    // another (newer) tab bumps the version → onversionchange fires here: close
    // the dead handle AND signal the memoizer so the next open reopens.
    db.onversionchange?.();
    expect(db.closed).toBe(true);
    expect(closedSignals).toBe(1);
  });
});

describe('getDb rejection is not cached', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('retries the open on a later call instead of returning the cached rejection', async () => {
    // first call: no IndexedDB in the node test env → openExplorerDb rejects
    vi.stubGlobal('indexedDB', undefined);
    await expect(getDb()).rejects.toThrow(/IndexedDB/);
    // a poisoned cache would keep rejecting forever; a working env must now open
    vi.stubGlobal('indexedDB', new IDBFactory());
    await expect(getDb()).resolves.toBeDefined();
  });
});
