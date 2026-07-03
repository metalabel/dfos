import { IDBFactory } from 'fake-indexeddb';
import { describe, expect, it } from 'vitest';
import { openExplorerDb, type ChainRollup, type ExplorerOp } from '../src/lib/db';

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
    expect(recent[0]?.chainId).toBe('new');
    const byOps = await db.chainsQuery({ sort: 'ops', limit: 10 });
    expect(byOps[0]?.chainId).toBe('old');
    const contentOnly = await db.chainsQuery({ sort: 'recent', kind: 'content-op', limit: 10 });
    expect(contentOnly.map((c) => c.chainId)).toEqual(['content1']);
    const limited = await db.chainsQuery({ sort: 'recent', limit: 2 });
    expect(limited).toHaveLength(2);
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
    await db.wipe();
    expect(await db.getOp('bafy1')).toBeUndefined();
    expect(await db.getCursor('https://r1')).toBeUndefined();
    expect((await db.counts()).chains).toBe(0);
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
