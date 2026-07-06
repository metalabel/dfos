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
