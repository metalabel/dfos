import { IDBFactory } from 'fake-indexeddb';
import { describe, expect, it } from 'vitest';
import { openExplorerDb } from '../src/lib/db';
import { indexChainOps } from '../src/lib/sync';

const b64url = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
const mkJws = (createdAt: string, type = 'create'): string =>
  `${b64url({ typ: 'did:dfos:identity', kid: 'did:dfos:aaa#key1' })}.${b64url({ type, createdAt })}.sig`;

const op = (cid: string, createdAt: string, type = 'create') => ({
  cid,
  jwsToken: mkJws(createdAt, type),
});

const freshDb = () => openExplorerDb('jit-test', new IDBFactory());

describe('indexChainOps (JIT single-chain indexing)', () => {
  it('lands a chain and computes an exact rollup', async () => {
    const db = await freshDb();
    const res = await indexChainOps(db, 'did:dfos:aaa', 'identity-op', [
      op('bafy-a1', '2026-01-01T00:00:00.000Z'),
      op('bafy-a2', '2026-01-02T00:00:00.000Z', 'update'),
    ]);
    expect(res.added).toBe(2);

    const rollup = await db.getChain('did:dfos:aaa');
    expect(rollup?.opCount).toBe(2);
    expect(rollup?.headCid).toBe('bafy-a2'); // latest createdAt is the head
    expect(rollup?.kind).toBe('identity-op');

    const ops = await db.chainOps('did:dfos:aaa', 'identity-op');
    expect(ops.map((o) => o.cid)).toEqual(['bafy-a1', 'bafy-a2']);
    expect(ops[0]?.createdAt).toBe('2026-01-01T00:00:00.000Z');
  });

  it('is idempotent — re-indexing the same ops adds nothing and keeps the rollup exact', async () => {
    const db = await freshDb();
    const ops = [
      op('bafy-a1', '2026-01-01T00:00:00.000Z'),
      op('bafy-a2', '2026-01-02T00:00:00.000Z'),
    ];
    await indexChainOps(db, 'did:dfos:aaa', 'identity-op', ops);
    const again = await indexChainOps(db, 'did:dfos:aaa', 'identity-op', ops);
    expect(again.added).toBe(0);
    expect((await db.getChain('did:dfos:aaa'))?.opCount).toBe(2);
    expect((await db.counts()).ops).toBe(2);
  });

  it('extends an existing chain and re-heads it', async () => {
    const db = await freshDb();
    await indexChainOps(db, 'did:dfos:aaa', 'identity-op', [
      op('bafy-a1', '2026-01-01T00:00:00.000Z'),
    ]);
    const res = await indexChainOps(db, 'did:dfos:aaa', 'identity-op', [
      op('bafy-a1', '2026-01-01T00:00:00.000Z'),
      op('bafy-a2', '2026-02-01T00:00:00.000Z', 'update'),
    ]);
    expect(res.added).toBe(1);
    expect((await db.getChain('did:dfos:aaa'))?.headCid).toBe('bafy-a2');
    expect((await db.getChain('did:dfos:aaa'))?.opCount).toBe(2);
  });

  it('ignores empty chainId / empty op sets', async () => {
    const db = await freshDb();
    expect(
      (await indexChainOps(db, '', 'identity-op', [op('x', '2026-01-01T00:00:00.000Z')])).added,
    ).toBe(0);
    expect((await indexChainOps(db, 'did:dfos:aaa', 'identity-op', [])).added).toBe(0);
    expect((await db.counts()).ops).toBe(0);
  });
});
