import { IDBFactory, IDBKeyRange } from 'fake-indexeddb';
import { describe, expect, it } from 'vitest';
import { openExplorerDb, type ExplorerOp } from '../src/lib/db';
import { localOpRows, toLogRows } from '../src/lib/log-feed';

// the keyset queries use the global IDBKeyRange a browser provides; the node
// test environment has only the injected factory, so supply the matching one.
globalThis.IDBKeyRange = IDBKeyRange as unknown as typeof globalThis.IDBKeyRange;

const b64url = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');

/** A decodable JWS with the header/payload fields the log rows read. */
const jws = (payload: Record<string, unknown>): string =>
  `${b64url({ alg: 'EdDSA', typ: 'did:dfos:identity-op', cid: 'bafy1' })}.${b64url(payload)}.sig`;

describe('toLogRows — global-log entries → display rows', () => {
  it('decodes type and createdAt out of the JWS payload', () => {
    const [row] = toLogRows([
      {
        cid: 'bafy1',
        jwsToken: jws({ type: 'create', createdAt: '2026-01-01T00:00:00.000Z' }),
        kind: 'identity-op',
        chainId: 'did:dfos:aaa',
      },
    ]);
    expect(row).toEqual({
      cid: 'bafy1',
      kind: 'identity-op',
      chainId: 'did:dfos:aaa',
      type: 'create',
      createdAt: '2026-01-01T00:00:00.000Z',
    });
  });

  it('an unknown relay-asserted kind falls into the standalone-op bucket', () => {
    // matches how the sync engine classifies an unrecognized kind — a routing
    // hint is never a verification input, so an odd one degrades, never throws
    const [row] = toLogRows([
      { cid: 'bafy2', jwsToken: jws({}), kind: 'something-new', chainId: 'x' },
    ]);
    expect(row?.kind).toBe('artifact');
  });

  it('an undecodable token still yields a linkable row', () => {
    const [row] = toLogRows([{ cid: 'bafy3', jwsToken: 'garbage', kind: 'content-op' }]);
    expect(row).toEqual({
      cid: 'bafy3',
      kind: 'content-op',
      chainId: '',
      type: '',
      createdAt: '',
    });
  });
});

describe('localOpRows — local index ops → the same row shape', () => {
  it('carries the already-decoded metadata straight through', () => {
    const op: ExplorerOp = {
      cid: 'bafy1',
      jwsToken: 'x.y.z',
      kind: 'credential',
      chainId: 'did:dfos:aaa',
      type: 'grant',
      createdAt: '2026-02-02T00:00:00.000Z',
      kid: 'did:dfos:aaa#k',
      seq: 4,
    };
    expect(localOpRows([op])).toEqual([
      {
        cid: 'bafy1',
        kind: 'credential',
        chainId: 'did:dfos:aaa',
        type: 'grant',
        createdAt: '2026-02-02T00:00:00.000Z',
      },
    ]);
  });
});

// -----------------------------------------------------------------------------

const op = (cid: string, createdAt: string): ExplorerOp => ({
  cid,
  jwsToken: 'x.y.z',
  kind: 'identity-op',
  chainId: 'did:dfos:aaa',
  type: 'create',
  createdAt,
  kid: '',
  seq: 0,
});

describe('db.opsPage — the newest-first local operation pager', () => {
  const seed = async () => {
    const db = await openExplorerDb('ops-page', new IDBFactory());
    await db.putBatch(
      [
        op('bafy1', '2026-01-01T00:00:00.000Z'),
        op('bafy2', '2026-01-02T00:00:00.000Z'),
        op('bafy3', '2026-01-03T00:00:00.000Z'),
        op('bafy4', '2026-01-04T00:00:00.000Z'),
        op('bafy5', '2026-01-05T00:00:00.000Z'),
      ],
      [],
    );
    return db;
  };

  it('serves newest first', async () => {
    const db = await seed();
    const page = await db.opsPage({ before: '', limit: 2 });
    expect(page.rows.map((r) => r.cid)).toEqual(['bafy5', 'bafy4']);
  });

  it('resumes strictly past the cursor, without repeats or gaps', async () => {
    const db = await seed();
    const first = await db.opsPage({ before: '', limit: 2 });
    const second = await db.opsPage({ before: first.next ?? '', limit: 2 });
    const third = await db.opsPage({ before: second.next ?? '', limit: 2 });
    expect(second.rows.map((r) => r.cid)).toEqual(['bafy3', 'bafy2']);
    expect(third.rows.map((r) => r.cid)).toEqual(['bafy1']);
  });

  it('issues `next` only on a FULL page — a short page means the corpus ran out', async () => {
    const db = await seed();
    expect((await db.opsPage({ before: '', limit: 2 })).next).toBeTruthy();
    expect((await db.opsPage({ before: '', limit: 10 })).next).toBeNull();
  });

  it('breaks same-timestamp ties by cid so a page boundary is deterministic', async () => {
    const db = await openExplorerDb('ops-page-ties', new IDBFactory());
    const at = '2026-01-01T00:00:00.000Z';
    await db.putBatch([op('bafyA', at), op('bafyB', at), op('bafyC', at)], []);
    const first = await db.opsPage({ before: '', limit: 2 });
    const second = await db.opsPage({ before: first.next ?? '', limit: 2 });
    const seen = [...first.rows, ...second.rows].map((r) => r.cid);
    expect(seen).toHaveLength(3);
    expect(new Set(seen).size).toBe(3);
  });

  it('an empty corpus is an empty page, not a hang', async () => {
    const db = await openExplorerDb('ops-page-empty', new IDBFactory());
    expect(await db.opsPage({ before: '', limit: 5 })).toEqual({ rows: [], next: null });
  });
});
