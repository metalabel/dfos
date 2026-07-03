import { dagCborCanonicalEncode } from '@metalabel/dfos-protocol/crypto';
import { describe, expect, it } from 'vitest';
import { foldIndexChain, isIndexDocument } from '../src/lib/index-fold';
import { parseMediaObject, rawCidOf } from '../src/lib/media';
import type { OpRow } from '../src/lib/op-rows';

const b64url = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');

const mkRow = async (
  cid: string,
  createdAt: string,
  doc: unknown,
): Promise<{ row: OpRow; body: string | null; documentCID: string | null }> => {
  const documentCID = doc === null ? null : (await dagCborCanonicalEncode(doc)).cid.toString();
  const jwsToken = `${b64url({ typ: 'did:dfos:content-op', kid: 'did:dfos:aaa#k' })}.${b64url({
    type: 'update',
    createdAt,
    documentCID,
  })}.sig`;
  return {
    row: { cid, jwsToken, type: 'update', createdAt, kid: 'did:dfos:aaa#k' },
    body: doc === null ? null : JSON.stringify(doc),
    documentCID,
  };
};

const SCHEMA = 'https://schemas.dfos.com/index/v1';

describe('foldIndexChain', () => {
  it('folds set/remove deltas across ops with doc integrity', async () => {
    const a = await mkRow('bafy-1', '2026-01-01T00:00:00.000Z', {
      $schema: SCHEMA,
      deltas: [
        { op: 'set', key: 'ref-one', value: { label: 'first', order: 2 } },
        { op: 'set', key: 'ref-two', value: {} },
      ],
    });
    const b = await mkRow('bafy-2', '2026-01-02T00:00:00.000Z', {
      $schema: SCHEMA,
      deltas: [
        { op: 'remove', key: 'ref-two' },
        { op: 'set', key: 'ref-three', value: { order: 1 } },
        { op: 'teleport', key: 'ref-x' }, // unknown shape — skipped deterministically
      ],
    });
    const bodies = new Map([
      ['bafy-1', a.body],
      ['bafy-2', b.body],
    ]);
    const fetchImpl = (async (url: unknown) => {
      const cid = String(url).split('/blob/')[1];
      const body = cid ? bodies.get(cid) : undefined;
      if (!body) return new Response('nope', { status: 404 });
      return new Response(body, { status: 200 });
    }) as typeof fetch;

    const folded = await foldIndexChain({
      contentId: 'c1',
      rows: [b.row, a.row], // reversed arrival — the fold linearizes
      relays: ['http://fake'],
      fetchImpl,
    });

    expect(folded.gaps).toEqual([]);
    expect([...folded.entries.keys()].sort()).toEqual(['ref-one', 'ref-three']);
    expect(folded.entries.get('ref-one')).toEqual({ label: 'first', order: 2 });
    expect(folded.docs.map((d) => d.opCid)).toEqual(['bafy-1', 'bafy-2']);
  });

  it('reports unreadable and tampered docs as coverage gaps', async () => {
    const good = await mkRow('bafy-ok', '2026-01-01T00:00:00.000Z', {
      $schema: SCHEMA,
      deltas: [{ op: 'set', key: 'kept', value: {} }],
    });
    const tampered = await mkRow('bafy-bad', '2026-01-02T00:00:00.000Z', {
      $schema: SCHEMA,
      deltas: [{ op: 'set', key: 'evil', value: {} }],
    });
    const fetchImpl = (async (url: unknown) => {
      const cid = String(url).split('/blob/')[1];
      if (cid === 'bafy-ok') return new Response(good.body, { status: 200 });
      if (cid === 'bafy-bad')
        // served bytes differ from what the op committed
        return new Response(JSON.stringify({ $schema: SCHEMA, deltas: [] }), { status: 200 });
      return new Response('', { status: 404 });
    }) as typeof fetch;

    const folded = await foldIndexChain({
      contentId: 'c1',
      rows: [good.row, tampered.row],
      relays: ['http://fake'],
      fetchImpl,
    });

    expect([...folded.entries.keys()]).toEqual(['kept']); // tampered doc never folds
    expect(folded.gaps).toHaveLength(1);
    expect(folded.gaps[0]?.reason).toMatch(/re-hash/);
  });

  it('counts null documents (delete/clear) without gap noise', async () => {
    const cleared = await mkRow('bafy-null', '2026-01-01T00:00:00.000Z', null);
    const folded = await foldIndexChain({
      contentId: 'c1',
      rows: [cleared.row],
      relays: ['http://fake'],
      fetchImpl: (async () => new Response('', { status: 404 })) as typeof fetch,
    });
    expect(folded.nulls).toBe(1);
    expect(folded.gaps).toEqual([]);
    expect(folded.entries.size).toBe(0);
  });
});

describe('isIndexDocument', () => {
  it('detects by $schema only', () => {
    expect(isIndexDocument({ $schema: SCHEMA, deltas: [] })).toBe(true);
    expect(isIndexDocument({ $schema: 'https://schemas.dfos.com/post/v1' })).toBe(false);
    expect(isIndexDocument(null)).toBe(false);
    expect(isIndexDocument([])).toBe(false);
  });
});

describe('media', () => {
  it('parses valid media objects and rejects malformed ones', () => {
    expect(parseMediaObject({ uri: 'attachment://abc', cid: 'bafkrei123' })).toEqual({
      uri: 'attachment://abc',
      cid: 'bafkrei123',
    });
    expect(parseMediaObject({ uri: 'attachment://abc', href: 'https://x/y.png' })).toEqual({
      uri: 'attachment://abc',
      href: 'https://x/y.png',
    });
    expect(parseMediaObject({ cid: 'bafkrei123' })).toBeNull();
    expect(parseMediaObject('attachment://abc')).toBeNull();
    expect(parseMediaObject(null)).toBeNull();
  });

  it('computes CIDv1/raw/sha2-256 (bafkrei…) over bytes', async () => {
    const cid = await rawCidOf(new TextEncoder().encode('hello dfos'));
    expect(cid).toMatch(/^bafkrei[a-z2-7]{52}$/);
    // deterministic
    expect(await rawCidOf(new TextEncoder().encode('hello dfos'))).toBe(cid);
    expect(await rawCidOf(new TextEncoder().encode('hello dfos!'))).not.toBe(cid);
  });
});
