import { describe, expect, it } from 'vitest';
import {
  nextCursor,
  toArtifactRows,
  toContentRows,
  toCreditRows,
  toOperationRows,
} from '../src/lib/index-raw';

describe('toOperationRows — /index/v0/operations page → rows', () => {
  it('reads the documented row shape', () => {
    expect(
      toOperationRows({
        operations: [
          {
            cid: 'bafy1',
            kind: 'content-op',
            chainId: 'a3n7r3nde8e4keeak92rr3aeztftvc2',
            createdAt: '2026-04-02T00:00:00.000Z',
            ingestedAt: '2026-04-02T00:00:01.123Z',
          },
        ],
        next: null,
      }),
    ).toEqual([
      {
        cid: 'bafy1',
        kind: 'content-op',
        chainId: 'a3n7r3nde8e4keeak92rr3aeztftvc2',
        createdAt: '2026-04-02T00:00:00.000Z',
        ingestedAt: '2026-04-02T00:00:01.123Z',
      },
    ]);
  });

  it('drops a row that names no operation — it would not be addressable', () => {
    expect(toOperationRows({ operations: [{ kind: 'artifact' }, { cid: '' }] })).toEqual([]);
  });

  it('coerces missing/odd fields to empty strings rather than throwing', () => {
    const [row] = toOperationRows({ operations: [{ cid: 'bafy1', kind: 42, chainId: null }] });
    expect(row).toEqual({ cid: 'bafy1', kind: '', chainId: '', createdAt: '', ingestedAt: '' });
  });

  it('a body that is not a page yields no rows', () => {
    expect(toOperationRows(null)).toEqual([]);
    expect(toOperationRows({})).toEqual([]);
    expect(toOperationRows({ operations: 'nope' })).toEqual([]);
  });
});

describe('toArtifactRows — /index/v0/artifacts page → rows', () => {
  it('reads the documented row shape', () => {
    expect(
      toArtifactRows({
        artifacts: [
          {
            cid: 'bafy1',
            signerDID: 'did:dfos:hd34z9a4tf6h62864nh4f7at6hr36r4',
            createdAt: '2026-04-02T00:00:00.000Z',
            ingestedAt: '2026-04-02T00:00:01.123Z',
            docSchema: 'https://example.com/schema/v1',
          },
        ],
      }),
    ).toEqual([
      {
        cid: 'bafy1',
        signerDID: 'did:dfos:hd34z9a4tf6h62864nh4f7at6hr36r4',
        createdAt: '2026-04-02T00:00:00.000Z',
        ingestedAt: '2026-04-02T00:00:01.123Z',
        docSchema: 'https://example.com/schema/v1',
      },
    ]);
  });

  it('keeps the honest unknown: a non-string docSchema is null, never guessed', () => {
    expect(toArtifactRows({ artifacts: [{ cid: 'bafy1' }] })[0]?.docSchema).toBeNull();
    expect(
      toArtifactRows({ artifacts: [{ cid: 'bafy1', docSchema: null }] })[0]?.docSchema,
    ).toBeNull();
  });
});

describe('toCreditRows — /index/v0/credits page → rows', () => {
  it('reads the documented row shape', () => {
    expect(
      toCreditRows({
        credits: [
          {
            contentId: 'a3n7r3nde8e4keeak92rr3aeztftvc2',
            did: 'did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr',
            role: 'photography',
            position: 1,
            hasClaim: true,
          },
        ],
        next: null,
      }),
    ).toEqual([
      {
        contentId: 'a3n7r3nde8e4keeak92rr3aeztftvc2',
        did: 'did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr',
        role: 'photography',
        position: 1,
        hasClaim: true,
      },
    ]);
  });

  it('an unroled credit keeps the honest null — it is ordinary, not an error', () => {
    const [row] = toCreditRows({ credits: [{ contentId: 'c1', did: 'did:dfos:a', position: 0 }] });
    expect(row?.role).toBeNull();
    expect(row?.position).toBe(0);
  });

  it('hasClaim is byte-presence and strictly boolean — anything else is no claim', () => {
    // the relay reports whether a claim TOKEN sits in the entry, never whether it
    // verifies; a non-boolean must not soften into a truthy "probably claimed"
    const rows = toCreditRows({
      credits: [
        { contentId: 'c1', did: 'did:dfos:a', hasClaim: true },
        { contentId: 'c2', did: 'did:dfos:a', hasClaim: 'yes' },
        { contentId: 'c3', did: 'did:dfos:a' },
      ],
    });
    expect(rows.map((r) => r.hasClaim)).toEqual([true, false, false]);
  });

  it('drops a row missing either half of the credit — it names a credit OF someone ON something', () => {
    expect(
      toCreditRows({
        credits: [{ contentId: 'c1' }, { did: 'did:dfos:a' }, { contentId: '', did: '' }],
      }),
    ).toEqual([]);
  });

  it('a body that is not a page yields no rows', () => {
    expect(toCreditRows(null)).toEqual([]);
    expect(toCreditRows({})).toEqual([]);
    expect(toCreditRows({ credits: 'nope' })).toEqual([]);
  });
});

describe('toContentRows — /index/v0/content page → rows', () => {
  it('reads the documented row shape', () => {
    expect(
      toContentRows({
        content: [
          {
            contentId: 'a3n7r3nde8e4keeak92rr3aeztftvc2',
            genesisCID: 'bafyGenesis',
            headCID: 'bafyHead',
            creatorDID: 'did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr',
            isDeleted: false,
            opCount: 4,
            genesisAt: '2026-04-02T00:00:00.000Z',
            headAt: '2026-04-03T00:00:00.000Z',
            currentDocumentCID: 'bafyDoc',
            publicRead: true,
            docSchema: 'https://schemas.dfos.com/post/v1.json',
            title: 'A Post',
          },
        ],
        next: null,
      }),
    ).toEqual([
      {
        contentId: 'a3n7r3nde8e4keeak92rr3aeztftvc2',
        genesisCID: 'bafyGenesis',
        headCID: 'bafyHead',
        creatorDID: 'did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr',
        isDeleted: false,
        opCount: 4,
        genesisAt: '2026-04-02T00:00:00.000Z',
        headAt: '2026-04-03T00:00:00.000Z',
        currentDocumentCID: 'bafyDoc',
        publicRead: true,
        docSchema: 'https://schemas.dfos.com/post/v1.json',
        title: 'A Post',
      },
    ]);
  });

  it('publicRead is strictly boolean — anything else reads as GATED', () => {
    // the only direction that can misfire safely: a malformed flag costs a title,
    // where softening it into truthy would leak one off a non-public chain
    const rows = toContentRows({
      content: [
        { contentId: 'c1', publicRead: true },
        { contentId: 'c2', publicRead: 'yes' },
        { contentId: 'c3', publicRead: 1 },
        { contentId: 'c4' },
      ],
    });
    expect(rows.map((r) => r.publicRead)).toEqual([true, false, false, false]);
  });

  it('keeps the index’s honest nulls for schema, document, and title', () => {
    const [row] = toContentRows({ content: [{ contentId: 'c1' }] });
    expect(row?.docSchema).toBeNull();
    expect(row?.currentDocumentCID).toBeNull();
    expect(row?.title).toBeNull();
    expect(row?.opCount).toBe(0);
  });

  it('drops a row that names no chain — it would not be addressable', () => {
    expect(toContentRows({ content: [{ creatorDID: 'did:dfos:a' }, { contentId: '' }] })).toEqual(
      [],
    );
  });

  it('a body that is not a page yields no rows', () => {
    expect(toContentRows(null)).toEqual([]);
    expect(toContentRows({})).toEqual([]);
    expect(toContentRows({ content: 'nope' })).toEqual([]);
  });
});

describe('nextCursor — the resume token, or caught up', () => {
  it('a non-empty string resumes; anything else is caught up', () => {
    expect(nextCursor({ next: 'bafy9' })).toBe('bafy9');
    expect(nextCursor({ next: null })).toBeNull();
    expect(nextCursor({ next: '' })).toBeNull();
    expect(nextCursor({})).toBeNull();
    expect(nextCursor(null)).toBeNull();
  });
});
