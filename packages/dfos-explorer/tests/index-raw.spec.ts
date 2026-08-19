import { describe, expect, it } from 'vitest';
import { nextCursor, toArtifactRows, toOperationRows } from '../src/lib/index-raw';

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

describe('nextCursor — the resume token, or caught up', () => {
  it('a non-empty string resumes; anything else is caught up', () => {
    expect(nextCursor({ next: 'bafy9' })).toBe('bafy9');
    expect(nextCursor({ next: null })).toBeNull();
    expect(nextCursor({ next: '' })).toBeNull();
    expect(nextCursor({})).toBeNull();
    expect(nextCursor(null)).toBeNull();
  });
});
