/**
 * The pure parts of the operation-history table: the display ORDER and the
 * timestamp column.
 *
 * The ordering carries a real invariant. The table reads newest-first so the op
 * a reader came for is the first row rather than the last one after a scroll —
 * but the `#` column is the op's ABSOLUTE position on the chain, and reversing
 * the display must not renumber anything. Op 1 is genesis on any page.
 */

import { describe, expect, it } from 'vitest';
import { fmtStamp } from '../src/lib/format';
import { newestFirst, placeOp, type OpRow } from '../src/lib/op-rows';
import { mockJws } from './fixtures/mock-jws';

const op = (cid: string): OpRow => ({
  cid,
  jwsToken: '',
  type: 'update',
  createdAt: '2026-08-28T12:34:56.789Z',
  kid: '',
});

describe('newestFirst', () => {
  it('reverses the log the relay serves genesis-first', () => {
    const rows = newestFirst([op('a'), op('b'), op('c')]);
    expect(rows.map((r) => r.row.cid)).toEqual(['c', 'b', 'a']);
  });

  // the numbering is the chain's, not the table's: reversing the rows must not
  // renumber them, or "op 3" would mean a different op on a re-sorted view
  it('keeps each op’s absolute position, genesis = 1', () => {
    const rows = newestFirst([op('a'), op('b'), op('c')]);
    expect(rows.map((r) => r.n)).toEqual([3, 2, 1]);
    expect(rows[rows.length - 1]).toMatchObject({ n: 1, row: { cid: 'a' } });
  });

  it('leaves the caller’s array untouched', () => {
    const source = [op('a'), op('b')];
    newestFirst(source);
    expect(source.map((r) => r.cid)).toEqual(['a', 'b']);
  });

  it('is total over an empty log', () => {
    expect(newestFirst([])).toEqual([]);
  });
});

describe('fmtStamp', () => {
  it('trims an ISO timestamp to the width a column holds', () => {
    expect(fmtStamp('2026-08-28T12:34:56.789Z')).toBe('2026-08-28 12:34');
  });

  // an op whose createdAt we cannot parse still HAS one, and the raw value is the
  // honest thing to show — blanking the cell would hide the anomaly
  it('passes an unparseable value through rather than blanking the cell', () => {
    expect(fmtStamp('not a date')).toBe('not a date');
  });

  it('renders nothing for a missing timestamp', () => {
    expect(fmtStamp('')).toBe('');
    expect(fmtStamp(null)).toBe('');
    expect(fmtStamp(undefined)).toBe('');
  });
});

// A content log is branch-inclusive: the last row is not the head, and the row
// beside an op is not its parent. Placement reads the selected head and the
// signed `previousOperationCID`.
describe('placeOp — a fork is not a line', () => {
  const row = (cid: string, previousOperationCID: string | null, createdAt: string): OpRow => ({
    cid,
    jwsToken: mockJws(
      { typ: 'did:dfos:content-op', kid: 'did:dfos:x#k', cid },
      previousOperationCID === null
        ? { type: 'create', createdAt }
        : { type: 'update', previousOperationCID, createdAt },
    ),
    type: previousOperationCID === null ? 'create' : 'update',
    createdAt,
    kid: 'did:dfos:x#k',
  });
  // siblings A and B off G, A dated later, B served last
  const rows = [
    row('G', null, '2026-01-01T00:00:00.000Z'),
    row('A', 'G', '2026-01-03T00:00:00.000Z'),
    row('B', 'G', '2026-01-02T00:00:00.000Z'),
  ];

  it('the selected head is the head, wherever it sits in the log', () => {
    expect(placeOp(rows, 'A', 'A')).toMatchObject({ present: true, isHead: true, position: 2 });
    expect(placeOp(rows, 'B', 'A')).toMatchObject({ present: true, isHead: false });
  });

  it('previous is the signed parent, next is every child', () => {
    expect(placeOp(rows, 'B', 'A').previous).toBe('G');
    expect(placeOp(rows, 'A', 'A').previous).toBe('G');
    expect(placeOp(rows, 'G', 'A').previous).toBeNull();
    expect(placeOp(rows, 'G', 'A').next).toEqual(['A', 'B']);
    expect(placeOp(rows, 'A', 'A').next).toEqual([]);
  });

  it('an op not in the log is not present', () => {
    expect(placeOp(rows, 'Z', 'A')).toMatchObject({ present: false, isHead: false, position: 0 });
  });
});
