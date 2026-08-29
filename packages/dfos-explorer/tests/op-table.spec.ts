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
import { newestFirst, type OpRow } from '../src/lib/op-rows';

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
