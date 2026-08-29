/**
 * Client paging — the arithmetic under every table that holds its own rows.
 *
 * The keyset pager cannot be tested this way and does not need to be: it walks a
 * relay's opaque cursor and has no page count to get wrong. This one has both,
 * and the case that matters is the STALE INDEX — a row set that shrinks under a
 * pager parked past its new end (a relation filter narrowing a ledger lane, a
 * chain re-folding shorter). Clamping is what keeps that from rendering an empty
 * table under live controls.
 */

import { describe, expect, it } from 'vitest';
import { clampPage, clientPagerNoun, PAGE_ROWS, pageCount, pageSlice } from '../src/lib/paging';

/** `n` rows, each its own number, so a slice says exactly where it came from. */
const rows = (n: number): number[] => Array.from({ length: n }, (_, i) => i);

describe('PAGE_ROWS — the one page size', () => {
  it('is the ≤20 rows every table surface pages at', () => {
    expect(PAGE_ROWS).toBeLessThanOrEqual(20);
  });
});

describe('pageCount', () => {
  it('counts whole and partial pages', () => {
    expect(pageCount(0)).toBe(1);
    expect(pageCount(1)).toBe(1);
    expect(pageCount(20)).toBe(1);
    expect(pageCount(21)).toBe(2);
    expect(pageCount(40)).toBe(2);
    expect(pageCount(41)).toBe(3);
  });

  // an empty table is page 1 of 1, not page 1 of 0 — the label has to read
  it('never reports zero pages', () => {
    expect(pageCount(0)).toBe(1);
    expect(pageCount(-5)).toBe(1);
  });
});

describe('clampPage', () => {
  it('leaves an in-range page alone', () => {
    expect(clampPage(0, 100)).toBe(0);
    expect(clampPage(3, 100)).toBe(3);
    expect(clampPage(4, 100)).toBe(4);
  });

  it('pulls a page past the end back to the last one', () => {
    expect(clampPage(9, 100)).toBe(4);
    expect(clampPage(99, 21)).toBe(1);
  });

  it('pulls a negative page back to the first', () => {
    expect(clampPage(-1, 100)).toBe(0);
  });

  it('lands on the only page of an empty set', () => {
    expect(clampPage(7, 0)).toBe(0);
  });
});

describe('pageSlice', () => {
  it('serves consecutive, non-overlapping pages that cover the whole set', () => {
    const all = rows(45);
    const pages = [pageSlice(all, 0), pageSlice(all, 1), pageSlice(all, 2)];
    expect(pages[0]).toHaveLength(20);
    expect(pages[1]).toHaveLength(20);
    expect(pages[2]).toHaveLength(5);
    expect(pages.flat()).toEqual(all);
  });

  it('keeps the set order — a page is a window, never a re-sort', () => {
    expect(pageSlice(rows(25), 1)).toEqual([20, 21, 22, 23, 24]);
  });

  // THE REGRESSION THIS EXISTS FOR: a lane parked on page 4 that reloads holding
  // 3 rows must show those 3 rows, not an empty table under a live pager.
  it('shows real rows when the set shrinks under a stale page index', () => {
    expect(pageSlice(rows(3), 4)).toEqual([0, 1, 2]);
  });

  it('is empty only for an empty set', () => {
    expect(pageSlice([], 0)).toEqual([]);
    expect(pageSlice(rows(1), 0)).toEqual([0]);
  });

  it('honours a caller-supplied page size', () => {
    expect(pageSlice(rows(10), 1, 4)).toEqual([4, 5, 6, 7]);
  });
});

describe('clientPagerNoun', () => {
  // the one thing a client pager can say that a keyset pager cannot: the total
  it('names the total the keyset pager has no way to know', () => {
    expect(clientPagerNoun(137, 'operations')).toBe('of 137 operations');
  });
});
