/*

  CLIENT PAGING — a pager over rows this tab already holds

  Two different things page in this explorer and they must not be collapsed. A
  relay index serves a KEYSET cursor: there is no page count and no "page 7", so
  lib/index-light.ts walks it forward on the relay's own `next` and backward
  through the cursors it visited. This module is the other half — a table whose
  rows are already in memory (folded from a chain, accumulated off a ledger
  lane's cursor, read out of IndexedDB), where the whole set is known and paging
  it is arithmetic.

  Both feed the SAME `Pager` control, because twenty rows at a time, forward and
  back, is one idea and nobody should have to learn two sets of buttons for it.
  The one difference a reader sees is honest: a keyset pager's count is the page
  it holds, because a total is exactly what a cursor cannot tell it, while a
  client pager can name the total and does.

  The arithmetic is pure and total. An out-of-range page — a row set that shrank
  under a filter change, a lane that reloaded shorter than it was — CLAMPS rather
  than rendering an empty table under live controls.

*/

import { useEffect, useState } from 'preact/hooks';

/** Rows per page on every table surface. One number, so no two tables disagree
 *  about how much "a page" is. */
export const PAGE_ROWS = 20;

/** How many pages a row set fills. Always at least one — an empty table is page
 *  1 of 1, not page 1 of 0. */
export const pageCount = (total: number, size = PAGE_ROWS): number =>
  Math.max(1, Math.ceil(total / size));

/** A 0-based page index forced into range for `total` rows. */
export const clampPage = (page: number, total: number, size = PAGE_ROWS): number =>
  Math.min(Math.max(0, Math.trunc(page)), pageCount(total, size) - 1);

/** The rows of one page. The index clamps first, so this is never empty for a
 *  non-empty row set however stale the page number is. */
export const pageSlice = <T>(rows: readonly T[], page: number, size = PAGE_ROWS): T[] => {
  const at = clampPage(page, rows.length, size);
  return rows.slice(at * size, at * size + size);
};

/** What a client-paged table's count line says: the rows on screen, out of the
 *  total this tab holds — the sentence a keyset pager can never write and this
 *  one always can. Passed as the shared `Pager`'s noun so the two pagers stay
 *  one control. */
export const clientPagerNoun = (total: number, noun: string): string => `of ${total} ${noun}`;

/** One page of a locally-held row set, in the shape the `Pager` control reads. */
export interface ClientPage<T> {
  /** the rows of THIS page only. */
  rows: T[];
  /** every row this tab holds — never a corpus total (a ledger lane holding a
   *  live relay cursor knows what it loaded and nothing more). */
  total: number;
  /** 0-based, always in range. */
  page: number;
  pages: number;
  /** the set is longer than one page — the only case where the controls do
   *  anything, and therefore the only case worth rendering them in. */
  paged: boolean;
  hasNext: boolean;
  hasPrev: boolean;
  offFirst: boolean;
  first: () => void;
  prev: () => void;
  next: () => void;
}

/**
 * Page a row set this tab already holds. The rendered page is derived from a
 * CLAMPED index rather than the stored one, so a set that shrinks under the
 * pager (a relation filter narrowing a ledger lane, a chain re-folding shorter)
 * shows real rows on the very render it shrinks, and the stored value is put
 * back in agreement afterwards.
 */
export const useClientPager = <T>(rows: readonly T[], size = PAGE_ROWS): ClientPage<T> => {
  const [page, setPage] = useState(0);
  const total = rows.length;
  const at = clampPage(page, total, size);
  const pages = pageCount(total, size);

  // re-agree the stored index with what was rendered. Idempotent, so this
  // settles in one pass rather than looping.
  useEffect(() => {
    setPage((p) => clampPage(p, total, size));
  }, [total, size]);

  return {
    rows: pageSlice(rows, at, size),
    total,
    page: at,
    pages,
    paged: total > size,
    hasNext: at < pages - 1,
    hasPrev: at > 0,
    offFirst: at > 0,
    first: () => setPage(0),
    prev: () => setPage(Math.max(0, at - 1)),
    next: () => setPage(Math.min(pages - 1, at + 1)),
  };
};
