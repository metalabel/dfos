/*

  ACTOR LEDGER — pure derivations for the identity page's per-actor index lookups

  The relay's `signer=<did>` reverse lookup returns every chain the DID signed at
  least one op in — branch-inclusive, INCLUDING the chains it created (the creator
  signs genesis). "Contributed to but did not create" is the client-side
  subtraction the spec prescribes: signer minus creator.

  The subtraction shrinks the array, so the "showing the first 200" truncation
  hint MUST key off the RAW page length (before subtraction) — a full 200-row
  signer page that subtracts down to a handful is still truncated, and saying
  otherwise would under-report the omission the deep-sync audit exists to catch.

*/

import type { IndexContentRow } from '@metalabel/dfos-client';

export interface ContributedPage {
  /** signer rows minus the DID's own creations — "contributed, did not create". */
  rows: IndexContentRow[];
  /** the RAW signer page hit the limit — more may exist beyond this page. */
  truncated: boolean;
}

/**
 * Derive the Contributed tab from a raw `signer=` index page: the creator-
 * subtraction, plus a truncation flag keyed off the RAW page length (never the
 * post-subtraction length). Pure and total.
 */
export const contributedFromSignerPage = (
  rows: IndexContentRow[],
  did: string,
  limit = 200,
): ContributedPage => ({
  rows: rows.filter((r) => r.creatorDID !== did),
  truncated: rows.length === limit,
});
