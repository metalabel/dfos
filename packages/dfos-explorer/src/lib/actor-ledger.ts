/*

  ACTOR LEDGER — pure derivations for the identity page's per-actor index lookups

  The relay's `signer=<did>` reverse lookup returns every chain the DID signed at
  least one op in — branch-inclusive, INCLUDING the chains it created (the creator
  signs genesis). "Contributed to but did not create" is the client-side
  subtraction the spec prescribes: signer minus creator.

  The subtraction is ROW-LOCAL (`creatorDID !== did` reads one row and nothing
  else), which is what lets the identity view apply it per PAGE and concatenate:
  filtering each page and appending equals filtering the appended whole. So the
  ledger lanes accumulate pages off the relay's own `next` cursor, and the
  cursor — not a "did this page hit the limit" guess — is what says more exists.

  These lanes list EVERY chain on the actor axis, gated ones included. A gated row
  arrives with `publicRead: false` and no projected title, and renders as a bare
  id pill; `ledgerCounts` is how the surface says out loud how much of what it
  loaded is readable and how much is only listed.

*/

import type { IndexContentRow } from '@metalabel/dfos-client';

/**
 * Derive the Contributed tab from a raw `signer=` index page: the creator-
 * subtraction, and nothing else. Pure, total, and row-local — safe to apply to
 * each page of an accumulating lane rather than to the whole.
 */
export const contributedFromSignerPage = (
  rows: IndexContentRow[],
  did: string,
): IndexContentRow[] => rows.filter((r) => r.creatorDID !== did);

/** The public/gated split of the rows a ledger lane has LOADED. */
export interface LedgerCounts {
  /** rows loaded into the lane — never a corpus total (completeness is outside
   *  the proof, and a lane with a live cursor holds only what it has fetched). */
  total: number;
  /** rows the index marks publicly readable — their bytes answer an anonymous
   *  fetch, so a title can render. */
  publicCount: number;
  /** the rest: the chain's EXISTENCE is on the actor axis, its bytes are not
   *  public, and nothing but the short id is ever shown for it. */
  gatedCount: number;
}

/**
 * Count a ledger lane's loaded rows by read-visibility. `publicRead === true` is
 * the whole test — the narrow question "would an anonymous fetch be served these
 * bytes", not the broader "can a title render here" that the row's gated marker
 * asks. Pure and total.
 */
export const ledgerCounts = (rows: IndexContentRow[]): LedgerCounts => {
  const publicCount = rows.filter((r) => r.publicRead === true).length;
  return { total: rows.length, publicCount, gatedCount: rows.length - publicCount };
};
