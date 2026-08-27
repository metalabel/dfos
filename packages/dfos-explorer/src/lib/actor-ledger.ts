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

  The Witnessed lane's relation filter has the SAME SHAPE as the subtraction — a
  row-local narrowing applied per page — and therefore the same hazard: a page
  that narrows to nothing while the relay's cursor is still live is not an empty
  listing, and only an exhausted cursor ever licenses that claim.

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

/**
 * How a ledger lane names its own size. A lane with a live cursor holds a FLOOR,
 * not a total, and says so in words rather than leaving the reader to infer it
 * from a button; an exhausted cursor is the only thing that licenses the plain
 * count. Every lane on the panel shares this phrasing so the four tabs mean the
 * same thing by a number. Pure and total.
 */
export const ledgerCountPhrase = (total: number, noun: string, more: boolean): string =>
  more ? `${total} loaded so far` : `${total} ${noun}${total === 1 ? '' : 's'}`;

// -----------------------------------------------------------------------------
// WITNESSED — the relation filter, which has the same shape as the Contributed
// subtraction: a per-page narrowing that can empty a page while the relay still
// holds more.
// -----------------------------------------------------------------------------

/** The fields the relation derivations read — every countersignature row has
 *  them, and nothing here needs the rest. */
export interface WitnessRelationRow {
  relation: string | null;
}

/**
 * Keep only the rows that answer the exact relation question. `relation=` is a
 * SERVER-side filter, but a relay predating it ignores the param and answers
 * unfiltered — so the page is re-filtered here and the surface never presents
 * rows that do not answer what was asked (the index-point.ts rule). Row-local,
 * so it applies per page and concatenating equals filtering the whole.
 */
export const witnessedFromPage = <T extends WitnessRelationRow>(
  rows: T[],
  relation: string | null,
): T[] => (relation ? rows.filter((row) => row.relation === relation) : rows);

/**
 * The relation tags offered as filter buttons, merged across every UNFILTERED
 * page loaded so far. The namespace is open, so the buttons can only ever be a
 * sample of what exists — and a tag absent from the pages we hold is not offered
 * rather than guessed at. Merging (not replacing) is what lets a load-more widen
 * the button set instead of the second page silently narrowing it. Pure, total,
 * and sorted so the row order a relay happens to serve never moves the buttons.
 */
export const mergeWitnessRelations = (known: string[], rows: WitnessRelationRow[]): string[] =>
  [
    ...new Set([
      ...known,
      ...rows.map((row) => row.relation).filter((relation): relation is string => !!relation),
    ]),
  ].sort();
