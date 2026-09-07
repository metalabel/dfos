/**
 * H31 — what licenses the landing panel's GREEN tier.
 *
 * The app states its palette as a rule (`styles.css`: "amber = relay-asserted,
 * green = verified locally") and the glossary defines verified locally as "your
 * browser recomputed the signatures and CIDs itself and they matched". The panel
 * used to green on `localOps >= assertedOps`, a comparison of a stored-row count
 * against the relay's self-reported total — neither of which anything verified.
 */

import { describe, expect, it } from 'vitest';
import { fullyVerifiedLocally, logComplete } from '../src/views/home';

describe('fullyVerifiedLocally', () => {
  it('greens only when FOLDED ops meet the relay’s count', () => {
    expect(fullyVerifiedLocally(100, 100)).toBe(true);
    expect(fullyVerifiedLocally(120, 100)).toBe(true);
  });

  // the defect, as an assertion: a tab holding every row and having folded none
  // is the exact case the old comparison painted green
  it('never greens on row-count parity with nothing folded', () => {
    expect(fullyVerifiedLocally(0, 100)).toBe(false);
    expect(fullyVerifiedLocally(99, 100)).toBe(false);
  });

  // with no relay figure there is nothing to be complete AGAINST — a tab that
  // folded a chain has not thereby verified the network
  it('never greens without a relay-asserted total to meet', () => {
    expect(fullyVerifiedLocally(100, 0)).toBe(false);
    expect(fullyVerifiedLocally(0, 0)).toBe(false);
  });
});

describe('logComplete — the amber statement, and only ever amber', () => {
  it('is the row-count comparison, under its own name', () => {
    expect(logComplete(100, 100)).toBe(true);
    expect(logComplete(99, 100)).toBe(false);
    expect(logComplete(100, 0)).toBe(false);
  });

  // the two are independent: a complete log is not a verified one, which is the
  // whole reason they are separate functions with separate words
  it('is true exactly where the green tier is false, given no folds', () => {
    expect(logComplete(100, 100)).toBe(true);
    expect(fullyVerifiedLocally(0, 100)).toBe(false);
  });
});
