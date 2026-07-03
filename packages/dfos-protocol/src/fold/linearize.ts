/*

  CANONICAL FOLD — LINEARIZATION

  A deterministic total order over ALL operations in a content chain's log —
  every branch, not just the selected-head branch. This is the head-selection
  comparator (web relay `selectDeterministicHead`) generalized from "pick one
  tip" to "order the whole log".

  Head selection prefers, among tips: highest `createdAt`, then highest CID
  (byte-wise). The canonical linearization is the SAME order laid out in full,
  ascending, so the op head selection would prefer sorts LAST — last-applied
  wins under the LWW fold. See `compareHeadPreference` / `compareLinear` below:
  they are exact reverses of one another, so the two orderings can never
  disagree. Because the globally-maximal `createdAt` op is always a tip (any op
  with a child has a strictly-greater-`createdAt` child), the LAST element of a
  full-log linearization is exactly the op `selectDeterministicHead` selects.

  Pure — string comparison only. No crypto, no network, no JWS decoding. The
  caller passes already-verified operations reduced to their ordering keys.

*/

/**
 * Byte-wise (code-point) string comparison returning -1 | 0 | 1.
 *
 * NOT `localeCompare` — ICU collation is locale/engine dependent with no
 * determinism contract. For base32lower CIDs and ASCII ISO-8601 timestamps,
 * JS `<`/`>` (UTF-16 code-unit order) equals byte-wise order, and equals the
 * Go relay twin's `<`/`>` on the same strings. This is the single comparison
 * primitive both head selection and the canonical fold are built on.
 */
export const byteCompare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** The minimum an operation must expose to be ordered: its CID and `createdAt`. */
export interface OrderKey {
  /** Operation CID — multibase (base32lower) string from the JWS `cid` header. */
  cid: string;
  /** ISO-8601 `createdAt` from the operation payload. */
  createdAt: string;
}

/**
 * Head-preference comparator — the web relay's `selectDeterministicHead` tip
 * ordering, exported so head selection and the canonical fold cannot drift.
 *
 * Sorts the MORE head-preferred operation FIRST: highest `createdAt`, then
 * highest CID (both byte-wise). `array.sort(compareHeadPreference)[0]` is the
 * head among a set of tips.
 */
export const compareHeadPreference = (a: OrderKey, b: OrderKey): number => {
  if (a.createdAt !== b.createdAt) return byteCompare(b.createdAt, a.createdAt);
  return byteCompare(b.cid, a.cid);
};

/**
 * Canonical linearization comparator — the exact reverse of
 * `compareHeadPreference`. Sorts ascending (lowest `createdAt` first, then
 * lowest CID), so the head-preferred operation sorts LAST and, under the LWW
 * fold, is applied last (last-applied wins).
 */
export const compareLinear = (a: OrderKey, b: OrderKey): number => {
  if (a.createdAt !== b.createdAt) return byteCompare(a.createdAt, b.createdAt);
  return byteCompare(a.cid, b.cid);
};

/**
 * Order a set of operations into the canonical total order — createdAt
 * ascending, CID ascending tiebreak, branch-inclusive.
 *
 * Deterministic regardless of input order: CIDs are unique per operation, so
 * the order is a strict total order and any permutation of the same operation
 * set linearizes identically (this is what makes concurrent forks converge).
 * Returns a new array; the input is not mutated.
 */
export const linearize = <T extends OrderKey>(ops: readonly T[]): T[] =>
  [...ops].sort(compareLinear);
