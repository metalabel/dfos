/*

  THE WORD FINGERPRINT, ON THE THIRD SURFACE

  A key travels between surfaces and a human is asked whether the one in front of
  them is the one they meant. Two surfaces already render the six words that
  question is answered with — the CLI's `keys add` disclosure and the ceremony
  dialog — and this is the third: a reader chasing a key lands on `#/key/<z6Mk…>`
  and needs to read the same six words there, or the comparison has a gap exactly
  where a browser is the tool at hand.

  DERIVED HERE, FROM THE STRING THE PAGE ALREADY HAS. `keyWordFingerprint` hashes
  the multikey string, so this is a pure local render with nothing to fetch and
  nothing to await. The kit function is the ONLY source: computing these words a
  second way in the explorer would be a second table to drift.

  WHY THE GUARD, WHEN THE KIT FUNCTION CANNOT FAIL. `keyWordFingerprint` is total
  by design — it hashes whatever string it is given, deliberately unvalidating,
  because the two surfaces it was written for have already agreed on WHICH string
  they render. The explorer has made no such agreement: `#/key/<segment>` routes
  on any non-empty segment, so a typo, a truncated paste, or a `did:key:`-prefixed
  copy reaches this page as-is. Words rendered for one of those are six perfectly
  plausible words that belong to a string nothing declares — a reader comparing
  them against a CLI disclosure would read a real mismatch as a real difference in
  keys. So the fingerprint renders only for a string shaped like a key this
  protocol mints, and `null` — no row at all — is the honest output otherwise.

  STILL NEVER A VALIDATOR. The shape check gates the DISPLAY, and says nothing
  about whether the key exists, is held, or was ever proved into a chain; the page
  answers those from the relay index, below. And nothing here matches or verifies
  against the words: the multikey string is the identifier everywhere bytes are
  compared.

*/

import { keyWordFingerprint } from '@metalabel/dfos-protocol/key-proof';
import { isPublicKeyMultibase } from './resolve-input';

/**
 * The six words a key renders as for a human — the same six the CLI's key
 * disclosure and a ceremony dialog show for this key, from the same function over
 * the same `z…` string — or `null` when the page was handed something that is not
 * a multikey and therefore has no fingerprint worth showing.
 */
export const keyWords = (multibase: string): string | null =>
  isPublicKeyMultibase(multibase) ? keyWordFingerprint(multibase) : null;

/**
 * The same six words as a hover note for a key already rendered somewhere tight —
 * a table cell whose title carries the full multibase. Empty where the string has
 * no fingerprint to show, which the note's consumers already read as "no note":
 * a title gaining an empty clause would read as a fingerprint that failed rather
 * than one that was never offered.
 */
export const keyWordsNote = (multibase: string): string => {
  const words = keyWords(multibase);
  return words ? `six words: ${words}` : '';
};
