/*

  THE WORD FINGERPRINT — the tables, the encoding, and the twin pin.

  Byte-twin of packages/dfos-protocol-go/word_fingerprint_test.go, case for case.

  The risk this file is built around is not the algorithm — six bytes of SHA-256
  through two lookup tables has nowhere to hide a bug. It is the TABLES: 512
  hand-transcribable words where a single wrong entry produces a fingerprint that
  looks perfectly plausible, renders identically on the surface that got the same
  bad table, and silently fails to render identically anywhere else. Three
  independent checks pin them:

    1. THE PUBLISHED EXAMPLE. The PGP documentation's own worked example — a
       20-byte fingerprint and the exact 20 words it renders as — exercises 20
       positions across both tables against a value nobody here chose.

    2. THE SHAPE. 256 entries per table, no duplicates within a table, none
       shared across tables, all lowercase. A dropped or doubled entry shifts
       every word after it, and this catches that even where no vector reaches.

    3. THE TWIN CHECKSUM. `WORD_LIST_CHECKSUM` is SHA-256 over the newline-joined
       concatenation of both tables, and the same constant is pinned in the Go
       suite. One divergent word in either language — one letter — turns both
       suites red, so the tables cannot drift apart silently.

  Check 3 is the one that matters most: checks 1 and 2 can both pass on two
  DIFFERENT tables, because 20 words and a shape do not cover 512 entries.

*/

import { describe, expect, it } from 'vitest';
import { sha256 } from '../src/crypto';
import { PGP_EVEN_WORDS, PGP_ODD_WORDS, pgpWords } from '../src/key-proof/pgp-word-list';
import { keyWordFingerprint } from '../src/key-proof/word-fingerprint';

// -----------------------------------------------------------------------------
// vectors — every literal below is pinned identically in word_fingerprint_test.go
// -----------------------------------------------------------------------------

/**
 * SHA-256 over the newline-joined concatenation of the even table then the odd
 * table. The cross-language pin: this constant appears verbatim in the Go suite.
 */
const WORD_LIST_CHECKSUM =
  '41db18a831d9c40dc35b374ef36f0bf616d4f563768fcc1a5aa11c7b6530cf5e';

/** The worked example from the PGP word list's own documentation. */
const PUBLISHED_EXAMPLE_HEX = 'e58294f2e9a227486e8b061b31cc528fd7fa3f19';
const PUBLISHED_EXAMPLE_WORDS =
  'topmost istanbul pluto vagabond treadmill pacific brackish dictator ' +
  'goldfish medusa afflict bravado chatter revolver dupont midsummer ' +
  'stopwatch whimsical cowbell bottomless';

/** The two reference keys from specs/PROTOCOL.md, and their fingerprints. */
const REFERENCE_KEY_A = 'z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb';
const REFERENCE_KEY_A_FINGERPRINT = 'ragtime decadence python coherence belfast provincial';
const REFERENCE_KEY_B = 'z6MkfUd65JrAhfdgFuMCccU9ThQvjB2fJAMUHkuuajF992gK';
const REFERENCE_KEY_B_FINGERPRINT = 'talon hurricane breadline retrieval island hazardous';

const hexToBytes = (hex: string): Uint8Array =>
  Uint8Array.from(hex.match(/../g)!.map((byte) => parseInt(byte, 16)));

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

// -----------------------------------------------------------------------------

describe('the PGP word tables', () => {
  it('each hold exactly 256 entries', () => {
    expect(PGP_EVEN_WORDS).toHaveLength(256);
    expect(PGP_ODD_WORDS).toHaveLength(256);
  });

  it('hold no duplicates within a table', () => {
    expect(new Set(PGP_EVEN_WORDS).size).toBe(256);
    expect(new Set(PGP_ODD_WORDS).size).toBe(256);
  });

  it('share no word across the two tables', () => {
    const even = new Set(PGP_EVEN_WORDS);
    expect(PGP_ODD_WORDS.filter((word) => even.has(word))).toEqual([]);
  });

  it('are entirely lowercase ascii letters', () => {
    for (const word of [...PGP_EVEN_WORDS, ...PGP_ODD_WORDS]) {
      expect(word).toMatch(/^[a-z]+$/);
    }
  });

  it('separate by syllable count, which the published length bounds stand in for', () => {
    // The even table is the two-syllable list, the odd table the three-syllable
    // one; the documented maximum word lengths are 9 and 11 respectively.
    expect(Math.max(...PGP_EVEN_WORDS.map((word) => word.length))).toBe(9);
    expect(Math.max(...PGP_ODD_WORDS.map((word) => word.length))).toBe(11);
  });

  it('hash to the checksum the Go suite pins', () => {
    const joined = [...PGP_EVEN_WORDS, ...PGP_ODD_WORDS].join('\n');
    expect(toHex(sha256(new TextEncoder().encode(joined)))).toBe(WORD_LIST_CHECKSUM);
  });
});

describe('pgpWords', () => {
  it('renders the published PGP example exactly', () => {
    expect(pgpWords(hexToBytes(PUBLISHED_EXAMPLE_HEX))).toBe(PUBLISHED_EXAMPLE_WORDS);
  });

  it('alternates tables by offset, so a transposed pair does not read correctly', () => {
    // The documentation's own illustration: "E582" is topmost istanbul, while the
    // same two bytes swapped are two different words entirely.
    expect(pgpWords(hexToBytes('e582'))).toBe('topmost istanbul');
    expect(pgpWords(hexToBytes('82e5'))).toBe('miser travesty');
  });

  it('renders byte 0x00 from whichever table the offset selects', () => {
    expect(pgpWords(hexToBytes('0000'))).toBe(`${PGP_EVEN_WORDS[0]} ${PGP_ODD_WORDS[0]}`);
    expect(PGP_EVEN_WORDS[0]).not.toBe(PGP_ODD_WORDS[0]);
  });

  it('renders empty octets as the empty string', () => {
    expect(pgpWords(new Uint8Array(0))).toBe('');
  });
});

describe('keyWordFingerprint', () => {
  it('renders the first reference key from PROTOCOL.md', () => {
    expect(keyWordFingerprint(REFERENCE_KEY_A)).toBe(REFERENCE_KEY_A_FINGERPRINT);
  });

  it('renders the second reference key from PROTOCOL.md', () => {
    expect(keyWordFingerprint(REFERENCE_KEY_B)).toBe(REFERENCE_KEY_B_FINGERPRINT);
  });

  it('distinguishes the two reference keys', () => {
    expect(keyWordFingerprint(REFERENCE_KEY_A)).not.toBe(keyWordFingerprint(REFERENCE_KEY_B));
  });

  it('is six lowercase words joined by single spaces', () => {
    for (const key of [REFERENCE_KEY_A, REFERENCE_KEY_B]) {
      const fingerprint = keyWordFingerprint(key);
      expect(fingerprint).toMatch(/^[a-z]+( [a-z]+){5}$/);
      expect(fingerprint.split(' ')).toHaveLength(6);
    }
  });

  it('is deterministic across calls', () => {
    expect(keyWordFingerprint(REFERENCE_KEY_A)).toBe(keyWordFingerprint(REFERENCE_KEY_A));
  });

  it('is the six leading digest bytes and nothing else', () => {
    const digest = sha256(new TextEncoder().encode(REFERENCE_KEY_A));
    expect(keyWordFingerprint(REFERENCE_KEY_A)).toBe(pgpWords(digest.slice(0, 6)));
  });

  it('hashes the multikey string, so a prefixed or truncated form differs visibly', () => {
    // The obligation is that both surfaces render the SAME string — the `z…` form
    // as the chain declares it. Anything else is a different fingerprint, which is
    // exactly the mismatch a human comparison is there to catch.
    expect(keyWordFingerprint(`did:key:${REFERENCE_KEY_A}`)).not.toBe(
      REFERENCE_KEY_A_FINGERPRINT,
    );
    expect(keyWordFingerprint(REFERENCE_KEY_A.slice(0, 20))).not.toBe(
      REFERENCE_KEY_A_FINGERPRINT,
    );
  });

  it('renders a fingerprint for the empty string rather than failing', () => {
    // Total by construction: the function has no failure mode to surface to a
    // caller that is mid-render.
    expect(keyWordFingerprint('')).toMatch(/^[a-z]+( [a-z]+){5}$/);
  });
});
