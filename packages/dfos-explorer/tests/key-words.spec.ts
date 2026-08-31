/**
 * The word fingerprint, as the explorer renders it.
 *
 * The whole value of these six words is that a person reads them on one screen
 * and compares them against another — a CLI key disclosure, a ceremony dialog.
 * That only works while every surface derives the same words from the same
 * string, so this file pins the reference values TWICE: once against the kit's
 * own `keyWordFingerprint`, which catches the explorer computing them some other
 * way, and once against the literal string the kit's golden vectors and CLI.md
 * carry, which catches the derivation changing under everyone at once. A change
 * that is genuinely intended fails here loudly and gets made in every language.
 *
 * The second half is the guard: the kit function is total by design and will
 * happily render six plausible words for a truncated paste, so what the explorer
 * must never do is show them for a string that is not a key.
 */

import { keyWordFingerprint } from '@metalabel/dfos-protocol/key-proof';
import { describe, expect, it } from 'vitest';
import { keyWords, keyWordsNote } from '../src/lib/key-words';

/**
 * The reference genesis key — the same value pinned in the Go suite's key-id
 * vectors and in the CLI manual's word-fingerprint section, with the six words
 * that section prints for it.
 */
const GENESIS_KEY = 'z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';
const GENESIS_WORDS = 'mohawk cumbersome zulu dinosaur goldfish opulent';

/** The two PROTOCOL.md reference keys, and the fingerprints the kit's own golden
 *  vectors pin for them (dfos-protocol tests/word-fingerprint.spec.ts). */
const REFERENCE_KEY_A = 'z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb';
const REFERENCE_KEY_A_WORDS = 'ragtime decadence python coherence belfast provincial';
const REFERENCE_KEY_B = 'z6MkfUd65JrAhfdgFuMCccU9ThQvjB2fJAMUHkuuajF992gK';
const REFERENCE_KEY_B_WORDS = 'talon hurricane breadline retrieval island hazardous';

// -----------------------------------------------------------------------------
// the words themselves — pinned literals, and the kit as the single derivation
// -----------------------------------------------------------------------------

describe('keyWords', () => {
  it('renders the reference genesis key as the six words every other surface shows', () => {
    expect(keyWords(GENESIS_KEY)).toBe(GENESIS_WORDS);
  });

  it('derives the genesis key’s words through the protocol kit, not a local copy', () => {
    expect(keyWords(GENESIS_KEY)).toBe(keyWordFingerprint(GENESIS_KEY));
  });

  it('matches the kit’s golden vectors for both PROTOCOL.md reference keys', () => {
    expect(keyWords(REFERENCE_KEY_A)).toBe(REFERENCE_KEY_A_WORDS);
    expect(keyWords(REFERENCE_KEY_B)).toBe(REFERENCE_KEY_B_WORDS);
    expect(keyWords(REFERENCE_KEY_A)).toBe(keyWordFingerprint(REFERENCE_KEY_A));
    expect(keyWords(REFERENCE_KEY_B)).toBe(keyWordFingerprint(REFERENCE_KEY_B));
  });

  it('renders six lowercase words joined by single spaces', () => {
    for (const key of [GENESIS_KEY, REFERENCE_KEY_A, REFERENCE_KEY_B]) {
      const words = keyWords(key) ?? '';
      expect(words, key).toMatch(/^[a-z]+( [a-z]+){5}$/);
      expect(words.split(' '), key).toHaveLength(6);
    }
  });

  it('gives different keys different words', () => {
    expect(keyWords(REFERENCE_KEY_A)).not.toBe(keyWords(REFERENCE_KEY_B));
    expect(keyWords(GENESIS_KEY)).not.toBe(keyWords(REFERENCE_KEY_A));
  });

  it('is pure — the same key renders the same words every time', () => {
    expect(keyWords(GENESIS_KEY)).toBe(keyWords(GENESIS_KEY));
  });
});

// -----------------------------------------------------------------------------
// the guard — `#/key/<segment>` routes on anything, and words for a non-key would
// read as a real mismatch against a surface rendering a real key
// -----------------------------------------------------------------------------

describe('keyWords — what it refuses to render', () => {
  it('renders nothing for a truncated key, which the kit alone would happily hash', () => {
    const truncated = GENESIS_KEY.slice(0, 20);
    expect(keyWords(truncated)).toBeNull();
    // the kit is total on purpose; the refusal is this module's, not its
    expect(keyWordFingerprint(truncated)).toMatch(/^[a-z]+( [a-z]+){5}$/);
  });

  it('renders nothing for a did:key-prefixed paste', () => {
    expect(keyWords(`did:key:${GENESIS_KEY}`)).toBeNull();
  });

  it('renders nothing for a key one character short or one character long', () => {
    expect(keyWords(GENESIS_KEY.slice(0, 47))).toBeNull();
    expect(keyWords(`${GENESIS_KEY}A`)).toBeNull();
  });

  it('renders nothing for the right length outside the base58 alphabet', () => {
    // `0`, `O`, `I` and `l` are not base58btc digits, so no encoder emits them
    expect(keyWords(`${GENESIS_KEY.slice(0, 47)}0`)).toBeNull();
    expect(keyWords(`${GENESIS_KEY.slice(0, 47)}l`)).toBeNull();
  });

  it('renders nothing for a non-Ed25519 multikey head', () => {
    // z6Mk is the Ed25519 prefix; another curve's multikey is not this key type
    expect(keyWords(`z6LS${GENESIS_KEY.slice(4)}`)).toBeNull();
  });

  it('renders nothing for the empty string and for whitespace', () => {
    expect(keyWords('')).toBeNull();
    expect(keyWords('   ')).toBeNull();
    expect(keyWords(` ${GENESIS_KEY}`)).toBeNull();
  });
});

// -----------------------------------------------------------------------------
// the hover form
// -----------------------------------------------------------------------------

describe('keyWordsNote', () => {
  it('carries the same six words, labelled', () => {
    expect(keyWordsNote(GENESIS_KEY)).toBe(`six words: ${GENESIS_WORDS}`);
  });

  // an empty clause in a title that already carries the multibase is worse than
  // no clause: it reads as a fingerprint that failed rather than one not shown
  it('is empty where there are no words, so a title gains nothing', () => {
    expect(keyWordsNote('')).toBe('');
    expect(keyWordsNote('not-a-key')).toBe('');
  });
});
