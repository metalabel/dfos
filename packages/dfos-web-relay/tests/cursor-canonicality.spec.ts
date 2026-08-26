import { describe, expect, it } from 'vitest';
import {
  decodeIndexCreditCursor,
  decodeIndexOrderedCursor,
  encodeIndexCreditCursor,
  encodeIndexOrderedCursor,
} from '../src/index-routes';

// Both twins must agree on exactly which cursor strings are valid — a decoder
// that accepts non-canonical base64 (padding, whitespace) on one side is a
// live cross-implementation divergence the parity harness cannot see, because
// the harness only replays cursors the relays themselves emitted.
describe('index cursor canonicality', () => {
  const orderedCanonical = encodeIndexOrderedCursor('2026-08-25T00:00:00Z', 'did:dfos:abc');
  const creditCanonical = encodeIndexCreditCursor('a'.repeat(31), 7);

  const nonCanonicalVariants = (canonical: string): string[] => [
    `${canonical}=`,
    `${canonical}==`,
    `${canonical}\n`,
    `${canonical} `,
    ` ${canonical}`,
  ];

  it('accepts its own canonical ordered cursor', () => {
    expect(decodeIndexOrderedCursor(orderedCanonical)).toEqual({
      timestamp: '2026-08-25T00:00:00Z',
      key: 'did:dfos:abc',
    });
  });

  it('rejects non-canonical encodings of an ordered cursor', () => {
    for (const variant of nonCanonicalVariants(orderedCanonical)) {
      expect(decodeIndexOrderedCursor(variant)).toBeNull();
    }
  });

  it('accepts its own canonical credit cursor', () => {
    expect(decodeIndexCreditCursor(creditCanonical)).toEqual({
      contentId: 'a'.repeat(31),
      position: 7,
    });
  });

  it('rejects non-canonical encodings of a credit cursor', () => {
    for (const variant of nonCanonicalVariants(creditCanonical)) {
      expect(decodeIndexCreditCursor(variant)).toBeNull();
    }
  });
});
