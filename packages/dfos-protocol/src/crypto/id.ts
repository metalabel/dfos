/*

  ID

  Generate random or deterministic IDs

  Browser + Node compatible using Web Crypto API (globalThis.crypto)

*/

import { sha256 as sha256Hash } from '@noble/hashes/sha2.js';

export type PrefixedID<T extends string> = `${T}_${string}`;

// Alphabet sorted in lexicographic order (digits before letters)
// Removed visually ambiguous: 0, 1, 5, g, o, b, s, x
const alphabet = '2346789acdefhknrtvz';
const idLength = 22;

/**
 * Generate cryptographically secure random bytes
 *
 * Uses Web Crypto API which works in both browser and Node.js 22+
 */
const getRandomBytes = (length: number): Uint8Array => {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
};

/**
 * Generate an ID without a prefix
 *
 * Note: byte % 19 introduces ~0.3% modulo bias (256 is not divisible by 19).
 * This is not security-relevant for identifiers. The simplicity of the algorithm
 * is preferred over rejection sampling.
 *
 * @param options.seed - Optional seed for deterministic IDs
 */
export const generateIdNoPrefix = (options?: { seed?: Uint8Array }): string => {
  const hash = sha256Hash(options?.seed ?? getRandomBytes(32));
  let encoded = '';
  for (let i = 0; i < idLength; i++) {
    const byte = hash[i];
    if (byte === undefined) throw new Error('hash is too short');
    encoded += alphabet.charAt(byte % alphabet.length);
  }
  return encoded;
};

/**
 * Generate a prefixed ID
 *
 * Without options: generates random 22-char ID
 * With { seed }: generates deterministic ID from seed (for external ID mapping)
 *
 * @example
 * generateId('post') // random ID
 * generateId('session', { seed: new TextEncoder().encode('clerk:123') }) // deterministic
 */
export const generateId = <T extends string>(
  prefix: T,
  options?: { seed?: Uint8Array },
): PrefixedID<T> => {
  const encoded = generateIdNoPrefix(options);
  return `${prefix}_${encoded}`;
};

/**
 * Validate that an ID has the expected prefix and correct length
 *
 * @param prefix - Expected prefix (e.g., 'msg', 'post')
 * @param id - ID to validate
 * @returns true if ID has correct prefix and length (prefix + _ + 22 chars)
 *
 * @example
 * isValidId('msg', 'msg_abc123...') // true
 * isValidId('msg', 'post_abc123...') // false (wrong prefix)
 * isValidId('msg', 'msg_short') // false (wrong length)
 */
export const isValidId = (prefix: string, id: string): boolean => {
  const expectedLength = prefix.length + 1 + idLength; // prefix + '_' + 22 chars
  return id.startsWith(`${prefix}_`) && id.length === expectedLength;
};

/**
 * Given an ID, validate prefix and return a normalized ID
 */
export const normalizedId = <T extends string>(prefix: T, id: string) => {
  const prefixLowered = prefix.toLowerCase();
  const idLowered = id.toLowerCase();

  if (idLowered.startsWith(`${prefixLowered}_`)) {
    return idLowered as PrefixedID<T>;
  } else if (idLowered.includes('_')) {
    throw new Error(`unexpected id prefix for ${id}`);
  }
  return `${prefixLowered}_${idLowered}` as PrefixedID<T>;
};
