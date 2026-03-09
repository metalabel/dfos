/*

  CHAIN IDENTIFIER DERIVATION

  Derive protocol identifiers from CID bytes using the standard hash-to-ID
  algorithm.

    Identity chains: did:dfos:<hash>   (DID spec conformant)
    Content chains:  <hash>            (bare 22-char identifier, no prefix)

*/

import { generateIdNoPrefix } from '../crypto/id';

/**
 * Derive a prefixed chain identifier from CID bytes
 *
 * Used for identity DIDs: deriveChainIdentifier(cidBytes, 'did:dfos') → 'did:dfos:xxxx'
 */
export const deriveChainIdentifier = (cidBytes: Uint8Array, prefix: string): string => {
  const id = generateIdNoPrefix({ seed: cidBytes });
  return `${prefix}:${id}`;
};

/**
 * Derive a bare entity identifier from CID bytes
 *
 * Returns the raw 22-char hash with no prefix. Applications may add
 * their own prefix for routing (e.g., post_xxxx) — that's semantic sugar.
 */
export const deriveEntityId = (cidBytes: Uint8Array): string => {
  return generateIdNoPrefix({ seed: cidBytes });
};
