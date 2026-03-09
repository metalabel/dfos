/*

  MULTIKEY

  W3C Multikey encoding for Ed25519 public keys

*/

import { base58btc } from 'multiformats/bases/base58';

// Ed25519 public key multicodec: 0xed, varint-encoded as [0xed, 0x01]
const ED25519_PUB_PREFIX = new Uint8Array([0xed, 0x01]);

// Ed25519 private key multicodec: 0x1300, varint-encoded as [0x80, 0x26]
const ED25519_PRIV_PREFIX = new Uint8Array([0x80, 0x26]);

/** Ed25519 public key multicodec value */
export const ED25519_PUB_MULTICODEC = 0xed;

/** Ed25519 private key multicodec value */
export const ED25519_PRIV_MULTICODEC = 0x1300;

/**
 * Encode an Ed25519 public key as a W3C Multikey multibase string
 *
 * Format: 'z' + base58btc([0xed, 0x01] + publicKeyBytes)
 * Result starts with "z6Mk..."
 */
export const encodeEd25519Multikey = (publicKeyBytes: Uint8Array): string => {
  if (publicKeyBytes.length !== 32) {
    throw new Error(`expected 32-byte Ed25519 public key, got ${publicKeyBytes.length}`);
  }
  const prefixed = new Uint8Array(ED25519_PUB_PREFIX.length + publicKeyBytes.length);
  prefixed.set(ED25519_PUB_PREFIX);
  prefixed.set(publicKeyBytes, ED25519_PUB_PREFIX.length);
  return base58btc.encode(prefixed);
};

/**
 * Decode a Multikey multibase string to raw key bytes and codec
 *
 * Supports Ed25519 public keys (z6Mk... prefix)
 */
export const decodeMultikey = (multibase: string): { keyBytes: Uint8Array; codec: number } => {
  const bytes = base58btc.decode(multibase);

  if (bytes.length < 2) {
    throw new Error('multikey too short');
  }

  // Ed25519 public key
  if (bytes[0] === ED25519_PUB_PREFIX[0] && bytes[1] === ED25519_PUB_PREFIX[1]) {
    const keyBytes = bytes.slice(2);
    if (keyBytes.length !== 32) {
      throw new Error(`expected 32-byte Ed25519 public key, got ${keyBytes.length}`);
    }
    return { keyBytes, codec: ED25519_PUB_MULTICODEC };
  }

  // Ed25519 private key
  if (bytes[0] === ED25519_PRIV_PREFIX[0] && bytes[1] === ED25519_PRIV_PREFIX[1]) {
    const keyBytes = bytes.slice(2);
    if (keyBytes.length !== 32) {
      throw new Error(`expected 32-byte Ed25519 private key, got ${keyBytes.length}`);
    }
    return { keyBytes, codec: ED25519_PRIV_MULTICODEC };
  }

  throw new Error(
    `unsupported multikey codec: [0x${bytes[0]?.toString(16)}, 0x${bytes[1]?.toString(16)}]`,
  );
};
