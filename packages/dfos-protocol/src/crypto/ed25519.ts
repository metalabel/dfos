/*

  ED25519

  Core crypto suite for Ed25519

*/

import { ed25519 } from '@noble/curves/ed25519.js';

/**
 * Generate a new random Ed25519 keypair
 */
export const createNewEd25519Keypair = () => {
  const privateKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
};

/**
 * Generate an Ed25519 keypair from a private key
 */
export const importEd25519Keypair = (privateKey: Uint8Array) => {
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
};

/**
 * Sign a payload with an Ed25519 private key
 *
 * Ed25519 handles hashing internally (SHA-512) — no external prehash needed
 */
export const signPayloadEd25519 = (payload: Uint8Array, privateKey: Uint8Array) => {
  return ed25519.sign(payload, privateKey);
};

/**
 * Check that a signature is valid for a given payload and Ed25519 public key
 */
export const isValidEd25519Signature = (
  payload: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
) => {
  return ed25519.verify(signature, payload, publicKey);
};
