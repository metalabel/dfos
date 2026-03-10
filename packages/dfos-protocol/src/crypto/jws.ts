/*

  JWS

  EdDSA JWS compact serialization for signed envelopes

*/

import { base64urlDecode, base64urlEncode } from './base64url';
import { isValidEd25519Signature } from './ed25519';

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

export interface JwsHeader {
  alg: 'EdDSA';
  typ: string;
  kid: string;
  /** CIDv1 of the operation payload (dag-cbor + SHA-256), signed in the protected header */
  cid?: string;
}

// -----------------------------------------------------------------------------
// jws functions
// -----------------------------------------------------------------------------

/**
 * Create an EdDSA JWS compact token
 *
 * The signer receives the signing input bytes and returns the raw Ed25519
 * signature (64 bytes)
 */
export const createJws = async (options: {
  header: JwsHeader;
  payload: Record<string, unknown>;
  sign: (message: Uint8Array) => Promise<Uint8Array>;
}): Promise<string> => {
  const headerB64 = base64urlEncode(JSON.stringify(options.header));
  const payloadB64 = base64urlEncode(JSON.stringify(options.payload));

  const signingInput = `${headerB64}.${payloadB64}`;
  const signingInputBytes = new TextEncoder().encode(signingInput);

  const signatureBytes = await options.sign(signingInputBytes);
  const signatureB64 = base64urlEncode(signatureBytes);

  return `${signingInput}.${signatureB64}`;
};

/**
 * Verify an EdDSA JWS compact token and return the decoded header and payload
 *
 * Throws JwsVerificationError if the signature is invalid
 */
export const verifyJws = (options: {
  token: string;
  publicKey: Uint8Array;
}): { header: JwsHeader; payload: Record<string, unknown> } => {
  const parts = options.token.split('.');
  if (parts.length !== 3) {
    throw new JwsVerificationError('Invalid token format');
  }

  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];

  let header: JwsHeader;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(new TextDecoder().decode(base64urlDecode(headerB64)));
    payload = JSON.parse(new TextDecoder().decode(base64urlDecode(payloadB64)));
  } catch {
    throw new JwsVerificationError('Failed to decode token');
  }

  if (header.alg !== 'EdDSA') {
    throw new JwsVerificationError(`Unsupported algorithm: ${header.alg}`);
  }

  const signingInput = `${headerB64}.${payloadB64}`;
  const signingInputBytes = new TextEncoder().encode(signingInput);
  const signatureBytes = base64urlDecode(signatureB64);

  const isValid = isValidEd25519Signature(signingInputBytes, signatureBytes, options.publicKey);
  if (!isValid) {
    throw new JwsVerificationError('Invalid signature');
  }

  return { header, payload };
};

/**
 * Decode a JWS compact token without verifying the signature
 *
 * Returns null if the token is malformed
 */
export const decodeJwsUnsafe = (
  token: string,
): { header: JwsHeader; payload: Record<string, unknown> } | null => {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  try {
    const [headerB64, payloadB64] = parts as [string, string, string];
    const header = JSON.parse(new TextDecoder().decode(base64urlDecode(headerB64))) as JwsHeader;
    const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(payloadB64))) as Record<
      string,
      unknown
    >;
    return { header, payload };
  } catch {
    return null;
  }
};

/**
 * Error thrown when JWS verification fails
 */
export class JwsVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JwsVerificationError';
  }
}
