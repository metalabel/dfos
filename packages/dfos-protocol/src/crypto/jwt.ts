/*

  JWT

  EdDSA (Ed25519) JWT creation and verification

*/

import { base64urlDecode, base64urlEncode } from './base64url';
import { isValidEd25519Signature } from './ed25519';

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

export interface JwtHeader {
  alg: 'EdDSA';
  typ: 'JWT';
  kid?: string;
}

export interface JwtClaims {
  iss: string;
  sub: string;
  aud?: string;
  exp: number;
  iat: number;
  jti?: string;
  [key: string]: unknown;
}

export interface JwtVerifyOptions {
  /** The JWT token string */
  token: string;
  /** Raw Ed25519 public key bytes (32 bytes) */
  publicKey: Uint8Array;
  /** Expected audience claim */
  audience?: string;
  /** Expected issuer claim */
  issuer?: string;
  /** Current time in seconds (defaults to Date.now() / 1000) */
  currentTime?: number;
}

export interface JwtCreateOptions {
  header: JwtHeader;
  payload: JwtClaims;
  /** Signer function that signs payload bytes and returns signature bytes */
  sign: (payload: Uint8Array) => Promise<Uint8Array>;
}

// -----------------------------------------------------------------------------
// jwt functions
// -----------------------------------------------------------------------------

/**
 * Create a JWT signed with EdDSA (Ed25519)
 *
 * The signer receives the raw signing input bytes and signs them directly
 * (Ed25519 handles hashing internally)
 */
export const createJwt = async (options: JwtCreateOptions): Promise<string> => {
  const headerJson = JSON.stringify(options.header);
  const payloadJson = JSON.stringify(options.payload);

  const headerB64 = base64urlEncode(headerJson);
  const payloadB64 = base64urlEncode(payloadJson);

  const signingInput = `${headerB64}.${payloadB64}`;
  const signingInputBytes = new TextEncoder().encode(signingInput);

  // Sign the raw signing input (Ed25519 handles hashing internally)
  // Expects 64-byte compact signature (R || S format)
  const signatureBytes = await options.sign(signingInputBytes);
  const signatureB64 = base64urlEncode(signatureBytes);

  return `${signingInput}.${signatureB64}`;
};

/**
 * Decode a JWT without verification (for extracting claims before key lookup)
 *
 * Returns null if the token is malformed
 */
export const decodeJwtUnsafe = (
  token: string,
): { header: JwtHeader; payload: JwtClaims } | null => {
  const parts = token.split('.') as [string, string, string] | string[];
  if (parts.length !== 3) return null;

  try {
    const [headerB64, payloadB64] = parts as [string, string, string];
    const headerJson = new TextDecoder().decode(base64urlDecode(headerB64));
    const payloadJson = new TextDecoder().decode(base64urlDecode(payloadB64));

    const header = JSON.parse(headerJson) as JwtHeader;
    const payload = JSON.parse(payloadJson) as JwtClaims;

    return { header, payload };
  } catch {
    return null;
  }
};

/**
 * Verify a JWT signature and claims
 *
 * Supports EdDSA (Ed25519) only. Throws if verification fails.
 */
export const verifyJwt = (options: JwtVerifyOptions): { header: JwtHeader; payload: JwtClaims } => {
  const parts = options.token.split('.') as [string, string, string] | string[];
  if (parts.length !== 3) {
    throw new JwtVerificationError('Invalid token format');
  }

  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];

  // Decode header and payload
  let header: JwtHeader;
  let payload: JwtClaims;
  try {
    const headerJson = new TextDecoder().decode(base64urlDecode(headerB64));
    const payloadJson = new TextDecoder().decode(base64urlDecode(payloadB64));
    header = JSON.parse(headerJson);
    payload = JSON.parse(payloadJson);
  } catch {
    throw new JwtVerificationError('Failed to decode token');
  }

  // Verify signature
  const signingInput = `${headerB64}.${payloadB64}`;
  const signingInputBytes = new TextEncoder().encode(signingInput);
  const signatureBytes = base64urlDecode(signatureB64);

  if (header.alg !== 'EdDSA') {
    throw new JwtVerificationError(`Unsupported algorithm: ${header.alg}`);
  }

  const isValid = isValidEd25519Signature(signingInputBytes, signatureBytes, options.publicKey);
  if (!isValid) throw new JwtVerificationError('Invalid signature');

  // Verify expiration
  const currentTime = options.currentTime ?? Math.floor(Date.now() / 1000);
  if (payload.exp <= currentTime) {
    throw new JwtVerificationError('Token expired');
  }

  // Verify issuer if specified
  if (options.issuer !== undefined && payload.iss !== options.issuer) {
    throw new JwtVerificationError(
      `Invalid issuer: expected ${options.issuer}, got ${payload.iss}`,
    );
  }

  // Verify audience if specified
  if (options.audience !== undefined && payload.aud !== options.audience) {
    throw new JwtVerificationError(
      `Invalid audience: expected ${options.audience}, got ${payload.aud}`,
    );
  }

  return { header, payload };
};

/**
 * Error thrown when JWT verification fails
 */
export class JwtVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JwtVerificationError';
  }
}
