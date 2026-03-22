/*

  AUTH TOKEN

  DID-signed JWT for relay authentication (AuthN). Proves the caller controls
  a DID. Short-lived, scoped to a specific relay via audience claim.

*/

import { createJwt, verifyJwt, type JwtClaims, type JwtHeader } from '../crypto';
import { AuthTokenClaims } from './schemas';

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

export interface AuthTokenCreateOptions {
  /** The DID proving identity */
  iss: string;
  /** Target relay hostname (prevents cross-relay replay) */
  aud: string;
  /** Expiration — unix seconds */
  exp: number;
  /** kid — DID URL: "did:dfos:xxx#key_yyy" */
  kid: string;
  /** Issued-at override — unix seconds (defaults to Date.now()) */
  iat?: number;
  /** Signer function */
  sign: (message: Uint8Array) => Promise<Uint8Array>;
}

export interface AuthTokenVerifyOptions {
  /** The JWT token string */
  token: string;
  /** Raw Ed25519 public key bytes (32 bytes) */
  publicKey: Uint8Array;
  /** Expected audience (relay hostname) */
  audience: string;
  /** Current time in seconds (defaults to Date.now() / 1000) */
  currentTime?: number;
}

export interface VerifiedAuthToken {
  /** The DID that created the token */
  iss: string;
  /** The target relay */
  aud: string;
  /** Token expiration (unix seconds) */
  exp: number;
  /** kid from the JWT header */
  kid: string;
}

// -----------------------------------------------------------------------------
// create
// -----------------------------------------------------------------------------

/**
 * Create a DID-signed auth token JWT for relay authentication
 */
export const createAuthToken = async (options: AuthTokenCreateOptions): Promise<string> => {
  // validate kid is a DID URL
  if (!options.kid.includes('#')) {
    throw new Error('kid must be a DID URL (did:dfos:xxx#key_yyy)');
  }

  // validate kid DID matches iss
  const kidDid = options.kid.substring(0, options.kid.indexOf('#'));
  if (kidDid !== options.iss) {
    throw new Error('kid DID does not match iss');
  }

  const now = options.iat ?? Math.floor(Date.now() / 1000);

  const header: JwtHeader = { alg: 'EdDSA', typ: 'JWT', kid: options.kid };
  const payload: JwtClaims = {
    iss: options.iss,
    sub: options.iss,
    aud: options.aud,
    exp: options.exp,
    iat: now,
  };

  return createJwt({ header, payload, sign: options.sign });
};

// -----------------------------------------------------------------------------
// verify
// -----------------------------------------------------------------------------

/**
 * Verify a DID-signed auth token JWT
 *
 * Checks signature, expiration, audience, and payload structure.
 */
export const verifyAuthToken = (options: AuthTokenVerifyOptions): VerifiedAuthToken => {
  // verify JWT signature + expiration + audience
  const { header, payload } = verifyJwt({
    token: options.token,
    publicKey: options.publicKey,
    audience: options.audience,
    ...(options.currentTime !== undefined ? { currentTime: options.currentTime } : {}),
  });

  // validate payload structure
  const result = AuthTokenClaims.safeParse(payload);
  if (!result.success) {
    const messages = result.error.issues.map((e) => e.message).join(', ');
    throw new AuthTokenVerificationError(`invalid auth token claims: ${messages}`);
  }

  // verify iat temporal validity
  const currentTime = options.currentTime ?? Math.floor(Date.now() / 1000);
  if (result.data.iat > currentTime) {
    throw new AuthTokenVerificationError('auth token not yet valid (iat is in the future)');
  }

  // validate kid is a DID URL
  const kid = header.kid;
  if (!kid || !kid.includes('#')) {
    throw new AuthTokenVerificationError('auth token kid must be a DID URL');
  }

  // validate kid DID matches iss
  const kidDid = kid.substring(0, kid.indexOf('#'));
  if (kidDid !== result.data.iss) {
    throw new AuthTokenVerificationError('auth token kid DID does not match iss');
  }

  return {
    iss: result.data.iss,
    aud: result.data.aud,
    exp: result.data.exp,
    kid,
  };
};

// -----------------------------------------------------------------------------
// errors
// -----------------------------------------------------------------------------

export class AuthTokenVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthTokenVerificationError';
  }
}
