/*

  CREDENTIAL

  VC-JWT credentials for protocol-level authorization. Two credential types:

  - DFOSContentWrite: authorize extending a content chain (embedded in ops)
  - DFOSContentRead: authorize reading content plane data (presented to relay)

  Credentials are JWTs with a `vc` claim following the W3C VC Data Model v2.
  Signed by the issuer DID (content creator/controller), granted to a subject
  DID (collaborator/reader).

*/

import { base64urlDecode, base64urlEncode, isValidEd25519Signature } from '../crypto';
import {
  CredentialClaims,
  VC_TYPE_CONTENT_READ,
  VC_TYPE_CONTENT_WRITE,
  type DFOSCredentialType,
} from './schemas';

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

export interface CredentialCreateOptions {
  /** The DID granting the credential (content creator/controller) */
  iss: string;
  /** The DID receiving the credential (collaborator/reader) */
  sub: string;
  /** Expiration — unix seconds */
  exp: number;
  /** kid — DID URL of the issuer: "did:dfos:xxx#key_yyy" */
  kid: string;
  /** Credential type */
  type: DFOSCredentialType;
  /** Optional content chain narrowing */
  contentId?: string;
  /** Issued-at override — unix seconds (defaults to Date.now()) */
  iat?: number;
  /** Signer function */
  sign: (message: Uint8Array) => Promise<Uint8Array>;
}

export interface CredentialVerifyOptions {
  /** The VC-JWT token string */
  token: string;
  /** Raw Ed25519 public key bytes (32 bytes) of the issuer */
  publicKey: Uint8Array;
  /** Expected subject DID (optional — if provided, sub must match) */
  subject?: string;
  /** Expected credential type (optional — if provided, type must match) */
  expectedType?: DFOSCredentialType;
  /** Current time in seconds (defaults to Date.now() / 1000) */
  currentTime?: number;
}

export interface VerifiedCredential {
  /** The DID that issued the credential */
  iss: string;
  /** The DID the credential was issued to */
  sub: string;
  /** Credential expiration (unix seconds) */
  exp: number;
  /** The DFOS credential type */
  type: DFOSCredentialType;
  /** kid from the JWT header */
  kid: string;
  /** Optional content chain narrowing */
  contentId?: string;
}

// -----------------------------------------------------------------------------
// create
// -----------------------------------------------------------------------------

/**
 * Create a VC-JWT credential
 *
 * The credential is a JWT with `typ: "vc+jwt"` in the header and a `vc`
 * claim in the payload following W3C VC Data Model v2.
 */
export const createCredential = async (options: CredentialCreateOptions): Promise<string> => {
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

  const header = { alg: 'EdDSA' as const, typ: 'vc+jwt', kid: options.kid };

  const credentialSubject: Record<string, string> = {};
  if (options.contentId) {
    credentialSubject.contentId = options.contentId;
  }

  const payload = {
    iss: options.iss,
    sub: options.sub,
    exp: options.exp,
    iat: now,
    vc: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential', options.type],
      credentialSubject,
    },
  };

  // encode as JWT (header.payload.signature)
  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signingInputBytes = new TextEncoder().encode(signingInput);
  const signatureBytes = await options.sign(signingInputBytes);
  const signatureB64 = base64urlEncode(signatureBytes);

  return `${signingInput}.${signatureB64}`;
};

// -----------------------------------------------------------------------------
// verify
// -----------------------------------------------------------------------------

/**
 * Verify a VC-JWT credential
 *
 * Checks signature, expiration, payload structure, and optionally subject
 * and credential type.
 */
export const verifyCredential = (options: CredentialVerifyOptions): VerifiedCredential => {
  const parts = options.token.split('.');
  if (parts.length !== 3) {
    throw new CredentialVerificationError('invalid token format');
  }

  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];

  // decode header
  let header: { alg: string; typ: string; kid: string };
  let payload: unknown;
  try {
    header = JSON.parse(new TextDecoder().decode(base64urlDecode(headerB64)));
    payload = JSON.parse(new TextDecoder().decode(base64urlDecode(payloadB64)));
  } catch {
    throw new CredentialVerificationError('failed to decode token');
  }

  // verify header
  if (header.alg !== 'EdDSA') {
    throw new CredentialVerificationError(`unsupported algorithm: ${header.alg}`);
  }
  if (header.typ !== 'vc+jwt') {
    throw new CredentialVerificationError(`invalid typ: ${header.typ}`);
  }

  // verify signature
  const signingInput = `${headerB64}.${payloadB64}`;
  const signingInputBytes = new TextEncoder().encode(signingInput);
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64urlDecode(signatureB64);
  } catch {
    throw new CredentialVerificationError('failed to decode signature');
  }
  const isValid = isValidEd25519Signature(signingInputBytes, signatureBytes, options.publicKey);
  if (!isValid) {
    throw new CredentialVerificationError('invalid signature');
  }

  // validate payload structure
  const result = CredentialClaims.safeParse(payload);
  if (!result.success) {
    const messages = result.error.issues.map((e) => e.message).join(', ');
    throw new CredentialVerificationError(`invalid credential claims: ${messages}`);
  }
  const claims = result.data;

  // verify kid
  const kid = header.kid;
  if (!kid || !kid.includes('#')) {
    throw new CredentialVerificationError('credential kid must be a DID URL');
  }
  const kidDid = kid.substring(0, kid.indexOf('#'));
  if (kidDid !== claims.iss) {
    throw new CredentialVerificationError('credential kid DID does not match iss');
  }

  // verify temporal validity
  const currentTime = options.currentTime ?? Math.floor(Date.now() / 1000);
  if (claims.iat > currentTime) {
    throw new CredentialVerificationError('credential not yet valid (iat is in the future)');
  }
  if (claims.exp <= currentTime) {
    throw new CredentialVerificationError('credential expired');
  }

  // verify subject if specified
  if (options.subject !== undefined && claims.sub !== options.subject) {
    throw new CredentialVerificationError(
      `subject mismatch: expected ${options.subject}, got ${claims.sub}`,
    );
  }

  // extract credential type
  const vcType = claims.vc.type[1] as DFOSCredentialType;

  // verify type if specified
  if (options.expectedType !== undefined && vcType !== options.expectedType) {
    throw new CredentialVerificationError(
      `type mismatch: expected ${options.expectedType}, got ${vcType}`,
    );
  }

  const contentId = claims.vc.credentialSubject.contentId;

  return {
    iss: claims.iss,
    sub: claims.sub,
    exp: claims.exp,
    type: vcType,
    kid,
    ...(contentId !== undefined ? { contentId } : {}),
  };
};

// -----------------------------------------------------------------------------
// decode (unsafe)
// -----------------------------------------------------------------------------

/**
 * Decode a VC-JWT credential without verifying the signature
 *
 * Returns null if the token is malformed or claims are invalid.
 */
export const decodeCredentialUnsafe = (
  token: string,
): { header: { alg: string; typ: string; kid: string }; claims: CredentialClaims } | null => {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  try {
    const [headerB64, payloadB64] = parts as [string, string, string];
    const header = JSON.parse(new TextDecoder().decode(base64urlDecode(headerB64)));
    const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(payloadB64)));
    const result = CredentialClaims.safeParse(payload);
    if (!result.success) return null;
    return { header, claims: result.data };
  } catch {
    return null;
  }
};

// -----------------------------------------------------------------------------
// errors
// -----------------------------------------------------------------------------

export class CredentialVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CredentialVerificationError';
  }
}
