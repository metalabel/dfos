/*

  JWS

  EdDSA JWS compact serialization for signed envelopes

*/

import { base64urlDecode, base64urlEncode } from './base64url';
import { isValidEd25519Signature } from './ed25519';
import { assertCanonicalJsonText } from './json-scan';
import { assertJwsProfile } from './jws-profile';

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

export interface JwsHeader {
  alg: 'EdDSA';
  typ: string;
  kid?: string;
  /** CIDv1 of the operation payload (dag-cbor + SHA-256), signed in the protected header */
  cid?: string;
}

// -----------------------------------------------------------------------------
// decode helpers
// -----------------------------------------------------------------------------

/**
 * Decode one base64url JWS segment to the object it denotes, or null.
 *
 * `JSON.parse` returns `null` for the text `"null"` and an array for `"[]"`
 * without throwing, so `as JwsHeader` / `as Record<string, unknown>` is a
 * compile-time fiction that a hand-built token defeats: every caller then reads
 * `header.typ` off `null` and gets a raw `TypeError` instead of this module's
 * error class. The shape check is what makes the cast true.
 *
 * The raw text is scanned before it is parsed — duplicate keys and lone
 * surrogate escapes are only visible there (see json-scan.ts). That scan throws;
 * a malformed segment returns null.
 *
 * The decoder is FATAL. A lenient `TextDecoder` repairs an invalid UTF-8
 * sequence to U+FFFD, which would let this side scan, parse and verify a
 * payload whose bytes the Go reference refuses outright (`utf8.Valid` in
 * AssertCanonicalJSONText) — the same signed bytes, two verdicts. Undecodable
 * bytes are malformed, not repairable.
 *
 * IT ALSO KEEPS THE BOM. `fatal` governs malformed byte sequences only; BOM
 * stripping is the separate `ignoreBOM` option, which defaults to false —
 * meaning the BOM IS silently removed. Go hands the raw bytes to
 * `json.Unmarshal`, which rejects a leading U+FEFF, so a segment signed with a
 * BOM verified here and failed there on identical bytes. `ignoreBOM: true`
 * hands the character through, and it is then rejected explicitly: a JWS segment
 * is canonical JSON, and canonical JSON does not start with a byte order mark.
 */
const decodeJwsSegment = (segmentB64: string): Record<string, unknown> | null => {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(
      base64urlDecode(segmentB64),
    );
  } catch {
    return null;
  }
  if (text.charCodeAt(0) === 0xfeff) {
    throw new Error('leading byte order mark is not canonicalizable');
  }
  assertCanonicalJsonText(text);
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
};

/**
 * A protected header requires string `alg` and `typ`; `kid` and `cid` must
 * be strings when present. Missing required or wrongly-typed fields mean the
 * decode fails here rather than throwing a `TypeError` out of whichever caller
 * reads the field first.
 */
const asJwsHeader = (raw: Record<string, unknown>): JwsHeader | null => {
  if (typeof raw['alg'] !== 'string') return null;
  if (typeof raw['typ'] !== 'string') return null;
  if ('kid' in raw && typeof raw['kid'] !== 'string') return null;
  if ('cid' in raw && typeof raw['cid'] !== 'string') return null;
  return raw as unknown as JwsHeader;
};

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
  header: JwsHeader & { kid: string };
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

  let rawHeader: Record<string, unknown> | null;
  let payload: Record<string, unknown> | null;
  try {
    rawHeader = decodeJwsSegment(headerB64);
    payload = decodeJwsSegment(payloadB64);
  } catch (e) {
    // the raw-text scan's verdict (duplicate key, lone surrogate) is a
    // rejection in this module's vocabulary, not a decode failure
    throw new JwsVerificationError((e as Error).message);
  }
  if (!rawHeader || !payload) {
    throw new JwsVerificationError('Failed to decode token');
  }

  // apply the DFOS signature verification profile (alg pin, crit, no
  // header-key-trust) BEFORE any signature check
  assertJwsProfile(rawHeader, (m) => new JwsVerificationError(m));

  const header = asJwsHeader(rawHeader);
  if (!header) {
    throw new JwsVerificationError('Invalid protected header');
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

  const [headerB64, payloadB64] = parts as [string, string, string];
  let rawHeader: Record<string, unknown> | null;
  let payload: Record<string, unknown> | null;
  try {
    rawHeader = decodeJwsSegment(headerB64);
    payload = decodeJwsSegment(payloadB64);
  } catch {
    // duplicate key / lone surrogate — malformed, same answer as a bad decode
    return null;
  }
  if (!rawHeader || !payload) return null;
  const header = asJwsHeader(rawHeader);
  if (!header) return null;
  return { header, payload };
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
