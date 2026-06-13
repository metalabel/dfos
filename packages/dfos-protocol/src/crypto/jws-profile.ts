/*

  JWS PROFILE

  DFOS Signature Verification Profile (pragmatic v1) — header gates that every
  verification path MUST apply BEFORE checking the signature. See PROTOCOL.md
  "Signature Verification Profile".

  These gates are deliberately strict and library-independent:

  1. alg pinning      — protected header alg MUST equal the exact string "EdDSA"
  2. crit rejection   — a "crit" member MUST be absent (DFOS emits none)
  3. no header-key-trust — jwk / x5c (or any embedded key) MUST be absent; the
                          key is resolved from kid against the identity chain

  The canonical-scalar (S < L) gate is enforced by the underlying Ed25519
  verifier (@noble/curves rejects S >= L), so it is not duplicated here.

*/

/**
 * Apply the DFOS signature verification profile to a decoded protected header.
 *
 * Throws the provided error type with a precise message on any violation. The
 * caller invokes this BEFORE verifying the signature so that an out-of-profile
 * token is rejected regardless of whether its signature would have verified.
 */
export const assertJwsProfile = (
  header: Record<string, unknown>,
  makeError: (message: string) => Error,
): void => {
  // 1. alg pinning — exact string "EdDSA", no algorithm agility
  if (header.alg !== 'EdDSA') {
    throw makeError(`Unsupported algorithm: ${String(header.alg)}`);
  }

  // 2. crit — reject any protected header carrying a crit member
  if ('crit' in header) {
    throw makeError('crit header is not supported');
  }

  // 3. no header-key-trust — reject embedded key material; key comes from kid
  if ('jwk' in header) {
    throw makeError('jwk header is not allowed (key is resolved from kid)');
  }
  if ('x5c' in header) {
    throw makeError('x5c header is not allowed (key is resolved from kid)');
  }
};
