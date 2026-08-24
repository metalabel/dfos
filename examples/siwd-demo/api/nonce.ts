/*

  TIER 2, STEP 1 — the backend mints the nonce.

  The whole reason this endpoint exists: the party presenting a signed challenge
  must never get to tell the verifier which nonce to expect. A verifier that
  accepts `{ jws, nonce }` from a client is comparing a value against itself and
  has checked nothing. So the nonce is minted HERE and remembered HERE — in an
  HttpOnly cookie, which is the verifier's own memory of what it issued. The
  browser carries the value into the challenge; it never carries it back.

  Zero server state: the cookie IS the state, so any instance can verify a
  callback minted by any other instance. Nothing to share, nothing to expire.

*/

import { randomBytes } from 'node:crypto';

const NONCE_COOKIE = 'siwd_nonce';

/**
 * Matches the platform's own authorize window. A nonce that outlives the
 * challenge it was minted for is a replay window nobody is watching.
 */
const NONCE_TTL_SECONDS = 300;

/**
 * 24 random bytes as base64url — 32 characters, ~192 bits. The kit's own
 * `createSiwdChallenge` mints 31 characters over a 19-symbol alphabet (~131
 * bits); both are far past the 128-bit floor, and the alphabets differ only
 * because `node:crypto` gives base64url for free. A nonce is opaque: nothing
 * downstream parses it, the platform passes it through untouched, and the
 * verifier only ever compares it for equality.
 */
const mintNonce = (): string => randomBytes(24).toString('base64url');

/**
 * `Secure` is set even for local development: browsers treat http://localhost
 * as a secure context, so `vercel dev` still gets the cookie. `Path=/api` keeps
 * it off every static asset request, and `SameSite=Lax` still sends it on the
 * same-origin POST the callback makes.
 */
const setCookie = (nonce: string): string =>
  `${NONCE_COOKIE}=${nonce}; HttpOnly; Secure; SameSite=Lax; Path=/api; Max-Age=${NONCE_TTL_SECONDS}`;

export default function handler(request: Request): Response {
  if (request.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'method not allowed' }), {
      status: 405,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        Allow: 'GET',
      },
    });
  }

  const nonce = mintNonce();

  return new Response(JSON.stringify({ nonce }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      // a cached nonce is not a nonce
      'Cache-Control': 'no-store',
      'Set-Cookie': setCookie(nonce),
    },
  });
}
