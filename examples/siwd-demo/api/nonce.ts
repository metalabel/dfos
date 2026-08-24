/*

  TIER 2, STEP 1 — the backend mints the nonce.

  The whole reason this endpoint exists: the party presenting a signed challenge
  must never get to tell the verifier which nonce to expect. A verifier that
  accepts `{ jws, nonce }` from a client is comparing a value against itself and
  has checked nothing. So the nonce is minted HERE, and the cookie is how this
  backend remembers what it minted across the redirect.

  The cookie is a CARRIER, not a replay defense — see the long note in verify.ts.
  Real single-use consumption needs a store, which this demo does not run; what
  it would look like is written out at the verify call.

  Zero server state, which is what keeps the demo forkable: the cookie carries
  it, so any instance can handle a callback that any other instance started.

*/

import { randomBytes } from 'node:crypto';

const NONCE_COOKIE = 'siwd_nonce';

/**
 * Matched to the acceptance window `verify.ts` applies, so the cookie stops
 * being useful at the same moment a challenge minted with it would be refused
 * as stale. With a real nonce store this TTL and the store's expiry are the
 * same number, set in both places for the same reason.
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
