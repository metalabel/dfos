/*

  STEP 1 — the server mints the challenge and remembers what it minted.

  The nonce is minted HERE and sealed into an httpOnly cookie before the browser
  is told where to go, because the party presenting a signed challenge must
  never get to tell the verifier which nonce to expect. `/api/verify` recovers
  its expectation from that seal and from nothing else; see the note in
  `_lib.ts` for what the seal buys and what it does not.

  THE SERVER'S CLOCK AUTHORS THE TIMESTAMP. That is a second, quieter win of
  minting here rather than in the page: a browser whose clock is minutes off
  used to produce challenges that were born stale or born in the future, and a
  correct verifier refused them. The user experienced a working sign-in that
  simply would not complete. A server clock is NTP-disciplined, so that whole
  failure mode leaves with this endpoint.

  Zero server state: the cookie carries it, so any instance can finish a sign-in
  any other instance started, given the same `SESSION_SECRET`.

*/

import { createSiwdLoginRequest } from '@metalabel/dfos-client/siwd';
import {
  AUTHORIZE_URL,
  FLIGHT_COOKIE,
  FLIGHT_TTL_SECONDS,
  json,
  methodNotAllowed,
  originAllowed,
  requestOrigin,
  SCOPE,
  seal,
  SECRET_ERROR,
  setCookie,
  STATEMENT,
} from './_lib';
import type { VercelRequest, VercelResponse } from './_types';

export default function handler(req: VercelRequest, res: VercelResponse): void {
  if (req.method !== 'POST') {
    methodNotAllowed(res, 'POST');
    return;
  }

  // A deployment without a usable secret cannot mint a seal `/api/verify`
  // could ever unseal (see _lib.ts) — refuse HERE, by name, instead of letting
  // the sign-in die three redirects later as a mystery.
  if (SECRET_ERROR !== null) {
    json(res, 500, { ok: false, reason: SECRET_ERROR });
    return;
  }

  const self = requestOrigin(req);
  if (self === null) {
    json(res, 400, { ok: false, reason: 'could not determine this request’s origin' });
    return;
  }
  if (!originAllowed(req, self)) {
    json(res, 403, { ok: false, reason: 'cross-origin request refused' });
    return;
  }

  // `domain` and `redirectUri` come from ONE derivation of this request's own
  // origin, so the string signed into the challenge and the string the platform
  // exact-matches against `redirect_uris` cannot drift apart. Three wire params
  // go out — challenge, redirect_uri, scope — and never `client_did`: the
  // platform learns who this app is by fetching the well-known from the
  // redirect's own origin, and an identity-scope sign-in returns no credential
  // for a `client_did` to be the `aud` of.
  const request = createSiwdLoginRequest({
    authorizeUrl: AUTHORIZE_URL,
    domain: self.domain,
    redirectUri: self.redirectUri,
    scope: SCOPE,
    statement: STATEMENT,
  });

  // The nonce leaves in two places at once: in the clear inside the challenge
  // the user's host will sign, and sealed under this server's key in a cookie
  // the browser carries back. Verification is the two meeting again.
  json(res, 200, { url: request.url }, [
    setCookie(
      FLIGHT_COOKIE,
      seal('flight', request.expect.nonce, FLIGHT_TTL_SECONDS),
      FLIGHT_TTL_SECONDS,
    ),
  ]);
}
