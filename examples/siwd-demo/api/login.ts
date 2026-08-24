/*

  STEP 1 — the server mints the challenge and remembers what it minted.

  The nonce is minted here and sealed into an httpOnly cookie before the browser
  is told where to go, because the party presenting a signed challenge must
  never get to tell the verifier which nonce to expect. `/api/verify` recovers
  its expectation from that seal and nothing else; `_lib.ts` says what the seal
  buys and what it does not.

  Minting here also means the server's clock authors the timestamp. A browser
  whose clock is minutes off produced challenges that were born stale or born in
  the future, which a correct verifier refused — a sign-in that looked fine and
  never completed. Server clocks are NTP-disciplined, so that failure mode goes
  away.

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
} from './_lib.js';
import type { VercelRequest, VercelResponse } from './_types.js';

export default function handler(req: VercelRequest, res: VercelResponse): void {
  if (req.method !== 'POST') {
    methodNotAllowed(res, 'POST');
    return;
  }

  // A deployment without a usable secret cannot mint a seal `/api/verify` could
  // unseal (see _lib.ts), so refuse here, by name, instead of letting the
  // sign-in die three redirects later as a mystery.
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
  // exact-matches against `redirect_uris` cannot drift apart. Three params go
  // out — challenge, redirect_uri, scope — and never `client_did`: the platform
  // learns who this app is from the well-known at the redirect's own origin,
  // and an identity-scope sign-in returns no credential for it to be the `aud`
  // of.
  const request = createSiwdLoginRequest({
    authorizeUrl: AUTHORIZE_URL,
    domain: self.domain,
    redirectUri: self.redirectUri,
    scope: SCOPE,
    statement: STATEMENT,
  });

  // The nonce leaves in two places: in the clear inside the challenge the
  // user's host will sign, and sealed under this server's key in a cookie the
  // browser carries back.
  json(res, 200, { url: request.url }, [
    setCookie(
      FLIGHT_COOKIE,
      seal('flight', request.expect.nonce, FLIGHT_TTL_SECONDS),
      FLIGHT_TTL_SECONDS,
    ),
  ]);
}
