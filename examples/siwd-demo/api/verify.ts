/*

  STEP 2 — the server verifies the signed challenge and grants the session.

  This runs where the grant happens, which is the whole reason it exists. A bare
  DID is an address, not a proof: no code path here takes a DID and believes it,
  and the request body carries exactly one thing — the JWS.

  The expectation comes from the sealed cookie, NEVER the body. The flight
  cookie is this verifier's own prior state, recoverable only through an HMAC
  its key produced, so a presenter holding a captured JWS cannot forge it from
  the nonce sitting in the payload.

  `verifySiwd` checks the nonce last (spec step 6), after the signature, the
  current-key resolution, the domain, and the timestamp window. Under the
  flow-bound discipline that ordering costs nothing; under `consumeNonce` it
  keeps an invalid presentation from spending a nonce its legitimate holder is
  still carrying. Same function, same order either way, which is why moving to
  the consumed discipline is a one-field change.

  This grants a session with this browser and nothing else — the grant
  flow-binding is admissible for.

*/

import { createClient } from '@metalabel/dfos-client';
import { verifySiwd } from '@metalabel/dfos-client/siwd';
import {
  clearCookie,
  encodeSession,
  FLIGHT_COOKIE,
  json,
  methodNotAllowed,
  originAllowed,
  readCookie,
  readJws,
  RELAY_URL,
  requestOrigin,
  SECRET_ERROR,
  SESSION_COOKIE,
  SESSION_TTL_SECONDS,
  setCookie,
  unseal,
} from './_lib.js';
import type { VercelRequest, VercelResponse } from './_types.js';

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  if (req.method !== 'POST') {
    methodNotAllowed(res, 'POST');
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
  if (SECRET_ERROR !== null) {
    json(res, 500, { ok: false, reason: SECRET_ERROR });
    return;
  }

  // 1. Recover the expectation FIRST. No sign-in in flight means there is
  //    nothing to grant, so refuse before touching the JWS. This is a grant
  //    guard, not an abuse guard: anyone can mint themselves a flight via
  //    /api/login, but nobody can verify against a seal this server did not
  //    produce.
  const nonce = unseal('flight', readCookie(req, FLIGHT_COOKIE));
  if (nonce === null) {
    json(res, 401, { ok: false, reason: 'no sign-in in flight (or it expired)' }, [
      clearCookie(FLIGHT_COOKIE),
    ]);
    return;
  }

  const jws = readJws(req);
  if (jws === null) {
    json(res, 400, { ok: false, reason: 'body must be JSON with a `jws` string' }, [
      clearCookie(FLIGHT_COOKIE),
    ]);
    return;
  }

  // 2. The verification itself: resolve the signer's identity chain from a
  //    public relay, replay it to CURRENT state, and accept only a key that is
  //    still an authKey of a non-deleted identity. No DFOS platform server is
  //    contacted; the relay is untrusted and the crypto is what convinces us.
  //    `verifySiwd` is no-throw — the relay hop, the decode, and every check
  //    share one result channel — so its error string is what the page gets.
  const client = createClient({ relays: [RELAY_URL] });
  const result = await verifySiwd(client, jws, { domain: self.domain, nonce });

  if (!result.ok || result.value === undefined) {
    json(res, 401, { ok: false, reason: result.error ?? 'verification failed' }, [
      clearCookie(FLIGHT_COOKIE),
    ]);
    return;
  }

  // 3. Granted. The flight cookie is cleared in the same response that mints
  //    the session, and the JWS is discarded: a signed challenge is a one-shot
  //    authentication proof, not a bearer token.
  const { did, kid, timestamp } = result.value;
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + SESSION_TTL_SECONDS;

  json(res, 200, { ok: true, did, kid, timestamp }, [
    clearCookie(FLIGHT_COOKIE),
    setCookie(SESSION_COOKIE, encodeSession({ did, kid, iat, exp }), SESSION_TTL_SECONDS),
  ]);
}
