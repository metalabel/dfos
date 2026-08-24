/*

  Who this browser is, according to the session this server minted.

  The answer comes from unsealing the session cookie — never from a DID handed
  in by the caller. A cookie that does not unseal, does not parse, or has passed
  its own `exp` is the same fact as no cookie at all: nobody is signed in.

  This is also the endpoint the page renders the signed-in card from, including
  right after a successful verification, so what you are looking at is always
  the session as the SERVER reads it back — not a client-side memory of a
  verdict that has since expired.

*/

import { clearCookie, json, methodNotAllowed, readSession, SESSION_COOKIE } from './_lib.js';
import type { VercelRequest, VercelResponse } from './_types.js';

export default function handler(req: VercelRequest, res: VercelResponse): void {
  if (req.method !== 'GET') {
    methodNotAllowed(res, 'GET');
    return;
  }

  const session = readSession(req);
  if (session === null) {
    // The stale cookie is cleared on the way out: it will never unseal into
    // anything again, and leaving it in the jar means sending it on every
    // subsequent request for nothing.
    json(res, 401, { ok: false }, [clearCookie(SESSION_COOKIE)]);
    return;
  }

  json(res, 200, { ...session });
}
