/*

  Sign out — expire the session cookie.

  A POST rather than a GET, and origin-checked like the rest, because a sign-out
  is a state change and a GET would be firable from any `<img>` anywhere. There
  is no server-side session to revoke — the cookie IS the session — so expiring
  it is the whole operation.

*/

import {
  clearCookie,
  json,
  methodNotAllowed,
  noContent,
  originAllowed,
  requestOrigin,
  SESSION_COOKIE,
} from './_lib.js';
import type { VercelRequest, VercelResponse } from './_types.js';

export default function handler(req: VercelRequest, res: VercelResponse): void {
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

  noContent(res, [clearCookie(SESSION_COOKIE)]);
}
