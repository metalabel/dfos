/*

  Sign out — expire the session cookie, and drop the credential behind it.

  A POST rather than a GET, and origin-checked like the rest, because a sign-out
  is a state change and a GET would be firable from any `<img>` anywhere.

  There is no server-side session to revoke — the cookie IS the session — but on
  the credential path there is one piece of server state, and it is somebody's
  standing authorization. Signing out should not leave it sitting in a store, so
  it goes in the same breath. That is hygiene, not revocation: the credential
  still exists and is still valid until it expires or the user revokes it at the
  platform. What ends here is this app's copy.

*/

import { kvDel } from './_kv.js';
import {
  clearCookie,
  json,
  kvCredentialKey,
  methodNotAllowed,
  noContent,
  originAllowed,
  readSession,
  requestOrigin,
  SESSION_COOKIE,
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

  // Best-effort, and never a reason to refuse the sign-out: the record carries
  // its own TTL, so a store that did not answer forgets it anyway.
  const session = readSession(req);
  if (session?.sid !== undefined) await kvDel(kvCredentialKey(session.sid));

  noContent(res, [clearCookie(SESSION_COOKIE)]);
}
