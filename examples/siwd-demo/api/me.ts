/*

  Who this browser is, according to the session this server minted — and what it
  was granted alongside.

  The answer comes from unsealing the session cookie, never from a DID handed in
  by the caller. A cookie that does not unseal, does not parse, or has passed its
  own `exp` means the same thing as no cookie at all: nobody is signed in.

  When the session was granted under the credential set, the credential's
  already-verified facts come back with it, so the page can render the grant
  BEFORE anything is spent against it. The credential JWS stays here: the browser
  has no key to exercise it with, and handing it out would move a durable
  authorization into the one place that cannot hold anything safely.

  The page renders its signed-in card from here, including right after a
  successful verification, so the card always shows the session as the SERVER
  reads it back.

*/

import { kvGet } from './_kv.js';
import {
  clearCookie,
  json,
  kvCredentialKey,
  methodNotAllowed,
  parseHeldCredential,
  readSession,
  SESSION_COOKIE,
} from './_lib.js';
import type { VercelRequest, VercelResponse } from './_types.js';

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  if (req.method !== 'GET') {
    methodNotAllowed(res, 'GET');
    return;
  }

  const session = readSession(req);
  if (session === null) {
    // The stale cookie is cleared on the way out: it will never unseal again,
    // and leaving it in the jar means sending it on every request for nothing.
    json(res, 401, { ok: false }, [clearCookie(SESSION_COOKIE)]);
    return;
  }

  const { sid, ...rest } = session;
  if (sid === undefined) {
    json(res, 200, { ...rest });
    return;
  }

  // A missing record is not an error: the store's TTL can expire before the
  // cookie's, and the honest answer is a session that no longer holds a grant.
  let held = null;
  try {
    held = parseHeldCredential(await kvGet(kvCredentialKey(sid)));
  } catch {
    held = null;
  }

  json(res, 200, { ...rest, ...(held !== null ? { credential: held.facts } : {}) });
}
