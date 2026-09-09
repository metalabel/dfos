/*

  Undo, and the reason this route exists at all.

  A demo whose write path only ever ADDS leaves the reader's own space littered
  with whatever they clicked through. `write:comments` covers removing a comment
  as well as writing one, so the affordance that made the mess is the affordance
  that clears it.

  OWN CONTENT ONLY, and not because this file checks. The credential names its
  issuer, and the API serves the issuer's own comments — a delete presented for
  somebody else's comment is refused there, on the authority that holds the
  facts, rather than guessed at here on the authority that does not.

  Same discipline as every other write: `signedFetch`, so the `jti` is minted
  automatically on this non-safe method; one fixed template with two validated
  slots, a space id and a comment id.

  The comment id is validated against the POST id grammar, because that is the
  namespace comments are minted in — `_lib.ts` says so where the pattern lives.
  The check is a shape check and nothing more: it keeps path grammar out of a
  path this file wrote, and it cannot tell a comment from a post. Whether the id
  names a comment, and whether that comment is this grant's to remove, are both
  the API's to answer, and it answers them on the route it was asked.

*/

import { openGatedSession, sendApiRefusal, signedFetch } from './_gated.js';
import {
  API_HOST,
  COMMENT_ID_RE,
  DEMO_SPACE_ID,
  json,
  readJsonBody,
  SPACE_ID_RE,
  spaceDid,
} from './_lib.js';
import type { VercelRequest, VercelResponse } from './_types.js';

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const gated = await openGatedSession(req, res);
  if (gated === null) return;

  const body = readJsonBody(req);

  const askedSpace = body?.['space'];
  if (
    askedSpace !== undefined &&
    (typeof askedSpace !== 'string' || !SPACE_ID_RE.test(askedSpace))
  ) {
    json(res, 400, {
      ok: false,
      reason: 'name one space by its bare 31-character id, or send no space at all',
    });
    return;
  }
  const space = typeof askedSpace === 'string' ? askedSpace : DEMO_SPACE_ID;

  const comment = body?.['comment'];
  if (typeof comment !== 'string' || !COMMENT_ID_RE.test(comment)) {
    json(res, 400, {
      ok: false,
      reason:
        'name one comment by its id — post_ followed by its digits; a comment shares the post ' +
        'id namespace',
    });
    return;
  }

  const signed = signedFetch(gated.held, gated.kid);
  const url = `https://${API_HOST}/v1/spaces/${spaceDid(space)}/comments/${comment}`;

  let response: Response;
  try {
    response = await signed(url, { method: 'DELETE' });
  } catch (err) {
    json(res, 502, {
      ok: false,
      reason: `the API call did not complete: ${err instanceof Error ? err.message : String(err)}`,
    });
    return;
  }

  let answered: unknown;
  try {
    answered = await response.json();
  } catch {
    answered = undefined;
  }

  if (!response.ok) {
    sendApiRefusal(res, response.status, answered);
    return;
  }

  const raw =
    typeof answered === 'object' && answered !== null && !Array.isArray(answered)
      ? (answered as Record<string, unknown>)
      : {};
  json(res, 200, { ok: true, host: API_HOST, deleted: raw['deleted'] });
}
