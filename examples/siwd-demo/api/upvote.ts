/*

  The first write: an upvote, toggled on or off.

  Everything before this route READ. A read that is refused costs the reader an
  answer; a write that runs twice costs them a state they did not ask for, so
  the protocol puts a replay guard on the write path specifically — and this is
  the route where that guard first matters.

  THE `jti` IS AUTOMATIC HERE, and that is the whole reason `signedFetch` is what
  this route uses. `createApiAuthFetch` mints a fresh unique id on every request
  whose method is not GET, HEAD, or OPTIONS, so a PUT or a DELETE through it
  carries one without this file arranging anything. The API records it and
  refuses a second presentation of the same proof inside its freshness window.
  `api/comment.ts` is where that refusal is demonstrated on purpose; here it is
  simply the thing that makes a double-clicked button harmless.

  THE CONFUSED-DEPUTY RULE, as `api/check.ts` argues it at length: the caller
  fills NAMED SLOTS in a request this file wrote. There are three — a space id, a
  post id, and which of two fixed methods — each validated against its own
  grammar before it reaches the path. A browser cannot reach any other method,
  path, or body through this route, which is what keeps a signing backend from
  being an oracle.

  The method is a slot rather than two routes because PUT and DELETE here are one
  affordance: a toggle. Both are written out below; the caller picks between
  them and composes neither.

*/

import { openGatedSession, sendApiRefusal, signedFetch } from './_gated.js';
import {
  API_HOST,
  DEMO_SPACE_ID,
  json,
  POST_ID_RE,
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

  const post = body?.['post'];
  if (typeof post !== 'string' || !POST_ID_RE.test(post)) {
    json(res, 400, { ok: false, reason: 'name one post by its id — post_ followed by its digits' });
    return;
  }

  // The toggle's direction, and the only thing that decides the method. A body
  // member that is not a boolean is a caller that does not know which way it
  // meant to go, which is a 400 rather than a guess at the friendlier direction.
  const on = body?.['on'];
  if (typeof on !== 'boolean') {
    json(res, 400, { ok: false, reason: 'say which way: `on` is true to upvote, false to remove' });
    return;
  }

  const signed = signedFetch(gated.held, gated.kid);
  const url = `https://${API_HOST}/v1/spaces/${spaceDid(space)}/posts/${post}/upvote`;

  let response: Response;
  try {
    // No body on either method, so no media type to pin: the proof covers the
    // method, the target, and an empty body, which is all there is to cover.
    response = await signed(url, { method: on ? 'PUT' : 'DELETE' });
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

  // The API's own count, not one this server incremented. A client that guesses
  // the new total is right until two people vote at once.
  const raw =
    typeof answered === 'object' && answered !== null && !Array.isArray(answered)
      ? (answered as Record<string, unknown>)
      : {};
  json(res, 200, {
    ok: true,
    host: API_HOST,
    upvoted: raw['upvoted'],
    upvoteCount: raw['upvoteCount'],
  });
}
