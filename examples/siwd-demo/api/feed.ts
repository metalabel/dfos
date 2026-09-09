/*

  The read that only a credential can make: the signed-in user's own feed.

  Where `api/posts.ts` shows what a grant ADDS to a public read, this shows a
  read that has no public form at all. There is no anonymous projection to
  compare against — a feed is assembled from who you follow and where you are a
  member, so without a credential there is no one to assemble it for.

  Same seam and same discipline as every other gated route: ONE fixed request,
  `GET /v1/feed`, no parameters from the caller. It goes through `signedFetch`
  rather than the typed client because `@metalabel/dfos-api` does not model this
  path; the request is composed here and the adapter signs exactly it.

  WHATEVER THE API ANSWERS IS THE ANSWER. A refusal is passed through in the
  shared envelope with its status intact, and no status is special-cased into
  something friendlier — a route that translated one code into a reassurance
  would be reporting its author's expectations rather than the API's verdict.

*/

import { openGatedSession, sendApiRefusal, signedFetch } from './_gated.js';
import { API_HOST, json } from './_lib.js';
import type { VercelRequest, VercelResponse } from './_types.js';

/** One screen of feed, and no way for a caller to ask for another. */
const FEED_LIMIT = 10;

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const gated = await openGatedSession(req, res);
  if (gated === null) return;

  const signed = signedFetch(gated.held, gated.kid);

  let response: Response;
  try {
    response = await signed(`https://${API_HOST}/v1/feed?limit=${FEED_LIMIT}`);
  } catch (err) {
    json(res, 502, {
      ok: false,
      reason: `the API call did not complete: ${err instanceof Error ? err.message : String(err)}`,
    });
    return;
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }

  if (response.ok) {
    if (typeof body !== 'object' || body === null || Array.isArray(body)) {
      json(res, 502, {
        ok: false,
        reason: `the API answered HTTP ${response.status} with a body this route could not read as a JSON object`,
      });
      return;
    }
    json(res, 200, { ok: true, feed: body, host: API_HOST });
    return;
  }

  sendApiRefusal(res, response.status, body);
}
