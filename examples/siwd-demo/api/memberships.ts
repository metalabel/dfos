/*

  The second gated call: one credential, a second endpoint.

  `api/profile.ts` holds the long explanation of the seam, and `api/_gated.ts`
  is that seam factored — this route is three lines of composition on top of it.
  It used to hand-compose the `Request` itself, because `@metalabel/dfos-api`
  predated `/v1/memberships`; the package ships the route now, so the
  hand-composition is gone and the shape it was defending is not.

  THE CONFUSED-DEPUTY RULE holds here exactly as it holds there: this route signs
  ONE request, `GET /v1/memberships`, with no query parameters, and the only
  thing the caller supplies is a session cookie saying which credential to use.
  `limit`, `after`, and `space` exist on the API; a browser cannot reach them
  through here, so the default page is what the page renders.

  POST rather than GET, for a read, and every POST is origin-checked — browsers
  omit `Origin` on GET, so the same check on a GET would be no check at all.

*/

import { openGatedSession, sendApiOutcome, signedApi } from './_gated.js';
import { json } from './_lib.js';
import type { VercelRequest, VercelResponse } from './_types.js';

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const gated = await openGatedSession(req, res);
  if (gated === null) return;

  const api = signedApi(gated.held, gated.kid);

  let response;
  try {
    response = await api.GET('/memberships');
  } catch (err) {
    json(res, 502, {
      ok: false,
      reason: `the API call did not complete: ${err instanceof Error ? err.message : String(err)}`,
    });
    return;
  }

  sendApiOutcome(res, 'memberships', response);
}
