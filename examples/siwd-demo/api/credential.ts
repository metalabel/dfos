/*

  Introspection: what the API says about the credential being presented to it.

  This is a different question from the one `/api/me` answers. That route reports
  facts this server read out of the credential at grant time and stored — true
  when they were checked, and still true only as far as anything stored is. This
  route asks the API, right now, about the artifact it is holding in its hands.

  It requires NO particular scope: a credential may always describe itself. Which
  is exactly what makes it the "is this grant still standing" probe — a revoked
  or expired credential does not describe itself, it is refused with 403 here
  like anywhere else.

  Same seam and same discipline as every other gated route (`api/_gated.ts`, and
  `api/profile.ts` for the long form): ONE fixed request, `GET /v1/credential`,
  no parameters, authorized by the session alone.

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
    response = await api.GET('/credential');
  } catch (err) {
    json(res, 502, {
      ok: false,
      reason: `the API call did not complete: ${err instanceof Error ? err.message : String(err)}`,
    });
    return;
  }

  sendApiOutcome(res, 'credential', response);
}
