/*

  The other half of the membership graph.

  The API serves two flat walks rather than one nested page: `GET /v1/memberships`
  lists the spaces, this lists the groups across every space, and each group
  carries a flat `spaceId` / `spaceDid` ref. The page correlates them client-side
  on `group.spaceId`, which is what lets either walk page independently.

  Same seam as every other gated route (`api/_gated.ts`, and `api/profile.ts` for
  the long form), and the same discipline: ONE fixed request, `GET
  /v1/group-memberships`, with no query parameters. `space`, `role`, and `limit`
  exist on the API; a browser cannot reach them through here.

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
    response = await api.GET('/group-memberships');
  } catch (err) {
    json(res, 502, {
      ok: false,
      reason: `the API call did not complete: ${err instanceof Error ? err.message : String(err)}`,
    });
    return;
  }

  sendApiOutcome(res, 'groupMemberships', response);
}
