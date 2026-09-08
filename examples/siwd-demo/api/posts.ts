/*

  The comparison route: one API path, read twice — once with nothing, and once
  with this app's credential.

  Everywhere else on this page a gated call answers one question. This one
  answers a different kind: what does the grant actually BUY. A space's posts
  route is optionally authenticated, so it serves an anonymous projection to a
  caller with no credential and a member projection to one whose credential
  reaches that space. Calling it both ways in the same breath puts the two
  answers side by side, which is the only way to see the difference the
  credential makes rather than be told about it.

  The anonymous call is a bare `fetch` with no headers at all — not a stripped
  version of the signed one. A "credential-free" request assembled by deleting
  headers is one refactor away from carrying one.

  THE CONFUSED-DEPUTY RULE, as `api/check.ts` argues it at length: the caller
  fills a NAMED SLOT in a request this file wrote, never coordinates. The slot
  here is one space id, validated against the id grammar before it reaches the
  path, and everything else about both requests is written below.

  POST rather than GET, for a read: the call spends a proof against a live API,
  and every POST here is origin-checked.

*/

import { openGatedSession, signedFetch } from './_gated.js';
import { API_HOST, DEMO_SPACE_ID, json, readJsonBody, SPACE_ID_RE, spaceDid } from './_lib.js';
import type { VercelRequest, VercelResponse } from './_types.js';

/** Enough posts to compare, few enough to render two of side by side. */
const POSTS_LIMIT = 5;

/**
 * One side's answer, whatever it was. A non-2xx is reported INSIDE the
 * projection rather than as a refusal of this route, because the comparison is
 * the point: a route that collapsed on one side's 403 would hide the very thing
 * it was built to show.
 */
interface Projection {
  status: number;
  /** The 2xx body, when it parsed as JSON. */
  page?: unknown;
  /** The non-2xx body, when it parsed as JSON. */
  error?: unknown;
}

const projection = async (response: Response): Promise<Projection> => {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    // A body that is not JSON is still a status worth reporting; the member is
    // simply absent, rather than filled with a guess at what was in there.
    body = undefined;
  }
  const status = response.status;
  if (body === undefined) return { status };
  return response.ok ? { status, page: body } : { status, error: body };
};

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const gated = await openGatedSession(req, res);
  if (gated === null) return;

  // The `{space}` path parameter takes the DID form; the body takes the bare
  // id, which is the form the credential's `api:<host>/spaces/<id>` resource and
  // the SIWD `spaces` parameter both use. The conversion happens here, once, so
  // no caller has to know which form belongs where.
  const asked = readJsonBody(req)?.['space'];
  if (asked !== undefined && (typeof asked !== 'string' || !SPACE_ID_RE.test(asked))) {
    json(res, 400, {
      ok: false,
      reason: 'name one space by its bare 31-character id, or send no space at all',
    });
    return;
  }
  const space = typeof asked === 'string' ? asked : DEMO_SPACE_ID;
  const did = spaceDid(space);
  const url = `https://${API_HOST}/v1/spaces/${did}/posts?limit=${POSTS_LIMIT}`;

  const signed = signedFetch(gated.held, gated.kid);

  let anonymous: Projection;
  let member: Projection;
  try {
    // In parallel, and against the same URL string byte for byte: two reads of
    // one route differing in exactly one thing, which is what makes the diff
    // below attributable to the credential.
    [anonymous, member] = await Promise.all([
      fetch(url).then(projection),
      signed(url).then(projection),
    ]);
  } catch (err) {
    json(res, 502, {
      ok: false,
      reason: `the API call did not complete: ${err instanceof Error ? err.message : String(err)}`,
    });
    return;
  }

  // TRIGGER-A: on the API this demo is built against, this route is
  // anonymous-only, so both sides return the same projection and the diff below
  // is empty. A covered credential is what makes the two differ.
  json(res, 200, {
    ok: true,
    host: API_HOST,
    space: { id: space, did },
    anonymous,
    member,
  });
}
