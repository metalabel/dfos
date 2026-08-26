/*

  The ONE route here where a value from the browser reaches signed coordinates,
  and the only one — so this is where the discipline has to be argued rather than
  assumed.

  THE CONFUSED-DEPUTY RULE (the long form is in `api/profile.ts`) forbids signing
  arbitrary coordinates a browser hands over: a backend that signs whatever
  `{method, path, body}` it is asked to is an oracle, and an XSS on the page
  obtains proofs for every request against every credential the backend holds.

  This route does not do that. It holds two fixed request TEMPLATES —
  `GET /v1/membership/{space}` and `GET /v1/group-membership/{group}` — and the
  only thing the caller supplies is the identifier that fills the one path
  segment, validated here and percent-encoded by the client. Everything else
  about the request is written in this file. An XSS here can ask membership
  questions the session's credential already answers; it cannot obtain a proof
  for any other method, path, or body.

  That is the rule worth copying: parameterizing a signer means confining the
  input to a NAMED SLOT in a request you wrote, never accepting coordinates.

  What comes back is the collapsed 404 — the API deliberately cannot distinguish
  "no such space" from "you are not a member", because this credential discloses
  the user's own memberships and never the existence of anything else. The
  identifier is matched against the user's own membership rows rather than
  resolved against the platform, which is also why a tight charset costs nothing
  here: there is no path to traverse to.

*/

import { openGatedSession, sendApiRefusal, signedApi } from './_gated.js';
import { API_HOST, json, readJsonBody, readTokenField } from './_lib.js';
import type { VercelRequest, VercelResponse } from './_types.js';

/** The two questions this route knows how to ask. Anything else is a 400. */
const KINDS = ['space', 'group'] as const;
type Kind = (typeof KINDS)[number];

const isKind = (value: string | null): value is Kind =>
  value !== null && (KINDS as readonly string[]).includes(value);

/**
 * Entity ids (`space_…`), DIDs (`did:dfos:…`), and subdomains all live inside
 * this charset; path metacharacters do not. The client percent-encodes the
 * segment anyway — this refuses outright rather than encoding something that had
 * no business being an identifier.
 */
const IDENTIFIER = /^[A-Za-z0-9._:-]+$/;
const MAX_IDENTIFIER_CHARS = 200;

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const gated = await openGatedSession(req, res);
  if (gated === null) return;

  const body = readJsonBody(req);
  const kind = readTokenField(body, 'kind');
  if (!isKind(kind)) {
    json(res, 400, { ok: false, reason: 'ask about a "space" or a "group" — nothing else' });
    return;
  }
  const target = readTokenField(body, 'target');
  if (target === null || target.length > MAX_IDENTIFIER_CHARS || !IDENTIFIER.test(target)) {
    json(res, 400, {
      ok: false,
      reason:
        `name one ${kind} by its id, DID, or domain — letters, digits, and . _ : - only, ` +
        `up to ${MAX_IDENTIFIER_CHARS} characters`,
    });
    return;
  }

  const api = signedApi(gated.held, gated.kid);

  let response;
  try {
    response =
      kind === 'space'
        ? await api.GET('/membership/{space}', { params: { path: { space: target } } })
        : await api.GET('/group-membership/{group}', { params: { path: { group: target } } });
  } catch (err) {
    json(res, 502, {
      ok: false,
      reason: `the API call did not complete: ${err instanceof Error ? err.message : String(err)}`,
    });
    return;
  }

  if (response.data !== undefined) {
    json(res, 200, { ok: true, member: true, kind, target, entry: response.data, host: API_HOST });
    return;
  }

  // `ok: true` on a 404, deliberately. The collapsed 404 is the ANSWER to the
  // question that was asked — "not a member, or there is no such thing, and you
  // do not get to learn which" — not a failure of the call. Reporting it as a
  // refusal would teach the reader to treat a negative membership check as an
  // error condition, which is the opposite of what this primitive is for.
  if (response.response.status === 404) {
    json(res, 200, { ok: true, member: false, kind, target, host: API_HOST });
    return;
  }

  sendApiRefusal(res, response.response.status, response.error);
}
