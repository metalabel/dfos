/*

  The second gated call: one credential, two endpoints.

  `api/profile.ts` holds the long explanation of the seam — an API client
  composes a `Request`, and the wrapper signs exactly that request. This route is
  the same seam with the client half written out by hand, because
  `@metalabel/dfos-api@0.2.0` predates `/v1/memberships` and has no typed method
  for it. That changes which package composes the request and nothing else: the
  same `signApiRequest` covers the same method, host, path, and body octets that
  are about to go on the wire. (When dfos-api ships the route, the two lines that
  build the `Request` become `api.GET('/memberships')` and this file loses its
  hand-composition, not its shape.)

  THE CONFUSED-DEPUTY RULE holds here for the same reason it holds there, and
  hand-composing is exactly where it would be easiest to lose: this route signs
  one request, `GET /v1/memberships`, with no query parameters, and the only
  thing the caller supplies is a session cookie saying which credential to use.
  The route's coordinates are written in this file, not read off a request body.
  `limit`, `after`, and `space` exist on the API; a browser cannot reach them
  through here, so the default page is what the page renders.

  POST rather than GET, for a read, and every POST is origin-checked — browsers
  omit `Origin` on GET, so the same check on a GET would be no check at all.

*/

import { buildApiAuthHeaders, signApiRequest } from '@metalabel/dfos-client/api-auth';
import { kvGet } from './_kv.js';
import {
  API_HOST,
  API_REFUSALS,
  APP_KEY_ERROR,
  APP_KID,
  json,
  kvCredentialKey,
  methodNotAllowed,
  originAllowed,
  parseHeldCredential,
  readSession,
  requestOrigin,
  signAsApp,
  type HeldCredential,
} from './_lib.js';
import type { VercelRequest, VercelResponse } from './_types.js';

/*

  What comes back, written down because the generated client does not carry it
  yet. Nothing here casts to these types — the response is passed through as it
  arrived and the page reads every field defensively, since a shape declared in
  this file proves nothing about the bytes on the wire. They are documentation,
  and they are the swap-in point: when `@metalabel/dfos-api` ships the route,
  they are deleted in favor of the generated ones.

*/

/** A space the user belongs to. `id` and `did` are canonical; `domain` is a mutable alias. */
export interface MembershipSpaceOutput {
  id: string;
  did: string;
  domain: string;
  displayName: string | null;
  description: string | null;
  avatarUrl: string | null;
  links: unknown[];
  /** A worded bucket — "a few dozen members" — deliberately inexact. */
  memberCountSummary: string;
}

/** A group inside a space. `color` is a named palette token, not a CSS value. */
export interface MembershipGroupOutput {
  id: string;
  did: string;
  name: string;
  description: string | null;
  avatarUrl: string | null;
  color: string | null;
  role: string;
}

/** One membership: the space, the user's role in it, and their groups inside it. */
export interface MembershipOutput {
  space: MembershipSpaceOutput;
  role: string;
  groups: MembershipGroupOutput[];
}

/** The standard external-API page envelope. */
export interface MembershipsPage {
  items: MembershipOutput[];
  nextCursor: string | null;
  previousCursor?: string | null;
  totalCount?: number | null;
}

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
  if (APP_KEY_ERROR !== null || APP_KID === null) {
    json(res, 500, { ok: false, reason: APP_KEY_ERROR });
    return;
  }

  // The session is the ONLY authorization for signing. It names which stored
  // credential this caller is entitled to spend, and nothing else about the
  // request is negotiable.
  const session = readSession(req);
  if (session === null) {
    json(res, 401, { ok: false, reason: 'nobody is signed in' });
    return;
  }
  if (session.sid === undefined) {
    json(res, 403, {
      ok: false,
      reason:
        'this session was granted at identity scope, which returns no credential. Sign out ' +
        'and sign in again asking for the credential scope.',
    });
    return;
  }

  let held: HeldCredential | null = null;
  try {
    held = parseHeldCredential(await kvGet(kvCredentialKey(session.sid)));
  } catch (err) {
    json(res, 503, {
      ok: false,
      reason: `could not read the stored credential: ${err instanceof Error ? err.message : String(err)}`,
    });
    return;
  }
  if (held === null) {
    json(res, 403, {
      ok: false,
      reason: 'this session no longer holds a credential — sign out and sign in again',
    });
    return;
  }

  // The one request this route may make, composed here rather than taken from
  // anywhere. `API_HOST` is the same constant the credential's `api:<host>`
  // resource names, so the authority signed into the proof and the authority the
  // request is sent to cannot drift.
  const request = new Request(`https://${API_HOST}/v1/memberships`, { method: 'GET' });

  let response: Response;
  try {
    const url = new URL(request.url);
    const { proof } = await signApiRequest({
      method: request.method,
      // `url.host` carries the port when there is one, which is exactly the
      // authority form API-AUTH.md's `host` member wants.
      host: url.host,
      // Path plus query, byte for byte — no normalization, because the verifier
      // compares against the request target it actually received.
      path: url.pathname + url.search,
      body: new Uint8Array(await request.clone().arrayBuffer()),
      credentialCID: held.facts.credentialCID,
      kid: APP_KID,
      sign: signAsApp,
    });

    const headers = new Headers(request.headers);
    for (const [name, value] of Object.entries(
      buildApiAuthHeaders({ proof, credential: held.jws }),
    )) {
      headers.set(name, value);
    }
    response = await fetch(new Request(request, { headers }));
  } catch (err) {
    json(res, 502, {
      ok: false,
      reason: `the API call did not complete: ${err instanceof Error ? err.message : String(err)}`,
    });
    return;
  }

  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }

  if (response.status === 200 && typeof body === 'object' && body !== null) {
    json(res, 200, { ok: true, memberships: body, host: API_HOST });
    return;
  }

  // A refusal. The status and the envelope's `code` are the machine signals —
  // never the challenge header, which this deployment's CDN currently renames on
  // error responses (see the README).
  const status = response.status;
  const envelope =
    typeof body === 'object' && body !== null && !Array.isArray(body)
      ? (body as Record<string, unknown>)
      : {};

  json(res, 200, {
    ok: false,
    host: API_HOST,
    status,
    ...(typeof envelope['code'] === 'string' ? { code: envelope['code'] } : {}),
    ...(typeof envelope['message'] === 'string' ? { message: envelope['message'] } : {}),
    reason: API_REFUSALS[status] ?? `The API answered HTTP ${status}.`,
  });
}
