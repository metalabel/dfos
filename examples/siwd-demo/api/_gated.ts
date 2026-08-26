/*

  The credential-gated preamble and the signing seam, factored once.

  `api/profile.ts` is this same seam written out long-form, and it stays that
  way deliberately: it is the file the README quotes and the page shows under
  "Show the receipts", and its comment carries the argument — the confused-deputy
  rule, why the coordinates are never an input, why the backend is the party that
  signs. Read that file for the reasoning; this one is here because four more
  gated routes arrived behind it, and copying ninety lines of identical plumbing
  five times is how plumbing drifts.

  What is shared is the preamble and the seam. What is NOT shared is the one
  thing that must stay per-route: WHICH request gets signed. Every caller writes
  its own fixed coordinates in its own file, because that is the discipline the
  factoring must not quietly dissolve.

*/

import { createDfosApi } from '@metalabel/dfos-api';
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

/** A caller entitled to spend a stored credential, and the key that spends it. */
export interface GatedSession {
  held: HeldCredential;
  /** The app's own signing key, narrowed to non-null by the preamble. */
  kid: string;
}

/**
 * The preamble every gated route runs before it signs anything: is this a POST,
 * is it same-origin, does this deployment hold a key, is anybody signed in, did
 * that sign-in return a credential, and is the credential still in the store.
 *
 * On any failure this writes the JSON response itself and answers `null`, so a
 * route's whole check is `if (gated === null) return;`. The refusal strings are
 * the ones a reader sees, so they are worded as the thing to do next rather than
 * as a status name.
 *
 * POST rather than GET, for a read: the call spends a proof against a live API,
 * and every POST here is origin-checked (browsers omit `Origin` on GET, so the
 * same check on a GET would be no check at all).
 */
export const openGatedSession = async (
  req: VercelRequest,
  res: VercelResponse,
): Promise<GatedSession | null> => {
  if (req.method !== 'POST') {
    methodNotAllowed(res, 'POST');
    return null;
  }

  const self = requestOrigin(req);
  if (self === null) {
    json(res, 400, { ok: false, reason: 'could not determine this request’s origin' });
    return null;
  }
  if (!originAllowed(req, self)) {
    json(res, 403, { ok: false, reason: 'cross-origin request refused' });
    return null;
  }
  if (APP_KEY_ERROR !== null || APP_KID === null) {
    json(res, 500, { ok: false, reason: APP_KEY_ERROR });
    return null;
  }

  // The session is the ONLY authorization for signing. It names which stored
  // credential this caller is entitled to spend, and nothing else about the
  // request is negotiable.
  const session = readSession(req);
  if (session === null) {
    json(res, 401, { ok: false, reason: 'nobody is signed in' });
    return null;
  }
  if (session.sid === undefined) {
    json(res, 403, {
      ok: false,
      reason:
        'this session was granted at identity scope, which returns no credential. Sign out ' +
        'and sign in again asking for the credential scope.',
    });
    return null;
  }

  let held: HeldCredential | null = null;
  try {
    held = parseHeldCredential(await kvGet(kvCredentialKey(session.sid)));
  } catch (err) {
    json(res, 503, {
      ok: false,
      reason: `could not read the stored credential: ${err instanceof Error ? err.message : String(err)}`,
    });
    return null;
  }
  if (held === null) {
    json(res, 403, {
      ok: false,
      reason: 'this session no longer holds a credential — sign out and sign in again',
    });
    return null;
  }

  return { held, kid: APP_KID };
};

/**
 * THE SEAM, as `api/profile.ts` writes it out. `createDfosApi` composes the
 * request; this wrapper receives it fully formed and signs exactly what it
 * received — the same method, the same origin-form target, the same body octets
 * that are about to go on the wire.
 *
 * `baseUrl` is derived from `API_HOST` rather than left to the package default,
 * so the authority the request is SENT to and the authority the credential's
 * `api:<host>` resource names are one constant and cannot drift.
 */
export const signedApi = (held: HeldCredential, kid: string) =>
  createDfosApi({
    baseUrl: `https://${API_HOST}/v1/`,
    fetch: async (request: Request): Promise<Response> => {
      const url = new URL(request.url);
      const { proof } = await signApiRequest({
        // `url.host` carries the port when there is one, and path plus query is
        // taken byte for byte — the verifier compares against the request target
        // it actually received, so nothing here normalizes.
        method: request.method,
        host: url.host,
        path: url.pathname + url.search,
        body: new Uint8Array(await request.clone().arrayBuffer()),
        credentialCID: held.facts.credentialCID,
        kid,
        sign: signAsApp,
      });

      const headers = new Headers(request.headers);
      for (const [name, value] of Object.entries(
        buildApiAuthHeaders({ proof, credential: held.jws }),
      )) {
        headers.set(name, value);
      }
      return fetch(new Request(request, { headers }));
    },
  });

/** What the typed client answers with, read structurally rather than imported. */
interface ApiOutcome {
  data?: unknown;
  error?: unknown;
  response: Response;
}

/**
 * The refusal tail. The status and the typed envelope's `code` are the machine
 * signals — never the challenge header, which this deployment's CDN currently
 * renames on error responses (see the README).
 */
export const sendApiRefusal = (res: VercelResponse, status: number, error: unknown): void => {
  const envelope =
    typeof error === 'object' && error !== null && !Array.isArray(error)
      ? (error as Record<string, unknown>)
      : {};

  json(res, 200, {
    ok: false,
    host: API_HOST,
    status,
    ...(typeof envelope['code'] === 'string' ? { code: envelope['code'] } : {}),
    ...(typeof envelope['message'] === 'string' ? { message: envelope['message'] } : {}),
    reason: API_REFUSALS[status] ?? `The API answered HTTP ${status}.`,
  });
};

/**
 * The whole tail for a route that just passes the API's answer through: the body
 * under the member name this route owns, or the refusal envelope. The member
 * name is the caller's, because `profile`, `memberships`, and `credential` are
 * what the page reads and a generic `data` would tell the reader nothing.
 */
export const sendApiOutcome = (res: VercelResponse, member: string, outcome: ApiOutcome): void => {
  if (outcome.data !== undefined) {
    json(res, 200, { ok: true, [member]: outcome.data, host: API_HOST });
    return;
  }
  sendApiRefusal(res, outcome.response.status, outcome.error);
};
