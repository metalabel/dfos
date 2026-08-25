/*

  STEP 3 — spend the credential: one credential-gated call to the DFOS API.

  This is the whole point of the credential path, and it is four moving parts:

    @metalabel/dfos-api      knows the API's shape — paths, params, response
                             types, generated from the live OpenAPI spec.
    @metalabel/dfos-client   knows the byte contract — `signApiRequest` builds
                             the request proof specs/API-AUTH.md defines.
    this file                holds the key and decides WHAT may be signed.
    the fetch seam           is where the two meet: `createDfosApi({ fetch })`
                             hands the wrapper one fully-composed `Request`, and
                             the wrapper signs exactly that request.

  The seam is why neither package had to learn about the other. The API client
  composes a request; the signer covers it; nothing in between needs a concept of
  the other's job.

  THE CONFUSED-DEPUTY RULE, which is the reason this endpoint takes no
  parameters at all. API-AUTH.md's Security Considerations: a backend that signs
  whatever `{method, path, body}` a browser hands it is an oracle — an XSS on the
  page, or simply a hostile client, would obtain proofs for arbitrary requests
  against every credential this backend holds. So the coordinates are not an
  input here. This route signs one request, `GET /v1/profile`, and the only thing
  the caller supplies is a session cookie that says which credential to use. A
  browser cannot ask for anything else, because there is nothing to ask with.

  POST rather than GET, for a read: this call SPENDS a proof against a live API,
  and every POST here is origin-checked (browsers omit `Origin` on GET, so the
  same check on a GET would be no check at all).

*/

import { createDfosApi } from '@metalabel/dfos-api';
import { buildApiAuthHeaders, signApiRequest } from '@metalabel/dfos-client/api-auth';
import { kvGet } from './_kv.js';
import {
  API_HOST,
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

/** The API refusals worth explaining, mapped from what the wire actually says. */
const REFUSALS: Record<number, string> = {
  401: 'The API refused the request proof. Either the proof did not verify against this app’s key, or the app’s configured key is not a current key of its identity.',
  403: 'The API accepted the proof and refused the credential. The usual cause is revocation — the user revoked this grant, and the API re-checks that on every request.',
  503: 'The API could not complete the check — a resolution or revocation source was unreachable. That is the server’s condition, not a judgment about the grant, and it is reported as unverifiable rather than as a refusal.',
};

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
        'and sign in again asking for read:profile.',
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

  // Captured as locals: the checks above narrowed both, and narrowing does not
  // survive into the closure below.
  const kid = APP_KID;
  const grant = held;

  // THE SEAM. `createDfosApi` composes the request; this wrapper receives it
  // fully formed and signs exactly what it received — the same method, the same
  // origin-form target, the same body octets that are about to go on the wire.
  // Signing the request the client actually built, rather than a description of
  // it, is what keeps the proof's binding honest.
  const api = createDfosApi({
    // Derived from API_HOST rather than taken from the package default, so the
    // authority this request is SENT to and the authority named by the
    // credential's `api:<host>` resource are the same constant. Left implicit,
    // they would be two independent facts that happen to agree today — and
    // `_lib.ts` promises they cannot drift.
    baseUrl: `https://${API_HOST}/v1/`,
    fetch: async (request: Request): Promise<Response> => {
      const url = new URL(request.url);
      const { proof } = await signApiRequest({
        method: request.method,
        // `url.host` carries the port when there is one, which is exactly the
        // authority form API-AUTH.md's `host` member wants.
        host: url.host,
        // Path plus query, byte for byte — no normalization, because the
        // verifier compares against the request target it actually received.
        path: url.pathname + url.search,
        body: new Uint8Array(await request.clone().arrayBuffer()),
        credentialCID: grant.facts.credentialCID,
        kid,
        sign: signAsApp,
      });

      const headers = new Headers(request.headers);
      for (const [name, value] of Object.entries(
        buildApiAuthHeaders({ proof, credential: grant.jws }),
      )) {
        headers.set(name, value);
      }
      return fetch(new Request(request, { headers }));
    },
  });

  let response;
  try {
    response = await api.GET('/profile');
  } catch (err) {
    json(res, 502, {
      ok: false,
      reason: `the API call did not complete: ${err instanceof Error ? err.message : String(err)}`,
    });
    return;
  }

  if (response.data !== undefined) {
    json(res, 200, { ok: true, profile: response.data, host: API_HOST });
    return;
  }

  // A refusal. The status and the typed envelope's `code` are the machine
  // signals — never the challenge header, which this deployment's CDN currently
  // renames on error responses (see the README).
  const status = response.response.status;
  const envelope =
    typeof response.error === 'object' && response.error !== null
      ? (response.error as Record<string, unknown>)
      : {};

  json(res, 200, {
    ok: false,
    host: API_HOST,
    status,
    ...(typeof envelope['code'] === 'string' ? { code: envelope['code'] } : {}),
    ...(typeof envelope['message'] === 'string' ? { message: envelope['message'] } : {}),
    reason: REFUSALS[status] ?? `The API answered HTTP ${status}.`,
  });
}
