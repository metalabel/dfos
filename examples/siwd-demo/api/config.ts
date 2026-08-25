/*

  What this deployment can actually do, answered before the user clicks anything.

  The demo offers two scopes, and the second one has real preconditions: a
  signing key, a store, and a domain. Rather than let a reader pick `read:profile`
  and discover three redirects later that the deployment was never set up for it,
  the page asks here first and renders each scope with its own verdict — the same
  posture as the boot-time registration self-check, which says what is missing
  while there is still something to do about it.

  Nothing secret leaves this endpoint. The app's DID is published in a well-known
  file, and the public key is public by definition — it is here precisely so a
  fork can compare it against `dfos identity keys` and catch the one
  misconfiguration whose only other symptom arrives much later, from the API, as
  a 401.

*/

import { KV_ERROR } from './_kv.js';
import {
  API_ACTION,
  API_HOST,
  API_RESOURCE,
  APP_DID,
  APP_KEY_ERROR,
  APP_PUBLIC_KEY_MULTIBASE,
  isLoopbackDomain,
  json,
  methodNotAllowed,
  requestOrigin,
  SCOPE_IDENTITY,
  SCOPE_READ_PROFILE,
} from './_lib.js';
import type { VercelRequest, VercelResponse } from './_types.js';

export default function handler(req: VercelRequest, res: VercelResponse): void {
  if (req.method !== 'GET') {
    methodNotAllowed(res, 'GET');
    return;
  }

  const self = requestOrigin(req);
  const loopback = self !== null && isLoopbackDomain(self.domain);

  // The order matters: the domain rule is the one a fork cannot fix with an
  // environment variable, so it is reported first when it applies.
  const unavailable = loopback
    ? 'This is a loopback host. specs/SIWD.md admits a local redirect target for ' +
      'scope=identity only — a local port holds no domain, so it can prove no client_did, ' +
      'and a credential has to be issued to someone. Deploy to a domain to exercise this path.'
    : (APP_KEY_ERROR ?? KV_ERROR);

  json(res, 200, {
    scopes: [
      {
        scope: SCOPE_IDENTITY,
        discipline: 'flow-bound',
        available: true,
        summary: 'Proves who you are. Returns no credential, so nothing portable is granted.',
      },
      {
        scope: SCOPE_READ_PROFILE,
        discipline: 'consumed',
        available: unavailable === null,
        ...(unavailable !== null ? { unavailable } : {}),
        summary:
          'Proves who you are AND returns a credential this app can spend against the ' +
          'DFOS API — once per request, and only with its own key.',
      },
    ],
    api: {
      host: API_HOST,
      // Shown verbatim on the page: these two strings are what the user is
      // consenting to and what the API verifier byte-matches. If they read
      // differently in the two places, one of them is wrong.
      resource: API_RESOURCE,
      action: API_ACTION,
    },
    app: {
      ...(APP_DID !== null ? { did: APP_DID } : {}),
      ...(APP_PUBLIC_KEY_MULTIBASE !== null
        ? { publicKeyMultibase: APP_PUBLIC_KEY_MULTIBASE }
        : {}),
    },
  });
}
