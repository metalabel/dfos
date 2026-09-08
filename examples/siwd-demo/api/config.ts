/*

  What this deployment can actually do, answered before the user clicks anything.

  The demo offers three options, and the two credential sets have real
  preconditions: a signing key, a store, and a domain. Rather than let a reader
  pick one and discover three redirects later that the deployment was never set
  up for it, the page asks here first and renders each option with its own
  verdict — the same posture as the boot-time registration self-check, which says
  what is missing while there is still something to do about it.

  The two credential options share one precondition chain and differ only in
  their action tokens, so the verdict is computed once and the tokens are
  reported per option. The page reads that structure rather than a pair of
  pre-joined strings: what a credential covers is now a list of entries, and a
  config that flattened it would be describing a shape that no longer exists.

  Nothing secret leaves this endpoint. The app's DID is published in a well-known
  file, and the public key is public by definition — it is here precisely so a
  fork can compare it against `dfos identity keys` and catch the one
  misconfiguration whose only other symptom arrives much later, from the API, as
  a 401.

*/

import { KV_ERROR } from './_kv.js';
import {
  API_ACTIONS,
  API_HOST,
  APP_DID,
  APP_KEY_ERROR,
  APP_PUBLIC_KEY_MULTIBASE,
  DEMO_SPACE_DID,
  DEMO_SPACE_ID,
  DEMO_SPACE_NAME,
  isLoopbackDomain,
  json,
  methodNotAllowed,
  requestOrigin,
  SCOPE_API,
  SCOPE_IDENTITY,
  SCOPE_SPACES,
  SECRET_ERROR,
  SPACES_ACTIONS,
} from './_lib.js';
import type { VercelRequest, VercelResponse } from './_types.js';

export default function handler(req: VercelRequest, res: VercelResponse): void {
  if (req.method !== 'GET') {
    methodNotAllowed(res, 'GET');
    return;
  }

  const self = requestOrigin(req);
  const loopback = self !== null && isLoopbackDomain(self.domain);

  // `SESSION_SECRET` is the one precondition BOTH scopes share: without a usable
  // seal this server cannot mint a flight cookie that `/api/verify` could unseal,
  // so every sign-in refuses. It belongs in the preflight for the same reason
  // everything else here does — a fork should read it on the page rather than
  // meet it as a 500 on the first click.
  const blocked = SECRET_ERROR;

  // The credential options' own chain, layered on top and shared by both of
  // them: a signing key and a store are what a returned credential needs, and
  // neither option needs anything the other does not. Order matters — the domain
  // rule is the one a fork cannot fix with an environment variable, so it is
  // reported first when it applies.
  const unavailable =
    blocked ??
    (loopback
      ? 'This is a loopback host. The SIWD spec (protocol.dfos.com/siwd) admits a local redirect target for ' +
        'scope=identity only — a local port holds no domain, so it can prove no client_did, ' +
        'and a credential has to be issued to someone. Deploy to a domain to exercise this path.'
      : (APP_KEY_ERROR ?? KV_ERROR));

  json(res, 200, {
    scopes: [
      {
        scope: SCOPE_IDENTITY,
        available: blocked === null,
        ...(blocked !== null ? { unavailable: blocked } : {}),
        summary: 'Proves who you are. Nothing else.',
      },
      {
        scope: SCOPE_API,
        available: unavailable === null,
        ...(unavailable !== null ? { unavailable } : {}),
        summary:
          'Proves who you are and grants this app a credential to read your profile, your ' +
          'account email, and the spaces you belong to.',
      },
      {
        scope: SCOPE_SPACES,
        available: unavailable === null,
        ...(unavailable !== null ? { unavailable } : {}),
        summary:
          'Proves who you are and grants this app a credential to read your profile and to ' +
          'read posts as you, upvote, and comment in the spaces you choose.',
      },
    ],
    api: {
      host: API_HOST,
      // Per option, because the action tokens are what each one asks for and
      // the RESOURCE is no longer a fact this endpoint can state: a
      // space-addressed grant's resources are decided at consent, and printing
      // one here would be printing the ask as if it were the answer.
      options: {
        [SCOPE_API]: { actions: API_ACTIONS },
        [SCOPE_SPACES]: { actions: SPACES_ACTIONS },
      },
    },
    // The space this demo reads posts from, in both id forms, because they are
    // used in different places and neither is derivable from the other by a
    // reader who has only seen one of them.
    space: {
      id: DEMO_SPACE_ID,
      did: DEMO_SPACE_DID,
      name: DEMO_SPACE_NAME,
    },
    app: {
      ...(APP_DID !== null ? { did: APP_DID } : {}),
      ...(APP_PUBLIC_KEY_MULTIBASE !== null
        ? { publicKeyMultibase: APP_PUBLIC_KEY_MULTIBASE }
        : {}),
    },
  });
}
