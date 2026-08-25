/*

  STEP 1 — the server mints the challenge and remembers what it minted.

  The nonce is minted here and remembered before the browser is told where to go,
  because the party presenting a signed challenge must never get to tell the
  verifier which nonce to expect. `/api/verify` recovers its expectation from
  what this file wrote and nothing else.

  WHERE it is remembered depends on the scope, and that is the whole point of
  the toggle:

    identity     — sealed into an httpOnly cookie. Success grants a session with
                   this browser, so the flow-bound discipline is admissible, and
                   the seal is what binds the redemption to this channel.
    read:profile — written to the shared store. Success also hands back a
                   CREDENTIAL, which is portable and outlives this browser, so
                   specs/SIWD.md requires the consumed discipline: the nonce must
                   be spendable exactly once, globally, by an atomic delete that
                   no second presentation can win.

  Minting here also means the server's clock authors the timestamp. A browser
  whose clock is minutes off produced challenges that were born stale or born in
  the future, which a correct verifier refused — a sign-in that looked fine and
  never completed. Server clocks are NTP-disciplined, so that failure mode goes
  away.

*/

import { createSiwdLoginRequest } from '@metalabel/dfos-client/siwd';
import { KV_ERROR, kvSet } from './_kv.js';
import {
  APP_DID,
  APP_KEY_ERROR,
  AUTHORIZE_URL,
  FLIGHT_COOKIE,
  FLIGHT_PURPOSE_CONSUMED,
  FLIGHT_PURPOSE_FLOW_BOUND,
  FLIGHT_TTL_SECONDS,
  isLoopbackDomain,
  isScope,
  json,
  kvNonceKey,
  methodNotAllowed,
  originAllowed,
  readJsonBody,
  requestOrigin,
  SCOPE_IDENTITY,
  SCOPE_READ_PROFILE,
  seal,
  SECRET_ERROR,
  setCookie,
  STATEMENT,
} from './_lib.js';
import type { VercelRequest, VercelResponse } from './_types.js';

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  if (req.method !== 'POST') {
    methodNotAllowed(res, 'POST');
    return;
  }

  // A deployment without a usable secret cannot mint a seal `/api/verify` could
  // unseal (see _lib.ts), so refuse here, by name, instead of letting the
  // sign-in die three redirects later as a mystery.
  if (SECRET_ERROR !== null) {
    json(res, 500, { ok: false, reason: SECRET_ERROR });
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

  const requested = readJsonBody(req)?.['scope'] ?? SCOPE_IDENTITY;
  if (!isScope(requested)) {
    json(res, 400, {
      ok: false,
      reason: `unknown scope: this demo asks for identity or read:profile`,
    });
    return;
  }

  // The credential scope's preconditions, checked BEFORE the redirect — each
  // would otherwise surface as a refusal at the host or a dead end on the way
  // back. Ordered the same way `/api/config` reports them, so a direct caller
  // and the page are told the same thing first: the domain rule leads, because
  // it is the one no environment variable can fix.
  if (requested === SCOPE_READ_PROFILE) {
    if (isLoopbackDomain(self.domain)) {
      json(res, 400, {
        ok: false,
        reason:
          'loopback redirects support scope=identity only — a local port holds no domain, ' +
          'so it can prove no client_did, and a credential has to be issued to someone',
      });
      return;
    }
    // specs/SIWD.md: `client_did` is REQUIRED for every credential-returning
    // scope, because a credential is issued TO a named DID. No key, no DID to
    // issue to, no scope.
    if (APP_KEY_ERROR !== null || APP_DID === null) {
      json(res, 500, { ok: false, reason: APP_KEY_ERROR });
      return;
    }
    // No store, no consumed discipline — and the consumed discipline is not
    // optional on this path, so this is a refusal rather than a downgrade.
    if (KV_ERROR !== null) {
      json(res, 500, { ok: false, reason: KV_ERROR });
      return;
    }
  }

  // `domain` and `redirectUri` come from ONE derivation of this request's own
  // origin, so the string signed into the challenge and the string the platform
  // exact-matches against `redirect_uris` cannot drift apart. `client_did` rides
  // along only on the credential scope: at identity scope the platform learns
  // who this app is from the well-known at the redirect's own origin, and there
  // is no returned credential for the DID to be the `aud` of.
  let request: ReturnType<typeof createSiwdLoginRequest>;
  try {
    request = createSiwdLoginRequest({
      authorizeUrl: AUTHORIZE_URL,
      domain: self.domain,
      redirectUri: self.redirectUri,
      scope: requested,
      statement: STATEMENT,
      ...(requested === SCOPE_READ_PROFILE && APP_DID !== null ? { clientDid: APP_DID } : {}),
    });
  } catch (err) {
    // The kit refuses a credential scope over a loopback redirect, because a
    // local port can prove no `client_did` and so can never receive a
    // credential. Its message says exactly that; pass it through rather than
    // inventing a second wording for the same rule.
    json(res, 400, {
      ok: false,
      reason: err instanceof Error ? err.message : 'could not build the sign-in request',
    });
    return;
  }

  if (requested === SCOPE_READ_PROFILE) {
    // Written BEFORE the redirect, and a failure here refuses the sign-in: the
    // consumed discipline fails closed, since a nonce this server did not record
    // is one it could never retire.
    try {
      await kvSet(kvNonceKey(request.expect.nonce), '1', FLIGHT_TTL_SECONDS);
    } catch (err) {
      json(res, 503, {
        ok: false,
        reason: `could not record the sign-in nonce: ${err instanceof Error ? err.message : String(err)}`,
      });
      return;
    }

    // The cookie carries no expectation on this path — the store holds that.
    // It records only WHICH discipline the callback owes, sealed so the
    // presenter cannot relabel a credential flight as the weaker kind.
    json(res, 200, { url: request.url, scope: requested }, [
      setCookie(
        FLIGHT_COOKIE,
        seal(FLIGHT_PURPOSE_CONSUMED, SCOPE_READ_PROFILE, FLIGHT_TTL_SECONDS),
        FLIGHT_TTL_SECONDS,
      ),
    ]);
    return;
  }

  // Identity scope: the nonce leaves in two places — in the clear inside the
  // challenge the user's host will sign, and sealed under this server's key in a
  // cookie the browser carries back.
  json(res, 200, { url: request.url, scope: requested }, [
    setCookie(
      FLIGHT_COOKIE,
      seal(FLIGHT_PURPOSE_FLOW_BOUND, request.expect.nonce, FLIGHT_TTL_SECONDS),
      FLIGHT_TTL_SECONDS,
    ),
  ]);
}
