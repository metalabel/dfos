/*

  STEP 2 — the server verifies the signed challenge and grants the session.

  This runs where the grant happens, which is the whole reason it exists. A bare
  DID is an address, not a proof: no code path here takes a DID and believes it.

  The expectation NEVER comes from the request body. Which prior state it comes
  from is decided by what success is about to grant:

    identity       — the sealed flight cookie. Recovering it IS the flow-bound
                     check: the artifact redeems only through the channel that
                     started the flow.
    credential set — the shared store, spent by an atomic GETDEL. Success hands
                     back a credential that outlives this browser, so
                     specs/SIWD.md requires the artifact be retired globally, not
                     merely bound to a channel. `consumeNonce` is that one-field
                     difference.

  `verifySiwd` checks the nonce LAST (spec step 6), after the signature, the
  current-key resolution, the domain, and the timestamp window — same function,
  same order under both disciplines. Under flow-binding that ordering costs
  nothing; under `consumeNonce` it is what keeps an invalid presentation from
  spending a nonce its legitimate holder is still carrying.

  On the credential path there is a second artifact to answer for, and this file
  answers for it BEFORE storing it: a returned credential is verified in full and
  checked to say what this app actually asked for. An RP that files away an
  unverified grant has learned nothing from having a verifier.

*/

import { createClient } from '@metalabel/dfos-client';
import { verifySiwd } from '@metalabel/dfos-client/siwd';
import {
  CredentialVerificationError,
  matchesResource,
  verifyDFOSCredential,
} from '@metalabel/dfos-protocol/credentials';
import { KV_ERROR, kvGetDel, kvSet } from './_kv.js';
import {
  API_ACTION,
  API_RESOURCE,
  APP_DID,
  APP_KEY_ERROR,
  clearCookie,
  encodeSession,
  FLIGHT_COOKIE,
  FLIGHT_PURPOSE_CONSUMED,
  FLIGHT_PURPOSE_FLOW_BOUND,
  json,
  kvCredentialKey,
  kvNonceKey,
  methodNotAllowed,
  newSessionId,
  originAllowed,
  readCookie,
  readJsonBody,
  readTokenField,
  RELAY_URL,
  requestOrigin,
  SCOPE_API,
  SCOPE_IDENTITY,
  SECRET_ERROR,
  SESSION_COOKIE,
  SESSION_TTL_SECONDS,
  setCookie,
  unseal,
  type CredentialFacts,
} from './_lib.js';
import type { VercelRequest, VercelResponse } from './_types.js';

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
  if (SECRET_ERROR !== null) {
    json(res, 500, { ok: false, reason: SECRET_ERROR });
    return;
  }

  // 1. Recover the expectation FIRST. No sign-in in flight means there is
  //    nothing to grant, so refuse before touching the JWS. This is a grant
  //    guard, not an abuse guard: anyone can mint themselves a flight via
  //    /api/login, but nobody can verify against a seal this server did not
  //    produce.
  //
  //    The cookie is tried under BOTH purposes, and the one that unseals names
  //    the discipline. The MAC is domain-separated per purpose, so this is not a
  //    label the presenter gets to choose: a credential flight cannot be
  //    downgraded into the weaker check by editing a cookie.
  const cookie = readCookie(req, FLIGHT_COOKIE);
  const flowBoundNonce = unseal(FLIGHT_PURPOSE_FLOW_BOUND, cookie);
  const consumedMarker = unseal(FLIGHT_PURPOSE_CONSUMED, cookie);
  if (flowBoundNonce === null && consumedMarker === null) {
    json(res, 401, { ok: false, reason: 'no sign-in in flight (or it expired)' }, [
      clearCookie(FLIGHT_COOKIE),
    ]);
    return;
  }
  const scope = consumedMarker !== null ? SCOPE_API : SCOPE_IDENTITY;

  const body = readJsonBody(req);
  const jws = readTokenField(body, 'jws');
  if (jws === null) {
    json(res, 400, { ok: false, reason: 'body must be JSON with a `jws` string' }, [
      clearCookie(FLIGHT_COOKIE),
    ]);
    return;
  }
  // Present only on the credential path; the browser reads it out of the
  // callback's URL fragment and posts it here, where the key that could exercise it
  // actually lives.
  const credential = readTokenField(body, 'credential');
  if (scope === SCOPE_API && credential === null) {
    json(
      res,
      400,
      {
        ok: false,
        reason:
          'this sign-in asked for a credential scope, so the callback should have carried a ' +
          'credential — none arrived',
      },
      [clearCookie(FLIGHT_COOKIE)],
    );
    return;
  }

  // 2. Deployment configuration, checked BEFORE any verification runs — because
  //    verification on this path SPENDS the nonce, and a misconfigured server
  //    must not burn a user's one-shot challenge only to answer 500. The window
  //    is small (a redeploy between the redirect out and the callback back) but
  //    the cost is a sign-in the user cannot retry with the artifact in hand.
  if (scope === SCOPE_API && (APP_KEY_ERROR !== null || APP_DID === null)) {
    json(res, 500, { ok: false, reason: APP_KEY_ERROR }, [clearCookie(FLIGHT_COOKIE)]);
    return;
  }
  if (scope === SCOPE_API && KV_ERROR !== null) {
    json(res, 500, { ok: false, reason: KV_ERROR }, [clearCookie(FLIGHT_COOKIE)]);
    return;
  }

  // 3. The verification itself: resolve the signer's identity chain from a
  //    public relay, replay it to CURRENT state, and accept only a key that is
  //    still an authKey of a non-deleted identity. No DFOS platform server is
  //    contacted; the relay is untrusted and the crypto is what convinces us.
  //    `verifySiwd` is no-throw — the relay hop, the decode, and every check
  //    share one result channel — so its error string is what the page gets.
  //
  //    `consumeNonce` can fail two different ways, and they are not the same
  //    verdict. "The store answered, and this nonce is not outstanding" is the
  //    caller's problem — an invalid or replayed presentation, a 401. "The store
  //    did not answer at all" is the SERVER's condition and must not be reported
  //    as a judgment about the artifact; that is a 503, the same classification
  //    `api/login.ts` and `api/profile.ts` already use for an unreachable
  //    dependency. `verifySiwd` is no-throw and collapses both into one refusal,
  //    so the outage is recorded here and re-read below.
  //
  //    Held on an object rather than a bare `let` because the assignment happens
  //    inside a closure the compiler cannot see run.
  const store: { failure: Error | null } = { failure: null };
  const client = createClient({ relays: [RELAY_URL] });
  const result = await verifySiwd(client, jws, {
    domain: self.domain,
    // The one-field difference between the two disciplines, and the reason the
    // kit puts the nonce check last: an atomic GETDEL either returns the value
    // this server minted — retiring it for everyone — or answers null, and a
    // presentation that failed any earlier check never reaches it.
    ...(scope === SCOPE_API
      ? {
          consumeNonce: async (nonce: string): Promise<boolean> => {
            try {
              return (await kvGetDel(kvNonceKey(nonce))) !== null;
            } catch (err) {
              // Refuse either way — the consumed discipline fails CLOSED, and a
              // consume this server could not confirm is one it must not treat
              // as having succeeded.
              store.failure = err instanceof Error ? err : new Error(String(err));
              return false;
            }
          },
        }
      : { nonce: flowBoundNonce as string }),
  });

  if (store.failure !== null) {
    json(
      res,
      503,
      {
        ok: false,
        reason: `could not spend the sign-in nonce: ${store.failure.message}`,
      },
      [clearCookie(FLIGHT_COOKIE)],
    );
    return;
  }
  if (!result.ok || result.value === undefined) {
    json(res, 401, { ok: false, reason: result.error ?? 'verification failed' }, [
      clearCookie(FLIGHT_COOKIE),
    ]);
    return;
  }

  const { did, kid, timestamp } = result.value;

  // 4. On the credential path, answer for the second artifact too — before it is
  //    stored, and before any session exists that could exercise it.
  let facts: CredentialFacts | null = null;
  if (scope === SCOPE_API && APP_DID !== null) {
    const checked = await checkCredential(client, credential as string, did, APP_DID);
    if ('error' in checked) {
      json(res, 400, { ok: false, reason: checked.error }, [clearCookie(FLIGHT_COOKIE)]);
      return;
    }
    facts = checked.facts;
  }

  // 5. Granted. The flight cookie is cleared in the same response that mints the
  //    session, and the JWS is discarded: a signed challenge is a one-shot
  //    authentication proof, not a bearer token. The CREDENTIAL is not discarded
  //    — it is the durable half of what the user granted, and holding it is the
  //    point.
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + SESSION_TTL_SECONDS;
  const sid = facts !== null ? newSessionId() : undefined;

  if (facts !== null && sid !== undefined) {
    try {
      await kvSet(
        kvCredentialKey(sid),
        JSON.stringify({ jws: credential, facts }),
        SESSION_TTL_SECONDS,
      );
    } catch (err) {
      json(
        res,
        503,
        {
          ok: false,
          reason: `verified, but the credential could not be stored: ${err instanceof Error ? err.message : String(err)}`,
        },
        [clearCookie(FLIGHT_COOKIE)],
      );
      return;
    }
  }

  json(res, 200, { ok: true, did, kid, timestamp, scope }, [
    clearCookie(FLIGHT_COOKIE),
    setCookie(
      SESSION_COOKIE,
      encodeSession({ did, kid, iat, exp, scope, ...(sid !== undefined ? { sid } : {}) }),
      SESSION_TTL_SECONDS,
    ),
  ]);
}

/**
 * Verify a returned credential in full, then check it is the grant this app
 * asked for and can actually use. The four questions, in the order they matter:
 *
 *   1. Is it a valid, unexpired DFOS credential, signed by a current key of the
 *      identity chain it names? (`verifyDFOSCredential` — signature, schema, CID
 *      integrity, expiry at read time.)
 *   2. Did the person who just signed in issue it? Otherwise the callback
 *      delivered somebody else's grant.
 *   3. Is THIS app the audience? A credential audienced elsewhere is one this
 *      app's key can never produce a request proof for.
 *   4. Does it cover the resource and action that were requested?
 *
 * Revocation is deliberately NOT checked here, and that is a considered
 * omission rather than a gap. API-AUTH.md puts revocation in the VERIFY path —
 * the API re-checks it on every request against its own current knowledge, which
 * is what gives the user a timely lever. A check at receipt would be a snapshot
 * of a fact that changes afterwards, and caching its answer would be worse than
 * not asking.
 */
const checkCredential = async (
  client: ReturnType<typeof createClient>,
  credential: string,
  signerDID: string,
  appDID: string,
): Promise<{ facts: CredentialFacts } | { error: string }> => {
  const { resolveIdentity } = client.callbacks();

  let verified;
  try {
    verified = await verifyDFOSCredential(credential, { resolveIdentity });
  } catch (err) {
    if (err instanceof CredentialVerificationError) {
      return { error: `the returned credential did not verify: ${err.message}` };
    }
    return {
      error: `the returned credential could not be checked: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  // This demo asks for the one credential SIWD's API scope set mints: a
  // single hop, issued by the user directly. A delegated chain is perfectly
  // legal protocol — it is just not what this flow produces, and walking one
  // correctly means `verifyDelegationChain`, not this function.
  if (verified.prf.length > 0) {
    return {
      error:
        'the returned credential carries a delegation chain; this demo expects the ' +
        'single-hop credential the API scope set mints',
    };
  }
  if (verified.iss !== signerDID) {
    return { error: 'the returned credential was not issued by the identity that just signed in' };
  }
  if (verified.aud !== appDID) {
    return {
      error: `the returned credential is audienced to ${verified.aud}, not to this app (${appDID}) — this app’s key could never prove possession of it`,
    };
  }
  if (!(await matchesResource(verified.att, API_RESOURCE, API_ACTION))) {
    return { error: `the returned credential does not cover ${API_ACTION} on ${API_RESOURCE}` };
  }

  return {
    facts: {
      issuer: verified.iss,
      audience: verified.aud,
      resource: API_RESOURCE,
      action: API_ACTION,
      issuedAt: verified.iat,
      expiresAt: verified.exp,
      credentialCID: verified.credentialCID,
    },
  };
};
