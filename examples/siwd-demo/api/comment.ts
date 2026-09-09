/*

  The write with a body, and the one place this demo replays a proof on purpose.

  Two paths through one route, and they differ in exactly one thing: who mints
  the `jti`.

  THE NORMAL PATH goes through `signedFetch`, like every other write here.
  `createApiAuthFetch` mints a fresh unique id for each non-safe method, so two
  clicks of the button are two different proofs and both run.

  THE RESEND PATH EXISTS BECAUSE THAT ADAPTER CANNOT DEMONSTRATE A REPLAY. A
  replay is not a second request that looks the same — it is THE SAME PROOF
  presented again, and an adapter that mints per call can never produce one. So
  this path signs by hand exactly once, with an explicit `jti`, and sends the
  byte-identical request twice with a plain `fetch`: same method, same target,
  same body octets, same Authorization header. The first runs. The second is the
  API refusing to run a proof it has already seen inside its freshness window,
  and its answer is passed through verbatim rather than translated into
  something calmer.

  That is the guarantee worth seeing rather than reading: a client whose request
  times out does not know whether the write landed, and retrying blind is how a
  timeout becomes two comments. The `jti` is what makes the retry safe to refuse
  and the state safe to re-read.

  THE BODY OCTETS ARE COMPOSED ONCE, above both paths, and both the hash inside
  the proof and the bytes on the wire come from that one array. A body
  serialized twice is two chances to differ by a byte, and the proof covers a
  hash of exactly what goes out. The media type is pinned to `application/json`
  and nothing else touches the body path: no compression, no method override, no
  second serialization.

  THE CONFUSED-DEPUTY RULE holds as it does everywhere here. The slots are a
  space id, a post id, and the comment text; the method, the target template, and
  the media type are written in this file.

*/

import { buildApiAuthHeaders, generateJti, signApiRequest } from '@metalabel/dfos-client/api-auth';
import { openGatedSession, sendApiRefusal, signedFetch } from './_gated.js';
import {
  API_HOST,
  DEMO_SPACE_ID,
  json,
  POST_ID_RE,
  readJsonBody,
  signAsApp,
  SPACE_ID_RE,
  spaceDid,
} from './_lib.js';
import type { VercelRequest, VercelResponse } from './_types.js';

/** What the API accepts, refused here first so the message names the field. */
const MIN_COMMENT_CHARS = 1;
const MAX_COMMENT_CHARS = 2000;

/** One send's outcome, whichever way it went. */
interface Attempt {
  status: number;
  /** The 2xx body. */
  comment?: unknown;
  /** The non-2xx body, verbatim. */
  error?: unknown;
}

const attempt = async (response: Response): Promise<Attempt> => {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  const status = response.status;
  if (body === undefined) return { status };
  return response.ok ? { status, comment: body } : { status, error: body };
};

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const gated = await openGatedSession(req, res);
  if (gated === null) return;

  const raw = readJsonBody(req);

  const askedSpace = raw?.['space'];
  if (
    askedSpace !== undefined &&
    (typeof askedSpace !== 'string' || !SPACE_ID_RE.test(askedSpace))
  ) {
    json(res, 400, {
      ok: false,
      reason: 'name one space by its bare 31-character id, or send no space at all',
    });
    return;
  }
  const space = typeof askedSpace === 'string' ? askedSpace : DEMO_SPACE_ID;

  const post = raw?.['post'];
  if (typeof post !== 'string' || !POST_ID_RE.test(post)) {
    json(res, 400, { ok: false, reason: 'name one post by its id — post_ followed by its digits' });
    return;
  }

  const written = raw?.['body'];
  const text = typeof written === 'string' ? written.trim() : '';
  if (text.length < MIN_COMMENT_CHARS || text.length > MAX_COMMENT_CHARS) {
    json(res, 400, {
      ok: false,
      reason: `a comment is between ${MIN_COMMENT_CHARS} and ${MAX_COMMENT_CHARS} characters once trimmed`,
    });
    return;
  }

  const resend = raw?.['resend'];
  if (resend !== undefined && typeof resend !== 'boolean') {
    json(res, 400, { ok: false, reason: '`resend` is a boolean when it is present at all' });
    return;
  }

  const path = `/v1/spaces/${spaceDid(space)}/posts/${post}/comments`;
  const url = `https://${API_HOST}${path}`;

  // ONCE. Both the proof's body hash and the bytes on the wire read this array.
  const payload = new TextEncoder().encode(JSON.stringify({ body: text }));

  if (resend !== true) {
    const signed = signedFetch(gated.held, gated.kid);

    let response: Response;
    try {
      response = await signed(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload,
      });
    } catch (err) {
      json(res, 502, {
        ok: false,
        reason: `the API call did not complete: ${err instanceof Error ? err.message : String(err)}`,
      });
      return;
    }

    const outcome = await attempt(response);
    if (outcome.comment === undefined) {
      sendApiRefusal(res, outcome.status, outcome.error);
      return;
    }
    json(res, 200, { ok: true, host: API_HOST, comment: outcome.comment });
    return;
  }

  // The demonstration. One signature, one `jti`, two sends.
  let headers: Record<string, string>;
  try {
    const { proof } = await signApiRequest({
      method: 'POST',
      host: API_HOST,
      path,
      body: payload,
      credentialCID: gated.held.facts.credentialCID,
      kid: gated.kid,
      sign: signAsApp,
      // Explicit, because the point is that BOTH sends carry this exact value.
      jti: generateJti(),
    });
    headers = {
      ...buildApiAuthHeaders({ proof, credential: gated.held.jws }),
      'Content-Type': 'application/json',
    };
  } catch (err) {
    json(res, 500, {
      ok: false,
      reason: `could not sign the request: ${err instanceof Error ? err.message : String(err)}`,
    });
    return;
  }

  // Sequential, not parallel: the second send has to arrive after the first has
  // been recorded, or the race decides the answer instead of the rule.
  let first: Attempt;
  let second: Attempt;
  try {
    first = await attempt(await fetch(url, { method: 'POST', headers, body: payload }));
    second = await attempt(await fetch(url, { method: 'POST', headers, body: payload }));
  } catch (err) {
    json(res, 502, {
      ok: false,
      reason: `the API call did not complete: ${err instanceof Error ? err.message : String(err)}`,
    });
    return;
  }

  // `ok: true` even when the second send is refused, because the refusal IS the
  // answer this route was asked for. Reporting it as a failure would teach the
  // reader that a working replay guard is an error condition.
  json(res, 200, { ok: true, host: API_HOST, first, resend: second });
}
