/*

  TIER 2, STEP 2 — the backend verifies the signed challenge.

  This is the endpoint that makes the trust ladder real. It runs the SAME
  `verifySiwd` the browser tier runs, in Node, where a session would actually be
  granted. Three rules it does not bend:

  1. THE NONCE COMES FROM THE COOKIE, NEVER THE BODY. The request body carries
     exactly one thing — the JWS. Reading an expected nonce from the presenter
     would turn the replay guard into a self-comparison.
  2. THE NONCE IS SINGLE USE, PASS OR FAIL. The clearing Set-Cookie is built
     before anything else can go wrong and rides on every response below, so a
     failed attempt burns the nonce exactly like a successful one.
  3. A BARE DID IS NEVER ACCEPTED. There is no code path here that takes a DID
     and believes it. A DID is an address; anyone can type one. Only a signature
     over a nonce this backend minted proves anybody is anybody.

  What it deliberately does NOT do: mint a session. That needs a signing secret,
  which would break zero-config fork-and-deploy — and verification is the lesson
  here. The response says where your own session mint belongs.

*/

import { createClient } from '@metalabel/dfos-client';
import { verifySiwd } from '@metalabel/dfos-client/siwd';

const NONCE_COOKIE = 'siwd_nonce';

/** The public relay this backend resolves identity chains through. */
const RELAY_URL = 'https://relay.dfos.com';

/**
 * The one deployed host this demo answers for. Vercel routes by Host, so the
 * header is trustworthy here — but pinning it keeps a COPIED deployment (a
 * fork on someone else's domain) from silently verifying challenges bound to a
 * domain it does not serve. The browser half needs no such constant: it reads
 * `location.hostname`, which is the same fact with no opportunity to drift.
 */
const PRODUCTION_HOST = 'dfos-siwd-demo.vercel.app';

/** `vercel dev` — the local equivalents of the deployed host. */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);

/** A signed challenge is a few hundred bytes; anything near this is not one. */
const MAX_BODY_BYTES = 16 * 1024;

/**
 * The nonce cookie, expired. Built once and attached to every response from the
 * moment the cookie is read, so there is no code path where a nonce survives an
 * attempt to use it.
 */
const CLEAR_NONCE_COOKIE = `${NONCE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/api; Max-Age=0`;

const json = (status: number, body: unknown, clearNonce = true): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      ...(clearNonce ? { 'Set-Cookie': CLEAR_NONCE_COOKIE } : {}),
    },
  });

/** Hand-rolled on purpose: a cookie parser is four lines, not a dependency. */
const readCookie = (header: string | null, name: string): string | undefined => {
  if (header === null) return undefined;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return undefined;
};

/** The hostname out of a Host header, brackets and port stripped. */
const hostnameOf = (host: string): string => {
  const lower = host.toLowerCase().trim();
  if (lower.startsWith('[')) {
    const end = lower.indexOf(']');
    return end < 0 ? lower : lower.slice(1, end);
  }
  const colon = lower.indexOf(':');
  return colon < 0 ? lower : lower.slice(0, colon);
};

/** The domain this request may verify for, or undefined if it is not ours. */
const expectedDomain = (request: Request): string | undefined => {
  const host = request.headers.get('host');
  if (host === null) return undefined;
  const hostname = hostnameOf(host);
  if (hostname === PRODUCTION_HOST || LOOPBACK_HOSTS.has(hostname)) return hostname;
  return undefined;
};

export default async function handler(request: Request): Promise<Response> {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ ok: false, error: 'method not allowed' }), {
      status: 405,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        Allow: 'POST',
      },
    });
  }

  // 1. The nonce, from the cookie and nowhere else. No cookie means there is
  //    nothing to verify against — refuse BEFORE touching the JWS, so a caller
  //    cannot use this endpoint as a free signature oracle.
  const nonce = readCookie(request.headers.get('cookie'), NONCE_COOKIE);
  if (nonce === undefined || nonce === '') {
    return json(400, {
      ok: false,
      error: 'no nonce in flight — start at /api/nonce',
    });
  }

  // 2. From here on every response clears the cookie: single use, pass or fail.

  const domain = expectedDomain(request);
  if (domain === undefined) {
    return json(400, {
      ok: false,
      error: 'this deployment does not verify for that host',
    });
  }

  const declaredLength = Number(request.headers.get('content-length') ?? '0');
  if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
    return json(413, { ok: false, error: 'request body too large' });
  }

  let jws: string;
  try {
    const raw = await request.text();
    if (raw.length > MAX_BODY_BYTES) {
      return json(413, { ok: false, error: 'request body too large' });
    }
    const body = JSON.parse(raw) as { jws?: unknown };
    if (typeof body.jws !== 'string' || body.jws === '') {
      return json(400, { ok: false, error: 'body must be JSON with a `jws` string' });
    }
    jws = body.jws;
  } catch {
    return json(400, { ok: false, error: 'body must be JSON with a `jws` string' });
  }

  // 3. The same function the browser tier calls — same rules, same relay, now
  //    running where a grant would actually be made.
  const client = createClient({ relays: [RELAY_URL] });
  let result;
  try {
    result = await verifySiwd(client, jws, { domain, nonce });
  } catch (err) {
    return json(502, {
      ok: false,
      error: `could not reach ${RELAY_URL}: ${err instanceof Error ? err.message : String(err)}`,
    });
  }

  if (!result.ok || result.value === undefined) {
    return json(401, { ok: false, error: result.error ?? 'verification failed' });
  }

  // Only these four fields. The session also carries the nonce — which is the
  // secret the cookie was holding, and echoing it back would hand the presenter
  // the very value they were never supposed to choose — and the requester's
  // `statement`, which this demo does not render anywhere.
  const { did, domain: signedDomain, timestamp, kid } = result.value;
  return json(200, {
    ok: true,
    session: { did, domain: signedDomain, timestamp, kid },
    note: 'verification ran server-side; a real app mints its session cookie here.',
  });
}
