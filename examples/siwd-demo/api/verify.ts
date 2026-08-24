/*

  TIER 2, STEP 2 — the backend verifies the signed challenge.

  This is the endpoint that makes the trust ladder real. It runs the SAME
  `verifySiwd` the browser tier runs, in Node, where a session would actually be
  granted. Two rules it does not bend:

  1. THE NONCE COMES FROM THE COOKIE, NEVER THE BODY. The request body carries
     exactly one thing — the JWS. An endpoint that reads its expectation out of
     the request it is checking has checked nothing.
  2. A BARE DID IS NEVER ACCEPTED. There is no code path here that takes a DID
     and believes it. A DID is an address; anyone can type one. Only a signature
     over a challenge this backend's nonce went into proves anybody is anybody.

  WHAT THE COOKIE IS, AND IS NOT. It is how this backend REMEMBERS, across the
  redirect, which nonce it minted — a carrier for its own state, nothing more.
  It is NOT a replay defense, and this file used to imply otherwise. The nonce
  travels inside the signed challenge, so anyone holding a JWS can read it
  straight out of the payload and, as a plain HTTP client, send it back in a
  Cookie header of their own; `HttpOnly` constrains a browser's scripts, not
  curl. Clearing the cookie on the way out is hygiene, not a control — a client
  that ignores `Set-Cookie` is unaffected.

  Real replay protection needs SERVER-SIDE SINGLE-USE CONSUMPTION, which is a
  store, which a zero-infrastructure demo deliberately does not run. specs/SIWD.md
  §Security Considerations is explicit that a third party MUST store the nonce
  server-side and reject an artifact whose nonce was already consumed. This demo
  does not do that, and so accepts replay bounded by the acceptance window. The
  `PRODUCTION` block at the verify call names the missing line and where it goes.

  It also does NOT mint a session: that needs a signing secret, which would break
  zero-config fork-and-deploy. The response says where your own session mint
  belongs.

*/

import { createClient } from '@metalabel/dfos-client';
import { verifySiwd } from '@metalabel/dfos-client/siwd';
import type { VercelRequest, VercelResponse } from './vercel';

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
 * The nonce cookie, expired. Attached to every response so a browser does not
 * carry a spent nonce into the next attempt — housekeeping for the honest
 * client, NOT a security control: a caller that ignores `Set-Cookie` keeps
 * whatever it had.
 */
const CLEAR_NONCE_COOKIE = `${NONCE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/api; Max-Age=0`;

const json = (res: VercelResponse, status: number, body: unknown, clearNonce = true): void => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  if (clearNonce) res.setHeader('Set-Cookie', CLEAR_NONCE_COOKIE);
  res.status(status).send(JSON.stringify(body));
};

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

/** The first value of a possibly-repeated Node header. */
const headerValue = (value: string | string[] | undefined): string | undefined =>
  Array.isArray(value) ? value[0] : value;

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
const expectedDomain = (req: VercelRequest): string | undefined => {
  const host = headerValue(req.headers.host);
  if (host === undefined) return undefined;
  const hostname = hostnameOf(host);
  if (hostname === PRODUCTION_HOST || LOOPBACK_HOSTS.has(hostname)) return hostname;
  return undefined;
};

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  if (req.method !== 'POST') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Allow', 'POST');
    res.status(405).send(JSON.stringify({ ok: false, error: 'method not allowed' }));
    return;
  }

  // 1. The nonce, from the cookie and nowhere else. No cookie means there is
  //    nothing to verify against — refuse BEFORE touching the JWS, so a caller
  //    cannot use this endpoint as a free signature oracle.
  const nonce = readCookie(headerValue(req.headers.cookie) ?? null, NONCE_COOKIE);
  if (nonce === undefined || nonce === '') {
    json(res, 400, {
      ok: false,
      error: 'no nonce in flight — start at /api/nonce',
    });
    return;
  }

  // 2. From here on every response clears the cookie, so an honest browser does
  //    not carry a spent nonce forward. See the header comment for why that is
  //    hygiene rather than a replay defense.

  const domain = expectedDomain(req);
  if (domain === undefined) {
    json(res, 400, {
      ok: false,
      error: 'this deployment does not verify for that host',
    });
    return;
  }

  const declaredLength = Number(headerValue(req.headers['content-length']) ?? '0');
  if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
    json(res, 413, { ok: false, error: 'request body too large' });
    return;
  }

  // Vercel's Node runtime pre-parses a JSON body into `req.body`; re-serialize
  // to re-apply the size cap and the shape guard on one path, whatever arrived.
  let jws: string;
  try {
    const raw = typeof req.body === 'string' ? req.body : JSON.stringify(req.body ?? '');
    if (raw.length > MAX_BODY_BYTES) {
      json(res, 413, { ok: false, error: 'request body too large' });
      return;
    }
    const body = (typeof req.body === 'string' ? JSON.parse(req.body) : req.body) as {
      jws?: unknown;
    };
    if (typeof body?.jws !== 'string' || body.jws === '') {
      json(res, 400, { ok: false, error: 'body must be JSON with a `jws` string' });
      return;
    }
    jws = body.jws;
  } catch {
    json(res, 400, { ok: false, error: 'body must be JSON with a `jws` string' });
    return;
  }

  // 3. The same function the browser tier calls — same rules, same relay, now
  //    running where a grant would actually be made.
  //
  //    PRODUCTION: MAKE THE NONCE SINGLE-USE HERE. This is the one line a real
  //    deployment adds and this demo cannot. Mint into a store at /api/nonce:
  //
  //      await store.set(nonce, '1', { EX: 300 });   // when you mint it
  //
  //    and atomically consume it here, BEFORE trusting the JWS:
  //
  //      const fresh = await store.getdel(nonce);    // Redis GETDEL, KV, a row
  //      if (!fresh) return json(401, { ok: false, error: 'nonce already used' });
  //
  //    THAT is what stops a captured JWS from being replayed inside its window
  //    — not the cookie. It has to be atomic (getdel, not get-then-delete) or
  //    two simultaneous replays both win the check. specs/SIWD.md
  //    §Security Considerations makes it a MUST for third parties; a demo with
  //    no infrastructure is the one place it is honest to skip it and say so.
  const client = createClient({ relays: [RELAY_URL] });
  let result;
  try {
    result = await verifySiwd(client, jws, {
      domain,
      nonce,
      // The acceptance window is the ONLY replay bound this demo has, so it is
      // worth being deliberate about — but it cannot simply be made small. It
      // is measured from the challenge's own timestamp, minted before the
      // redirect, so everything the user spends reading the consent screen is
      // already inside it. A host may legitimately sign a challenge near the
      // end of its own mint window; a window tight enough to feel strict here
      // would reject people who merely read carefully before approving.
      // SIWD.md's conventional ~5 minutes for this profile is that allowance,
      // and it is what `verifySiwd` defaults to. Stated explicitly rather than
      // inherited, because it is a security parameter and the reason it is not
      // smaller is not obvious.
      maxAgeSeconds: 300,
    });
  } catch (err) {
    json(res, 502, {
      ok: false,
      error: `could not reach ${RELAY_URL}: ${err instanceof Error ? err.message : String(err)}`,
    });
    return;
  }

  if (!result.ok || result.value === undefined) {
    json(res, 401, { ok: false, error: result.error ?? 'verification failed' });
    return;
  }

  // Only these four fields. The session also carries the nonce — which is the
  // secret the cookie was holding, and echoing it back would hand the presenter
  // the very value they were never supposed to choose — and the requester's
  // `statement`, which this demo does not render anywhere.
  const { did, domain: signedDomain, timestamp, kid } = result.value;
  json(res, 200, {
    ok: true,
    session: { did, domain: signedDomain, timestamp, kid },
    note: 'verification ran server-side; a real app mints its session cookie here.',
  });
}
