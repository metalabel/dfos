/*

  The backend's shared parts: the seal, the cookies, and this request's origin.

  THE SEAL IS THE REPLAY DEFENSE. specs/SIWD.md §Replay prevention admits two
  disciplines, and which one you owe is decided by WHAT SUCCESS GRANTS. This
  demo grants exactly one thing — a session with the browser that is standing
  here — so it runs the FLOW-BOUND discipline: at mint time the server binds the
  nonce to the agent that started the flow, statelessly, by sealing it under a
  key only this server holds and parking it in an httpOnly cookie that expires
  with the acceptance window. At verification the server recovers its
  expectation from that seal and nowhere else.

  A BARE COOKIE WOULD BE THE TRAP IN A COSTUME. Cookies are presenter-supplied
  on every request: an attacker holding a captured JWS reads the nonce straight
  out of the payload and sends it back in a Cookie header of their own —
  `HttpOnly` constrains a browser's scripts, not curl. What makes this bind is
  that the value carries an HMAC only this server's key can produce, so the
  expectation is recoverable only from the server's own prior act of minting it.

  AND THE GUARANTEE IS EXACTLY THIS, no more: the artifact redeems only through
  the channel that started the flow, inside the timestamp window. It is NOT
  global single-use — a party holding both the artifact and the cookie jar can
  redeem again within the window, and that is the accepted trade, because a
  party holding the cookie jar already holds the session they would gain. The
  moment success grants anything portable — a credential scope, a token
  redeemable elsewhere, profile B — this discipline is no longer admissible and
  `verifySiwd`'s `consumeNonce` is. The README says where that line is.

*/

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { VercelRequest, VercelResponse } from './_types';

// deployment coordinates — edit these when forking the demo
export const AUTHORIZE_URL = 'https://app.dfos.com/authorize';
export const RELAY_URL = 'https://relay.dfos.com';

/** Consent-screen prose. The host renders it as the app's own words. */
export const STATEMENT = 'Sign in to the SIWD demo';

/** The only scope SIWD implements today, and the only one flow-binding covers. */
export const SCOPE = 'identity';

/** The sealed nonce, in flight between the redirect out and the callback back. */
export const FLIGHT_COOKIE = 'siwd_flight';

/** The sealed session this backend mints once verification passes. */
export const SESSION_COOKIE = 'siwd_session';

/**
 * Matched to `verifySiwd`'s default acceptance window: the cookie stops being
 * useful at the same moment a challenge minted alongside it would be refused as
 * stale, so there is exactly one expiry story rather than two that can disagree.
 */
export const FLIGHT_TTL_SECONDS = 300;

/** How long a verified sign-in is good for. One day, and no refresh dance. */
export const SESSION_TTL_SECONDS = 86_400;

/** A signed challenge is a few hundred bytes; anything near this is not one. */
const MAX_BODY_BYTES = 16 * 1024;

// -----------------------------------------------------------------------------
// the seal
// -----------------------------------------------------------------------------

/**
 * Set `SESSION_SECRET` to any long random string and sealed values survive
 * across instances and deploys. Left unset — the fork-and-deploy default, one
 * click and no configuration — the server mints a random key per cold start
 * rather than throwing, so the demo still runs and still runs the real
 * discipline. What it loses is durability: every session dies with the instance
 * that issued it, and a sign-in started on one instance cannot be completed on
 * another. That is a visible, explainable degradation rather than a silent
 * weakening, so every session-bearing response says `ephemeral: true` and the
 * page says so out loud.
 */
const configured = process.env['SESSION_SECRET'];
const SECRET = configured !== undefined && configured !== '' ? configured : randomBytes(32);

/** Whether this instance is running on a key nobody chose. Told to the UI. */
export const EPHEMERAL_SECRET = !(configured !== undefined && configured !== '');

const mac = (value: string): string =>
  createHmac('sha256', SECRET).update(value).digest('base64url');

/**
 * `value.mac`. Both halves are base64url, so the dot is an unambiguous
 * separator and the whole thing is a legal cookie value with no encoding hop.
 */
export const seal = (value: string): string => `${value}.${mac(value)}`;

/**
 * The inverse, or `null` — for a missing cookie, a malformed one, or a tag that
 * does not check out. Callers get one falsy answer for "this did not come from
 * me", because from the verifier's side those are the same fact.
 */
export const unseal = (sealed: string | undefined): string | null => {
  if (sealed === undefined || sealed === '') return null;
  const split = sealed.lastIndexOf('.');
  if (split < 0) return null;

  const value = sealed.slice(0, split);
  const presented = Buffer.from(sealed.slice(split + 1));
  const expected = Buffer.from(mac(value));
  // `timingSafeEqual` throws on a length mismatch, so the guard is required
  // before the comparison rather than merely polite.
  if (presented.length !== expected.length) return null;
  return timingSafeEqual(presented, expected) ? value : null;
};

// -----------------------------------------------------------------------------
// cookies
// -----------------------------------------------------------------------------

/** The first value of a possibly-repeated Node header. */
const headerValue = (value: string | string[] | undefined): string | undefined =>
  Array.isArray(value) ? value[0] : value;

/**
 * `Secure` is set even for local development: browsers treat http://localhost
 * as a secure context, so `npm run dev` still gets the cookie. `Path=/api`
 * keeps it off every static asset request, and `SameSite=Lax` still sends it on
 * the same-origin fetch the callback makes.
 */
const cookieFlags = `HttpOnly; Secure; SameSite=Lax; Path=/api`;

export const setCookie = (name: string, value: string, maxAgeSeconds: number): string =>
  `${name}=${value}; ${cookieFlags}; Max-Age=${maxAgeSeconds}`;

export const clearCookie = (name: string): string => `${name}=; ${cookieFlags}; Max-Age=0`;

/** Hand-rolled on purpose: a cookie parser is four lines, not a dependency. */
export const readCookie = (req: VercelRequest, name: string): string | undefined => {
  const header = headerValue(req.headers.cookie);
  if (header === undefined) return undefined;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return undefined;
};

// -----------------------------------------------------------------------------
// this request's origin
// -----------------------------------------------------------------------------

/** Hosts that ride the platform's loopback tier — and speak http, not https. */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);

export interface RequestOrigin {
  /** Scheme and authority, no trailing slash — what an `Origin` header holds. */
  origin: string;
  /** The bare hostname signed into the challenge and checked back out of it. */
  domain: string;
  /** The exact redirect target, trailing slash included. */
  redirectUri: string;
}

/**
 * Where this request thinks it arrived, derived rather than hardcoded so that a
 * fork on any domain works with no edit here — and so the domain the server
 * SIGNS into a challenge and the domain it CHECKS on the way back are the same
 * expression, which is the only way they cannot drift apart.
 *
 * The `Host` header is client-controllable in principle, and deriving from it
 * buys an attacker nothing: a forged host yields a self-consistent flow bound
 * to a domain whose well-known will not list the redirect, so the platform
 * refuses it — and anyone can construct that URL by hand anyway. What would be
 * dangerous is verifying a challenge for one domain against a cookie minted for
 * another, and a single derivation is what rules that out.
 */
export const requestOrigin = (req: VercelRequest): RequestOrigin | null => {
  const host = (headerValue(req.headers['x-forwarded-host']) ?? headerValue(req.headers.host))
    ?.trim()
    .toLowerCase();
  if (host === undefined || host === '') return null;

  // Parsed rather than string-sliced, so ports and IPv6 brackets are handled by
  // the URL grammar itself: `URL.hostname` brackets an IPv6 literal, and every
  // verifier compares the signed `domain` EXACTLY, so the challenge carries the
  // bare form the platform will compare against the redirect's host.
  let parsed: URL;
  try {
    parsed = new URL(`https://${host}/`);
  } catch {
    return null;
  }
  const hostname = parsed.hostname;
  const domain =
    hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;

  const proto = forwardedProto(req) ?? (LOOPBACK_HOSTS.has(domain) ? 'http' : 'https');
  const origin = `${proto}://${host}`;
  return { origin, domain, redirectUri: `${origin}/` };
};

/** `x-forwarded-proto` may be a comma-joined chain; only the first hop is ours. */
const forwardedProto = (req: VercelRequest): string | undefined => {
  const raw = headerValue(req.headers['x-forwarded-proto']);
  if (raw === undefined) return undefined;
  const first = raw.split(',')[0]?.trim().toLowerCase();
  return first === 'http' || first === 'https' ? first : undefined;
};

/**
 * CSRF, the cheap way. Every endpoint here is same-origin by construction, so a
 * present `Origin` that is not ours is a cross-site request and gets nothing.
 * An ABSENT one is allowed through: browsers attach it to every POST, so its
 * absence means a non-browser caller (curl, the smoke test) — which cannot be
 * riding a victim's cookie jar, since there is no victim in the loop. A present
 * `null` is not that case and is refused like any other foreign origin.
 */
export const originAllowed = (req: VercelRequest, self: RequestOrigin): boolean => {
  const origin = headerValue(req.headers.origin);
  return origin === undefined ? true : origin.trim().toLowerCase() === self.origin;
};

// -----------------------------------------------------------------------------
// the session
// -----------------------------------------------------------------------------

export interface Session {
  did: string;
  /** The DID URL of the key that signed the challenge. */
  kid: string;
  /** Issued-at and expiry, unix seconds. */
  iat: number;
  exp: number;
}

/**
 * The session rides in the cookie itself: base64url JSON under the same seal.
 * Zero server state is what keeps the demo forkable — any instance can answer
 * for a session any other instance issued, given the same `SESSION_SECRET`.
 *
 * The nonce is deliberately NOT in here. It was the secret the flight cookie
 * held, and echoing it back would hand the presenter the one value they were
 * never supposed to choose.
 */
export const encodeSession = (session: Session): string =>
  seal(Buffer.from(JSON.stringify(session)).toString('base64url'));

/** The session this request carries, or `null` — unsealed, parsed, unexpired. */
export const readSession = (req: VercelRequest): Session | null => {
  const value = unseal(readCookie(req, SESSION_COOKIE));
  if (value === null) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;

  const raw = parsed as Record<string, unknown>;
  if (typeof raw['did'] !== 'string' || typeof raw['kid'] !== 'string') return null;
  if (typeof raw['iat'] !== 'number' || typeof raw['exp'] !== 'number') return null;

  // The seal makes the cookie unforgeable, not immortal. `Max-Age` is the
  // browser's copy of the expiry and a non-browser keeps whatever it was given,
  // so the server checks the one that is actually inside the signed bytes.
  if (raw['exp'] * 1000 <= Date.now()) return null;

  return { did: raw['did'], kid: raw['kid'], iat: raw['iat'], exp: raw['exp'] };
};

// -----------------------------------------------------------------------------
// responses
// -----------------------------------------------------------------------------

/**
 * `ephemeral` is stamped onto EVERY JSON body rather than onto the ones that
 * carry a session, because it is a property of the deployment and the page
 * renders a persistent notice from it. Reported on failures too, or the notice
 * would blink out the moment anything went wrong — which is exactly when a fork
 * that forgot `SESSION_SECRET` most needs to be reading it.
 */
export const json = (
  res: VercelResponse,
  status: number,
  body: Record<string, unknown>,
  cookies?: string[],
): void => {
  res.setHeader('Content-Type', 'application/json');
  // nothing here is cacheable: a cached nonce is not a nonce, and a cached
  // session belongs to whoever the cache hands it to
  res.setHeader('Cache-Control', 'no-store');
  if (cookies !== undefined && cookies.length > 0) res.setHeader('Set-Cookie', cookies);
  res.status(status).send(JSON.stringify({ ...body, ephemeral: EPHEMERAL_SECRET }));
};

export const noContent = (res: VercelResponse, cookies?: string[]): void => {
  res.setHeader('Cache-Control', 'no-store');
  if (cookies !== undefined && cookies.length > 0) res.setHeader('Set-Cookie', cookies);
  res.status(204).send('');
};

export const methodNotAllowed = (res: VercelResponse, allow: string): void => {
  res.setHeader('Allow', allow);
  json(res, 405, { ok: false, reason: 'method not allowed' });
};

/**
 * The JWS out of a JSON body, or `null`. Vercel's Node runtime pre-parses a
 * JSON body onto `req.body`; the string branch covers a runtime that did not,
 * and the size cap is re-applied to whatever arrived on one path.
 */
export const readJws = (req: VercelRequest): string | null => {
  let body: unknown = req.body;
  if (typeof body === 'string') {
    if (body.length > MAX_BODY_BYTES) return null;
    try {
      body = JSON.parse(body);
    } catch {
      return null;
    }
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return null;
  const jws = (body as Record<string, unknown>)['jws'];
  if (typeof jws !== 'string' || jws === '' || jws.length > MAX_BODY_BYTES) return null;
  return jws;
};
