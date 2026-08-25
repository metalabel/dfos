/*

  The backend's shared parts: the seal, the cookies, and this request's origin.

  The seal is the replay defense. specs/SIWD.md §Replay prevention admits two
  disciplines, and which one you owe is decided by WHAT SUCCESS GRANTS. This
  demo grants one thing — a session with the browser standing here — so it runs
  the flow-bound discipline: at mint time the server seals the nonce under a key
  only it holds and parks it in an httpOnly cookie that expires with the
  acceptance window. At verification the expectation comes from that seal and
  nowhere else.

  A bare nonce cookie would not do. Cookies are presenter-supplied on every
  request: an attacker holding a captured JWS reads the nonce out of the payload
  and sends it back in a Cookie header of their own, since `HttpOnly` constrains
  a browser's scripts and not curl. The HMAC is what binds — only this server's
  key can produce it.

  The guarantee, exactly: the artifact redeems only through the channel that
  started the flow, inside the timestamp window. Not global single-use — a party
  holding both the artifact and the cookie jar can redeem again within the
  window, which is the accepted trade, since they already hold the session they
  would gain. The moment success grants anything portable — a credential scope,
  a token redeemable elsewhere, profile B — use `verifySiwd`'s `consumeNonce`
  instead. `api/_kv.ts` is where this demo does exactly that, for the one scope
  that earns it.

  This file also holds THE APP'S OWN SIGNING KEY. That is a second key of a
  different kind: the seal above is a secret this server keeps from everyone,
  while the app key is a DFOS identity key whose public half is published in an
  identity chain. It exists because a credential is issued TO someone, and
  spending one means proving you are that someone on every request.

*/

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { encodeEd25519Multikey } from '@metalabel/dfos-protocol/chain';
import {
  base64urlDecode,
  importEd25519Keypair,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import type { VercelRequest, VercelResponse } from './_types.js';

// deployment coordinates — edit these when forking the demo
export const AUTHORIZE_URL = 'https://app.dfos.com/authorize';
export const RELAY_URL = 'https://relay.dfos.com';

/**
 * The API host this demo spends its credential against. It is the `<host>` half
 * of the `api:<host>` resource string AND the `host` member of every request
 * proof, and specs/API-AUTH.md requires those to name the same origin — so it
 * is one constant here rather than two strings that could drift.
 */
export const API_HOST = 'api.dfos.com';

/** Consent-screen prose. The host renders it as the app's own words. */
export const STATEMENT = 'Sign in to the SIWD demo';

// -----------------------------------------------------------------------------
// scopes
// -----------------------------------------------------------------------------

/**
 * The two scopes this demo can ask for, and the whole reason it has a toggle.
 *
 *   identity     — proves who you are, and returns nothing else. Success grants
 *                  a session with the browser standing here, so specs/SIWD.md
 *                  admits the FLOW-BOUND replay discipline (the sealed cookie).
 *   read:profile — additionally returns a DFOS credential, which is portable and
 *                  outlives this browser, so the CONSUMED discipline is REQUIRED.
 *
 * The discipline is not a preference. It is decided by what success grants, and
 * the toggle exists so the reader can watch the same flow owe a different
 * obligation depending on which line they picked.
 */
export const SCOPE_IDENTITY = 'identity';
export const SCOPE_READ_PROFILE = 'read:profile';

export type Scope = typeof SCOPE_IDENTITY | typeof SCOPE_READ_PROFILE;

export const isScope = (value: unknown): value is Scope =>
  value === SCOPE_IDENTITY || value === SCOPE_READ_PROFILE;

/**
 * The wire scope string maps 1:1 to the credential's action token
 * (specs/SIWD.md → `read:profile`), so the string the user consented to and the
 * string the API verifier requires are the same string.
 */
export const API_ACTION = SCOPE_READ_PROFILE;

/** The credential's attenuation, as the API verifier byte-matches it. */
export const API_RESOURCE = `api:${API_HOST}`;

/** The sealed nonce, in flight between the redirect out and the callback back. */
export const FLIGHT_COOKIE = 'siwd_flight';

/**
 * ONE cookie, two seal purposes — and the purpose IS the record of which replay
 * discipline this flight owes, sealed so the presenter cannot pick.
 *
 *   'flight'            — identity scope. The sealed value is the NONCE, and the
 *                         cookie IS the expectation: recovering it is the whole
 *                         flow-bound check.
 *   'flight-credential' — read:profile. The sealed value is the SCOPE, a marker
 *                         and nothing more. The expectation lives in the KV
 *                         store and is spent there by an atomic GETDEL, because
 *                         under the consumed discipline the expectation must be
 *                         state the verifier can RETIRE — which a cookie handed
 *                         back by the presenter can never be.
 *
 * The tags are domain-separated (see `mac`), so a flight of one class cannot be
 * presented as the other: an attacker cannot downgrade a credential callback
 * into the weaker discipline by relabelling a cookie.
 */
export const FLIGHT_PURPOSE_FLOW_BOUND = 'flight';
export const FLIGHT_PURPOSE_CONSUMED = 'flight-credential';

/** The sealed session this backend mints once verification passes. */
export const SESSION_COOKIE = 'siwd_session';

/** Namespaces in the shared store, so the two uses never collide. */
export const kvNonceKey = (nonce: string): string => `siwd:nonce:${nonce}`;
export const kvCredentialKey = (sessionId: string): string => `siwd:credential:${sessionId}`;

/**
 * Matched to `verifySiwd`'s default acceptance window: the cookie stops being
 * useful at the same moment a challenge minted alongside it goes stale, so
 * there is one expiry rather than two that can disagree.
 */
export const FLIGHT_TTL_SECONDS = 300;

/** How long a verified sign-in is good for. One day, and no refresh dance. */
export const SESSION_TTL_SECONDS = 86_400;

/**
 * A signed challenge is a few hundred bytes and a single-hop credential about a
 * kilobyte; anything near this is neither. Well under the protocol's own 256 KiB
 * credential cap, deliberately — that cap is what the PROTOCOL accepts, and what
 * a given deployment accepts is its own, smaller, business.
 */
const MAX_BODY_BYTES = 16 * 1024;

// -----------------------------------------------------------------------------
// the seal
// -----------------------------------------------------------------------------

/**
 * Set `SESSION_SECRET` to any long random string (32+ characters) and sealed
 * values survive across instances and deploys.
 *
 * The random fallback is DEV-ONLY, and that matters: on Vercel every file in
 * api/ deploys as its own function with its own module instance and its own
 * `randomBytes`, so `/api/login` would seal with one key and `/api/verify`
 * would unseal with another. Every deployed sign-in would die as "no sign-in in
 * flight" while `npm run dev` — one process, one module graph — worked fine. So
 * deployed-without-a-secret is a named misconfiguration instead, and the random
 * key is reserved for the dev server, where a single process is guaranteed.
 */
const configured = process.env['SESSION_SECRET'];
const ON_VERCEL = process.env['VERCEL'] !== undefined;
const MIN_SECRET_CHARS = 32;

/** The named misconfiguration, or null. Checked by the seal-producing routes. */
export const SECRET_ERROR: string | null =
  configured === undefined || configured === ''
    ? ON_VERCEL
      ? 'SESSION_SECRET is not set — add it in your Vercel project settings ' +
        '(any long random string, 32+ characters), then redeploy'
      : null
    : configured.length < MIN_SECRET_CHARS
      ? `SESSION_SECRET must be at least ${MIN_SECRET_CHARS} characters — a short secret makes every cookie forgeable offline`
      : null;

const SECRET =
  configured !== undefined && configured !== '' && configured.length >= MIN_SECRET_CHARS
    ? configured
    : randomBytes(32);

/** Dev-server-only: running on a key nobody chose. Told to the UI. */
export const EPHEMERAL_SECRET =
  SECRET_ERROR === null && (configured === undefined || configured === '');

/**
 * The tag is domain-separated by PURPOSE, so a sealed value of one class cannot
 * be replayed as another: a session cookie presented as a flight cookie fails
 * its MAC even under the same key.
 */
const mac = (purpose: string, body: string): string =>
  createHmac('sha256', SECRET).update(`${purpose}:${body}`).digest('base64url');

/**
 * `value.exp.mac` — the expiry is INSIDE the sealed bytes, so the verifier's
 * clock enforces it. A cookie's `Max-Age` is only the honest browser's copy;
 * without this field a captured seal would stay valid forever. Every segment is
 * dot-free (base64url values, a decimal epoch), so the dots are unambiguous
 * separators and the whole thing is a legal cookie value.
 */
export const seal = (purpose: string, value: string, ttlSeconds: number): string => {
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const body = `${value}.${exp}`;
  return `${body}.${mac(purpose, body)}`;
};

/**
 * The inverse, or `null` — for a missing cookie, a malformed one, a tag that
 * does not check out, or a seal past its own expiry. One answer for all four,
 * because from the verifier's side they are the same fact.
 */
export const unseal = (purpose: string, sealed: string | undefined): string | null => {
  if (sealed === undefined || sealed === '') return null;
  const tagAt = sealed.lastIndexOf('.');
  if (tagAt < 0) return null;

  const body = sealed.slice(0, tagAt);
  const presented = Buffer.from(sealed.slice(tagAt + 1));
  const expected = Buffer.from(mac(purpose, body));
  // `timingSafeEqual` throws on a length mismatch, so this guard is required.
  if (presented.length !== expected.length) return null;
  if (!timingSafeEqual(presented, expected)) return null;

  // only after the MAC: these bytes are now known to be this server's own
  const expAt = body.lastIndexOf('.');
  if (expAt < 0) return null;
  const exp = Number(body.slice(expAt + 1));
  if (!Number.isSafeInteger(exp) || exp * 1000 <= Date.now()) return null;
  return body.slice(0, expAt);
};

// -----------------------------------------------------------------------------
// the app's own key
// -----------------------------------------------------------------------------

/*

  The second key, and the one that makes a credential spendable.

  A DFOS credential is issued TO a named DID — `aud` is the app's `client_did`,
  the one served in `/.well-known/dfos-app.json`. specs/API-AUTH.md is built so
  that holding the credential bytes is not enough: every request additionally
  carries a fresh JWS signed by that DID's key, binding the credential's CID to
  this exact method, host, path, and body. So a captured credential authorizes
  nothing, and this key is the only artifact here that must never leak.

  It lives on the server, never in the browser. API-AUTH.md's Security
  Considerations say why: a browser cannot hold a key non-extractably, so the
  supported shape is a backend-for-frontend — the browser holds an ordinary
  session with this backend, and this backend signs. `api/profile.ts` is that
  seam, and it takes no request coordinates from the browser at all.

  Two variables, because the proof needs both halves of a DID URL: which
  identity is signing, and which of its keys.

*/

const kidConfigured = process.env['DFOS_APP_KID'];
const privateKeyConfigured = process.env['DFOS_APP_PRIVATE_KEY'];

/** 32 raw seed bytes are exactly 43 canonical unpadded base64url characters. */
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/;

interface AppKey {
  /** The signing key's DID URL — `did:dfos:<id>#key_<id>`. */
  kid: string;
  /** The DID half: this app's `client_did`, and the `aud` of its credentials. */
  did: string;
  /** The public half, multibase-encoded, so an operator can eyeball it. */
  publicKeyMultibase: string;
  privateKey: Uint8Array;
}

/**
 * Parse the pair, or name what is wrong with it. Every failure is a deployment
 * mistake rather than a runtime condition, so each one is worded as the edit
 * that fixes it — the same posture `SECRET_ERROR` takes.
 */
const readAppKey = (): { key: AppKey } | { error: string } => {
  if (kidConfigured === undefined || kidConfigured === '') {
    return {
      error:
        'DFOS_APP_KID is not set, so this app holds no signing key and cannot spend a ' +
        'credential. Set it to the DID URL of a current key of your app’s identity — ' +
        'did:dfos:<id>#key_<id> — and set DFOS_APP_PRIVATE_KEY to that key’s secret.',
    };
  }
  if (!kidConfigured.includes('#')) {
    return {
      error: `DFOS_APP_KID must be a DID URL naming a key — did:dfos:<id>#key_<id> — not ${kidConfigured}`,
    };
  }
  if (privateKeyConfigured === undefined || privateKeyConfigured === '') {
    return {
      error:
        'DFOS_APP_PRIVATE_KEY is not set. It is the Ed25519 secret for the key named by ' +
        'DFOS_APP_KID, as 43 base64url characters.',
    };
  }
  if (!BASE64URL_32.test(privateKeyConfigured)) {
    return {
      error:
        'DFOS_APP_PRIVATE_KEY must be a 32-byte Ed25519 secret encoded as 43 unpadded ' +
        'base64url characters.',
    };
  }

  let key: AppKey;
  try {
    const { privateKey, publicKey } = importEd25519Keypair(base64urlDecode(privateKeyConfigured));
    key = {
      kid: kidConfigured,
      did: kidConfigured.substring(0, kidConfigured.indexOf('#')),
      publicKeyMultibase: encodeEd25519Multikey(publicKey),
      privateKey,
    };
  } catch (err) {
    return {
      error: `DFOS_APP_PRIVATE_KEY is not a usable Ed25519 secret: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  return { key };
};

const appKey = readAppKey();

/** The named misconfiguration, or null. Checked by every credential-path route. */
export const APP_KEY_ERROR: string | null = 'error' in appKey ? appKey.error : null;

/** This app's `client_did` — the `aud` of any credential issued to it. */
export const APP_DID: string | null = 'key' in appKey ? appKey.key.did : null;

/** The DID URL the request proof's `kid` header carries. */
export const APP_KID: string | null = 'key' in appKey ? appKey.key.kid : null;

/**
 * The public half of the configured secret. Reported to the page so a fork can
 * compare it against `dfos identity keys` output: a secret that does not belong
 * to the key `DFOS_APP_KID` names is the one misconfiguration whose only other
 * symptom is a 401 from the API, arriving several steps later with nothing local
 * to compare against.
 */
export const APP_PUBLIC_KEY_MULTIBASE: string | null =
  'key' in appKey ? appKey.key.publicKeyMultibase : null;

/**
 * The raw Ed25519 signer `signApiRequest` takes. Async because that is the seam's
 * shape — a deployment holding its key in a KMS returns a promise from a network
 * call, and this demo should not make the local case look like the only one.
 */
export const signAsApp = async (message: Uint8Array): Promise<Uint8Array> => {
  if (!('key' in appKey)) throw new Error(APP_KEY_ERROR ?? 'no app key configured');
  return signPayloadEd25519(message, appKey.key.privateKey);
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

/**
 * A local port holds no domain, so it can prove no `client_did` — which is why
 * the loopback tier admits `scope=identity` and nothing else. The credential
 * path is therefore unavailable under `npm run dev`, by design and at both ends:
 * the kit refuses to build the request, and the platform would refuse it too.
 */
export const isLoopbackDomain = (domain: string): boolean => LOOPBACK_HOSTS.has(domain);

export interface RequestOrigin {
  /** Scheme and authority, no trailing slash — what an `Origin` header holds. */
  origin: string;
  /** The bare hostname signed into the challenge and checked back out of it. */
  domain: string;
  /** The exact redirect target, trailing slash included. */
  redirectUri: string;
}

/**
 * Where this request thinks it arrived, derived rather than hardcoded so a fork
 * on any domain works with no edit here — and so the domain the server SIGNS
 * into a challenge and the domain it checks on the way back are one expression
 * and cannot drift apart.
 *
 * The `Host` header is client-controllable in principle, and deriving from it
 * buys an attacker nothing: a forged host yields a self-consistent flow bound to
 * a domain whose well-known will not list the redirect, so the platform refuses
 * it, and anyone can construct that URL by hand anyway. The dangerous case would
 * be verifying a challenge for one domain against a cookie minted for another,
 * which a single derivation rules out.
 */
export const requestOrigin = (req: VercelRequest): RequestOrigin | null => {
  const host = (headerValue(req.headers['x-forwarded-host']) ?? headerValue(req.headers.host))
    ?.trim()
    .toLowerCase();
  if (host === undefined || host === '') return null;

  // Parsed rather than string-sliced, so ports and IPv6 brackets are handled by
  // the URL grammar itself. `URL.hostname` brackets an IPv6 literal, and the
  // signed `domain` is compared EXACTLY, so the challenge carries the bare form
  // the platform will compare against the redirect's host.
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
 * present `Origin` that is not ours is a cross-site request and gets nothing. An
 * ABSENT one is allowed through: browsers attach it to every POST, so its
 * absence means a non-browser caller (curl, the smoke test), which cannot be
 * riding a victim's cookie jar. A present `null` is refused like any other
 * foreign origin.
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
  /** Which scope this sign-in was granted under. */
  scope: Scope;
  /**
   * An opaque id for THIS session, minted at grant time. It is the key the
   * credential is stored under, and it exists because the credential is the one
   * thing here that does not fit the zero-state pattern: it is a durable,
   * portable artifact that belongs on the server's side of the wire, so the
   * cookie carries a pointer to it rather than the artifact itself.
   *
   * Absent on an identity-scope session, which has nothing to point at.
   */
  sid?: string;
}

/**
 * The session rides in the cookie itself: base64url JSON under the same seal.
 * Zero server state, so any instance can answer for a session any other
 * instance issued, given the same `SESSION_SECRET` — the credential behind
 * `sid` being the one exception, and it lives in the shared store for exactly
 * that reason.
 *
 * The nonce is deliberately NOT in here. It was the secret the flight cookie
 * held, and echoing it back would hand the presenter the one value they must
 * never choose.
 */
export const encodeSession = (session: Session): string =>
  seal('session', Buffer.from(JSON.stringify(session)).toString('base64url'), SESSION_TTL_SECONDS);

/**
 * A fresh session id. Only ever used as a store key, never shown and never
 * meaningful on its own — but unguessable anyway, because a guessable one would
 * name another session's credential.
 */
export const newSessionId = (): string => randomBytes(16).toString('base64url');

/** The session this request carries, or `null` — unsealed, parsed, unexpired. */
export const readSession = (req: VercelRequest): Session | null => {
  // the seal enforces its own expiry; the checks below re-validate the fields
  // INSIDE the sealed JSON, because authenticated bytes are still parsed bytes
  const value = unseal('session', readCookie(req, SESSION_COOKIE));
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
  const iat = raw['iat'];
  const exp = raw['exp'];
  // safe integers only — `JSON.parse("1e309")` is `Infinity` and still a
  // "number" — and the pair must describe a lifetime this server would issue:
  // not future-dated, not expired, not longer than the configured TTL.
  if (!Number.isSafeInteger(iat) || !Number.isSafeInteger(exp)) return null;
  const now = Math.floor(Date.now() / 1000);
  if ((iat as number) > now + 60 || (exp as number) <= now) return null;
  if ((exp as number) - (iat as number) > SESSION_TTL_SECONDS) return null;

  // The scope is re-validated like every other field: it decides whether this
  // session may reach the signing seam at all, so a value this server would not
  // have written is no session.
  const scope = raw['scope'];
  if (!isScope(scope)) return null;
  const sid = raw['sid'];
  if (sid !== undefined && (typeof sid !== 'string' || sid === '')) return null;

  return {
    did: raw['did'],
    kid: raw['kid'],
    iat: iat as number,
    exp: exp as number,
    scope,
    ...(typeof sid === 'string' ? { sid } : {}),
  };
};

// -----------------------------------------------------------------------------
// the held credential
// -----------------------------------------------------------------------------

/**
 * What the demo shows about a credential it holds — the RENDER-BEFORE-TRUST
 * habit, in a UI. Every field here was read out of a credential this server had
 * already verified: signature, schema, CID integrity, expiry, issuer identity
 * chain. Displaying an unverified grant would teach the opposite reflex.
 */
export interface CredentialFacts {
  /** Who authorized this — and, for a single-hop grant, whose data it serves. */
  issuer: string;
  /** Who may spend it: this app's DID, and nobody else's. */
  audience: string;
  /** The attenuation, exactly as the API verifier byte-matches it. */
  resource: string;
  action: string;
  /** Issued-at and expiry, unix seconds. */
  issuedAt: number;
  expiresAt: number;
  /** The CID every request proof binds to. */
  credentialCID: string;
}

/** The credential and its already-verified facts, as one stored record. */
export interface HeldCredential {
  jws: string;
  facts: CredentialFacts;
}

/** Parse a stored record back, or `null` if the store held something unusable. */
export const parseHeldCredential = (stored: string | null): HeldCredential | null => {
  if (stored === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(stored);
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
  const raw = parsed as Record<string, unknown>;
  if (typeof raw['jws'] !== 'string' || typeof raw['facts'] !== 'object' || raw['facts'] === null) {
    return null;
  }
  return { jws: raw['jws'], facts: raw['facts'] as CredentialFacts };
};

// -----------------------------------------------------------------------------
// responses
// -----------------------------------------------------------------------------

/**
 * `ephemeral` is stamped onto EVERY JSON body, not just the ones carrying a
 * session, because it is a property of the deployment and the page renders a
 * persistent notice from it. Reported on failures too: that is exactly when a
 * fork that forgot `SESSION_SECRET` most needs to read it.
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
 * The JSON body as an object, or `null`. Vercel's Node runtime pre-parses a
 * JSON body onto `req.body`; the string branch covers a runtime that did not.
 */
export const readJsonBody = (req: VercelRequest): Record<string, unknown> | null => {
  // `req.body` is a LAZY GETTER on Vercel's runtime and throws on malformed
  // JSON sent with a JSON content-type, so reading it bare would turn a bad
  // body into a 500 instead of this function's `null`. The dev shim pre-parses
  // and never throws; the catch keeps both runtimes on one error path.
  let body: unknown;
  try {
    body = req.body;
  } catch {
    return null;
  }
  if (typeof body === 'string') {
    if (body.length > MAX_BODY_BYTES) return null;
    try {
      body = JSON.parse(body);
    } catch {
      return null;
    }
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return null;
  return body as Record<string, unknown>;
};

/** One member of a JSON body, as a bounded non-empty string — or `null`. */
export const readTokenField = (
  body: Record<string, unknown> | null,
  field: string,
): string | null => {
  if (body === null) return null;
  const value = body[field];
  if (typeof value !== 'string' || value === '' || value.length > MAX_BODY_BYTES) return null;
  return value;
};
