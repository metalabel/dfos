/*

  The verifier's own state — the store the CONSUMED replay discipline needs.

  specs/SIWD.md requires consumed verification for every credential-returning
  scope: each minted nonce is held server-side and spent by an ATOMIC
  check-and-delete, so a signed challenge redeems exactly once anywhere, not
  once per channel. `api/_lib.ts`'s sealed cookie cannot do that job — it is the
  flow-bound discipline, and it binds a redemption to one browser rather than
  retiring the artifact.

  Redis `GETDEL` is that atomic primitive: one round trip that returns the value
  and deletes it, so two concurrent replays cannot both win. A read followed by
  a delete is not a substitute; it is a race with a login in it.

  Hand-rolled against the REST API on purpose, the same way `readCookie` is
  hand-rolled: the whole surface this demo needs is three commands, and the
  Upstash REST protocol is a JSON array of arguments and a `{ result }` back.

  The same store holds the credential the callback returns, keyed by the session
  that earned it. That is not replay state — it is the grant itself, which the
  RP is supposed to HOLD. A cookie is the browser's copy of something; a durable
  90-day authorization belongs on the RP's own side of the wire.

*/

/**
 * Vercel's Upstash integration writes the first pair; a database connected
 * directly at Upstash writes the second. Same protocol either way.
 *
 * A pair is taken WHOLE or not at all. Falling back per-variable would let a
 * stale `KV_REST_API_URL` from one store pick up the token of another — a
 * credential sent to the wrong host, which fails as an opaque 401 from a
 * service the operator was not thinking about. Two complete pairs, first one
 * wins, no mixing.
 */
const credentialPair = (urlVar: string, tokenVar: string): [string, string] | null => {
  const url = process.env[urlVar];
  const token = process.env[tokenVar];
  return url !== undefined && url !== '' && token !== undefined && token !== ''
    ? [url, token]
    : null;
};

const KV_CREDENTIALS =
  credentialPair('KV_REST_API_URL', 'KV_REST_API_TOKEN') ??
  credentialPair('UPSTASH_REDIS_REST_URL', 'UPSTASH_REDIS_REST_TOKEN');

const URL_VAR = KV_CREDENTIALS?.[0];
const TOKEN_VAR = KV_CREDENTIALS?.[1];

/** Bounded, so a stalled store surfaces as a refusal rather than a hung sign-in. */
const KV_TIMEOUT_MS = 5000;

/**
 * The named misconfiguration, or null — reported the way `SECRET_ERROR` is, so a
 * fork that skipped the store learns it from the page instead of from a sign-in
 * that dies halfway through.
 */
export const KV_ERROR: string | null =
  KV_CREDENTIALS === null
    ? 'No KV store is configured — set KV_REST_API_URL and KV_REST_API_TOKEN ' +
      '(Vercel’s Upstash integration writes both when you add a Redis store to the ' +
      'project), then redeploy. Both halves of a pair are required; a URL without ' +
      'its own token is ignored rather than paired with another store’s.'
    : null;

/** True when the consumed discipline is available at all. */
export const KV_CONFIGURED = KV_ERROR === null;

/**
 * One Redis command. Throws on anything that is not a clean `{ result }` —
 * an unreachable store, a non-2xx, a Redis-level error. Callers do NOT catch:
 * the consumed discipline fails CLOSED, so "the store did not answer" must
 * refuse the sign-in rather than fall through to granting one.
 */
const command = async (...args: string[]): Promise<unknown> => {
  if (URL_VAR === undefined || TOKEN_VAR === undefined) {
    throw new Error('KV store is not configured');
  }

  const response = await fetch(URL_VAR, {
    method: 'POST',
    headers: { Authorization: `Bearer ${TOKEN_VAR}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(args),
    signal: AbortSignal.timeout(KV_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`KV store answered HTTP ${response.status}`);
  }

  const body: unknown = await response.json();
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new Error('KV store returned an unexpected body');
  }
  const raw = body as Record<string, unknown>;
  if (typeof raw['error'] === 'string') {
    throw new Error(`KV store error: ${raw['error']}`);
  }
  return raw['result'] ?? null;
};

/** `SET key value EX ttl` — write with an expiry, so nothing outlives its purpose. */
export const kvSet = async (key: string, value: string, ttlSeconds: number): Promise<void> => {
  await command('SET', key, value, 'EX', String(ttlSeconds));
};

/** `GET key` — the value, or `null`. */
export const kvGet = async (key: string): Promise<string | null> => {
  const result = await command('GET', key);
  return typeof result === 'string' ? result : null;
};

/**
 * `GETDEL key` — THE ATOMIC CHECK-AND-DELETE. Returns the value iff this call
 * is the one that removed it; every later caller gets `null`. This single round
 * trip is what makes the consumed discipline real, and why the demo reaches for
 * a store at all.
 */
export const kvGetDel = async (key: string): Promise<string | null> => {
  const result = await command('GETDEL', key);
  return typeof result === 'string' ? result : null;
};

/** `DEL key` — best-effort cleanup; a failure here is never a refusal. */
export const kvDel = async (key: string): Promise<void> => {
  try {
    await command('DEL', key);
  } catch {
    // The key carries its own TTL, so a missed delete expires on its own.
  }
};
