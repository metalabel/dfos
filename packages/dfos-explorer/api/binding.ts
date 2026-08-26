/*

  ORIGIN-BINDING ATTEST-BACK PROBE — the explorer's second serverless route

  GET /api/binding?host=<hostname> runs BOTH attest-back methods ORIGIN-BINDING.md
  defines — the HTTPS document at /.well-known/dfos-did and the DNS TXT record at
  _dfos.<host> — and answers 200 with a BindingEnvelope carrying one result per
  method. It exists because a browser tab can do neither honestly: origins do not
  reliably send CORS headers on well-knowns, and a page cannot query DNS at all.
  It stores nothing, decides nothing, and calls no platform API — the VERDICT is
  computed in the tab (src/lib/origin-binding.ts).

  Same policy as `api/wellknown.ts`, whose hostname and address guards this route
  imports rather than restates:
   - https only, port 443 only — the caller supplies ONLY a hostname; the path is
     fixed to /.well-known/dfos-did and nothing else is ever fetched
   - resolve-then-check: every resolved address is refused if it is private,
     loopback, link-local, unique-local, or v4-mapped into any of those
   - redirects are not followed: a redirect attests nothing (ORIGIN-BINDING.md),
     so it is reported as SILENCE, never as a contradiction
   - 1024-byte response cap (a conforming body is under a hundred bytes), 5s timeout
   - the TXT lookup makes no connection, so it needs no address policy of its own

  The one rule the whole route exists to protect: silence is not contradiction.
  A failed lookup, a timeout, an absent record and an absent document are all
  distinct from a domain that ANSWERS with something — and the envelope keeps
  them distinguishable so the fold in the tab can honour the stale/broken split.

*/

import { isForbiddenAddress, validateHostname } from './wellknown';

const FIXED_PATH = '/.well-known/dfos-did';
const MAX_BODY_BYTES = 1024;
const TIMEOUT_MS = 5000;
const TXT_NAME_PREFIX = '_dfos.';

/** A DFOS DID: the 31-char id alphabet the protocol mints. */
const DID_RE = /^did:dfos:[2346789acdefhknrtvz]{31}$/;
/** The DNS attestation's exact value form (ORIGIN-BINDING.md, "DNS"). */
const TXT_CLAIM_RE = /^did=(did:dfos:[2346789acdefhknrtvz]{31})$/;
/** ASCII whitespace only — the spec trims ASCII, not Unicode. */
const ASCII_WS_RE = /^[\t\n\f\r ]+|[\t\n\f\r ]+$/g;

/**
 * What ONE method established. Six outcomes, and the split between them is the
 * whole point:
 *
 *   ok            — the domain answered with a DFOS DID
 *   none          — the domain is silent (no record, no document: an ABSENCE it
 *                   affirmatively demonstrated). Fallback-eligible on HTTPS.
 *   malformed     — the domain answered with something that is NOT a DID. Present
 *                   without an answer: silence for the verdict, but it BLOCKS the
 *                   app-description fallback, which applies only on absence.
 *   contradiction — the domain answered more than once, with a set it cannot mean
 *   error         — we could not check (timeout, resolver failure, 5xx)
 *   refused       — the fetch never left this route (policy)
 */
export type BindingMethodResult =
  | { status: 'ok'; did: string }
  | { status: 'none'; reason?: string }
  | { status: 'malformed'; reason: string }
  | { status: 'contradiction'; reason: string }
  | { status: 'error'; reason?: string; httpStatus?: number }
  | { status: 'refused'; reason: string };

export interface BindingEnvelope {
  https: BindingMethodResult;
  dns: BindingMethodResult;
}

// -----------------------------------------------------------------------------
// the pure halves — parsing, with no network in sight
// -----------------------------------------------------------------------------

/**
 * Fold a `resolveTxt` answer into a method result. Node hands back one array of
 * STRING CHUNKS per record (a TXT record over 255 bytes is split on the wire),
 * so the chunks of a record are joined before anything is read from it.
 *
 * Records not beginning `did=` are ignored — the name may legitimately carry
 * other TXT. MORE THAN ONE `did=` record is a contradiction whatever the values
 * are, including two records carrying the SAME did: the spec forbids picking one,
 * and "they happen to agree" is a tiebreak by another name.
 */
export const parseTxtRecords = (records: string[][]): BindingMethodResult => {
  const claims = records.map((chunks) => chunks.join('')).filter((v) => v.startsWith('did='));
  if (claims.length === 0) {
    return { status: 'none', reason: `no did= TXT record at ${TXT_NAME_PREFIX}<domain>` };
  }
  if (claims.length > 1) {
    return { status: 'contradiction', reason: 'multiple did= records' };
  }
  const match = TXT_CLAIM_RE.exec(claims[0]!);
  // a single MALFORMED did= record is not an answer — it is a record that says
  // nothing, and a domain that says nothing is silent, not contradicting itself
  if (!match) return { status: 'none', reason: 'the did= record is not a DFOS DID' };
  return { status: 'ok', did: match[1]! };
};

/**
 * Read a 200 body from `/.well-known/dfos-did`. A body that is exactly one DFOS
 * DID after ASCII trimming attests it; ANYTHING else is `malformed` — the
 * document is present, so the origin is not silent here, and the fallback to the
 * app description (which applies on ABSENCE only) must not fire.
 */
export const parseDidBody = (body: string): BindingMethodResult => {
  const trimmed = body.replace(ASCII_WS_RE, '');
  if (trimmed === '') return { status: 'malformed', reason: 'the document is empty' };
  if (!DID_RE.test(trimmed)) {
    return { status: 'malformed', reason: 'the document is not exactly one DFOS DID' };
  }
  return { status: 'ok', did: trimmed };
};

// -----------------------------------------------------------------------------
// the DNS method
// -----------------------------------------------------------------------------

const probeDns = async (host: string): Promise<BindingMethodResult> => {
  const { resolveTxt } = await import('node:dns/promises');
  try {
    return parseTxtRecords(await resolveTxt(`${TXT_NAME_PREFIX}${host}`));
  } catch (e) {
    const code = typeof e === 'object' && e !== null ? String((e as { code?: string }).code) : '';
    // the resolver answered, and the answer is "there is nothing here"
    if (code === 'ENOTFOUND' || code === 'ENODATA') {
      return { status: 'none', reason: `no TXT record at ${TXT_NAME_PREFIX}${host}` };
    }
    // everything else is a failure to CHECK — silence, never a contradiction
    return { status: 'error', reason: `the DNS lookup failed (${code || 'unknown error'})` };
  }
};

// -----------------------------------------------------------------------------
// the HTTPS method
// -----------------------------------------------------------------------------

/** Read a response body as text under the byte cap. Throws past it. */
const boundedText = async (res: Response): Promise<string> => {
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > MAX_BODY_BYTES) throw new Error('too-large');
  const reader = res.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new Error('too-large');
    }
    chunks.push(value);
  }
  return new TextDecoder().decode(
    chunks.length === 1 ? chunks[0] : Buffer.concat(chunks as Buffer[]),
  );
};

const probeHttps = async (host: string): Promise<BindingMethodResult> => {
  const { lookup } = await import('node:dns/promises');
  let addresses: { address: string }[];
  try {
    addresses = await lookup(host, { all: true, verbatim: true });
  } catch {
    // not an observed absence of the document — we never reached the origin
    return { status: 'error', reason: 'the hostname did not resolve' };
  }
  if (addresses.length === 0) {
    return { status: 'error', reason: 'the hostname did not resolve' };
  }
  if (addresses.some(({ address }) => isForbiddenAddress(address))) {
    return { status: 'refused', reason: 'the hostname resolves to a non-public address' };
  }

  let res: Response;
  try {
    res = await fetch(`https://${host}${FIXED_PATH}`, {
      redirect: 'manual',
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { accept: 'text/plain' },
    });
  } catch (e) {
    const name = e instanceof Error ? e.name : '';
    if (name === 'TimeoutError' || name === 'AbortError') {
      return { status: 'error', reason: 'the origin did not answer in time' };
    }
    return { status: 'error', reason: 'the origin could not be reached' };
  }

  // a redirect attests NOTHING — the attestation must come from the named origin
  // at the fixed path, so this is silence rather than a contradiction
  if (res.status >= 300 && res.status < 400) {
    return { status: 'none', reason: 'the origin redirected; redirects are not followed' };
  }
  if (res.status === 404 || res.status === 410) {
    return { status: 'none', reason: `the origin serves no ${FIXED_PATH} (HTTP ${res.status})` };
  }
  if (!res.ok) {
    return {
      status: 'error',
      httpStatus: res.status,
      reason: 'the origin answered with an error status',
    };
  }

  try {
    return parseDidBody(await boundedText(res));
  } catch (e) {
    if (e instanceof Error && e.message === 'too-large') {
      return { status: 'error', reason: 'too-large' };
    }
    return { status: 'error', reason: 'the document could not be read' };
  }
};

// -----------------------------------------------------------------------------
// the route
// -----------------------------------------------------------------------------

// minimal structural types so this file carries no @vercel/node dependency
interface NodeishRequest {
  method?: string;
  query?: Record<string, string | string[]>;
  url?: string;
}
interface NodeishResponse {
  status(code: number): NodeishResponse;
  setHeader(name: string, value: string): void;
  json(body: unknown): void;
}

export default async function handler(req: NodeishRequest, res: NodeishResponse): Promise<void> {
  if (req.method && req.method !== 'GET') {
    res.status(405).json({ error: 'method not allowed' });
    return;
  }
  const rawHost = Array.isArray(req.query?.host) ? req.query?.host[0] : req.query?.host;
  const host = validateHostname(rawHost);

  res.setHeader('cache-control', 'public, s-maxage=60, stale-while-revalidate=300');
  res.setHeader('content-type', 'application/json');

  // an invalid host is a refusal INSIDE the envelope, not a transport error — a
  // bare 4xx would read to the client as "our route is broken" and get reported
  // as proxy-unavailable, which misattributes a caller mistake
  if (!host) {
    const reason = 'host must be a bare public DNS hostname';
    res.status(200).json({
      https: { status: 'refused', reason },
      dns: { status: 'refused', reason },
    } satisfies BindingEnvelope);
    return;
  }

  // both methods are independent single round-trips; neither gates the other
  const [https, dns] = await Promise.all([probeHttps(host), probeDns(host)]);
  res.status(200).json({ https, dns } satisfies BindingEnvelope);
}
