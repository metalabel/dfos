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
     so it is reported as its own status — never as a contradiction, and never
     as an answer. The spec puts it in the NON-ANSWER class, where a verifier
     "treats the path exactly as it treats absence": it licenses the
     app-description fallback exactly as a 404 does
   - 1024-byte response cap (a conforming body is under a hundred bytes), 5s timeout
   - the TXT lookup makes no connection, so it needs no address policy of its own

  The one rule the whole route exists to protect: silence is not contradiction.
  A failed lookup, a timeout, an absent record and an absent document are all
  distinct from a domain that ANSWERS with something — and the envelope keeps
  them distinguishable so the fold in the tab can honour the stale/broken split.

*/

// NB: the `.js` extension is load-bearing — Vercel's node runtime loads these
// routes as ESM (package.json `"type": "module"`) without bundling them, and
// Node's ESM loader refuses extensionless relative specifiers at module load
// (FUNCTION_INVOCATION_FAILED before the handler ever runs)
import { isForbiddenAddress, validateHostname } from './wellknown.js';

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
 * What ONE method established. Seven outcomes, and the split between them is the
 * whole point. ORIGIN-BINDING.md sorts them into three classes, and the class a
 * result lands in is what decides whether the app-description fallback fires:
 *
 * NON-ANSWERS — "the file attests nothing"; each licenses the fallback on HTTPS,
 * because the spec's trigger is the class, not the status code:
 *
 *   none          — an ABSENCE the domain affirmatively demonstrated: an HTTPS
 *                   404/410, or a DNS name carrying no `did=` record.
 *   redirected    — any 3xx. "A redirect is a non-answer, never a contradiction …
 *                   A verifier that receives any 3xx therefore treats the path
 *                   exactly as it treats absence: the file attests nothing, the
 *                   app-description fallback applies as it does on a 404."
 *   malformed     — a 200 whose trimmed body is not exactly one DFOS DID — "the
 *                   shape a host serving its application shell for every unknown
 *                   path produces". Present without an answer, and the spec names
 *                   it in the same fallback trigger as the other two.
 *
 * ANSWERS — the domain said something, and the fallback must NOT be reached past
 * it (a document that IS a DID naming a different one is a contradiction):
 *
 *   ok            — the domain answered with a DFOS DID
 *   contradiction — the domain answered more than once, with a set it cannot mean
 *
 * QUERY FAILURE — its own class in the spec's stale row ("or the queries fail:
 * network error, TLS failure, timeout, server error"), listed apart from the
 * non-answers and therefore NOT fallback-licensing: we did not observe the path,
 * so we cannot say it declined to answer.
 *
 *   error         — we could not check (timeout, resolver failure, 5xx)
 *   refused       — the fetch never left this route (policy)
 */
export type BindingMethodResult =
  | { status: 'ok'; did: string }
  | { status: 'none'; reason?: string }
  | { status: 'redirected'; httpStatus: number; reason: string }
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
 * DID after ASCII trimming attests it; ANYTHING else is `malformed` — a document
 * that is present and says nothing the spec can read, which is the third member
 * of its non-answer class ("a 200 whose trimmed body is not exactly one DFOS
 * DID, the shape a host serving its application shell for every unknown path
 * produces") and licenses the app-description fallback exactly as a 404 does.
 */
export const parseDidBody = (body: string): BindingMethodResult => {
  const trimmed = body.replace(ASCII_WS_RE, '');
  if (trimmed === '') return { status: 'malformed', reason: 'the document is empty' };
  if (!DID_RE.test(trimmed)) {
    return { status: 'malformed', reason: 'the document is not exactly one DFOS DID' };
  }
  return { status: 'ok', did: trimmed };
};

/**
 * What the HTTPS response STATUS alone establishes, before a byte of the body is
 * read. Pure, so the one judgement this method makes about a domain's answer is
 * testable without a network — the same shape `api/wellknown.ts` uses.
 *
 * The three outcomes are the spec's three classes, and which one a status lands
 * in is what decides whether the app-description fallback fires:
 *
 *   3xx      → `redirected`. A NON-ANSWER: the attestation must come from the
 *              named origin at the fixed path, and a redirect is that origin
 *              declining to answer there. It gets its own status rather than
 *              folding into `none` because the two are different observations and
 *              the evidence row says which — an absent document and an origin
 *              pointing elsewhere are not the same fact about a domain. For the
 *              FALLBACK they are one class: "A verifier that receives any 3xx
 *              therefore treats the path exactly as it treats absence."
 *   404/410  → `none`. An absence the origin affirmatively demonstrated.
 *   4xx/5xx  → `error`. A QUERY FAILURE, the spec's separate class — we did not
 *              observe the path, so it never declined to answer, and nothing is
 *              licensed off a channel we never saw.
 *
 * `null` means the status settles nothing on its own — the answer is in the body.
 */
export const classifyDidStatus = (status: number): BindingMethodResult | null => {
  if (status >= 300 && status < 400) {
    return {
      status: 'redirected',
      httpStatus: status,
      reason: 'the origin redirected; redirects are not followed',
    };
  }
  if (status === 404 || status === 410) {
    return { status: 'none', reason: `the origin serves no ${FIXED_PATH} (HTTP ${status})` };
  }
  if (status < 200 || status >= 300) {
    return {
      status: 'error',
      httpStatus: status,
      reason: 'the origin answered with an error status',
    };
  }
  return null;
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

  const byStatus = classifyDidStatus(res.status);
  if (byStatus !== null) return byStatus;

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
