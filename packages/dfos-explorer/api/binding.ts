/*

  ORIGIN-BINDING ATTEST-BACK PROBE — the explorer's second serverless route

  GET /api/binding?host=<hostname> runs BOTH attest-back methods INTEGRATIONS.md,
  Attest-back: the domain's half defines — the HTTPS document at
  /.well-known/dfos-did and the DNS TXT record at _dfos.<host> — and answers 200
  with a BindingEnvelope carrying one result per method. It exists because a
  browser tab can do neither honestly: origins do not reliably send CORS headers
  on well-knowns, and a page cannot query DNS at all.
  It stores nothing, decides nothing, and calls no platform API — the VERDICT is
  computed in the tab (src/lib/origin-binding.ts).

  Same policy as `api/wellknown.ts`, whose hostname and address guards this route
  imports rather than restates:
   - https only, port 443 only — the caller supplies ONLY a hostname; the path is
     fixed to /.well-known/dfos-did and nothing else is ever fetched
   - resolve-then-check: every resolved address must be globally routable, and
     only globally routable addresses are fetched — an allowlist of public
     unicast, so a range nobody named is refused rather than reached
   - redirects are not followed: a redirect attests nothing (INTEGRATIONS.md,
     HTTPS: `/.well-known/dfos-did`), so it is reported as its own status —
     never as a contradiction, and never as an answer. The spec puts it in the
     NON-ANSWER class, where a verifier "treats the path exactly as it treats
     absence": it licenses the app-description fallback exactly as a 404 does
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
import {
  classifyDidStatus,
  WELL_KNOWN_PATH as FIXED_PATH,
  foldTxtClaims,
  MAX_BODY_BYTES,
  parseDidBody,
  TXT_NAME_PREFIX,
  type BindingMethodResult,
} from './binding-parse.js';
import { isForbiddenAddress, validateHostname } from './wellknown.js';

const TIMEOUT_MS = 5000;

// the seven outcomes, the DID grammar, the trim set and the body/TXT/status
// readers all live in ./binding-parse.ts — the browser vantage reads the same
// bytes the same way, and the two used to drift (see that file's header)
export { classifyDidStatus, parseDidBody, type BindingMethodResult };

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
export const parseTxtRecords = (records: string[][]): BindingMethodResult =>
  foldTxtClaims(records.map((chunks) => chunks.join('')));

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

/** The over-cap signal, distinguishable from any other read failure. */
const OVER_CAP = 'over-cap';

/** Read a response body as text under the byte cap. Throws {@link OVER_CAP} past it. */
export const boundedText = async (res: Response): Promise<string> => {
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > MAX_BODY_BYTES) throw new Error(OVER_CAP);
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
      throw new Error(OVER_CAP);
    }
    chunks.push(value);
  }
  return new TextDecoder().decode(
    chunks.length === 1 ? chunks[0] : Buffer.concat(chunks as Buffer[]),
  );
};

/**
 * What a failed body read means. AN OVER-CAP 200 IS A NON-ANSWER, NOT A FAILED
 * QUERY: the origin answered, and what it sent is not a DID, because no
 * conforming body reaches 1024 bytes. That is `malformed` — the non-answer class
 * the spec's app-description fallback triggers on — and it is the reading the Go
 * CLI already gives the same input (`classifyWellKnown` in
 * packages/dfos-cli/internal/cmd/originbinding.go, "A body over the cap is that
 * same 200-that-is-not-a-DID"). Calling it `error` suppressed the fallback the
 * CLI performs, so two reference verifiers disagreed on identical bytes.
 * `error` is kept for a read that genuinely failed. Pure, unit-tested.
 */
export const bodyReadFailure = (e: unknown): BindingMethodResult =>
  e instanceof Error && e.message === OVER_CAP
    ? { status: 'malformed', reason: 'the document exceeds 1024 bytes' }
    : { status: 'error', reason: 'the document could not be read' };

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
    return bodyReadFailure(e);
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
