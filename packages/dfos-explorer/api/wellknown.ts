/*

  WELL-KNOWN FETCH PROXY — the explorer's one serverless route

  GET /api/wellknown?host=<hostname> fetches https://<host>/.well-known/dfos-app.json
  on the browser's behalf and answers 200 with a ProxyEnvelope (see
  src/lib/wellknown.ts). It exists solely because third-party origins do not
  reliably send CORS headers on their well-knowns. It stores nothing and calls
  no platform API.

  This route fetches from caller-supplied hosts, so its policy is the point:
   - https only, port 443 only — the caller supplies ONLY a hostname; the path
     is fixed to /.well-known/dfos-app.json and nothing else is ever fetched
   - the hostname must be a public DNS name: no IP literals, no userinfo, no
     ports, no paths; it must carry a dot and an alphabetic TLD
   - resolve-then-check: every resolved address is refused if it is private,
     loopback, link-local, unique-local, or v4-mapped into any of those.
     (The runtime's fetch re-resolves on connect, so a rebinding window
     remains between check and connect; with the fixed path, https-only, and
     port 443 the residue is a GET of one constant path — accepted and named
     here rather than hidden.)
   - redirects are not followed, and a redirect is reported as its own
     `redirected` status: the document lives at the fixed path or it doesn't,
     so a redirect is a NON-ANSWER — never a contradiction, and never the
     absence a 404 affirmatively demonstrates
   - 512KB response cap (well-knowns carry at most 100 ops), 5s timeout
   - short CDN caching via Cache-Control; Vercel's edge cache is the only
     cache and there is no per-caller state to rate-limit with — the CDN
     collapse plus the small timeout is the throttle this route gets

*/

const FIXED_PATH = '/.well-known/dfos-app.json';
const MAX_BODY_BYTES = 512 * 1024;
const TIMEOUT_MS = 5000;

// public DNS name: dot-separated labels, alphabetic TLD of 2+, total <= 253
const HOSTNAME_RE = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

/** Reject anything that is not a bare public-DNS-shaped hostname. */
export const validateHostname = (raw: unknown): string | null => {
  if (typeof raw !== 'string') return null;
  const host = raw.trim().toLowerCase().replace(/\.$/, '');
  if (!HOSTNAME_RE.test(host)) return null;
  if (IPV4_RE.test(host)) return null; // dotted-quad sneaking past the TLD rule
  return host;
};

/** True when a resolved address must not be fetched from this route. */
export const isForbiddenAddress = (address: string): boolean => {
  const addr = address.toLowerCase();
  if (addr.includes(':')) {
    // v6: loopback, unspecified, link-local fe80::/10, unique-local fc00::/7
    if (addr === '::' || addr === '::1') return true;
    if (/^fe[89ab]/.test(addr)) return true;
    if (/^f[cd]/.test(addr)) return true;
    // v4-mapped (::ffff:a.b.c.d) — check the embedded v4
    const mapped = addr.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (mapped) return isForbiddenAddress(mapped[1]!);
    return false;
  }
  const octets = addr.split('.').map(Number);
  if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n) || n > 255)) return true;
  const [a, b] = octets as [number, number, number, number];
  if (a === 0 || a === 10 || a === 127) return true; // this-net, private, loopback
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
  if (a === 169 && b === 254) return true; // link-local
  if (a === 172 && b >= 16 && b <= 31) return true; // private 172.16/12
  if (a === 192 && b === 168) return true; // private 192.168/16
  return false;
};

interface ProxyEnvelope {
  status:
    | 'ok'
    | 'no-app-description'
    | 'redirected'
    | 'http-error'
    | 'unreachable'
    | 'too-large'
    | 'timeout'
    | 'refused';
  httpStatus?: number;
  body?: unknown;
  reason?: string;
}

/**
 * What the response STATUS alone establishes, before a byte of the body is read.
 * Split out as a pure function because it is the only judgement this route makes
 * about the origin's answer, and the three outcomes it separates are the three
 * the tab must keep apart:
 *
 *   redirected         — the origin answered, and its answer was "look elsewhere".
 *                        The document must be served at the fixed path and
 *                        redirects are never followed, so nothing was learned
 *                        about what this origin serves there. A NON-ANSWER: not a
 *                        contradiction, and not the absence a 404 demonstrates.
 *   no-app-description — the origin answered, and the document is not there. An
 *                        affirmative, complete answer: this origin describes no app.
 *   http-error         — the origin answered with an error status.
 *
 * `null` means the status settles nothing on its own — the answer is in the body.
 */
export const classifyStatus = (status: number): ProxyEnvelope | null => {
  if (status >= 300 && status < 400) {
    return {
      status: 'redirected',
      httpStatus: status,
      reason: 'the origin redirected; redirects are not followed',
    };
  }
  if (status === 404 || status === 410) return { status: 'no-app-description', httpStatus: status };
  if (status < 200 || status >= 300) return { status: 'http-error', httpStatus: status };
  return null;
};

/** Read a response body under the byte cap. Throws 'too-large' past it. */
const boundedJson = async (res: Response): Promise<unknown> => {
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > MAX_BODY_BYTES) throw new Error('too-large');
  const reader = res.body?.getReader();
  if (!reader) throw new Error('no body');
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
  const text = new TextDecoder().decode(
    chunks.length === 1 ? chunks[0] : Buffer.concat(chunks as Buffer[]),
  );
  return JSON.parse(text);
};

const fetchEnvelope = async (host: string): Promise<ProxyEnvelope> => {
  const { lookup } = await import('node:dns/promises');
  let addresses: { address: string }[];
  try {
    addresses = await lookup(host, { all: true, verbatim: true });
  } catch {
    return { status: 'unreachable', reason: 'the hostname did not resolve' };
  }
  if (addresses.length === 0) {
    return { status: 'unreachable', reason: 'the hostname did not resolve' };
  }
  if (addresses.some(({ address }) => isForbiddenAddress(address))) {
    return { status: 'refused', reason: 'the hostname resolves to a non-public address' };
  }

  let res: Response;
  try {
    res = await fetch(`https://${host}${FIXED_PATH}`, {
      redirect: 'manual',
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { accept: 'application/json' },
    });
  } catch (e) {
    const name = e instanceof Error ? e.name : '';
    if (name === 'TimeoutError' || name === 'AbortError') return { status: 'timeout' };
    return {
      status: 'unreachable',
      reason: 'the origin could not be reached',
    };
  }

  const byStatus = classifyStatus(res.status);
  if (byStatus !== null) return byStatus;

  try {
    return { status: 'ok', httpStatus: res.status, body: await boundedJson(res) };
  } catch (e) {
    if (e instanceof Error && e.message === 'too-large') return { status: 'too-large' };
    return {
      status: 'http-error',
      httpStatus: res.status,
      reason: 'the origin served a document that is not JSON',
    };
  }
};

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

  // an invalid host is a refusal inside the envelope, not a transport error —
  // a bare 4xx would read to the client as "our route is broken" and get
  // reported as proxy-unavailable, which misattributes a caller mistake
  if (!host) {
    res.status(200).json({
      status: 'refused',
      reason: 'host must be a bare public DNS hostname',
    } satisfies ProxyEnvelope);
    return;
  }

  res.status(200).json(await fetchEnvelope(host));
}
