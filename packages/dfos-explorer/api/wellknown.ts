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
   - resolve-then-check: every resolved address must be globally routable, and
     only globally routable addresses are fetched. The rule is an ALLOWLIST, not
     a denylist — an address passes by being demonstrably public unicast, so a
     range nobody thought of is refused by default rather than reached.
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

import { BlockList, isIPv4, isIPv6 } from 'node:net';

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

/*

  WHICH ADDRESSES THIS ROUTE MAY FETCH FROM

  The rule is an ALLOWLIST — an address passes only by being demonstrably public
  unicast — because the denylist this replaced was the wrong shape for the job.
  A denylist has to name every range that must not be reached, and the ranges it
  forgets are exactly the ones an attacker aims a DNS record at: it knew about
  RFC1918 and loopback but not 192.0.0.0/24, 198.18.0.0/15, 240.0.0.0/4,
  fec0::/10, or the transition prefixes that smuggle a v4 inside a v6 literal.
  Inverting the predicate makes every such omission harmless — a range nobody
  thought of is refused by default, and the burden of proof sits on the address.

  `node:net`'s BlockList does the CIDR matching, which is what keeps the tables
  below declarative: it expands `::`, compares on prefix length rather than on
  text, and unwraps a v4-mapped literal against v4 rules, so nothing here parses
  an address by hand. It is a STATIC import, unlike the deferred
  `import('node:dns/promises')` in `fetchEnvelope`, because the predicate is
  synchronous and both call sites read it that way. That costs nothing: this
  module is only ever loaded on Node — as a Vercel function, through the dev
  server's `ssrLoadModule`, and in the node-environment tests. The browser
  reaches this route over HTTP and never imports it.

*/

/**
 * The IPv4 special-purpose ranges (IANA's registry). None of them is a public
 * destination, whether because it is private (10/8, 172.16/12, 192.168/16),
 * infrastructure (100.64/10, 192.0.0/24), local to the host or link (127/8,
 * 169.254/16 — which is where cloud metadata services sit), documentation or
 * benchmarking (192.0.2/24, 198.18/15, 198.51.100/24, 203.0.113/24), or simply
 * not unicast (224/4, 240/4). 240/4 subsumes the broadcast address
 * 255.255.255.255, so that needs no entry of its own.
 */
const V4_SPECIAL_PURPOSE: readonly [string, number][] = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];

/**
 * Every globally routable IPv6 unicast address lives in 2000::/3. That single
 * membership test is what a v6 denylist can never be: loopback, unspecified,
 * link-local, unique-local, site-local fec0::/10, multicast ff00::/8 and every
 * transition prefix all sit OUTSIDE it, so they are refused without being named.
 */
const V6_GLOBAL_UNICAST: readonly [string, number][] = [['2000::', 3]];

/**
 * The carve-outs inside 2000::/3 that are still not destinations. 2002::/16 is
 * refused OUTRIGHT rather than judged by the v4 it embeds: 6to4 relaying is
 * deprecated (RFC 7526), so nothing this route wants to read is only reachable
 * through it, and refusing the prefix is a smaller rule than unpacking it.
 */
const V6_SPECIAL_PURPOSE: readonly [string, number][] = [
  ['2001::', 32], // Teredo
  ['2001:2::', 48], // benchmarking
  ['2001:10::', 28], // ORCHID (deprecated)
  ['2001:20::', 28], // ORCHIDv2
  ['2001:db8::', 32], // documentation
  ['2002::', 16], // 6to4
];

/**
 * IPv4-mapped IPv6 (`::ffff:a.b.c.d`) — the form `dns.lookup` hands back for an
 * A record on a dual-stack resolve. It names a v4 destination, not a v6 one, so
 * its verdict must be the EMBEDDED v4's; left to the 2000::/3 gate it would fall
 * outside and every mapped public address would be refused.
 *
 * The other two v4-embedding prefixes need no such handling, and deliberately
 * get none. `::/96` (IPv4-compatible, deprecated) and `64:ff9b::/96` (the NAT64
 * well-known prefix) both sit outside 2000::/3, so they are refused whatever
 * they carry — which is the right answer both ways round: a private v4 inside
 * one is an SSRF attempt, and a public v4 inside one is only reachable through a
 * NAT64 gateway this route does not have.
 */
const V6_V4_MAPPED: readonly [string, number][] = [['::ffff:0.0.0.0', 96]];

const blockList = (subnets: readonly [string, number][], type: 'ipv4' | 'ipv6'): BlockList => {
  const list = new BlockList();
  for (const [network, prefix] of subnets) list.addSubnet(network, prefix, type);
  return list;
};

const V4_BLOCKED = blockList(V4_SPECIAL_PURPOSE, 'ipv4');
const V6_ROUTABLE = blockList(V6_GLOBAL_UNICAST, 'ipv6');
const V6_BLOCKED = blockList(V6_SPECIAL_PURPOSE, 'ipv6');
const V6_MAPPED = blockList(V6_V4_MAPPED, 'ipv6');

/**
 * True when an address is a public unicast destination — the only kind this
 * route fetches from. A string that is neither a v4 nor a v6 literal is NOT
 * routable: it cannot be shown to be safe, so it is refused rather than passed
 * through on the assumption that it will fail to connect anyway.
 */
const isGloballyRoutable = (address: string): boolean => {
  if (isIPv4(address)) return !V4_BLOCKED.check(address, 'ipv4');
  if (!isIPv6(address)) return false;
  // BlockList unwraps a v4-mapped literal against its v4 rules, so the embedded
  // address is judged by the v4 table without this file parsing the text itself
  if (V6_MAPPED.check(address, 'ipv6')) return !V4_BLOCKED.check(address, 'ipv6');
  if (!V6_ROUTABLE.check(address, 'ipv6')) return false;
  return !V6_BLOCKED.check(address, 'ipv6');
};

/**
 * True when a resolved address must not be fetched from this route. It keeps its
 * own name because refusal is the decision both call sites are making, and the
 * inversion is where the allowlist meets them.
 */
export const isForbiddenAddress = (address: string): boolean => !isGloballyRoutable(address);

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
