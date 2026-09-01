/*

  BROWSER VANTAGE — checking both attest-back channels from the tab itself

  ORIGIN-BINDING.md defines two attest-back channels, and until now the explorer
  read both through its own serverless route (`/api/binding`), because the tab
  was assumed to be able to do neither: a page cannot open a DNS socket, and
  origins do not reliably send CORS headers on well-knowns. The first half of
  that is a browser limitation and stays true; the second is a per-ORIGIN fact,
  not a rule. Both have a client-side path:

    dns    `_dfos.<host>` TXT over DNS-over-HTTPS. A plain GET returning JSON,
           CORS-enabled at every public resolver — fully portable from a tab.
    https  `/.well-known/dfos-did` fetched DIRECTLY, which succeeds exactly when
           the origin serves `Access-Control-Allow-Origin: *` on it. Most origins
           today do not, and that is not a defect of theirs.

  So each channel now carries a VANTAGE — who established it — and the panel says
  so per row, because "your browser read this" and "our server read this for you"
  are different evidentiary claims and collapsing them would overstate one of
  them. The walk is browser-first: whatever the tab can check itself, it does;
  whatever it cannot, the route fills in; and where NEITHER can reach, the row is
  `not checkable from this browser` — a NEUTRAL state.

  That neutrality is the whole discipline, and it is the same one the verdict fold
  enforces one level up. A CORS refusal is not an answer. It is not an absence
  either: the document may well be sitting there, served correctly, to every
  client except a cross-origin script. Rendering that as "unavailable", "missing"
  or any red word would be the explorer reporting its own reach as the domain's
  failure. Silence is not contradiction; being unable to listen is not even
  silence.

  Mechanically, a not-checkable channel folds into the existing `BindingProbe` as
  `error` — "we could not check" — which the fold already treats as silence, so a
  domain verified over DNS alone reads `bound` with the HTTPS channel simply not
  answering. Only when BOTH channels are unreachable from both vantages does the
  probe become `proxy-unavailable`: nothing at all was learned, and that is a
  statement about us.

  PROVIDERS. Two, tried in order, and the choice is deliberate:

    1. Cloudflare  https://cloudflare-dns.com/dns-query  (1.1.1.1)
    2. Google      https://dns.google/resolve            (8.8.8.8)

  Both speak the same `application/dns-json` shape — a GET with `name` and `type`
  answering `{ Status, Answer: [{ type, data }] }` — so neither needs a wire-format
  library, which keeps this a plain `fetch` under the site's CSP. Both send
  permissive CORS headers, both are independently operated by different companies
  on different networks, and either alone is a single point of failure, so the
  second is tried when the first fails to ANSWER (transport error, off-contract
  body, or a resolver failure code). A definitive answer — including NXDOMAIN,
  which is an answer — is never second-guessed by asking a second resolver: that
  would be shopping for a reply, and the fold's whole discipline is that we report
  what we observed once.

  A resolver is a third party, and using one does not make the browser vantage
  more trustworthy than the route's — it makes it INDEPENDENT of it. Neither
  vantage is authority: the record is public data the domain publishes, the DID it
  carries is checked against a chain that is verified in this tab, and a resolver
  that lied would have to lie in agreement with a signed chain it cannot forge.
  (The responses do carry a DNSSEC `AD` flag. It is not surfaced: the great
  majority of zones are unsigned, so an absent `AD` would render as a warning
  about the ordinary case.)

*/

import {
  fetchBindingAttestation,
  type BindingMethodResult,
  type BindingProbe,
} from './origin-binding';

/** A DFOS DID: the 31-char id alphabet the protocol mints. Mirrors api/binding.ts
 *  — the two parsers must read the same bytes the same way, and the route cannot
 *  be imported here (it is Node-only). */
const DID_RE = /^did:dfos:[2346789acdefhknrtvz]{31}$/;
/** The DNS attestation's exact value form (ORIGIN-BINDING.md, "DNS"). */
const TXT_CLAIM_RE = /^did=(did:dfos:[2346789acdefhknrtvz]{31})$/;
/** ASCII whitespace only — the spec trims ASCII, not Unicode. */
const ASCII_WS_RE = /^[\t\n\f\r ]+|[\t\n\f\r ]+$/g;

const TXT_NAME_PREFIX = '_dfos.';
const WELL_KNOWN_PATH = '/.well-known/dfos-did';
const MAX_BODY_BYTES = 1024;
const TIMEOUT_MS = 8000;

/** The DoH endpoints, in the order they are tried. */
export const DOH_PROVIDERS: readonly { name: string; url: string }[] = [
  { name: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
  { name: 'Google', url: 'https://dns.google/resolve' },
];

// -----------------------------------------------------------------------------
// what one channel established, and from where
// -----------------------------------------------------------------------------

/**
 * Which observer established a channel — or that nobody could.
 *
 * `not-checkable` is NEUTRAL and stays its own thing at every layer: it is not
 * `none` (an observed absence), not `error` about the domain, and never a
 * negative verdict. The browser was refused a read, or a resolver did not answer,
 * and the explorer's route could not stand in. Nothing was observed.
 */
export type ChannelVantage =
  | { kind: 'browser' }
  | { kind: 'route' }
  | { kind: 'not-checkable'; reason: string };

/** One channel, as finally established: the reading, and who did the reading. */
export interface ChannelObservation {
  vantage: ChannelVantage;
  /**
   * What was established, in the `/api/binding` envelope's own vocabulary — so
   * every downstream fold is unchanged whichever vantage produced it. A
   * not-checkable channel carries `error`, which the fold already reads as
   * "could not check", i.e. silence, never contradiction.
   */
  result: BindingMethodResult;
}

/** Both channels, each with its vantage. */
export interface DualChannelProbe {
  https: ChannelObservation;
  dns: ChannelObservation;
}

/** What ONE vantage attempted for one channel, before any fill-in. `not-checkable`
 *  at this layer is narrower than the final state: it means THIS vantage could not
 *  look, which is what licenses asking the other one. */
export type ChannelAttempt =
  | { kind: 'observed'; result: BindingMethodResult }
  | { kind: 'not-checkable'; reason: string };

// -----------------------------------------------------------------------------
// DNS over HTTPS
// -----------------------------------------------------------------------------

/**
 * Unwrap one TXT record's presentation form. A TXT record is a SEQUENCE of
 * character-strings (each capped at 255 bytes), and the JSON APIs hand it back as
 * quoted, space-separated segments: `"first" "second"`. The segments are
 * CONCATENATED, exactly as the route joins Node's chunk array — a record split on
 * the wire is one value, and reading the first segment alone would silently
 * truncate a long one. Bare unquoted data (some resolvers omit quotes on a single
 * short string) is taken as-is.
 */
export const unquoteTxt = (data: string): string => {
  const segments = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) =>
    (m[1] ?? '').replace(/\\(.)/g, '$1'),
  );
  return segments.length > 0 ? segments.join('') : data.trim();
};

/**
 * Fold the `did=` records at a name into a method result — the same reading
 * `parseTxtRecords` does in api/binding.ts, and deliberately identical:
 *
 *   no `did=` record        → `none` (silence: the name may carry other TXT)
 *   more than one           → `contradiction`, whatever the values, INCLUDING two
 *                             records carrying the same DID. The spec forbids
 *                             picking one, and "they happen to agree" is a
 *                             tiebreak by another name.
 *   one, malformed          → `none`. A record that says nothing is a domain
 *                             saying nothing, not a domain contradicting itself.
 */
export const foldTxtClaims = (records: string[]): BindingMethodResult => {
  const claims = records.filter((v) => v.startsWith('did='));
  if (claims.length === 0) {
    return { status: 'none', reason: `no did= TXT record at ${TXT_NAME_PREFIX}<domain>` };
  }
  if (claims.length > 1) return { status: 'contradiction', reason: 'multiple did= records' };
  const match = TXT_CLAIM_RE.exec(claims[0] ?? '');
  if (!match) return { status: 'none', reason: 'the did= record is not a DFOS DID' };
  return { status: 'ok', did: match[1] ?? '' };
};

/**
 * Read one DoH JSON answer. Pure — the network is the caller's problem.
 *
 * `not-checkable` here means THIS RESOLVER did not answer for us (a body outside
 * the contract, or a failure status like SERVFAIL), which licenses trying the
 * next provider. NXDOMAIN and NOERROR are ANSWERS: the name does not exist, or it
 * exists and carries no `did=` TXT. Both are the domain's silence, observed, and
 * asking a second resolver about them would be shopping for a different reply.
 */
export const readDohAnswer = (value: unknown): ChannelAttempt => {
  if (typeof value !== 'object' || value === null) {
    return { kind: 'not-checkable', reason: 'the resolver did not answer with JSON' };
  }
  const rec = value as Record<string, unknown>;
  const status = rec['Status'];
  if (typeof status !== 'number') {
    return { kind: 'not-checkable', reason: 'the resolver answered outside the dns-json contract' };
  }
  // 3 = NXDOMAIN: the name does not exist, which is an answer, and the same
  // answer the route reports as ENOTFOUND
  if (status === 3) {
    return {
      kind: 'observed',
      result: { status: 'none', reason: `no TXT record at ${TXT_NAME_PREFIX}<domain>` },
    };
  }
  if (status !== 0) {
    return { kind: 'not-checkable', reason: `the resolver returned DNS status ${status}` };
  }
  const answer = Array.isArray(rec['Answer']) ? (rec['Answer'] as unknown[]) : [];
  // type 16 is TXT; a CNAME hop (type 5) rides along in the same array and is not
  // a record at this name
  const records = answer
    .filter((e): e is Record<string, unknown> => typeof e === 'object' && e !== null)
    .filter((e) => e['type'] === 16 && typeof e['data'] === 'string')
    .map((e) => unquoteTxt(e['data'] as string));
  return { kind: 'observed', result: foldTxtClaims(records) };
};

/**
 * Query `_dfos.<host>` TXT from the tab, over DNS-over-HTTPS. Providers are tried
 * in order and only until one ANSWERS; a provider that cannot be reached, or
 * answers off-contract, hands over to the next. Exhausting them is not-checkable
 * — never a statement that the domain published nothing.
 */
export const probeDnsFromBrowser = async (host: string): Promise<ChannelAttempt> => {
  const failures: string[] = [];
  for (const provider of DOH_PROVIDERS) {
    const url = `${provider.url}?name=${encodeURIComponent(`${TXT_NAME_PREFIX}${host}`)}&type=TXT`;
    let res: Response;
    try {
      // `accept: application/dns-json` selects the JSON API and is a
      // CORS-safelisted header value, so this stays a simple request — no
      // preflight, nothing for the resolver's CORS policy to refuse
      res = await fetch(url, {
        headers: { accept: 'application/dns-json' },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (e) {
      failures.push(`${provider.name} — ${e instanceof Error ? e.message : 'unreachable'}`);
      continue;
    }
    if (!res.ok) {
      failures.push(`${provider.name} — HTTP ${res.status}`);
      continue;
    }
    let body: unknown;
    try {
      body = (await res.json()) as unknown;
    } catch {
      failures.push(`${provider.name} — the answer was not JSON`);
      continue;
    }
    const read = readDohAnswer(body);
    if (read.kind === 'observed') return read;
    failures.push(`${provider.name} — ${read.reason}`);
  }
  return {
    kind: 'not-checkable',
    reason: `no DNS-over-HTTPS resolver answered (${failures.join('; ')})`,
  };
};

// -----------------------------------------------------------------------------
// the well-known document, fetched directly
// -----------------------------------------------------------------------------

/**
 * Read a 200 body from `/.well-known/dfos-did`. Mirrors `parseDidBody` in
 * api/binding.ts: exactly one DFOS DID after ASCII trimming attests it, and
 * ANYTHING else is `malformed` — a document that is present and answers nothing,
 * which is the third member of ORIGIN-BINDING.md's non-answer class and licenses
 * the app-description fallback exactly as a 404 does.
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
 * Fetch `https://<host>/.well-known/dfos-did` from the tab.
 *
 * Every failure mode a browser has here — a missing `Access-Control-Allow-Origin`
 * header, a preflight refusal, a DNS or TLS failure, a redirect — surfaces as one
 * indistinguishable `TypeError`. The browser will not say which, deliberately, so
 * the explorer does not guess: all of them are `not-checkable`, and the route is
 * asked instead. Reading "no CORS header" as "no document" would be the single
 * most misleading thing this module could do.
 *
 * `redirect: 'error'` keeps the spec's rule that a redirect attests nothing: the
 * attestation must come from the named origin at the fixed path, and a followed
 * hop would let another host answer for this one.
 */
export const probeWellKnownFromBrowser = async (host: string): Promise<ChannelAttempt> => {
  let res: Response;
  try {
    // no custom headers: the browser's default `accept` keeps this a simple
    // request, so an origin that permits the GET is never failed by a preflight
    // it does not answer
    res = await fetch(`https://${host}${WELL_KNOWN_PATH}`, {
      mode: 'cors',
      redirect: 'error',
      cache: 'no-store',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (e) {
    const name = e instanceof Error ? e.name : '';
    if (name === 'TimeoutError' || name === 'AbortError') {
      return { kind: 'not-checkable', reason: 'the origin did not answer in time' };
    }
    return {
      kind: 'not-checkable',
      reason: 'the origin sends no cross-origin permission for this path, or it could not be read',
    };
  }
  if (res.status === 404 || res.status === 410) {
    return {
      kind: 'observed',
      result: {
        status: 'none',
        reason: `the origin serves no ${WELL_KNOWN_PATH} (HTTP ${res.status})`,
      },
    };
  }
  if (!res.ok) {
    return {
      kind: 'observed',
      result: {
        status: 'error',
        httpStatus: res.status,
        reason: 'the origin answered with an error status',
      },
    };
  }
  let text: string;
  try {
    text = await res.text();
  } catch {
    return { kind: 'not-checkable', reason: 'the document could not be read' };
  }
  // a conforming body is under a hundred bytes; anything past the cap is not one,
  // and is not read further
  if (new TextEncoder().encode(text).byteLength > MAX_BODY_BYTES) {
    return {
      kind: 'observed',
      result: { status: 'malformed', reason: 'the document is far larger than one DID' },
    };
  }
  return { kind: 'observed', result: parseDidBody(text) };
};

// -----------------------------------------------------------------------------
// the two vantages, merged
// -----------------------------------------------------------------------------

/** The reading a not-checkable channel contributes to the fold: could-not-check,
 *  which the fold reads as silence. The neutral WORDING lives in the row; this is
 *  only what the verdict machinery sees. */
const notCheckableResult = (reason: string): BindingMethodResult => ({
  status: 'error',
  reason: `not checkable from this browser — ${reason}`,
});

/** Fold one channel's browser attempt and the route's answer for it into the
 *  final observation. Browser-first: the tab's own reading is never overridden by
 *  the route, which is consulted only where the tab could not look. */
export const mergeChannel = (
  browser: ChannelAttempt,
  route: BindingMethodResult | null,
  routeFailure: string | null,
): ChannelObservation => {
  if (browser.kind === 'observed') {
    return { vantage: { kind: 'browser' }, result: browser.result };
  }
  if (route !== null) return { vantage: { kind: 'route' }, result: route };
  const reason =
    routeFailure === null
      ? browser.reason
      : `${browser.reason}, and the explorer's lookup route did not answer either (${routeFailure})`;
  return { vantage: { kind: 'not-checkable', reason }, result: notCheckableResult(reason) };
};

/**
 * Check both attest-back channels, browser-first.
 *
 * The tab tries both itself; the route is consulted ONLY when a channel came back
 * not-checkable, which spares a third-party lookup on the domains that can be read
 * directly and keeps the route as what it now is — the fill-in vantage, not the
 * only one.
 */
export const probeBindingChannels = async (host: string): Promise<DualChannelProbe> => {
  const [https, dns] = await Promise.all([
    probeWellKnownFromBrowser(host),
    probeDnsFromBrowser(host),
  ]);

  let routeHttps: BindingMethodResult | null = null;
  let routeDns: BindingMethodResult | null = null;
  let routeFailure: string | null = null;
  if (https.kind === 'not-checkable' || dns.kind === 'not-checkable') {
    const probe = await fetchBindingAttestation(host);
    if (probe.kind === 'answered') {
      routeHttps = probe.https;
      routeDns = probe.dns;
    } else {
      routeFailure = probe.reason;
    }
  }

  return {
    https: mergeChannel(https, https.kind === 'not-checkable' ? routeHttps : null, routeFailure),
    dns: mergeChannel(dns, dns.kind === 'not-checkable' ? routeDns : null, routeFailure),
  };
};

/**
 * Bridge the two-vantage reading into the `BindingProbe` the verdict folds
 * consume, unchanged.
 *
 * The one structural rule: when NEITHER channel could be checked from either
 * vantage, nothing at all was observed, and the probe is `proxy-unavailable` — OUR
 * state. Letting two unreachable channels fold to `stale` would print "this domain
 * attests no identity" on the strength of never having asked.
 */
export const probeFromChannels = (channels: DualChannelProbe): BindingProbe => {
  if (
    channels.https.vantage.kind === 'not-checkable' &&
    channels.dns.vantage.kind === 'not-checkable'
  ) {
    return {
      kind: 'proxy-unavailable',
      reason: 'neither channel could be checked from your browser or the explorer’s lookup route',
    };
  }
  return { kind: 'answered', https: channels.https.result, dns: channels.dns.result };
};
