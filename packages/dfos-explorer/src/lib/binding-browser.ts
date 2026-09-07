/*

  BROWSER VANTAGE — checking both attest-back channels from the tab itself

  INTEGRATIONS.md, Attest-back: the domain's half defines two attest-back
  channels, and until now the explorer
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

// The PURE half is shared with the serverless route rather than mirrored: two
// copies of the same regexes drifted, and only one of them was ever checked
// against the Go CLI. `api/binding-parse.ts` carries no node builtins, so the
// bundler pulls it into the tab like any other module.
import {
  classifyDidStatus,
  foldTxtClaims,
  MAX_BODY_BYTES,
  parseDidBody,
  TXT_NAME_PREFIX,
  WELL_KNOWN_PATH,
} from '../../api/binding-parse.js';
import {
  fetchBindingAttestation,
  type BindingMethodResult,
  type BindingProbe,
} from './origin-binding';

export { foldTxtClaims, parseDidBody };

const TIMEOUT_MS = 8000;

/** The over-cap signal, thrown by {@link boundedText} and read by its one caller. */
const OVER_CAP = 'over-cap';

/**
 * Read a response body as text UNDER the byte cap, throwing {@link OVER_CAP} past
 * it. The mirror of `api/binding.ts`'s `boundedText`, and the reason it is a
 * streamed read rather than `res.text()` followed by a measurement: the cap has
 * to bound the MEMORY, not just the verdict. A declared content-length over the
 * cap is refused before a byte is read; otherwise the reader is cancelled the
 * moment the running total passes it, so a fast origin cannot push an unbounded
 * body into the tab. `AbortSignal.timeout` bounds duration only.
 */
const boundedText = async (res: Response): Promise<string> => {
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > MAX_BODY_BYTES) throw new Error(OVER_CAP);
  const reader = res.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new Error(OVER_CAP);
    }
    chunks.push(value);
  }
  const joined = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    joined.set(chunk, at);
    at += chunk.byteLength;
  }
  return new TextDecoder().decode(joined);
};

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
  // ONLY A 200 REACHES THE BODY — the route and the Go CLI both draw the line
  // there, so a 201 carrying a valid DID is silence in all three, not a binding
  const byStatus = classifyDidStatus(res.status);
  if (byStatus !== null) return { kind: 'observed', result: byStatus };
  let text: string;
  try {
    text = await boundedText(res);
  } catch (e) {
    // a conforming body is under a hundred bytes; anything past the cap is not
    // one, and the read was ABANDONED at the cap rather than measured after the
    // fact — see boundedText
    if (e instanceof Error && e.message === OVER_CAP) {
      return {
        kind: 'observed',
        result: { status: 'malformed', reason: 'the document is far larger than one DID' },
      };
    }
    return { kind: 'not-checkable', reason: 'the document could not be read' };
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
