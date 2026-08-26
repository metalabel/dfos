/*

  ORIGIN BINDING — the chain's domain claim, checked against the domain's answer

  ORIGIN-BINDING.md defines a BIDIRECTIONAL binding: the identity chain names a
  domain in a signed `DfosOrigin` services entry, and the domain attests the DID
  back over HTTPS (`/.well-known/dfos-did`) or DNS (a `_dfos` TXT record). Each
  half alone is a claim anyone could publish; only the PAIR proves one party
  controls both. This module is the pure logic behind the identity view's binding
  panel — claim reading, probe classification, and the verdict fold. The view owns
  the async orchestration and the rendering; nothing here touches the DOM.

  The chain half is already in hand (the identity view resolved and verified the
  chain before this runs). The domain half arrives through `/api/binding`, the
  second serverless route, because a tab can do neither method honestly: origins
  do not reliably send CORS headers, and a browser cannot query DNS at all.

  Three verdicts, and keeping them distinguishable is the whole discipline:

    bound   — at least one method attests EXACTLY this DID, and no method answers
              with anything else
    stale   — the chain names a domain and the domain is SILENT (absent record,
              absent document, or the lookups failed). Legal, and displayable.
    broken  — a method answers a DIFFERENT DID, the methods disagree, or the DNS
              name carries multiple did= records

  Silence is never contradiction (ORIGIN-BINDING.md, "Verdicts must stay
  machine-distinguishable"): reporting `stale` as `broken` turns a hosting blip
  into a public accusation, and reporting `broken` as `stale` hides a hijack. Our
  OWN route failing is a fourth state — `proxy-unavailable` — for the same reason
  the domain view keeps it separate: we cannot attribute to a third-party domain a
  fault we observed in our own infrastructure.

*/

import type { ServiceEntry } from '@metalabel/dfos-protocol/chain';
import { fetchAppDocument, validateStructure } from './wellknown';

/** The `DfosOrigin` service type this spec registers under the open namespace. */
export const ORIGIN_SERVICE_TYPE = 'DfosOrigin';

/**
 * A bare lowercase hostname: no scheme, no port, no path, no trailing dot, and
 * an internationalized name in its A-label form. ORIGIN-BINDING.md makes every
 * comparison an exact byte comparison of this string, so — unlike the proxy's
 * `validateHostname`, which NORMALIZES a caller's input — nothing is trimmed,
 * lowercased, or dot-stripped here. A domain that needs normalizing to pass is a
 * domain the chain wrote wrong, and it claims nothing.
 */
const BARE_HOSTNAME_RE = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

/** True when a string is the exact bare-hostname form the spec's `domain` takes. */
export const isBareHostname = (value: unknown): value is string =>
  typeof value === 'string' && BARE_HOSTNAME_RE.test(value);

// -----------------------------------------------------------------------------
// the chain half — reading the claim out of verified services state
// -----------------------------------------------------------------------------

/**
 * What the chain claims. `ambiguous` is deliberately NOT broken: more than one
 * `DfosOrigin` entry means the identity claims no binding at all ("an ambiguous
 * claim is no claim"), and contradiction verdicts are reserved for the domain's
 * side, where a second party is being contradicted.
 */
export type OriginClaim =
  | { kind: 'claimed'; domain: string }
  | { kind: 'unclaimed' }
  | { kind: 'ambiguous'; count: number };

/**
 * Read the `DfosOrigin` claim out of an identity's services. Structural
 * validation of the entry is a CONSUMER obligation under this spec — a core
 * verifier preserves the entry verbatim and never looks inside it — so it
 * happens here, and an entry whose `domain` is missing, empty, or not a bare
 * hostname claims nothing.
 */
export const readOriginClaim = (services: ServiceEntry[]): OriginClaim => {
  const entries = services.filter((e) => e.type === ORIGIN_SERVICE_TYPE);
  if (entries.length === 0) return { kind: 'unclaimed' };
  // counted by ENTRY, not by valid entry: two entries are ambiguous even when
  // only one of them parses, because the identity still named two things
  if (entries.length > 1) return { kind: 'ambiguous', count: entries.length };
  const domain = (entries[0] as unknown as Record<string, unknown>)['domain'];
  if (!isBareHostname(domain)) return { kind: 'unclaimed' };
  return { kind: 'claimed', domain };
};

// -----------------------------------------------------------------------------
// the domain half — the /api/binding contract
// -----------------------------------------------------------------------------

/** The per-method statuses `/api/binding` answers with (api/binding.ts). */
export type BindingMethodStatus =
  | 'ok'
  | 'none'
  | 'malformed'
  | 'contradiction'
  | 'error'
  | 'refused';

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

/** Which method spoke. `app-fallback` is an HTTPS answer by another document. */
export type BindingMethod = 'https' | 'dns' | 'app-fallback';

/**
 * What a probe attempt established. `proxy-unavailable` is its own outcome and
 * never collapses into silence: in dev (vite, no serverless route) the fetch 404s
 * or answers HTML, and reporting that as "this domain is silent" would be the
 * explorer inventing an observation it never made — and `stale` is a claim about
 * the DOMAIN.
 */
export type BindingProbe =
  | { kind: 'answered'; https: BindingMethodResult; dns: BindingMethodResult }
  | { kind: 'proxy-unavailable'; reason: string };

/** Coerce one member of the envelope, defensively — anything off-contract is a
 *  proxy fault, signalled by returning null so the caller can say so. */
const readMethod = (value: unknown): BindingMethodResult | null => {
  if (typeof value !== 'object' || value === null) return null;
  const rec = value as Record<string, unknown>;
  const reason = typeof rec['reason'] === 'string' ? rec['reason'] : undefined;
  const httpStatus = typeof rec['httpStatus'] === 'number' ? rec['httpStatus'] : undefined;
  switch (rec['status'] as BindingMethodStatus) {
    case 'ok':
      return typeof rec['did'] === 'string' && rec['did']
        ? { status: 'ok', did: rec['did'] }
        : null;
    case 'none':
      return { status: 'none', ...(reason ? { reason } : {}) };
    case 'malformed':
      return { status: 'malformed', reason: reason ?? 'the answer is not a DFOS DID' };
    case 'contradiction':
      return { status: 'contradiction', reason: reason ?? 'the domain answered more than once' };
    case 'error':
      return {
        status: 'error',
        ...(reason ? { reason } : {}),
        ...(httpStatus !== undefined ? { httpStatus } : {}),
      };
    case 'refused':
      return { status: 'refused', reason: reason ?? 'the lookup was refused before it left' };
    default:
      return null;
  }
};

/**
 * Classify a parsed `/api/binding` envelope. Pure — the view does the fetching,
 * this decides what was actually established. An envelope that does not match the
 * contract is `proxy-unavailable`, not a statement about the DOMAIN.
 */
export const classifyBindingEnvelope = (value: unknown): BindingProbe => {
  if (typeof value !== 'object' || value === null) {
    return { kind: 'proxy-unavailable', reason: 'the binding route did not answer with JSON' };
  }
  const rec = value as Record<string, unknown>;
  const https = readMethod(rec['https']);
  const dns = readMethod(rec['dns']);
  if (https === null || dns === null) {
    return { kind: 'proxy-unavailable', reason: 'the binding route answered outside its contract' };
  }
  return { kind: 'answered', https, dns };
};

/**
 * Run both attest-back methods through the proxy. The ONLY rejection path is the
 * proxy itself being unreachable or answering off-contract — everything about the
 * third-party domain arrives inside the envelope.
 */
export const fetchBindingAttestation = async (host: string): Promise<BindingProbe> => {
  let res: Response;
  try {
    res = await fetch(`/api/binding?host=${encodeURIComponent(host)}`, {
      signal: AbortSignal.timeout(20000),
    });
  } catch (e) {
    return {
      kind: 'proxy-unavailable',
      reason: e instanceof Error ? e.message : 'the binding route could not be reached',
    };
  }
  // a dev server (or a misrouted deploy) answers 404/HTML here — off-contract,
  // and emphatically not evidence about the domain
  if (!res.ok) {
    return { kind: 'proxy-unavailable', reason: `the binding route answered ${res.status}` };
  }
  try {
    return classifyBindingEnvelope((await res.json()) as unknown);
  } catch {
    return { kind: 'proxy-unavailable', reason: 'the binding route did not answer with JSON' };
  }
};

// -----------------------------------------------------------------------------
// the app-description fallback — MUST, and only on ABSENCE
// -----------------------------------------------------------------------------

/**
 * What the SIWD app description said when consulted. It is consulted only when
 * `/.well-known/dfos-did` is ABSENT: a document that is present but says
 * something else is a contradiction, and must not be fallen through.
 *
 * `answers-other` is not a near-miss — it is an HTTPS answer naming a different
 * DID, which is exactly what `broken` is for.
 */
export type FallbackResult =
  | { kind: 'attests'; did: string }
  | { kind: 'answers-other'; did: string }
  | { kind: 'silent'; reason: string };

/**
 * Fetch `/.well-known/dfos-app.json` and read its `client_did`. Rung 1 does the
 * fetching and the structural validation; nothing is duplicated here.
 *
 * The bar is deliberately the SPEC's bar and no higher: "a structurally valid
 * document whose `client_did` names the candidate DID attests it, exactly as the
 * well-known file would." Chain carriage is optional in the document and is NOT
 * required for the attestation — the domain serving the file is what attests,
 * the same doctrine that makes serving the file the registration.
 */
export const runAppFallback = async (host: string, candidate: string): Promise<FallbackResult> => {
  const outcome = await fetchAppDocument(host);
  if (outcome.kind === 'proxy-unavailable') {
    return {
      kind: 'silent',
      reason: `the app-description lookup route failed — ${outcome.reason}`,
    };
  }
  if (outcome.kind === 'unreachable') {
    return { kind: 'silent', reason: outcome.reason };
  }
  if (outcome.kind === 'no-app-description') {
    return { kind: 'silent', reason: 'the origin serves no app description either' };
  }
  const structural = validateStructure(outcome.document);
  if (!structural.ok) {
    return { kind: 'silent', reason: 'the app description is not structurally valid' };
  }
  const clientDid = structural.app.client_did;
  if (typeof clientDid !== 'string' || clientDid === '') {
    return { kind: 'silent', reason: 'the app description declares no client_did' };
  }
  return clientDid === candidate
    ? { kind: 'attests', did: clientDid }
    : { kind: 'answers-other', did: clientDid };
};

/**
 * True when the app-description fallback is eligible: the HTTPS well-known was
 * ABSENT. The spec's trigger is literal — "if /.well-known/dfos-did is absent (a
 * 404)" — so nothing weaker qualifies:
 *
 *   malformed — the document EXISTS (presence without an answer)
 *   error     — we never established anything, redirects included: an origin
 *               that redirects has not shown us the document is missing
 *
 * The stakes are the stale/broken split. Falling back on a non-absence lets a
 * dfos-app.json naming another DID turn a should-be-`stale` binding into a
 * public accusation of `broken`, which is exactly the over-accusation the
 * silence-is-not-contradiction discipline exists to prevent.
 */
export const fallbackEligible = (probe: BindingProbe): boolean =>
  probe.kind === 'answered' && probe.https.status === 'none';

// -----------------------------------------------------------------------------
// the fold
// -----------------------------------------------------------------------------

export type BindingVerdict =
  /** the chain claims nothing — there is nothing to check */
  | { kind: 'none'; claim: 'unclaimed' | 'ambiguous' }
  /** at least one method attests exactly this DID, and nothing answers otherwise */
  | { kind: 'bound'; domain: string; attestedBy: BindingMethod[]; silences: string[] }
  /** the claim stands and the domain is silent — legal, and displayable as such */
  | { kind: 'stale'; domain: string; reasons: string[] }
  /** a method answers a DIFFERENT DID, the methods disagree, or DNS contradicts */
  | { kind: 'broken'; domain: string; details: string[] }
  /** OUR route failed — never rendered as a statement about the domain */
  | { kind: 'proxy-unavailable'; domain: string; reason: string };

/** One method's contribution to the fold: an attestation, a contradiction, or
 *  silence. Only methods that ANSWERED participate in agreement. */
const foldMethod = (
  label: 'https' | 'dns',
  result: BindingMethodResult,
  candidate: string,
  attested: BindingMethod[],
  details: string[],
  silences: string[],
): void => {
  switch (result.status) {
    case 'ok':
      if (result.did === candidate) attested.push(label);
      else details.push(`${label} attests a different identity — ${result.did}`);
      return;
    case 'contradiction':
      details.push(`${label} — ${result.reason}`);
      return;
    case 'malformed':
      // present without an answer: silence for the verdict, and the caller has
      // already declined to fall back because the document exists
      silences.push(`${label} — ${result.reason}`);
      return;
    case 'none':
      silences.push(`${label} — ${result.reason ?? 'nothing published'}`);
      return;
    case 'error':
      silences.push(
        `${label} — ${result.reason ?? 'the lookup failed'}${
          result.httpStatus !== undefined ? ` (HTTP ${result.httpStatus})` : ''
        }`,
      );
      return;
    case 'refused':
      silences.push(`${label} — ${result.reason}`);
      return;
  }
};

/**
 * Fold a claim, a probe, and an optional fallback into ONE verdict.
 *
 * Pure and total. The order of the tests is the spec's order of severity:
 * contradiction outranks attestation (a domain that says two things is broken
 * even if one of them is right), attestation outranks silence, and silence with a
 * standing claim is stale. Agreement is required only among the methods that
 * ACTUALLY ANSWERED — an unanswered method is never evidence of anything.
 */
export const assessBinding = (
  did: string,
  claim: OriginClaim,
  probe: BindingProbe,
  fallback?: FallbackResult,
): BindingVerdict => {
  if (claim.kind === 'unclaimed') return { kind: 'none', claim: 'unclaimed' };
  if (claim.kind === 'ambiguous') return { kind: 'none', claim: 'ambiguous' };
  const domain = claim.domain;

  if (probe.kind === 'proxy-unavailable') {
    return { kind: 'proxy-unavailable', domain, reason: probe.reason };
  }

  const attested: BindingMethod[] = [];
  const details: string[] = [];
  const silences: string[] = [];

  foldMethod('https', probe.https, did, attested, details, silences);
  foldMethod('dns', probe.dns, did, attested, details, silences);

  if (fallback) {
    if (fallback.kind === 'attests') attested.push('app-fallback');
    else if (fallback.kind === 'answers-other') {
      details.push(
        `the app description at this origin names a different identity — ${fallback.did}`,
      );
    } else silences.push(`app-fallback — ${fallback.reason}`);
  }

  // a contradiction anywhere is the verdict: never a tiebreak, never averaged
  // against an attestation that happens to agree
  if (details.length > 0) return { kind: 'broken', domain, details };
  if (attested.length > 0) return { kind: 'bound', domain, attestedBy: attested, silences };
  return { kind: 'stale', domain, reasons: silences };
};
