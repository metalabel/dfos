/*

  ORIGIN BINDING — the chain's domain claim, checked against the domain's answer

  ORIGIN-BINDING.md defines a BIDIRECTIONAL binding: the identity chain names a
  domain in a signed `DfosOrigin` services entry, and the domain attests the DID
  back over HTTPS (`/.well-known/dfos-did`) or DNS (a `_dfos` TXT record). Each
  half alone is a claim anyone could publish; only the PAIR proves one party
  controls both. This module is the pure logic behind BOTH binding panels — the
  identity view's (chain-first) and the domain view's (domain-first) — claim
  reading, probe classification, and the two verdict folds. The views own the
  async orchestration and the rendering; nothing here touches the DOM.

  The walk runs in both directions, and the direction only changes which half is
  in hand first:

    chain-first   the identity's verified services name a domain; ask the domain
                  (`assessBinding`)
    domain-first  the domain attests a DID; resolve that DID's chain and require
                  it to name this exact domain back (`assessDomainBinding`)

  Both are the same walk `dfos identity verify-binding` runs, and this module
  mirrors that CLI's semantics deliberately — including its half-states.

  The chain half is always a chain the caller RESOLVED AND VERIFIED first —
  whichever direction the walk runs, a relay-asserted services set is not a signed
  claim. The domain half arrives through `/api/binding`, the second serverless
  route, because a tab can do neither method honestly: origins do not reliably
  send CORS headers, and a browser cannot query DNS at all.

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
  | 'redirected'
  | 'malformed'
  | 'contradiction'
  | 'error'
  | 'refused';

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
    case 'redirected':
      return typeof rec['httpStatus'] === 'number'
        ? {
            status: 'redirected',
            httpStatus: rec['httpStatus'],
            reason: reason ?? 'the origin redirected; redirects are not followed',
          }
        : null;
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
// the app-description fallback — MUST, and only on a NON-ANSWER
// -----------------------------------------------------------------------------

/**
 * What the SIWD app description said when consulted. It is consulted only when
 * `/.well-known/dfos-did` yielded a NON-ANSWER — absence, a redirect, or a body
 * that is not a DID. A document that ANSWERS with a different DID is a
 * contradiction and must not be fallen through.
 *
 * `answers-other` is not a near-miss — it is an HTTPS answer naming a different
 * DID, which is exactly what `broken` is for.
 */
export type FallbackResult =
  | { kind: 'attests'; did: string }
  | { kind: 'answers-other'; did: string }
  | { kind: 'silent'; reason: string };

/**
 * What the app description answered ON ITS OWN TERMS, with no candidate DID in
 * hand. The domain-first walk needs exactly this: when the origin publishes
 * nothing but its app description, that document's `client_did` IS the candidate,
 * and there is nothing yet to compare it against.
 */
export type AppAttestation = { kind: 'answers'; did: string } | { kind: 'silent'; reason: string };

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
export const readAppAttestation = async (host: string): Promise<AppAttestation> => {
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
  // a redirect here is silence for exactly the reason it is silence on the
  // dfos-did channel (api/binding.ts): the document must come from this origin at
  // the fixed path, so an origin that redirects has shown us nothing to attest
  // with — and nothing this fallback may treat as an answer
  if (outcome.kind === 'redirected') {
    return {
      kind: 'silent',
      reason: 'the origin redirects at the app-description path — a redirect is a non-answer',
    };
  }
  const structural = validateStructure(outcome.document);
  if (!structural.ok) {
    return { kind: 'silent', reason: 'the app description is not structurally valid' };
  }
  const clientDid = structural.app.client_did;
  if (typeof clientDid !== 'string' || clientDid === '') {
    return { kind: 'silent', reason: 'the app description declares no client_did' };
  }
  return { kind: 'answers', did: clientDid };
};

/** Judge an app-description answer against the candidate it is meant to attest.
 *  Split from the fetch so the domain-first walk can read the same document
 *  BEFORE it has a candidate, and judge it once the chain resolves. */
export const appFallbackAgainst = (answer: AppAttestation, candidate: string): FallbackResult =>
  answer.kind === 'silent'
    ? answer
    : answer.did === candidate
      ? { kind: 'attests', did: answer.did }
      : { kind: 'answers-other', did: answer.did };

/** The chain-first fallback: read the document, then judge it against the DID the
 *  chain already proved. */
export const runAppFallback = async (host: string, candidate: string): Promise<FallbackResult> =>
  appFallbackAgainst(await readAppAttestation(host), candidate);

/**
 * True when the app-description fallback is eligible: the HTTPS well-known
 * yielded a NON-ANSWER. The spec's trigger is the class, and it names all three
 * members — ORIGIN-BINDING.md, "App-description fallback": "If
 * /.well-known/dfos-did yields a **non-answer** — a `404`; a redirect, which is
 * absence in everything but status code; or a `200` whose trimmed body is not
 * exactly one DFOS DID, the shape a host serving its application shell for every
 * unknown path produces — a verifier MUST fall back."
 *
 *   none        the 404
 *   redirected  the redirect. "A verifier that receives any 3xx therefore treats
 *               the path exactly as it treats absence."
 *   malformed   the 200 that is not a DID
 *
 * What stays OUT is a query FAILURE, which the spec lists as its own class in the
 * stale row — "or the queries fail (network error, TLS failure, timeout, server
 * error)" — separately from the non-answers. A 5xx, a timeout, or a refusal is
 * not the origin declining to answer at the path; it is us never having seen the
 * path, and an unobserved channel licenses nothing.
 *
 * THE CONSEQUENCE, KEPT DELIBERATELY: a fallback document naming a DIFFERENT DID
 * now produces `broken` where this used to stop at silence. That is the spec's
 * intent, not a regression of the stale/broken discipline. The never-`broken`
 * clause attached to redirects is about NO channel answering ("if no channel
 * answers, the verdict is the silent one (stale) … never broken, because nothing
 * contradicted anything"); a fallback that answers with another identity IS a
 * channel answering, and the spec routes it to the contradiction verdict — "a
 * body that **is** exactly one DFOS DID naming a different DID is a
 * contradiction, and MUST NOT be fallen through" governs what the fallback may be
 * reached PAST, not what its own answer means once reached.
 */
export const fallbackEligible = (probe: BindingProbe): boolean =>
  probe.kind === 'answered' &&
  (probe.https.status === 'none' ||
    probe.https.status === 'redirected' ||
    probe.https.status === 'malformed');

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

/**
 * What ONE channel established, before any DID is compared: an answer, a
 * self-contradiction, or silence. Reading and JUDGING are split because the two
 * walks judge against different things — the chain-first walk against the DID the
 * chain already proved, the domain-first walk against the other channels first
 * and the resolved chain second — while what each channel SAID is the same
 * reading either way.
 */
type ChannelReading =
  | { kind: 'answer'; method: BindingMethod; did: string }
  | { kind: 'contradiction'; detail: string }
  | { kind: 'silence'; detail: string };

const readChannel = (label: 'https' | 'dns', result: BindingMethodResult): ChannelReading => {
  switch (result.status) {
    case 'ok':
      return { kind: 'answer', method: label, did: result.did };
    case 'contradiction':
      return { kind: 'contradiction', detail: `${label} — ${result.reason}` };
    case 'redirected':
      // a non-answer: the origin declined to answer at the path. Silence for the
      // verdict, and the row keeps the true reason rather than reading as absence
      return { kind: 'silence', detail: `${label} — ${result.reason} (HTTP ${result.httpStatus})` };
    case 'malformed':
      // present without an answer: silence for the verdict, and — since #400's
      // non-answer class — the caller has already fallen through to the app
      // description, because a body that is not a DID answered nothing
      return { kind: 'silence', detail: `${label} — ${result.reason}` };
    case 'none':
      return { kind: 'silence', detail: `${label} — ${result.reason ?? 'nothing published'}` };
    case 'error':
      return {
        kind: 'silence',
        detail: `${label} — ${result.reason ?? 'the lookup failed'}${
          result.httpStatus !== undefined ? ` (HTTP ${result.httpStatus})` : ''
        }`,
      };
    case 'refused':
      return { kind: 'silence', detail: `${label} — ${result.reason}` };
  }
};

/** One channel's contribution to the chain-first fold, judged against the DID the
 *  chain proved. Only channels that ANSWERED participate in agreement. */
const foldMethod = (
  label: 'https' | 'dns',
  result: BindingMethodResult,
  candidate: string,
  attested: BindingMethod[],
  details: string[],
  silences: string[],
): void => {
  const reading = readChannel(label, result);
  switch (reading.kind) {
    case 'answer':
      if (reading.did === candidate) attested.push(reading.method);
      else details.push(`${label} attests a different identity — ${reading.did}`);
      return;
    case 'contradiction':
      details.push(reading.detail);
      return;
    case 'silence':
      silences.push(reading.detail);
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

// -----------------------------------------------------------------------------
// the domain-first walk
// -----------------------------------------------------------------------------

/**
 * The attested identity's chain, as the domain-first walk got it. `unavailable`
 * is COULD NOT CHECK — no relay served the chain, or it failed verification here
 * — and it is deliberately not the same statement as a chain that resolved and
 * claims nothing. One is an absent answer; the other is an answer.
 */
export type AttestedChain =
  | { kind: 'verified'; did: string; services: ServiceEntry[] }
  | { kind: 'unavailable'; did: string; reason: string };

/**
 * What a DOMAIN lookup established about origin binding. The three spec verdicts
 * plus the proxy state, and two half-states that mirror the CLI's domain-first
 * walk (`verifyBindingFromDomain` in packages/dfos-cli):
 *
 *   bound             the domain attests a DID, that DID's chain verifies, and it
 *                     names this exact domain back
 *   broken            the domain contradicts itself (a channel carrying two
 *                     answers, or two channels answering differently), or the
 *                     attested identity's chain claims a DIFFERENT domain — the
 *                     CLI's "the two halves name different domains"
 *   stale             the domain publishes no attestation at all, so no binding
 *                     could be checked. Silence, and silence is not contradiction
 *   chain-unavailable the domain attests a DID and that identity would not
 *                     resolve. COULD NOT CHECK — the CLI exits with an error here
 *                     rather than a verdict, for exactly this reason
 *   no-chain-claim    the attested identity resolved and its verified chain claims
 *                     no domain (none, or an ambiguous set). CHECKED AND ABSENT —
 *                     an attestation without a chain claim is not a binding
 *   proxy-unavailable OUR route failed. Never a statement about the domain
 */
export type DomainBinding =
  | {
      kind: 'bound';
      domain: string;
      did: string;
      attestedBy: BindingMethod[];
      silences: string[];
    }
  | { kind: 'broken'; domain: string; did: string | null; details: string[] }
  | { kind: 'stale'; domain: string; reasons: string[] }
  | { kind: 'chain-unavailable'; domain: string; did: string; reason: string }
  | { kind: 'no-chain-claim'; domain: string; did: string; claim: 'unclaimed' | 'ambiguous' }
  | { kind: 'proxy-unavailable'; domain: string; reason: string };

/** Every channel that ANSWERED, in the CLI's fixed order: the HTTPS slot first
 *  (the well-known document, or the app description standing in for it on a
 *  non-answer), then DNS. Order makes the output stable; it never wins a
 *  disagreement. */
const domainAnswers = (
  probe: Extract<BindingProbe, { kind: 'answered' }>,
  fallback: AppAttestation | undefined,
): {
  answers: { method: BindingMethod; did: string }[];
  details: string[];
  silences: string[];
} => {
  const readings: ChannelReading[] = [readChannel('https', probe.https)];
  if (fallback) {
    readings.push(
      fallback.kind === 'answers'
        ? { kind: 'answer', method: 'app-fallback', did: fallback.did }
        : { kind: 'silence', detail: `app-fallback — ${fallback.reason}` },
    );
  }
  readings.push(readChannel('dns', probe.dns));

  const answers: { method: BindingMethod; did: string }[] = [];
  const details: string[] = [];
  const silences: string[] = [];
  for (const reading of readings) {
    if (reading.kind === 'answer') answers.push({ method: reading.method, did: reading.did });
    else if (reading.kind === 'contradiction') details.push(reading.detail);
    else silences.push(reading.detail);
  }
  return { answers, details, silences };
};

/**
 * The DID the domain attests, or null when it attests nothing. The first channel
 * that answered wins the CANDIDATE slot only — disagreement between channels is
 * caught by the fold as a contradiction, never resolved by this order.
 */
export const attestedCandidate = (
  probe: BindingProbe,
  fallback?: AppAttestation,
): string | null => {
  if (probe.kind === 'proxy-unavailable') return null;
  return domainAnswers(probe, fallback).answers[0]?.did ?? null;
};

/**
 * Fold a domain's attestation and the attested identity's chain into ONE verdict.
 *
 * Pure and total, and a direct mirror of the CLI's `verifyBindingFromDomain`:
 *
 *   1. our own route failing is our own state, first and always
 *   2. a domain that contradicts ITSELF is broken before any chain is resolved
 *   3. no channel answers → nothing was published, so nothing could be checked
 *   4. the attested chain must RESOLVE (else could-not-check) and must CLAIM a
 *      domain (else checked-and-absent: half a binding is no binding)
 *   5. that claim must be this exact host, byte for byte — a claim naming another
 *      domain is the two halves naming different things, which is broken
 *   6. and then the ordinary fold against the resolved chain's DID
 *
 * `chain` is null only before a candidate exists; the caller resolves the chain
 * for whatever `attestedCandidate` returned.
 */
export const assessDomainBinding = (
  domain: string,
  probe: BindingProbe,
  fallback: AppAttestation | undefined,
  chain: AttestedChain | null,
): DomainBinding => {
  if (probe.kind === 'proxy-unavailable') {
    return { kind: 'proxy-unavailable', domain, reason: probe.reason };
  }

  const { answers, details, silences } = domainAnswers(probe, fallback);

  // a domain that says two things is broken before anything else is asked: a
  // channel contradicting itself, or two channels answering differently. Never a
  // tiebreak, never first-checked-wins.
  if (answers.some((a) => a.did !== answers[0]?.did)) {
    details.push(
      `the channels attest different identities — ${answers
        .map((a) => `${a.method} ${a.did}`)
        .join(', ')}`,
    );
  }
  if (details.length > 0) return { kind: 'broken', domain, did: null, details };

  const candidate = answers[0]?.did;
  if (candidate === undefined) {
    // nothing published at all: unverifiable, not contradicted
    return { kind: 'stale', domain, reasons: silences };
  }

  if (chain === null || chain.kind === 'unavailable') {
    return {
      kind: 'chain-unavailable',
      domain,
      did: candidate,
      reason: chain?.reason ?? 'the attested identity was not resolved',
    };
  }

  const claim = readOriginClaim(chain.services);
  if (claim.kind !== 'claimed')
    return { kind: 'no-chain-claim', domain, did: chain.did, claim: claim.kind };
  if (claim.domain !== domain) {
    return {
      kind: 'broken',
      domain,
      did: chain.did,
      details: [
        `${domain} attests this identity, and its chain claims ${claim.domain} — the two halves name different domains`,
      ],
    };
  }

  // the ordinary fold, now against the DID the chain actually derived
  const attested: BindingMethod[] = [];
  const mismatched: string[] = [];
  for (const a of answers) {
    if (a.did === chain.did) attested.push(a.method);
    else mismatched.push(`${a.method} attests a different identity — ${a.did}`);
  }
  if (mismatched.length > 0) {
    return { kind: 'broken', domain, did: chain.did, details: mismatched };
  }
  return { kind: 'bound', domain, did: chain.did, attestedBy: attested, silences };
};

/**
 * True when the domain published something and the binding therefore has a story
 * to tell. Silence and our own route failing are not stories: the domain view
 * keeps them to one quiet line rather than a headline panel, because neither is
 * an observation ABOUT this domain's binding.
 */
export const domainBindingSpeaks = (binding: DomainBinding | null): boolean =>
  binding !== null && binding.kind !== 'stale' && binding.kind !== 'proxy-unavailable';
