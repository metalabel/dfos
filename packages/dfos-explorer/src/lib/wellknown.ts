/*

  WELL-KNOWN — app description documents, verified honestly

  An origin's `/.well-known/dfos-app.json` is the one place a DOMAIN vouches for
  a DFOS identity: serving the file IS the registration (SIWD.md, "The App
  Description Document"). This module is the pure logic behind the domain view —
  fetch classification, structural validation, chain verification, and the
  ordered-log comparison against what the relays hold. The view owns the async
  orchestration and the rendering; nothing here touches the DOM.

  The explorer reaches the origin through a serverless route
  (`/api/wellknown`), which exists solely because third-party origins do not
  reliably send CORS headers on well-knowns. The route is a stateless fetch
  proxy: it stores nothing and it decides nothing. Every verdict below is
  computed here, in the tab.

  What the four beats establish, in order:

    1. the ORIGIN served a document        (fetch, through the proxy)
    2. the document is STRUCTURALLY VALID  (the canonical JSON Schema)
    3. the carried chain VERIFIES and DERIVES the client_did it claims
    4. the relays' log for that DID AGREES with the carried one

  Beat 3 is where the domain↔DID binding becomes math instead of assertion, and
  it is strictly whole-document: a `client_did` the chain does not derive
  invalidates the document outright rather than merely the member (SIWD.md — "a
  document where they disagree makes no claim at all").

*/

import { verifyIdentityChain } from '@metalabel/dfos-protocol/chain';
import validateAppDocument from './generated/dfos-app-validator.js';

const DID_PREFIX = 'did:dfos';

/** The SIWD chain-carriage cap. The schema enforces it; this is for messages. */
export const CARRIAGE_CAP = 100;

// -----------------------------------------------------------------------------
// the proxy contract
// -----------------------------------------------------------------------------

/** Envelope statuses the `/api/wellknown` route answers with. It always replies
 *  200 with one of these — a rejected fetch means the PROXY was unreachable. */
export type ProxyStatus =
  | 'ok'
  | 'no-app-description'
  | 'redirected'
  | 'http-error'
  | 'unreachable'
  | 'too-large'
  | 'timeout'
  | 'refused';

export interface ProxyEnvelope {
  status: ProxyStatus;
  httpStatus?: number;
  body?: unknown;
  reason?: string;
}

/**
 * What a fetch attempt established. Three outcomes that are constantly collapsed
 * into one another are kept apart here, because each is a different claim:
 *
 *   no-app-description — the origin ANSWERED and the document is not there. A
 *                        complete, affirmative answer: this origin describes no app.
 *   redirected         — the origin answered the fixed path with a redirect. The
 *                        document lives at the path itself and redirects are never
 *                        followed, so this is a NON-ANSWER: nothing at all was
 *                        learned about what the origin serves there. Not an
 *                        absence, and not a failure to reach.
 *   proxy-unavailable  — OUR route did not answer. In dev (vite, no serverless
 *                        route) the fetch 404s or answers HTML, and reporting that
 *                        as "this origin serves no app description" would be the
 *                        explorer inventing an absence it never observed.
 */
export type FetchOutcome =
  | { kind: 'ok'; document: unknown }
  | { kind: 'no-app-description'; httpStatus: number | null }
  | { kind: 'redirected'; httpStatus: number | null }
  | { kind: 'unreachable'; status: ProxyStatus; reason: string; httpStatus: number | null }
  | { kind: 'proxy-unavailable'; reason: string };

/** Human-readable detail for the failure states, without inventing certainty. */
const REASONS: Record<Exclude<ProxyStatus, 'ok' | 'no-app-description' | 'redirected'>, string> = {
  'http-error': 'the origin answered with an error status',
  unreachable: 'the origin could not be reached',
  'too-large': 'the document exceeded the fetch size limit',
  timeout: 'the origin did not answer in time',
  refused: 'the fetch was refused before it left the proxy',
};

/**
 * Classify a parsed proxy envelope. Pure — the view does the fetching, this
 * decides what was actually established. An envelope that does not match the
 * contract is `proxy-unavailable`, not a failure of the ORIGIN: we cannot
 * attribute to a third-party domain a fault we observed in our own route.
 */
export const classifyEnvelope = (value: unknown): FetchOutcome => {
  if (typeof value !== 'object' || value === null) {
    return { kind: 'proxy-unavailable', reason: 'the lookup route did not answer with JSON' };
  }
  const env = value as Partial<ProxyEnvelope>;
  const httpStatus = typeof env.httpStatus === 'number' ? env.httpStatus : null;
  const reason = typeof env.reason === 'string' && env.reason ? env.reason : '';

  switch (env.status) {
    case 'ok':
      if (!('body' in env)) {
        return {
          kind: 'proxy-unavailable',
          reason: 'the lookup route reported ok with no document',
        };
      }
      return { kind: 'ok', document: env.body };
    case 'no-app-description':
      return { kind: 'no-app-description', httpStatus };
    case 'redirected':
      return { kind: 'redirected', httpStatus };
    case 'http-error':
      // BACK-COMPAT ACROSS THE CACHE SKEW. The route answered 3xx with
      // `http-error` before `redirected` existed, and its envelopes are held by
      // the CDN for about a minute — so for that window a deployed tab can read
      // an old-shaped answer. A 3xx httpStatus says unambiguously what happened
      // whatever word the route wrapped it in, and honouring it costs nothing.
      if (httpStatus !== null && httpStatus >= 300 && httpStatus < 400) {
        return { kind: 'redirected', httpStatus };
      }
      return {
        kind: 'unreachable',
        status: env.status,
        reason: reason || REASONS[env.status],
        httpStatus,
      };
    case 'unreachable':
    case 'too-large':
    case 'timeout':
    case 'refused':
      return {
        kind: 'unreachable',
        status: env.status,
        reason: reason || REASONS[env.status],
        httpStatus,
      };
    default:
      return {
        kind: 'proxy-unavailable',
        reason: 'the lookup route answered outside its contract',
      };
  }
};

/**
 * Fetch an origin's app description through the proxy. The ONLY rejection path
 * is the proxy itself being unreachable or answering off-contract — everything
 * about the third-party origin arrives inside the envelope.
 */
export const fetchAppDocument = async (host: string): Promise<FetchOutcome> => {
  let res: Response;
  try {
    res = await fetch(`/api/wellknown?host=${encodeURIComponent(host)}`, {
      signal: AbortSignal.timeout(20000),
    });
  } catch (e) {
    return {
      kind: 'proxy-unavailable',
      reason: e instanceof Error ? e.message : 'the lookup route could not be reached',
    };
  }
  // a dev server (or a misrouted deploy) answers 404/HTML here — off-contract,
  // and emphatically not evidence about the origin
  if (!res.ok) {
    return {
      kind: 'proxy-unavailable',
      reason: `the lookup route answered ${res.status}`,
    };
  }
  try {
    return classifyEnvelope((await res.json()) as unknown);
  } catch {
    return { kind: 'proxy-unavailable', reason: 'the lookup route did not answer with JSON' };
  }
};

// -----------------------------------------------------------------------------
// structural validation — against the CANONICAL schema
// -----------------------------------------------------------------------------

/** The document members, per SIWD.md's closed registry. */
export interface AppDescription {
  name?: string;
  redirect_uris: string[];
  client_did?: string;
  identity_chain?: string[];
}

export type StructuralVerdict = { ok: true; app: AppDescription } | { ok: false; errors: string[] };

/** Render one ajv error as a sentence a human can act on. */
const describeError = (e: {
  instancePath: string;
  keyword: string;
  params: Record<string, unknown>;
  message?: string;
}): string => {
  const at = e.instancePath ? e.instancePath.replace(/^\//, '').replace(/\//g, '.') : 'document';
  if (e.keyword === 'additionalProperties') {
    return `unrecognized member \`${String(e.params['additionalProperty'])}\` — the member set is closed`;
  }
  if (e.keyword === 'required') {
    return `missing required member \`${String(e.params['missingProperty'])}\``;
  }
  if (e.keyword === 'dependentRequired') {
    return `\`${String(e.params['missingProperty'])}\` is required when \`${String(e.params['property'])}\` is present`;
  }
  if (e.keyword === 'maxItems' && at === 'identity_chain') {
    return `identity_chain exceeds the ${CARRIAGE_CAP}-operation carriage cap`;
  }
  return `${at} ${e.message ?? 'is invalid'}`;
};

/**
 * Validate against `schemas/dfos-app.v1.json` — the canonical schema, compiled
 * to a plain JS validator at build time (scripts/build-schema-validator.mjs).
 * The schema is the source of truth for every structural rule SIWD states: the
 * closed member set, the presence-but-empty rule (a zero-length `name`, an empty
 * `redirect_uris` or `identity_chain` is malformed, not absent), the
 * chain-requires-`client_did` dependency, and the 100-operation carriage cap.
 * Nothing here restates them.
 */
export const validateStructure = (document: unknown): StructuralVerdict => {
  if (validateAppDocument(document)) {
    return { ok: true, app: document as unknown as AppDescription };
  }
  const errors = (validateAppDocument.errors ?? []).map(describeError);
  return { ok: false, errors: errors.length > 0 ? [...new Set(errors)] : ['document is invalid'] };
};

// -----------------------------------------------------------------------------
// chain verification — beat 3, where the binding becomes math
// -----------------------------------------------------------------------------

export type ChainVerdict =
  /** the carried chain verifies AND derives the client_did the document claims */
  | { ok: true; did: string; log: string[] }
  /** whole-document rejection: the chain is invalid, or derives a different DID */
  | { ok: false; error: string };

/**
 * Verify a carried `identity_chain` and BIND it to the document's `client_did`.
 *
 * The binding is the point. `verifyIdentityChain` derives a DID from whatever
 * genesis operation it is handed, so an internally-valid chain for a DIFFERENT
 * identity would otherwise sail through — the same trap dfos-client closes when
 * it resolves a DID against a relay's answer (resolvers.ts, "BIND to the
 * requested id"). A mismatch rejects the WHOLE document, per SIWD.md: the two
 * members make one claim, and a document where they disagree makes none.
 */
export const verifyCarriedChain = async (app: AppDescription): Promise<ChainVerdict> => {
  const log = app.identity_chain ?? [];
  if (log.length === 0) return { ok: false, error: 'no identity_chain carried' };
  let did: string;
  try {
    const state = await verifyIdentityChain({ didPrefix: DID_PREFIX, log });
    did = state.did;
  } catch (e) {
    return {
      ok: false,
      error: `carried chain failed verification — ${e instanceof Error ? e.message : String(e)}`,
    };
  }
  if (app.client_did && did !== app.client_did) {
    return {
      ok: false,
      error:
        `client_did does not match the chain it carries — the document claims ${app.client_did}, ` +
        `its genesis operation derives ${did}. The whole document is rejected.`,
    };
  }
  return { ok: true, did, log };
};

// -----------------------------------------------------------------------------
// beat 4 — the ordered-log comparison
// -----------------------------------------------------------------------------

/**
 * How the origin's carried log relates to the log the relays serve. An identity
 * chain is an ORDERED log, so the only honest comparison is positional: a shared
 * prefix, and then what each side has that the other does not.
 *
 *   identical    — same operations, same order. Nothing to say.
 *   ahead        — the relays' log is a strict prefix of the origin's. Benign:
 *                  the origin published operations the relays have not ingested.
 *   behind       — the ORIGIN's log is a strict prefix of the relays'. A
 *                  ROLLBACK SIGNAL: the document has shed operations it once
 *                  carried, against SIWD's monotonicity-on-operations rule.
 *   diverged     — the logs agree up to `shared` and then CONTRADICT. Both sides
 *                  are signed, so this is a signed contradiction, not a lag.
 */
export type ComparisonVerdict = 'identical' | 'ahead' | 'behind' | 'diverged';

export interface LogComparison {
  verdict: ComparisonVerdict;
  /** operations both logs agree on, from genesis */
  shared: number;
  /** operations the origin carries beyond the shared prefix */
  originOnly: number;
  /** operations the relays serve beyond the shared prefix */
  relayOnly: number;
}

/**
 * Compare two ordered JWS logs. Pure and total — modeled on the prefix-consistency
 * test dfos-client applies to a relay answer against its verified cache
 * (resolvers.ts): walk the overlap, and a single mismatched token is a fork claim
 * rather than a length difference.
 *
 * An EMPTY relay log compares as `ahead` with nothing shared, which is literally
 * true (the empty log is a prefix of every log) — but the view distinguishes
 * "the relays hold no chain for this DID" before it ever gets here, because that
 * is an absence, not agreement.
 */
export const compareLogs = (originLog: string[], relayLog: string[]): LogComparison => {
  const overlap = Math.min(originLog.length, relayLog.length);
  let shared = 0;
  while (shared < overlap && originLog[shared] === relayLog[shared]) shared++;

  const originOnly = originLog.length - shared;
  const relayOnly = relayLog.length - shared;

  // a mismatch INSIDE the overlap is a contradiction: both logs carry a signed
  // operation at the same position and they are not the same operation
  if (shared < overlap) return { verdict: 'diverged', shared, originOnly, relayOnly };
  if (originOnly === 0 && relayOnly === 0)
    return { verdict: 'identical', shared, originOnly, relayOnly };
  if (relayOnly === 0) return { verdict: 'ahead', shared, originOnly, relayOnly };
  return { verdict: 'behind', shared, originOnly, relayOnly };
};

// -----------------------------------------------------------------------------
// the top-level verdict
// -----------------------------------------------------------------------------

/**
 * What the domain view renders. FOUR honest top-level states — verified,
 * relay-diverged, unreachable, no-app-description — plus three outcomes that are
 * neither successes nor transport failures and must not be laundered into one:
 *
 *   malformed    — the origin served something, and it is not an app description
 *                  (or its chain does not verify / does not derive its client_did).
 *                  An explicit failure with its reasons spelled out.
 *   no-carriage  — a structurally VALID document that carries no identity_chain.
 *                  Legitimate (the member is optional at scope=identity), but
 *                  nothing about an identity is verifiable from the origin alone,
 *                  so it is never green.
 *   redirected   — the origin answered the fixed path with a redirect. It is kept
 *                  apart from BOTH neighbours it is mistaken for: it is not
 *                  `unreachable`, because the origin answered and the transport
 *                  worked, and it is not `no-app-description`, because nothing was
 *                  demonstrated about whether the document exists. A non-answer.
 *
 * Green requires a verified chain. There is no other way to earn it.
 */
export type DomainVerdict =
  | { kind: 'verified'; app: AppDescription; did: string; log: string[]; relayLog: string[] }
  | {
      kind: 'relay-diverged';
      app: AppDescription;
      did: string;
      log: string[];
      relayLog: string[];
      comparison: LogComparison;
    }
  | { kind: 'no-carriage'; app: AppDescription }
  | { kind: 'malformed'; errors: string[] }
  | { kind: 'unreachable'; reason: string; httpStatus: number | null; proxyDown: boolean }
  | { kind: 'no-app-description'; httpStatus: number | null }
  | { kind: 'redirected'; httpStatus: number | null };

/**
 * Fold a fetch outcome and the structural/chain checks into a verdict, WITHOUT
 * the relay beat. The view runs the relay comparison separately (it needs the
 * network), then upgrades a `verified` verdict to `relay-diverged` if the logs
 * disagree — so this stays synchronous-ish and fully testable.
 */
export const assessDocument = async (outcome: FetchOutcome): Promise<DomainVerdict> => {
  if (outcome.kind === 'proxy-unavailable') {
    return { kind: 'unreachable', reason: outcome.reason, httpStatus: null, proxyDown: true };
  }
  if (outcome.kind === 'unreachable') {
    return {
      kind: 'unreachable',
      reason: outcome.reason,
      httpStatus: outcome.httpStatus,
      proxyDown: false,
    };
  }
  if (outcome.kind === 'no-app-description') {
    return { kind: 'no-app-description', httpStatus: outcome.httpStatus };
  }
  if (outcome.kind === 'redirected') {
    return { kind: 'redirected', httpStatus: outcome.httpStatus };
  }

  const structural = validateStructure(outcome.document);
  if (!structural.ok) return { kind: 'malformed', errors: structural.errors };

  const app = structural.app;
  if (!app.identity_chain || app.identity_chain.length === 0) {
    return { kind: 'no-carriage', app };
  }

  const chain = await verifyCarriedChain(app);
  if (!chain.ok) return { kind: 'malformed', errors: [chain.error] };

  // the relay beat has not run yet; `withRelayLog` folds it in
  return { kind: 'verified', app, did: chain.did, log: chain.log, relayLog: [] };
};

/** Both verdicts in which the ORIGIN proved a DID — they carry the same fields,
 *  and differ only in whether the relays' log agreed. */
export type OriginVerified = Extract<
  DomainVerdict,
  { kind: 'verified' } | { kind: 'relay-diverged' }
>;

/** Narrow to the origin-verified verdicts, for surfaces that render either. */
export const originVerified = (verdict: DomainVerdict | null): OriginVerified | null =>
  verdict !== null && (verdict.kind === 'verified' || verdict.kind === 'relay-diverged')
    ? verdict
    : null;

/**
 * Fold the relay beat into a document verdict. Only an origin-verified document
 * can be downgraded here: divergence is a statement about two signed logs for a
 * DID, and there is no such DID until the carried chain derived one.
 *
 * Note what this deliberately does NOT do — treat an unresolvable identity as an
 * empty relay log. The caller only reaches this with a log the relays actually
 * served; "no relay holds this identity" is an absence the view renders as such.
 */
export const withRelayLog = (verdict: DomainVerdict, relayLog: string[]): DomainVerdict => {
  if (verdict.kind !== 'verified') return verdict;
  const comparison = compareLogs(verdict.log, relayLog);
  if (comparison.verdict === 'identical') return { ...verdict, relayLog };
  return {
    kind: 'relay-diverged',
    app: verdict.app,
    did: verdict.did,
    log: verdict.log,
    relayLog,
    comparison,
  };
};
