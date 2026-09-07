/*

  ORIGIN-BINDING PARSERS — the pure half, shared by both vantages

  The explorer reads the two attest-back channels from two places: the
  serverless route (`api/binding.ts`, which owns DNS and a server-side fetch)
  and the tab itself (`src/lib/binding-browser.ts`, over DNS-over-HTTPS and a
  CORS fetch). WHAT THE BYTES MEAN is the same question from both, and it used to
  be answered by two copies of the same regexes and the same reader — which then
  drifted: only one of them was ever compared against the Go CLI, so the pair
  disagreed with each other's reference implementation on the same input.

  So the pure half lives here, exactly once: the DID grammar, the trim set, the
  body reader, the TXT fold, and the status classification. This module is
  BROWSER-SAFE — no node builtins, no fetch, no DOM — so both callers can import
  it, and it holds no transport behaviour of its own.

  THE GO CLI IS THE REFERENCE for both. `packages/dfos-cli/internal/cmd/
  originbinding.go` is the third implementation of these same rules, and where
  this file names a Go symbol the two are meant to be read side by side.

*/

/**
 * What ONE method established. Seven outcomes, and the split between them is the
 * whole point. INTEGRATIONS.md, HTTPS: `/.well-known/dfos-did` sorts them into
 * three classes, and the class a result lands in is what decides whether the
 * app-description fallback fires:
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
 *   refused       — the fetch never left the route (policy)
 */
export type BindingMethodResult =
  | { status: 'ok'; did: string }
  | { status: 'none'; reason?: string }
  | { status: 'redirected'; httpStatus: number; reason: string }
  | { status: 'malformed'; reason: string }
  | { status: 'contradiction'; reason: string }
  | { status: 'error'; reason?: string; httpStatus?: number }
  | { status: 'refused'; reason: string };

/** A DFOS DID: the 31-char id alphabet the protocol mints. */
export const DID_RE = /^did:dfos:[2346789acdefhknrtvz]{31}$/;

/** The DNS attestation's exact value form
 *  (INTEGRATIONS.md, DNS: TXT at `_dfos.<domain>`). */
export const TXT_CLAIM_RE = /^did=(did:dfos:[2346789acdefhknrtvz]{31})$/;

/**
 * ASCII whitespace only — the spec trims ASCII, not Unicode.
 *
 * The set is the Go CLI's `asciiWhitespace` (`originbinding.go`: `" \t\r\n\v\f"`)
 * character for character, VERTICAL TAB INCLUDED. Both explorer parsers used to
 * omit `\v`, so a well-known document holding a valid DID wrapped in vertical
 * tabs bound in the CLI and read `malformed` here — two reference verifiers
 * disagreeing on identical bytes.
 */
export const ASCII_WS_RE = /^[\t\n\v\f\r ]+|[\t\n\v\f\r ]+$/g;

export const TXT_NAME_PREFIX = '_dfos.';
export const WELL_KNOWN_PATH = '/.well-known/dfos-did';

/** The response-body cap. A conforming body is under a hundred bytes. */
export const MAX_BODY_BYTES = 1024;

/**
 * Read a 200 body from `/.well-known/dfos-did`. A body that is exactly one DFOS
 * DID after ASCII trimming attests it; ANYTHING else is `malformed` — a document
 * that is present and says nothing the spec can read, which is the third member
 * of its non-answer class ("a 200 whose trimmed body is not exactly one DFOS
 * DID, the shape a host serving its application shell for every unknown path
 * produces") and licenses the app-description fallback exactly as a 404 does.
 *
 * The Go twin is `didFromWellKnownBody`.
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
 * Fold the `did=` records at a name into a method result:
 *
 *   no `did=` record        → `none` (silence: the name may carry other TXT)
 *   more than one           → `contradiction`, whatever the values, INCLUDING two
 *                             records carrying the same DID. The spec forbids
 *                             picking one, and "they happen to agree" is a
 *                             tiebreak by another name.
 *   one, malformed          → `none`. A record that says nothing is a domain
 *                             saying nothing, not a domain contradicting itself.
 *
 * Each record arrives already joined: a TXT record is a SEQUENCE of
 * character-strings split at 255 bytes on the wire, and the segments of one
 * record are one value. The two callers unwrap that differently (Node hands back
 * a chunk array; a DoH JSON answer hands back quoted segments), which is why the
 * joining is theirs and the reading is here.
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
 * What the HTTPS response STATUS alone establishes, before a byte of the body is
 * read. Pure, so the one judgement this method makes about a domain's answer is
 * testable without a network.
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
 *   anything
 *   but 200  → `error`. A QUERY FAILURE, the spec's separate class — we did not
 *              observe the path, so it never declined to answer, and nothing is
 *              licensed off a channel we never saw.
 *
 * `null` means the status settles nothing on its own — the answer is in the body,
 * and ONLY A 200 gets there. Go's `classifyWellKnown` reads the body on
 * `status == http.StatusOK` and drops every other status into its `default:`
 * branch ("silence, with no fallback owed"); this used to let the whole 2xx range
 * through, so a 201 carrying a valid DID bound here and was silence there.
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
    return { status: 'none', reason: `the origin serves no ${WELL_KNOWN_PATH} (HTTP ${status})` };
  }
  if (status !== 200) {
    return {
      status: 'error',
      httpStatus: status,
      reason: 'the origin answered with an error status',
    };
  }
  return null;
};
