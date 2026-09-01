/*

  BINDING EVIDENCE — the per-channel rows under any origin-binding verdict

  Both binding panels render the same evidence: what the HTTPS well-known said,
  what the `_dfos` TXT record said, and — where it was consulted — what the app
  description said. The identity view arrives from the chain and the domain view
  arrives from the domain, but the rows are a reading of the SAME probe, so they
  are written once here.

  The discipline the rows carry: an answer naming a different DID is red, every
  form of silence is amber, and only an exact match is green. Silence is never
  dressed as contradiction — a silent channel beside an attesting one is the
  ordinary shape of a healthy binding (either method suffices), and its row says
  what was observed, not that something is wrong.

  A row may also carry its VANTAGE — who established it. The domain view checks
  what it can from the tab itself (DNS over DNS-over-HTTPS, the well-known
  document directly where the origin permits a cross-origin read) and falls back
  to the explorer's own route for what it cannot, so "your browser read this" and
  "our route read this for you" are different claims and the row says which. A
  channel NEITHER could read is `not checkable from this browser`: neutral, and
  the one row state that overrides the reading underneath it, because there is no
  reading underneath it. It is not an absence and not a failure of the binding —
  nothing was observed, so nothing follows.

*/

import type { ChannelVantage } from '../lib/binding-browser';
import type { AppAttestation, BindingMethodResult, FallbackResult } from '../lib/origin-binding';
import { Check, type CheckState } from './checks';

/**
 * One channel's row state. `did` is the DID the answer must match, or null when
 * there is no such DID yet — the domain-first walk judging a domain that
 * contradicts itself before any chain is resolved. With nothing to match against,
 * an answer is simply an answer.
 *
 * `settled` is the binding standing WITHOUT this channel: either method suffices,
 * so a silent one beside an attesting one is the ordinary shape of a healthy
 * binding, and it is rendered as neutral detail rather than as a warning. Silence
 * only earns amber where it is the reason nothing could be confirmed.
 */
export const methodState = (
  result: BindingMethodResult,
  did: string | null,
  settled: boolean,
): CheckState => {
  if (result.status === 'ok') return did === null || result.did === did ? 'ok' : 'bad';
  if (result.status === 'contradiction') return 'bad';
  return settled ? 'pend' : 'warn';
};

/** The mechanical note under a channel row — what was actually observed. */
export const methodNote = (result: BindingMethodResult, did: string | null): string => {
  switch (result.status) {
    case 'ok':
      if (did === null) return `attests ${result.did}`;
      return result.did === did
        ? `attests ${result.did} — exactly this identity`
        : `attests ${result.did} — a DIFFERENT identity`;
    case 'contradiction':
      return result.reason;
    case 'redirected':
      // named for what it was, never folded into "absent": the origin answered
      // the path, and its answer was to point elsewhere
      return `${result.reason} (HTTP ${result.httpStatus}) — a non-answer at this path`;
    case 'malformed':
      return `${result.reason} — present, but not an attestation`;
    case 'none':
      return result.reason ?? 'nothing published';
    case 'error':
      return `${result.reason ?? 'the lookup failed'}${
        result.httpStatus !== undefined ? ` (HTTP ${result.httpStatus})` : ''
      } — could not check`;
    case 'refused':
      return `${result.reason} — refused before it left the explorer`;
  }
};

/**
 * The app-description row, from either walk's shape. The chain-first walk has
 * already judged the document against the DID its chain proved (`attests` /
 * `answers-other`); the domain-first walk hands over what the document SAID
 * (`answers`), which is judged here against the DID in hand — or left as a plain
 * answer when there is none.
 */
const fallbackRow = (
  fallback: FallbackResult | AppAttestation,
  did: string | null,
  settled: boolean,
): { state: CheckState; note: string } => {
  switch (fallback.kind) {
    case 'attests':
      return { state: 'ok', note: `client_did is ${fallback.did} — exactly this identity` };
    case 'answers-other':
      return { state: 'bad', note: `client_did is ${fallback.did} — a DIFFERENT identity` };
    case 'answers':
      if (did === null) return { state: 'ok', note: `client_did is ${fallback.did}` };
      return fallback.did === did
        ? { state: 'ok', note: `client_did is ${fallback.did} — exactly this identity` }
        : { state: 'bad', note: `client_did is ${fallback.did} — a DIFFERENT identity` };
    case 'silent':
      return { state: settled ? 'pend' : 'warn', note: fallback.reason };
  }
};

/** Where the reading came from, said in the row. Plain, and short enough to sit
 *  at the end of a note without burying what was actually observed. */
const VANTAGE_NOTE: Record<'browser' | 'route', string> = {
  browser: 'read by your browser',
  route: "read by the explorer's lookup route",
};

/**
 * One channel's row. Without a vantage this is the reading alone — the identity
 * view's single-vantage probe, unchanged.
 *
 * With one, `not-checkable` takes over the whole row: no vantage read this
 * channel, so there is nothing to state about the domain, and the row says
 * exactly that in neutral terms. Every other vantage appends who did the reading.
 */
const channelRow = (
  result: BindingMethodResult,
  did: string | null,
  settled: boolean,
  vantage: ChannelVantage | undefined,
): { state: CheckState; note: string } => {
  if (vantage?.kind === 'not-checkable') {
    return { state: 'pend', note: `not checkable from this browser — ${vantage.reason}` };
  }
  const note = methodNote(result, did);
  return {
    state: methodState(result, did, settled),
    note: vantage === undefined ? note : `${note} · ${VANTAGE_NOTE[vantage.kind]}`,
  };
};

/** The two attest-back channels, plus the app-description fallback on the rows
 *  where it was consulted. `fallback` is null when the well-known document
 *  ANSWERED — the fallback applies only on a non-answer (absence, a redirect, or
 *  a body that is not a DID), so there is nothing to show. */
export const BindingEvidence = (props: {
  https: BindingMethodResult;
  dns: BindingMethodResult;
  fallback: FallbackResult | AppAttestation | null;
  did: string | null;
  /** the binding is BOUND — a channel's silence is then evidence detail, not a
   *  warning, because another channel already attested */
  settled: boolean;
  /** per-channel vantage, where the caller checked from more than one. Omitted by
   *  a single-vantage caller, whose rows then read exactly as before. */
  vantage?: { https: ChannelVantage; dns: ChannelVantage };
}) => {
  const fallback =
    props.fallback === null ? null : fallbackRow(props.fallback, props.did, props.settled);
  const https = channelRow(props.https, props.did, props.settled, props.vantage?.https);
  const dns = channelRow(props.dns, props.did, props.settled, props.vantage?.dns);
  return (
    <>
      <Check state={https.state} note={https.note}>
        https attest-back <code>/.well-known/dfos-did</code>
      </Check>
      <Check state={dns.state} note={dns.note}>
        dns attest-back <code>_dfos</code> TXT
      </Check>
      {fallback !== null ? (
        <Check state={fallback.state} note={fallback.note}>
          app-description fallback <code>/.well-known/dfos-app.json</code>
        </Check>
      ) : null}
    </>
  );
};
