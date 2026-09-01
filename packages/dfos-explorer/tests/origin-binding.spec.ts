/**
 * Origin-binding logic — the pure half of the identity view's binding panel.
 *
 * The fallback case runs against the repo's ONE real app description
 * (examples/siwd-demo/public/.well-known/dfos-app.json) and compares against the
 * document's OWN client_did rather than a hardcoded string, so a re-minted demo
 * identity does not break these tests — only a genuinely broken binding does.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ServiceEntry } from '@metalabel/dfos-protocol/chain';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  assessBinding,
  assessDomainBinding,
  attestedCandidate,
  classifyBindingEnvelope,
  domainBindingSpeaks,
  fallbackEligible,
  fetchBindingAttestation,
  isBareHostname,
  readAppAttestation,
  readOriginClaim,
  runAppFallback,
  type AppAttestation,
  type AttestedChain,
  type BindingMethodResult,
  type BindingProbe,
  type FallbackResult,
  type OriginClaim,
} from '../src/lib/origin-binding';

const repoRoot = resolve(import.meta.dirname, '../../..');
const readJson = (rel: string): Record<string, unknown> =>
  JSON.parse(readFileSync(resolve(repoRoot, rel), 'utf-8')) as Record<string, unknown>;
const demoApp = (): Record<string, unknown> =>
  readJson('examples/siwd-demo/public/.well-known/dfos-app.json');

const DID = 'did:dfos:tn7kkfz7ehzvv6fzvate9rz2874nc3e';
const OTHER = 'did:dfos:2346789acdefhknrtvz2346789acdef';

const origin = (domain: unknown, id = 'origin-1'): ServiceEntry =>
  ({ id, type: 'DfosOrigin', domain }) as unknown as ServiceEntry;
const relay = (): ServiceEntry =>
  ({ id: 'r1', type: 'DfosRelay', endpoint: 'https://relay.dfos.com' }) as unknown as ServiceEntry;

const claimed: OriginClaim = { kind: 'claimed', domain: 'example.com' };
const answered = (https: BindingMethodResult, dns: BindingMethodResult): BindingProbe => ({
  kind: 'answered',
  https,
  dns,
});
const silentProbe = answered({ status: 'none' }, { status: 'none' });

// -----------------------------------------------------------------------------
// the chain half
// -----------------------------------------------------------------------------

describe('isBareHostname', () => {
  it('accepts a bare lowercase hostname', () => {
    for (const h of ['example.com', 'sub.example.co.uk', 'xn--80ak6aa92e.com', 'a-b.example.org']) {
      expect(isBareHostname(h), h).toBe(true);
    }
  });

  // every comparison in ORIGIN-BINDING.md is an exact byte comparison of this
  // string, so a value that would need normalizing to pass is simply wrong
  it('rejects anything that is not already in that exact form', () => {
    for (const h of [
      undefined,
      42,
      '',
      'Example.com', // not lowercase
      'example.com.', // trailing dot
      'example.com:443', // port
      'https://example.com', // scheme
      'example.com/path',
      ' example.com',
      'localhost',
      '10.0.0.1',
      '-bad.example.com',
    ]) {
      expect(isBareHostname(h as never), String(h)).toBe(false);
    }
  });
});

describe('readOriginClaim', () => {
  it('reads exactly one valid entry as a claim', () => {
    expect(readOriginClaim([relay(), origin('example.com')])).toEqual({
      kind: 'claimed',
      domain: 'example.com',
    });
  });

  it('reports no DfosOrigin entry as unclaimed', () => {
    expect(readOriginClaim([])).toEqual({ kind: 'unclaimed' });
    expect(readOriginClaim([relay()])).toEqual({ kind: 'unclaimed' });
  });

  // "an ambiguous claim is no claim" — and deliberately NOT broken: nobody is
  // being contradicted, the identity's own claim is simply unreadable
  it('reports more than one entry as ambiguous, never broken', () => {
    const out = readOriginClaim([origin('a.example.com', 'o1'), origin('b.example.com', 'o2')]);
    expect(out).toEqual({ kind: 'ambiguous', count: 2 });
  });

  it('counts ambiguity by entry, even when only one entry parses', () => {
    expect(readOriginClaim([origin('example.com', 'o1'), origin('', 'o2')]).kind).toBe('ambiguous');
  });

  it('reports a single malformed entry as unclaimed', () => {
    for (const bad of [undefined, '', 'Example.com', 'example.com.', 'https://example.com', 42]) {
      expect(readOriginClaim([origin(bad)]), String(bad)).toEqual({ kind: 'unclaimed' });
    }
  });
});

// -----------------------------------------------------------------------------
// the proxy contract
// -----------------------------------------------------------------------------

describe('classifyBindingEnvelope', () => {
  it('passes a well-formed envelope through', () => {
    const out = classifyBindingEnvelope({
      https: { status: 'ok', did: DID },
      dns: { status: 'none', reason: 'nothing' },
    });
    expect(out).toEqual({
      kind: 'answered',
      https: { status: 'ok', did: DID },
      dns: { status: 'none', reason: 'nothing' },
    });
  });

  it('keeps httpStatus on an error result', () => {
    const out = classifyBindingEnvelope({
      https: { status: 'error', httpStatus: 503 },
      dns: { status: 'error' },
    });
    expect(out.kind).toBe('answered');
    if (out.kind === 'answered' && out.https.status === 'error') {
      expect(out.https.httpStatus).toBe(503);
    }
  });

  it('carries a redirected result through with its status and reason', () => {
    const out = classifyBindingEnvelope({
      https: {
        status: 'redirected',
        httpStatus: 308,
        reason: 'the origin redirected; redirects are not followed',
      },
      dns: { status: 'none' },
    });
    expect(out.kind).toBe('answered');
    if (out.kind === 'answered') {
      expect(out.https).toEqual({
        status: 'redirected',
        httpStatus: 308,
        reason: 'the origin redirected; redirects are not followed',
      });
    }
  });

  // a redirect result with no status is incoherent — the row states the code, and
  // a redirect we cannot name is our route off-contract, not a fact about them
  it('rejects a redirected result carrying no httpStatus', () => {
    expect(
      classifyBindingEnvelope({ https: { status: 'redirected' }, dns: { status: 'none' } }).kind,
    ).toBe('proxy-unavailable');
  });

  // the honesty rule: OUR route misbehaving is never evidence about THEIR domain
  it('never blames the domain for an off-contract answer', () => {
    expect(classifyBindingEnvelope(null).kind).toBe('proxy-unavailable');
    expect(classifyBindingEnvelope('<!doctype html>').kind).toBe('proxy-unavailable');
    expect(classifyBindingEnvelope({ https: { status: 'ok', did: DID } }).kind).toBe(
      'proxy-unavailable',
    );
    expect(
      classifyBindingEnvelope({ https: { status: 'banana' }, dns: { status: 'none' } }).kind,
    ).toBe('proxy-unavailable');
    // "ok" with no did is incoherent — not an attestation of the empty string
    expect(classifyBindingEnvelope({ https: { status: 'ok' }, dns: { status: 'none' } }).kind).toBe(
      'proxy-unavailable',
    );
  });
});

describe('fetchBindingAttestation', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('treats a missing route (vite dev) as proxy-unavailable, not silence', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('not found', { status: 404 })),
    );
    expect((await fetchBindingAttestation('example.com')).kind).toBe('proxy-unavailable');
  });

  it('treats a rejected fetch as proxy-unavailable', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('network down');
      }),
    );
    const out = await fetchBindingAttestation('example.com');
    expect(out.kind).toBe('proxy-unavailable');
    if (out.kind === 'proxy-unavailable') expect(out.reason).toBe('network down');
  });

  it('classifies a contract answer and sends the host encoded', async () => {
    const seen: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        seen.push(url);
        return Response.json({ https: { status: 'ok', did: DID }, dns: { status: 'none' } });
      }),
    );
    const out = await fetchBindingAttestation('a b.com');
    expect(seen[0]).toBe('/api/binding?host=a%20b.com');
    expect(out.kind).toBe('answered');
  });
});

// -----------------------------------------------------------------------------
// the app-description fallback — MUST, and only on a NON-ANSWER
// -----------------------------------------------------------------------------

describe('fallbackEligible', () => {
  // ORIGIN-BINDING.md names all three members of the class: "If
  // /.well-known/dfos-did yields a non-answer — a 404; a redirect, which is
  // absence in everything but status code; or a 200 whose trimmed body is not
  // exactly one DFOS DID … a verifier MUST fall back."
  it('fires on every member of the non-answer class', () => {
    for (const https of [
      { status: 'none', reason: 'no document (HTTP 404)' },
      { status: 'redirected', httpStatus: 301, reason: 'the origin redirected' },
      { status: 'redirected', httpStatus: 308, reason: 'the origin redirected' },
      { status: 'malformed', reason: 'the document is not exactly one DFOS DID' },
    ] as BindingMethodResult[]) {
      expect(fallbackEligible(answered(https, { status: 'none' })), https.status).toBe(true);
    }
  });

  // a query FAILURE is its own class in the spec's stale row — "or the queries
  // fail (network error, TLS failure, timeout, server error)" — listed apart from
  // the non-answers. We never saw the path, so it never declined to answer, and
  // an unobserved channel licenses nothing.
  it('does NOT fire on a query failure, a refusal, or a document that ANSWERED', () => {
    for (const https of [
      { status: 'error', reason: 'timeout' },
      { status: 'error', httpStatus: 503, reason: 'the origin answered with an error status' },
      { status: 'refused', reason: 'policy' },
      { status: 'ok', did: DID },
      { status: 'contradiction', reason: 'multiple did= records' },
    ] as BindingMethodResult[]) {
      expect(fallbackEligible(answered(https, { status: 'none' })), https.status).toBe(false);
    }
    expect(fallbackEligible({ kind: 'proxy-unavailable', reason: 'down' })).toBe(false);
  });
});

describe('runAppFallback', () => {
  afterEach(() => vi.unstubAllGlobals());

  const stubApp = (envelope: unknown): void => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Response.json(envelope)),
    );
  };

  it('attests when the app description names the candidate DID', async () => {
    const app = demoApp();
    stubApp({ status: 'ok', httpStatus: 200, body: app });
    expect(await runAppFallback('example.com', app['client_did'] as string)).toEqual({
      kind: 'attests',
      did: app['client_did'],
    });
  });

  // an app description naming a DIFFERENT identity is an ANSWER, not a miss —
  // the caller folds it as a contradiction
  it('answers-other when the app description names a different DID', async () => {
    const app = demoApp();
    stubApp({ status: 'ok', httpStatus: 200, body: app });
    expect(await runAppFallback('example.com', OTHER)).toEqual({
      kind: 'answers-other',
      did: app['client_did'],
    });
  });

  it('is silent on absence, transport failure, and our own route failing', async () => {
    stubApp({ status: 'no-app-description', httpStatus: 404 });
    expect((await runAppFallback('example.com', DID)).kind).toBe('silent');
    stubApp({ status: 'timeout' });
    expect((await runAppFallback('example.com', DID)).kind).toBe('silent');
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('nope', { status: 500 })),
    );
    expect((await runAppFallback('example.com', DID)).kind).toBe('silent');
  });

  it('is silent on a structurally invalid document or one with no client_did', async () => {
    stubApp({ status: 'ok', httpStatus: 200, body: { name: 'x' } });
    expect((await runAppFallback('example.com', DID)).kind).toBe('silent');
    stubApp({
      status: 'ok',
      httpStatus: 200,
      body: { name: 'x', redirect_uris: ['https://x.com/cb'] },
    });
    const out = await runAppFallback('example.com', DID);
    expect(out.kind).toBe('silent');
    if (out.kind === 'silent') expect(out.reason).toMatch(/client_did/);
  });
});

// -----------------------------------------------------------------------------
// the fold — the whole verdict matrix
// -----------------------------------------------------------------------------

describe('assessBinding', () => {
  it('has nothing to check when the chain claims nothing', () => {
    expect(assessBinding(DID, { kind: 'unclaimed' }, silentProbe)).toEqual({
      kind: 'none',
      claim: 'unclaimed',
    });
    expect(assessBinding(DID, { kind: 'ambiguous', count: 2 }, silentProbe)).toEqual({
      kind: 'none',
      claim: 'ambiguous',
    });
  });

  it('binds when both methods attest exactly this DID', () => {
    const out = assessBinding(
      DID,
      claimed,
      answered({ status: 'ok', did: DID }, { status: 'ok', did: DID }),
    );
    expect(out).toMatchObject({ kind: 'bound', domain: 'example.com' });
    if (out.kind === 'bound') expect(out.attestedBy).toEqual(['https', 'dns']);
  });

  // agreement is required only among the methods that ACTUALLY ANSWERED — either
  // method alone suffices, and a silent one is never evidence against
  it('binds on one method with the other silent, either way round', () => {
    const httpsOnly = assessBinding(
      DID,
      claimed,
      answered({ status: 'ok', did: DID }, { status: 'none' }),
    );
    expect(httpsOnly).toMatchObject({ kind: 'bound' });
    if (httpsOnly.kind === 'bound') expect(httpsOnly.attestedBy).toEqual(['https']);

    const dnsOnly = assessBinding(
      DID,
      claimed,
      answered({ status: 'error', reason: 'timeout' }, { status: 'ok', did: DID }),
    );
    expect(dnsOnly).toMatchObject({ kind: 'bound' });
    if (dnsOnly.kind === 'bound') expect(dnsOnly.attestedBy).toEqual(['dns']);
  });

  it('breaks when a method answers with a different DID', () => {
    const out = assessBinding(
      DID,
      claimed,
      answered({ status: 'ok', did: OTHER }, { status: 'none' }),
    );
    expect(out.kind).toBe('broken');
    if (out.kind === 'broken') expect(out.details.join(' ')).toMatch(/different identity/);
  });

  // a domain that says two things is broken even when ONE of them is right —
  // never either-wins, never first-checked-wins
  it('breaks when the two methods disagree, even if one is correct', () => {
    const out = assessBinding(
      DID,
      claimed,
      answered({ status: 'ok', did: DID }, { status: 'ok', did: OTHER }),
    );
    expect(out.kind).toBe('broken');
  });

  it('breaks on a DNS contradiction', () => {
    const out = assessBinding(
      DID,
      claimed,
      answered({ status: 'none' }, { status: 'contradiction', reason: 'multiple did= records' }),
    );
    expect(out.kind).toBe('broken');
    if (out.kind === 'broken') expect(out.details.join(' ')).toMatch(/multiple did= records/);
  });

  // a contradiction outranks an attestation that happens to agree
  it('breaks on a DNS contradiction even with a correct https attestation', () => {
    const out = assessBinding(
      DID,
      claimed,
      answered({ status: 'ok', did: DID }, { status: 'contradiction', reason: 'two records' }),
    );
    expect(out.kind).toBe('broken');
  });

  it('is stale when the claim stands and every method is silent', () => {
    const out = assessBinding(DID, claimed, silentProbe);
    expect(out).toMatchObject({ kind: 'stale', domain: 'example.com' });
    if (out.kind === 'stale') expect(out.reasons).toHaveLength(2);
  });

  it('is stale — not broken — when the lookups merely failed', () => {
    const out = assessBinding(
      DID,
      claimed,
      answered(
        { status: 'error', reason: 'the origin did not answer in time' },
        { status: 'error', reason: 'the DNS lookup failed (SERVFAIL)' },
      ),
    );
    expect(out.kind).toBe('stale');
  });

  // the redirect corner, end to end. The fallback IS consulted now (#400's
  // non-answer class), and with nothing answering anywhere the verdict is still
  // the silent one: "if no channel answers, the verdict is the silent one
  // (stale) … never broken, because nothing contradicted anything".
  it('is stale on a redirecting origin whose fallback is also silent', () => {
    const redirected: BindingMethodResult = {
      status: 'redirected',
      httpStatus: 302,
      reason: 'the origin redirected; redirects are not followed',
    };
    const probe = answered(redirected, { status: 'none' });
    expect(fallbackEligible(probe)).toBe(true);
    const out = assessBinding(DID, claimed, probe, {
      kind: 'silent',
      reason: 'the origin serves no app description either',
    });
    expect(out.kind).toBe('stale');
    if (out.kind === 'stale') expect(out.reasons.join(' ')).toMatch(/HTTP 302/);
  });

  // and the consequence the widened trigger buys, kept deliberately: a redirect
  // no longer HIDES a fallback that attests. The origin declined to answer at
  // dfos-did and answered at dfos-app.json, and the spec's fallback reads it.
  it('binds through the fallback when the well-known redirected', () => {
    const out = assessBinding(
      DID,
      claimed,
      answered(
        { status: 'redirected', httpStatus: 308, reason: 'the origin redirected' },
        { status: 'none' },
      ),
      { kind: 'attests', did: DID },
    );
    expect(out.kind).toBe('bound');
    if (out.kind === 'bound') expect(out.attestedBy).toContain('app-fallback');
  });

  // the other side of the same coin, and the one that used to be unreachable: a
  // fallback that ANSWERS with a different identity is a channel answering, and
  // an answer naming someone else is what `broken` is for. L55's never-broken
  // clause is about NO channel answering, which is not this.
  it('is broken when a redirect’s fallback answers with a different identity', () => {
    const out = assessBinding(
      DID,
      claimed,
      answered(
        { status: 'redirected', httpStatus: 301, reason: 'the origin redirected' },
        { status: 'none' },
      ),
      { kind: 'answers-other', did: OTHER },
    );
    expect(out.kind).toBe('broken');
    if (out.kind === 'broken') expect(out.details.join(' ')).toContain(OTHER);
  });

  // a malformed document is presence without an answer: silence for the verdict,
  // and — since #400 — the third member of the class that licenses the fallback
  it('is stale on a malformed https body with nothing else answering', () => {
    const probe = answered(
      { status: 'malformed', reason: 'not exactly one DID' },
      {
        status: 'none',
      },
    );
    expect(fallbackEligible(probe)).toBe(true);
    const out = assessBinding(DID, claimed, probe);
    expect(out.kind).toBe('stale');
    if (out.kind === 'stale') expect(out.reasons.join(' ')).toMatch(/not exactly one DID/);
  });

  // a 5xx is a query failure, not a non-answer — the fallback stays shut, and a
  // dfos-app.json naming someone else cannot escalate an unobserved channel
  it('leaves a 5xx unlicensed, so an unseen path never reaches a fallback', () => {
    const probe = answered(
      { status: 'error', httpStatus: 503, reason: 'the origin answered with an error status' },
      { status: 'none' },
    );
    expect(fallbackEligible(probe)).toBe(false);
    expect(assessBinding(DID, claimed, probe).kind).toBe('stale');
  });

  it('keeps our own route failing as its own state, never as stale', () => {
    const out = assessBinding(DID, claimed, {
      kind: 'proxy-unavailable',
      reason: 'the binding route answered 404',
    });
    expect(out).toEqual({
      kind: 'proxy-unavailable',
      domain: 'example.com',
      reason: 'the binding route answered 404',
    });
  });

  it('binds on the app-description fallback alone', () => {
    const out = assessBinding(DID, claimed, silentProbe, { kind: 'attests', did: DID });
    expect(out).toMatchObject({ kind: 'bound' });
    if (out.kind === 'bound') expect(out.attestedBy).toEqual(['app-fallback']);
  });

  // the fallback IS an https answer: a document naming a different DID is a
  // method answering with a different DID, which is exactly what broken is for
  it('breaks when the fallback names a different DID', () => {
    const out = assessBinding(DID, claimed, silentProbe, { kind: 'answers-other', did: OTHER });
    expect(out.kind).toBe('broken');
    if (out.kind === 'broken') expect(out.details.join(' ')).toMatch(OTHER);
  });

  it('stays stale when the fallback is silent too', () => {
    const out = assessBinding(DID, claimed, silentProbe, {
      kind: 'silent',
      reason: 'the origin serves no app description either',
    } satisfies FallbackResult);
    expect(out.kind).toBe('stale');
    if (out.kind === 'stale') expect(out.reasons).toHaveLength(3);
  });

  it('records the silences alongside a binding that stands on one method', () => {
    const out = assessBinding(
      DID,
      claimed,
      answered({ status: 'ok', did: DID }, { status: 'none', reason: 'no TXT record' }),
    );
    if (out.kind === 'bound') expect(out.silences.join(' ')).toMatch(/no TXT record/);
  });
});

// -----------------------------------------------------------------------------
// the domain-first walk — the same walk `dfos identity verify-binding <host>` runs
// -----------------------------------------------------------------------------

describe('readAppAttestation', () => {
  afterEach(() => vi.unstubAllGlobals());

  // the domain-first walk has no candidate to compare against: the document's
  // client_did IS the candidate, so the read is judged by nobody
  it('reads the app description’s client_did with no candidate in hand', async () => {
    const app = demoApp();
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Response.json({ status: 'ok', httpStatus: 200, body: app })),
    );
    expect(await readAppAttestation('example.com')).toEqual({
      kind: 'answers',
      did: app['client_did'],
    });
  });

  // a redirect at the app-description path is a NON-ANSWER, and this fallback
  // treats it exactly as it treats a redirect on the dfos-did channel: silence.
  // The document must come from this origin at the fixed path, so an origin that
  // redirects has shown nothing that may be read as an attestation.
  it('is silent on a redirecting origin, and says a redirect is a non-answer', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json({
          status: 'redirected',
          httpStatus: 308,
          reason: 'the origin redirected; redirects are not followed',
        }),
      ),
    );
    const out = await readAppAttestation('example.com');
    expect(out.kind).toBe('silent');
    if (out.kind === 'silent') expect(out.reason).toMatch(/a redirect is a non-answer/);
  });
});

describe('attestedCandidate', () => {
  it('takes the first channel that answered, https before dns', () => {
    expect(
      attestedCandidate(answered({ status: 'ok', did: DID }, { status: 'ok', did: DID })),
    ).toBe(DID);
    expect(attestedCandidate(answered({ status: 'none' }, { status: 'ok', did: OTHER }))).toBe(
      OTHER,
    );
  });

  it('is null when the domain publishes nothing, and when OUR route failed', () => {
    expect(attestedCandidate(silentProbe)).toBeNull();
    expect(attestedCandidate({ kind: 'proxy-unavailable', reason: 'down' })).toBeNull();
  });

  // an origin publishing nothing but a SIWD app description already publishes its
  // DID, and the fallback supplies the candidate from it
  it('takes the app-description fallback as the https answer', () => {
    expect(attestedCandidate(silentProbe, { kind: 'answers', did: DID })).toBe(DID);
  });
});

describe('assessDomainBinding', () => {
  const host = 'example.com';
  const chainClaiming = (did: string, domain: string): AttestedChain => ({
    kind: 'verified',
    did,
    services: [relay(), origin(domain)],
  });

  // the live acceptance shape: a TXT record attests, the well-known document is a
  // 404. A healthy binding — either method suffices — and the silence is evidence
  // detail, never a warning
  it('binds on DNS alone with the https document silent', () => {
    const probe = answered(
      { status: 'none', reason: 'no dfos-did document' },
      {
        status: 'ok',
        did: DID,
      },
    );
    const out = assessDomainBinding(host, probe, undefined, chainClaiming(DID, host));
    expect(out).toMatchObject({ kind: 'bound', domain: host, did: DID });
    if (out.kind === 'bound') {
      expect(out.attestedBy).toEqual(['dns']);
      expect(out.silences.join(' ')).toMatch(/no dfos-did document/);
    }
  });

  // the live shape at dfos.com, as a regression: `_dfos.dfos.com` attests, both
  // HTTPS documents are 404, and the walk lands on `bound` with the two silences
  // recorded as detail
  it('binds dfos.com on its TXT record with both HTTPS documents absent', () => {
    const DFOS = 'did:dfos:9ctvrdn9vedda7efetrhcdakfh4cr2k';
    const out = assessDomainBinding(
      'dfos.com',
      answered(
        { status: 'none', reason: 'no dfos-did document (HTTP 404)' },
        { status: 'ok', did: DFOS },
      ),
      { kind: 'silent', reason: 'the origin serves no app description either' },
      { kind: 'verified', did: DFOS, services: [relay(), origin('dfos.com')] },
    );
    expect(out).toMatchObject({ kind: 'bound', domain: 'dfos.com', did: DFOS });
    if (out.kind === 'bound') {
      expect(out.attestedBy).toEqual(['dns']);
      expect(out.silences).toHaveLength(2);
    }
  });

  it('binds on the app-description fallback alone', () => {
    const out = assessDomainBinding(
      host,
      silentProbe,
      { kind: 'answers', did: DID },
      chainClaiming(DID, host),
    );
    expect(out).toMatchObject({ kind: 'bound', did: DID });
    if (out.kind === 'bound') expect(out.attestedBy).toEqual(['app-fallback']);
  });

  // a domain that says two things is broken BEFORE any chain is resolved — never
  // either-wins, never first-checked-wins
  it('breaks when the two channels attest different identities', () => {
    const out = assessDomainBinding(
      host,
      answered({ status: 'ok', did: DID }, { status: 'ok', did: OTHER }),
      undefined,
      null,
    );
    expect(out).toMatchObject({ kind: 'broken', did: null });
    if (out.kind === 'broken') {
      expect(out.details.join(' ')).toMatch(/different identities/);
      expect(out.details.join(' ')).toContain(OTHER);
    }
  });

  it('breaks on a self-contradicting channel, whatever the other one said', () => {
    const out = assessDomainBinding(
      host,
      answered(
        { status: 'ok', did: DID },
        {
          status: 'contradiction',
          reason: '2 did= records at _dfos.example.com',
        },
      ),
      undefined,
      null,
    );
    expect(out).toMatchObject({ kind: 'broken', did: null });
    if (out.kind === 'broken') expect(out.details.join(' ')).toMatch(/2 did= records/);
  });

  // the CLI's "the two halves name different domains" — the attestation stands,
  // the chain names somewhere else, and half a binding pointing elsewhere is a
  // contradiction between the two halves
  it('breaks when the attested identity’s chain claims another domain', () => {
    const out = assessDomainBinding(
      host,
      answered({ status: 'ok', did: DID }, { status: 'none' }),
      undefined,
      chainClaiming(DID, 'other.example.org'),
    );
    expect(out).toMatchObject({ kind: 'broken', did: DID });
    if (out.kind === 'broken') {
      expect(out.details.join(' ')).toMatch(/different domains/);
      expect(out.details.join(' ')).toContain('other.example.org');
    }
  });

  // the binding is EXACT: a claim on the parent says nothing about the subdomain
  it('breaks on a chain claim that differs only by a label', () => {
    const out = assessDomainBinding(
      'sub.example.com',
      answered({ status: 'ok', did: DID }, { status: 'none' }),
      undefined,
      chainClaiming(DID, 'example.com'),
    );
    expect(out.kind).toBe('broken');
  });

  // COULD NOT CHECK, and never folded into a verdict about the domain
  it('keeps an unresolvable attested chain as its own state', () => {
    const out = assessDomainBinding(
      host,
      answered({ status: 'ok', did: DID }, { status: 'none' }),
      undefined,
      { kind: 'unavailable', did: DID, reason: 'no relay served this identity' },
    );
    expect(out).toEqual({
      kind: 'chain-unavailable',
      domain: host,
      did: DID,
      reason: 'no relay served this identity',
    });
  });

  // CHECKED AND ABSENT — a different statement from could-not-check, and the two
  // must not collapse into each other
  it('separates a chain that claims nothing from a chain that could not be read', () => {
    const noEntry = assessDomainBinding(
      host,
      answered({ status: 'ok', did: DID }, { status: 'none' }),
      undefined,
      { kind: 'verified', did: DID, services: [relay()] },
    );
    expect(noEntry).toEqual({
      kind: 'no-chain-claim',
      domain: host,
      did: DID,
      claim: 'unclaimed',
    });

    const ambiguous = assessDomainBinding(
      host,
      answered({ status: 'ok', did: DID }, { status: 'none' }),
      undefined,
      { kind: 'verified', did: DID, services: [origin(host, 'o1'), origin(host, 'o2')] },
    );
    expect(ambiguous).toMatchObject({ kind: 'no-chain-claim', claim: 'ambiguous' });
  });

  it('is stale — no binding story — when both channels are silent', () => {
    const out = assessDomainBinding(host, silentProbe, undefined, null);
    expect(out).toMatchObject({ kind: 'stale', domain: host });
    if (out.kind === 'stale') expect(out.reasons).toHaveLength(2);
  });

  it('is stale, not broken, when the lookups merely failed', () => {
    const out = assessDomainBinding(
      host,
      answered(
        { status: 'error', reason: 'the origin did not answer in time' },
        { status: 'error', reason: 'the DNS lookup failed (SERVFAIL)' },
      ),
      undefined,
      null,
    );
    expect(out.kind).toBe('stale');
  });

  it('keeps our own route failing as its own state, never as silence', () => {
    const out = assessDomainBinding(
      host,
      { kind: 'proxy-unavailable', reason: 'the binding route answered 404' },
      undefined,
      null,
    );
    expect(out).toEqual({
      kind: 'proxy-unavailable',
      domain: host,
      reason: 'the binding route answered 404',
    });
  });

  // only a domain that SPOKE earns the headline panel: silence and our own route
  // failing are not observations about this domain's binding
  it('speaks only where the domain answered', () => {
    const attesting = answered({ status: 'ok', did: DID }, { status: 'none' });
    expect(
      domainBindingSpeaks(
        assessDomainBinding(host, attesting, undefined, chainClaiming(DID, host)),
      ),
    ).toBe(true);
    expect(domainBindingSpeaks(assessDomainBinding(host, silentProbe, undefined, null))).toBe(
      false,
    );
    expect(
      domainBindingSpeaks(
        assessDomainBinding(host, { kind: 'proxy-unavailable', reason: 'down' }, undefined, null),
      ),
    ).toBe(false);
    expect(domainBindingSpeaks(null)).toBe(false);
  });

  // the app description is the HTTPS channel's answer, so it disagrees with DNS
  // the same way the well-known document would
  it('breaks when the fallback and DNS attest different identities', () => {
    const out = assessDomainBinding(
      host,
      answered({ status: 'none' }, { status: 'ok', did: OTHER }),
      { kind: 'answers', did: DID } satisfies AppAttestation,
      null,
    );
    expect(out.kind).toBe('broken');
  });
});
