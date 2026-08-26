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
  classifyBindingEnvelope,
  fallbackEligible,
  fetchBindingAttestation,
  isBareHostname,
  readOriginClaim,
  runAppFallback,
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
// the app-description fallback — MUST, and only on ABSENCE
// -----------------------------------------------------------------------------

describe('fallbackEligible', () => {
  it('fires only on an ABSENT well-known document', () => {
    expect(fallbackEligible(answered({ status: 'none' }, { status: 'none' }))).toBe(true);
  });

  // presence without an answer is not absence: the document exists, so the spec's
  // fallback does not apply. Neither does a failure to establish anything at all
  // — the spec's trigger is literal, "absent (a 404)", and nothing weaker.
  it('does NOT fire on a malformed, errored, refused, or answered document', () => {
    for (const https of [
      { status: 'malformed', reason: 'not a did' },
      { status: 'error', reason: 'timeout' },
      { status: 'error', httpStatus: 302, reason: 'the origin redirected' },
      { status: 'refused', reason: 'policy' },
      { status: 'ok', did: DID },
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

  // the redirect corner, end to end: a redirecting origin is silence, the
  // fallback never runs, and the verdict is stale — NOT broken, even though that
  // origin's app description happens to name someone else
  it('is stale on a redirecting origin, with no fallback consulted', () => {
    const redirected: BindingMethodResult = {
      status: 'error',
      httpStatus: 302,
      reason: 'the origin redirected; redirects are not followed',
    };
    const probe = answered(redirected, { status: 'none' });
    expect(fallbackEligible(probe)).toBe(false);
    const out = assessBinding(DID, claimed, probe);
    expect(out.kind).toBe('stale');
    if (out.kind === 'stale') expect(out.reasons.join(' ')).toMatch(/HTTP 302/);
  });

  // a malformed document is presence without an answer: silence for the verdict
  it('is stale on a malformed https body with nothing else answering', () => {
    const out = assessBinding(
      DID,
      claimed,
      answered({ status: 'malformed', reason: 'not exactly one DID' }, { status: 'none' }),
    );
    expect(out.kind).toBe('stale');
    if (out.kind === 'stale') expect(out.reasons.join(' ')).toMatch(/not exactly one DID/);
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
