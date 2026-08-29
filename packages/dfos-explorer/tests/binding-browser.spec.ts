/**
 * The browser vantage — both attest-back channels read from the tab.
 *
 * The load-bearing property under test is one sentence: BEING UNABLE TO LOOK IS
 * NOT AN OBSERVATION. A CORS refusal, a dead resolver, a timeout — none of them
 * may reach the fold as anything the domain did, and none of them may turn a
 * binding that DNS verified into a verdict with a warning on it.
 *
 * The acceptance case has a name: a domain publishing a `_dfos` TXT record and no
 * well-known file (bvalosek.com, at the time of writing) must read as bound, via
 * DNS, with the HTTPS channel simply not answering.
 */

import type { ServiceEntry } from '@metalabel/dfos-protocol/chain';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  foldTxtClaims,
  mergeChannel,
  parseDidBody,
  probeBindingChannels,
  probeDnsFromBrowser,
  probeFromChannels,
  probeWellKnownFromBrowser,
  readDohAnswer,
  unquoteTxt,
  type ChannelAttempt,
  type DualChannelProbe,
} from '../src/lib/binding-browser';
import {
  assessDomainBinding,
  type AttestedChain,
  type BindingMethodResult,
} from '../src/lib/origin-binding';

const DID = 'did:dfos:tn7kkfz7ehzvv6fzvate9rz2874nc3e';
const OTHER = 'did:dfos:2346789acdefhknrtvz2346789acdef';

/** A dns-json body, as Cloudflare and Google both shape it. */
const dohBody = (records: string[], extra: Record<string, unknown> = {}): unknown => ({
  Status: 0,
  Answer: records.map((data) => ({ name: '_dfos.example.com', type: 16, TTL: 300, data })),
  ...extra,
});

const observed = (result: BindingMethodResult): ChannelAttempt => ({ kind: 'observed', result });

// -----------------------------------------------------------------------------
// reading a TXT record
// -----------------------------------------------------------------------------

describe('unquoteTxt', () => {
  it('strips the presentation quotes a resolver wraps a character-string in', () => {
    expect(unquoteTxt(`"did=${DID}"`)).toBe(`did=${DID}`);
  });

  // a TXT record over 255 bytes arrives as several character-strings, and the
  // record's VALUE is their concatenation — reading the first alone truncates
  it('concatenates a record split into several character-strings', () => {
    expect(unquoteTxt('"did=did:dfos:" "tn7kkfz7ehzvv6fzvate9rz2874nc3e"')).toBe(`did=${DID}`);
  });

  it('takes an unquoted answer as-is', () => {
    expect(unquoteTxt(` did=${DID} `)).toBe(`did=${DID}`);
  });

  it('unescapes an escaped quote inside a string', () => {
    expect(unquoteTxt('"a\\"b"')).toBe('a"b');
  });
});

describe('foldTxtClaims', () => {
  it('reads a single well-formed record as an answer', () => {
    expect(foldTxtClaims([`did=${DID}`])).toEqual({ status: 'ok', did: DID });
  });

  it('ignores records that are not did= claims', () => {
    expect(foldTxtClaims(['v=spf1 -all']).status).toBe('none');
  });

  // the spec forbids picking one, and "they happen to agree" is a tiebreak by
  // another name
  it('calls TWO did= records a contradiction even when they agree', () => {
    expect(foldTxtClaims([`did=${DID}`, `did=${DID}`]).status).toBe('contradiction');
  });

  it('calls two disagreeing did= records a contradiction', () => {
    expect(foldTxtClaims([`did=${DID}`, `did=${OTHER}`]).status).toBe('contradiction');
  });

  // a record that says nothing is a domain saying nothing — silence, not a
  // domain contradicting itself
  it('reads a single malformed did= record as silence, not as an answer', () => {
    expect(foldTxtClaims(['did=not-a-did']).status).toBe('none');
  });
});

// -----------------------------------------------------------------------------
// the DoH answer
// -----------------------------------------------------------------------------

describe('readDohAnswer', () => {
  it('reads an answered TXT set', () => {
    expect(readDohAnswer(dohBody([`"did=${DID}"`]))).toEqual({
      kind: 'observed',
      result: { status: 'ok', did: DID },
    });
  });

  // NXDOMAIN is an ANSWER: the name does not exist. It is the domain's silence,
  // observed — not a resolver that failed us
  it('reads NXDOMAIN as an observed absence', () => {
    const out = readDohAnswer({ Status: 3 });
    expect(out.kind).toBe('observed');
    if (out.kind === 'observed') expect(out.result.status).toBe('none');
  });

  it('reads NOERROR with no TXT answer as an observed absence', () => {
    const out = readDohAnswer({ Status: 0, Answer: [] });
    expect(out.kind).toBe('observed');
    if (out.kind === 'observed') expect(out.result.status).toBe('none');
  });

  // a CNAME hop rides along in the same array and is not a record at this name
  it('ignores non-TXT records in the answer set', () => {
    const body = {
      Status: 0,
      Answer: [
        { name: '_dfos.example.com', type: 5, data: 'alias.example.net.' },
        { name: 'alias.example.net', type: 16, data: `"did=${DID}"` },
      ],
    };
    expect(readDohAnswer(body)).toEqual({ kind: 'observed', result: { status: 'ok', did: DID } });
  });

  it('treats a resolver failure status as not-checkable, never as an absence', () => {
    expect(readDohAnswer({ Status: 2 }).kind).toBe('not-checkable');
  });

  it('treats an off-contract body as not-checkable', () => {
    expect(readDohAnswer('nope').kind).toBe('not-checkable');
    expect(readDohAnswer({ Answer: [] }).kind).toBe('not-checkable');
  });
});

// -----------------------------------------------------------------------------
// the DNS channel over the wire
// -----------------------------------------------------------------------------

describe('probeDnsFromBrowser', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('asks the first provider and stops once it answers', async () => {
    const seen: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        seen.push(url);
        return Response.json(dohBody([`"did=${DID}"`]));
      }),
    );
    const out = await probeDnsFromBrowser('example.com');
    expect(out).toEqual({ kind: 'observed', result: { status: 'ok', did: DID } });
    expect(seen).toHaveLength(1);
    expect(seen[0]).toContain('cloudflare-dns.com');
    expect(seen[0]).toContain('name=_dfos.example.com');
  });

  // an ANSWER is never re-asked elsewhere: a second opinion on NXDOMAIN is
  // shopping for a reply
  it('does not ask a second provider once one has answered NXDOMAIN', async () => {
    const fetchMock = vi.fn(async () => Response.json({ Status: 3 }));
    vi.stubGlobal('fetch', fetchMock);
    const out = await probeDnsFromBrowser('example.com');
    expect(out.kind).toBe('observed');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('falls through to the second provider when the first does not answer', async () => {
    const seen: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        seen.push(url);
        if (url.includes('cloudflare')) throw new TypeError('failed to fetch');
        return Response.json(dohBody([`"did=${DID}"`]));
      }),
    );
    const out = await probeDnsFromBrowser('example.com');
    expect(out).toEqual({ kind: 'observed', result: { status: 'ok', did: DID } });
    expect(seen).toHaveLength(2);
    expect(seen[1]).toContain('dns.google');
  });

  it('is not-checkable — never an absence — when no resolver answers', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('failed to fetch');
      }),
    );
    const out = await probeDnsFromBrowser('example.com');
    expect(out.kind).toBe('not-checkable');
  });
});

// -----------------------------------------------------------------------------
// the well-known channel, fetched directly
// -----------------------------------------------------------------------------

describe('probeWellKnownFromBrowser', () => {
  afterEach(() => vi.unstubAllGlobals());

  // THE case this whole layer exists for: a browser cannot tell a CORS refusal
  // from a network failure, so neither may be reported as the domain's doing
  it('reads a CORS refusal as not-checkable, never as an absence or a failure', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch');
      }),
    );
    const out = await probeWellKnownFromBrowser('example.com');
    expect(out.kind).toBe('not-checkable');
    if (out.kind === 'not-checkable') expect(out.reason).toContain('cross-origin');
  });

  it('reads a 404 as an observed absence', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('', { status: 404 })),
    );
    const out = await probeWellKnownFromBrowser('example.com');
    expect(out.kind).toBe('observed');
    if (out.kind === 'observed') expect(out.result.status).toBe('none');
  });

  it('reads a conforming document as an answer', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(`${DID}\n`, { status: 200 })),
    );
    expect(await probeWellKnownFromBrowser('example.com')).toEqual({
      kind: 'observed',
      result: { status: 'ok', did: DID },
    });
  });

  // present without an answer: the document exists, so the origin is not silent
  it('reads a present non-DID document as malformed', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('<!doctype html>', { status: 200 })),
    );
    const out = await probeWellKnownFromBrowser('example.com');
    expect(out.kind).toBe('observed');
    if (out.kind === 'observed') expect(out.result.status).toBe('malformed');
  });

  it('does not read a body past the cap', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('x'.repeat(2048), { status: 200 })),
    );
    const out = await probeWellKnownFromBrowser('example.com');
    expect(out.kind).toBe('observed');
    if (out.kind === 'observed') expect(out.result.status).toBe('malformed');
  });
});

describe('parseDidBody', () => {
  it('accepts exactly one DID, ASCII-trimmed', () => {
    expect(parseDidBody(` ${DID}\n`)).toEqual({ status: 'ok', did: DID });
  });

  it('calls an empty document malformed, not absent', () => {
    expect(parseDidBody('   ').status).toBe('malformed');
  });
});

// -----------------------------------------------------------------------------
// merging the two vantages
// -----------------------------------------------------------------------------

describe('mergeChannel', () => {
  it('keeps the browser reading and does not consult the route', () => {
    const out = mergeChannel(observed({ status: 'ok', did: DID }), { status: 'none' }, null);
    expect(out.vantage.kind).toBe('browser');
    expect(out.result).toEqual({ status: 'ok', did: DID });
  });

  it('fills a channel the browser could not check in from the route', () => {
    const out = mergeChannel(
      { kind: 'not-checkable', reason: 'no cross-origin permission' },
      { status: 'none', reason: 'the origin serves no document' },
      null,
    );
    expect(out.vantage.kind).toBe('route');
    expect(out.result.status).toBe('none');
  });

  it('stays not-checkable when neither vantage could look', () => {
    const out = mergeChannel(
      { kind: 'not-checkable', reason: 'no cross-origin permission' },
      null,
      'the binding route answered 404',
    );
    expect(out.vantage.kind).toBe('not-checkable');
    // could-not-check for the fold, which reads it as silence — never as a
    // contradiction, and never as an observed absence
    expect(out.result.status).toBe('error');
    if (out.result.status === 'error') {
      expect(out.result.reason).toContain('not checkable from this browser');
    }
  });
});

// -----------------------------------------------------------------------------
// the layered fold
// -----------------------------------------------------------------------------

const channels = (https: DualChannelProbe['https'], dns: DualChannelProbe['dns']) => ({
  https,
  dns,
});

const browserOk = (did: string): DualChannelProbe['dns'] => ({
  vantage: { kind: 'browser' },
  result: { status: 'ok', did },
});
const routeAbsent = (): DualChannelProbe['https'] => ({
  vantage: { kind: 'route' },
  result: { status: 'none', reason: 'the origin serves no /.well-known/dfos-did (HTTP 404)' },
});
const unreachable = (): DualChannelProbe['https'] => ({
  vantage: {
    kind: 'not-checkable',
    reason: 'no cross-origin permission, and the route was silent',
  },
  result: { status: 'error', reason: 'not checkable from this browser' },
});

const boundChain = (domain: string): AttestedChain => ({
  kind: 'verified',
  did: DID,
  services: [{ id: 'o1', type: 'DfosOrigin', domain } as unknown as ServiceEntry],
});

describe('probeFromChannels', () => {
  it('folds a mixed-vantage reading into an ordinary answered probe', () => {
    expect(probeFromChannels(channels(routeAbsent(), browserOk(DID)))).toEqual({
      kind: 'answered',
      https: routeAbsent().result,
      dns: browserOk(DID).result,
    });
  });

  // never `stale`: printing "this domain attests no identity" on the strength of
  // never having asked is the exact over-claim this layer exists to prevent
  it('is proxy-unavailable — not stale — when NEITHER channel could be checked', () => {
    const probe = probeFromChannels(channels(unreachable(), unreachable()));
    expect(probe.kind).toBe('proxy-unavailable');
  });
});

describe('the layered fold — vantage under the same verdicts', () => {
  // the acceptance case: a TXT record and no well-known file
  it('reads DNS-verified + well-known-absent as BOUND', () => {
    const dual = channels(routeAbsent(), browserOk(DID));
    const verdict = assessDomainBinding(
      'bvalosek.com',
      probeFromChannels(dual),
      undefined,
      boundChain('bvalosek.com'),
    );
    expect(verdict.kind).toBe('bound');
    if (verdict.kind === 'bound') {
      expect(verdict.attestedBy).toEqual(['dns']);
      // the silent channel is stated as what it is, and is not a shortfall
      expect(verdict.silences.join(' ')).toContain('serves no');
    }
  });

  // the neutral state does not weaken the verdict either: a channel nobody could
  // read is silence beside an attesting one
  it('still reads BOUND when the well-known channel was not checkable at all', () => {
    const dual = channels(unreachable(), browserOk(DID));
    const verdict = assessDomainBinding(
      'bvalosek.com',
      probeFromChannels(dual),
      undefined,
      boundChain('bvalosek.com'),
    );
    expect(verdict.kind).toBe('bound');
  });

  // and the loud negative stays loud: two channels answering differently is a
  // contradiction whichever vantage read them
  it('keeps a cross-vantage disagreement BROKEN', () => {
    const dual = channels(
      { vantage: { kind: 'route' }, result: { status: 'ok', did: OTHER } },
      browserOk(DID),
    );
    const verdict = assessDomainBinding(
      'bvalosek.com',
      probeFromChannels(dual),
      undefined,
      boundChain('bvalosek.com'),
    );
    expect(verdict.kind).toBe('broken');
  });

  // a channel answering a DID the chain does not derive is still broken
  it('keeps an answer naming another identity BROKEN', () => {
    const dual = channels(routeAbsent(), browserOk(OTHER));
    const verdict = assessDomainBinding('bvalosek.com', probeFromChannels(dual), undefined, {
      kind: 'verified',
      did: OTHER,
      services: [],
    });
    // the attested chain claims no domain at all — half a binding is no binding
    expect(verdict.kind).toBe('no-chain-claim');
  });
});

// -----------------------------------------------------------------------------
// the whole walk
// -----------------------------------------------------------------------------

describe('probeBindingChannels', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('reads both channels from the browser and never touches the route', async () => {
    const seen: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        seen.push(url);
        if (url.includes('dns-query')) return Response.json(dohBody([`"did=${DID}"`]));
        return new Response(`${DID}\n`, { status: 200 });
      }),
    );
    const out = await probeBindingChannels('example.com');
    expect(out.dns.vantage.kind).toBe('browser');
    expect(out.https.vantage.kind).toBe('browser');
    expect(seen.some((u) => u.startsWith('/api/binding'))).toBe(false);
  });

  // the bvalosek.com shape: DNS answers in the tab, the origin refuses the
  // cross-origin read, and the route fills that one channel in
  it('fills only the not-checkable channel in from the route', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url.includes('dns-query')) return Response.json(dohBody([`"did=${DID}"`]));
        if (url.startsWith('/api/binding')) {
          return Response.json({
            https: { status: 'none', reason: 'the origin serves no document' },
            dns: { status: 'ok', did: OTHER },
          });
        }
        throw new TypeError('Failed to fetch');
      }),
    );
    const out = await probeBindingChannels('bvalosek.com');
    // browser-first: the route's DNS answer never overrides the tab's own
    expect(out.dns).toEqual({ vantage: { kind: 'browser' }, result: { status: 'ok', did: DID } });
    expect(out.https.vantage.kind).toBe('route');
    expect(out.https.result.status).toBe('none');
  });

  it('leaves a channel not-checkable when the route is unavailable too', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url.startsWith('/api/binding')) return new Response('not found', { status: 404 });
        throw new TypeError('Failed to fetch');
      }),
    );
    const out = await probeBindingChannels('example.com');
    expect(out.https.vantage.kind).toBe('not-checkable');
    expect(out.dns.vantage.kind).toBe('not-checkable');
    expect(probeFromChannels(out).kind).toBe('proxy-unavailable');
  });
});
