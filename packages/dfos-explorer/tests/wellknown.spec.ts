/**
 * Well-known app description logic — the pure half of the domain view.
 *
 * TWO CARRIAGE DOCUMENTS, AND THE DIFFERENCE BETWEEN THEM IS THE POINT.
 *
 * The POSITIVE cases run against a minted fixture (tests/fixtures/dfos-app.minted.json,
 * re-mintable via tests/fixtures/mint-dfos-app.ts): a single-key genesis followed by
 * an introduction carrying that key's own possession proof. It exercises the same
 * parse/verify surface a real document does — multi-operation carriage, a client_did
 * the chain derives, an embedded envelope — and it verifies.
 *
 * The NEGATIVE case runs against tests/fixtures/dfos-app.plural-genesis.json —
 * the byte-preserved document the demo served before key possession, whose
 * genesis declares several distinct keys where a genesis declares exactly one,
 * in all three roles, and proves it by signing itself. It fails at log[0], and
 * it is kept as the documented rejection vector precisely because it is real:
 * a chain an actual deployment once carried, not a synthetic mutation.
 *
 * The repo's one REAL carriage document
 * (examples/siwd-demo/public/.well-known/dfos-app.json) carries the demo's
 * re-minted possession-conformant chain and is asserted here as a positive:
 * the suite fails if the document a real deployment serves stops verifying.
 *
 * Assertions compare a derived DID to the document's OWN client_did rather than to a
 * hardcoded string, so re-minting either identity does not break them — only a
 * genuinely broken binding does.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  assessDocument,
  classifyEnvelope,
  compareLogs,
  fetchAppDocument,
  originVerified,
  validateStructure,
  verifyCarriedChain,
  withRelayLog,
  type AppDescription,
} from '../src/lib/wellknown';

const repoRoot = resolve(import.meta.dirname, '../../..');
const readJson = (rel: string): Record<string, unknown> =>
  JSON.parse(readFileSync(resolve(repoRoot, rel), 'utf-8')) as Record<string, unknown>;

/**
 * The pre-possession demo document, bytes preserved from the deployment that
 * served it. Its multi-key genesis makes it the REJECTION vector — see the
 * file header.
 */
const pluralGenesisApp = (): AppDescription =>
  JSON.parse(
    readFileSync(resolve(import.meta.dirname, 'fixtures/dfos-app.plural-genesis.json'), 'utf-8'),
  ) as AppDescription;

/** The real deployed demo's document — re-minted under key possession, verifying. */
const deployedDemoApp = (): AppDescription =>
  readJson('examples/siwd-demo/public/.well-known/dfos-app.json') as unknown as AppDescription;

/** The minted, verifying carriage the positive cases run against. */
const demoApp = (): AppDescription =>
  JSON.parse(
    readFileSync(resolve(import.meta.dirname, 'fixtures/dfos-app.minted.json'), 'utf-8'),
  ) as AppDescription;

// -----------------------------------------------------------------------------
// the proxy contract
// -----------------------------------------------------------------------------

describe('classifyEnvelope', () => {
  it('passes an ok envelope through with its document', () => {
    expect(classifyEnvelope({ status: 'ok', httpStatus: 200, body: { name: 'x' } })).toEqual({
      kind: 'ok',
      document: { name: 'x' },
    });
  });

  it('reads a clean 404 as no-app-description', () => {
    expect(classifyEnvelope({ status: 'no-app-description', httpStatus: 404 })).toEqual({
      kind: 'no-app-description',
      httpStatus: 404,
    });
  });

  it.each(['http-error', 'unreachable', 'too-large', 'timeout', 'refused'] as const)(
    'reads %s as unreachable, keeping the reason',
    (status) => {
      const out = classifyEnvelope({ status, reason: 'because' });
      expect(out.kind).toBe('unreachable');
      if (out.kind === 'unreachable') {
        expect(out.status).toBe(status);
        expect(out.reason).toBe('because');
      }
    },
  );

  it('supplies its own reason when the proxy sends none', () => {
    const out = classifyEnvelope({ status: 'timeout' });
    expect(out.kind).toBe('unreachable');
    if (out.kind === 'unreachable') expect(out.reason).toMatch(/in time/);
  });

  // the honesty rule: OUR route misbehaving is never evidence about THEIR origin
  it('never blames the origin for an off-contract answer', () => {
    expect(classifyEnvelope(null).kind).toBe('proxy-unavailable');
    expect(classifyEnvelope('<!doctype html>').kind).toBe('proxy-unavailable');
    expect(classifyEnvelope({ status: 'banana' }).kind).toBe('proxy-unavailable');
    // "ok" with no body is incoherent — not an empty document
    expect(classifyEnvelope({ status: 'ok' }).kind).toBe('proxy-unavailable');
  });
});

describe('fetchAppDocument', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('treats a missing route (vite dev) as proxy-unavailable, not absence', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('not found', { status: 404 })),
    );
    const out = await fetchAppDocument('3p.com');
    expect(out.kind).toBe('proxy-unavailable');
  });

  it('treats an HTML answer as proxy-unavailable', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('<!doctype html><title>dev</title>', { status: 200 })),
    );
    expect((await fetchAppDocument('3p.com')).kind).toBe('proxy-unavailable');
  });

  it('treats a rejected fetch as proxy-unavailable', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('network down');
      }),
    );
    const out = await fetchAppDocument('3p.com');
    expect(out.kind).toBe('proxy-unavailable');
    if (out.kind === 'proxy-unavailable') expect(out.reason).toBe('network down');
  });

  it('classifies a contract answer', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Response.json({ status: 'no-app-description', httpStatus: 404 })),
    );
    expect((await fetchAppDocument('3p.com')).kind).toBe('no-app-description');
  });

  it('sends the host encoded', async () => {
    const seen: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        seen.push(url);
        return Response.json({ status: 'no-app-description' });
      }),
    );
    await fetchAppDocument('a b.com');
    expect(seen[0]).toBe('/api/wellknown?host=a%20b.com');
  });
});

// -----------------------------------------------------------------------------
// structural validation — the canonical schema, via the generated validator
// -----------------------------------------------------------------------------

describe('validateStructure', () => {
  it('accepts every valid fixture', () => {
    for (const f of ['client-did-no-chain', 'full-carriage', 'minimal-identity-scope']) {
      const doc = readJson(`schemas/dfos-app.v1.fixtures/valid/${f}.json`);
      expect(validateStructure(doc).ok, f).toBe(true);
    }
  });

  it('rejects every invalid fixture', () => {
    for (const f of [
      'chain-over-carriage-cap',
      'chain-without-client-did',
      'empty-identity-chain',
      'empty-name',
      'empty-redirect-uris',
      'malformed-client-did',
      'missing-redirect-uris',
      'non-string-client-did',
      'unknown-member',
    ]) {
      const doc = readJson(`schemas/dfos-app.v1.fixtures/invalid/${f}.json`);
      expect(validateStructure(doc).ok, f).toBe(false);
    }
  });

  it('names the closed member set when an unknown member appears', () => {
    const out = validateStructure(
      readJson('schemas/dfos-app.v1.fixtures/invalid/unknown-member.json'),
    );
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.errors.join(' ')).toMatch(/member set is closed/);
  });

  it('names the carriage cap when the chain is too long', () => {
    const out = validateStructure(
      readJson('schemas/dfos-app.v1.fixtures/invalid/chain-over-carriage-cap.json'),
    );
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.errors.join(' ')).toMatch(/100-operation carriage cap/);
  });

  it('names the missing member', () => {
    const out = validateStructure(
      readJson('schemas/dfos-app.v1.fixtures/invalid/missing-redirect-uris.json'),
    );
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.errors.join(' ')).toMatch(/missing required member `redirect_uris`/);
  });

  // a nameless document is fully valid — the domain leads (SIWD.md: name is optional)
  it('accepts a document with no name', () => {
    expect(validateStructure(readJson('schemas/dfos-app.v1.fixtures/valid/no-name.json')).ok).toBe(
      true,
    );
  });

  // presence-but-empty is malformed, not absent — SIWD.md is explicit
  it('rejects a present-but-empty member', () => {
    expect(validateStructure({ name: '', redirect_uris: ['https://x.com/cb'] }).ok).toBe(false);
    expect(validateStructure({ name: 'x', redirect_uris: [] }).ok).toBe(false);
  });

  it('rejects non-objects outright', () => {
    expect(validateStructure(null).ok).toBe(false);
    expect(validateStructure('a string').ok).toBe(false);
    expect(validateStructure([]).ok).toBe(false);
  });
});

// -----------------------------------------------------------------------------
// chain verification — the binding, and its rejection
// -----------------------------------------------------------------------------

describe('verifyCarriedChain', () => {
  it('verifies the real carried chain and derives its client_did', async () => {
    const app = demoApp();
    const out = await verifyCarriedChain(app);
    expect(out.ok, out.ok ? '' : out.error).toBe(true);
    if (out.ok) {
      expect(out.did).toBe(app.client_did);
      expect(out.log).toHaveLength(app.identity_chain?.length ?? 0);
    }
  });

  // the whole point of the beat: an internally-valid chain for a DIFFERENT
  // identity must not launder itself in under someone else's client_did
  it('REJECTS the whole document when client_did is not what the chain derives', async () => {
    const app = demoApp();
    const out = await verifyCarriedChain({
      ...app,
      client_did: 'did:dfos:2346789acdefhknrtvz2346789acdef',
    });
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.error).toMatch(/does not match the chain it carries/);
      expect(out.error).toMatch(/whole document is rejected/i);
    }
  });

  it('fails a chain that does not verify', async () => {
    const app = demoApp();
    const out = await verifyCarriedChain({ ...app, identity_chain: ['not.a.jws'] });
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error).toMatch(/failed verification/);
  });

  it('fails a suffix — carriage is the whole chain from genesis or nothing', async () => {
    const app = demoApp();
    const chain = app.identity_chain ?? [];
    const out = await verifyCarriedChain({ ...app, identity_chain: chain.slice(1) });
    expect(out.ok).toBe(false);
  });

  it('reports an absent chain rather than throwing', async () => {
    const out = await verifyCarriedChain({ name: 'x', redirect_uris: ['https://x.com/cb'] });
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error).toMatch(/no identity_chain/);
  });

  // THE PRE-POSSESSION DEMO DOCUMENT, PINNED AS A REJECTION.
  //
  // Its genesis declares several distinct keys. A genesis declares exactly one, in
  // all three roles, and proves it by signing itself — so this chain fails at its
  // FIRST operation, before any question of what the later ones say. The bytes are
  // preserved from the deployment that served them, which is what keeps this
  // negative honest: it is a chain the world actually held, not a mutation built
  // to fail.
  it('REJECTS the pre-possession demo document at log[0] — its genesis is multi-key', async () => {
    const out = await verifyCarriedChain(pluralGenesisApp());
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.error).toMatch(/log\[0\]/);
      expect(out.error).toMatch(/exactly one key/i);
    }
  });

  // THE DEPLOYED DEMO'S OWN DOCUMENT, ASSERTED AS A POSITIVE.
  //
  // The re-minted chain: a single-key genesis, then an introduction carrying the
  // key's own possession proof. The DID comparison is derived-vs-own, so a future
  // re-mint moves nothing here — only a genuinely broken binding fails.
  it('VERIFIES the deployed demo document, deriving its own client_did', async () => {
    const doc = deployedDemoApp();
    const out = await verifyCarriedChain(doc);
    expect(out.ok, out.ok ? '' : out.error).toBe(true);
    if (out.ok) expect(out.did).toBe(doc.client_did);
  });
});

// -----------------------------------------------------------------------------
// the ordered-log comparison
// -----------------------------------------------------------------------------

describe('compareLogs', () => {
  it('identical logs', () => {
    expect(compareLogs(['a', 'b'], ['a', 'b'])).toEqual({
      verdict: 'identical',
      shared: 2,
      originOnly: 0,
      relayOnly: 0,
    });
  });

  it('origin ahead — the relays simply have not ingested yet', () => {
    expect(compareLogs(['a', 'b', 'c'], ['a'])).toEqual({
      verdict: 'ahead',
      shared: 1,
      originOnly: 2,
      relayOnly: 0,
    });
  });

  // the rollback signal: the document has SHED operations it once carried
  it('origin behind — a strict prefix of the relay log is a rollback', () => {
    expect(compareLogs(['a'], ['a', 'b', 'c'])).toEqual({
      verdict: 'behind',
      shared: 1,
      originOnly: 0,
      relayOnly: 2,
    });
  });

  it('diverged — same position, different signed operation', () => {
    expect(compareLogs(['a', 'b'], ['a', 'x'])).toEqual({
      verdict: 'diverged',
      shared: 1,
      originOnly: 1,
      relayOnly: 1,
    });
  });

  it('divergence at genesis shares nothing', () => {
    expect(compareLogs(['a'], ['z'])).toMatchObject({ verdict: 'diverged', shared: 0 });
  });

  // a contradiction inside the overlap outranks a length difference — a longer
  // origin log that already disagrees is NOT "ahead"
  it('prefers divergence over a length verdict', () => {
    expect(compareLogs(['a', 'x', 'y'], ['a', 'b'])).toMatchObject({
      verdict: 'diverged',
      shared: 1,
    });
  });

  it('is total on empty logs', () => {
    expect(compareLogs([], [])).toMatchObject({ verdict: 'identical', shared: 0 });
    expect(compareLogs(['a'], [])).toMatchObject({ verdict: 'ahead' });
    expect(compareLogs([], ['a'])).toMatchObject({ verdict: 'behind' });
  });
});

// -----------------------------------------------------------------------------
// folding the relay beat into the verdict
// -----------------------------------------------------------------------------

describe('withRelayLog', () => {
  const verified = {
    kind: 'verified' as const,
    app: { name: 'x', redirect_uris: ['https://x.com/cb'] },
    did: 'did:dfos:x',
    log: ['a', 'b'],
    relayLog: [],
  };

  it('keeps a verified verdict green when the logs agree', () => {
    const out = withRelayLog(verified, ['a', 'b']);
    expect(out.kind).toBe('verified');
    if (out.kind === 'verified') expect(out.relayLog).toEqual(['a', 'b']);
  });

  it('downgrades to relay-diverged on any disagreement', () => {
    for (const relayLog of [['a'], ['a', 'b', 'c'], ['a', 'z']]) {
      const out = withRelayLog(verified, relayLog);
      expect(out.kind, JSON.stringify(relayLog)).toBe('relay-diverged');
    }
  });

  it('carries the comparison detail through', () => {
    const out = withRelayLog(verified, ['a']);
    expect(out.kind).toBe('relay-diverged');
    if (out.kind === 'relay-diverged') expect(out.comparison.verdict).toBe('ahead');
  });

  it('leaves every non-verified verdict alone', () => {
    const malformed = { kind: 'malformed' as const, errors: ['nope'] };
    expect(withRelayLog(malformed, ['a'])).toBe(malformed);
    const carriage = { kind: 'no-carriage' as const, app: verified.app };
    expect(withRelayLog(carriage, ['a'])).toBe(carriage);
  });

  it('originVerified narrows both proven verdicts and nothing else', () => {
    expect(originVerified(verified)?.did).toBe('did:dfos:x');
    expect(originVerified(withRelayLog(verified, ['a']))?.did).toBe('did:dfos:x');
    expect(originVerified({ kind: 'malformed', errors: [] })).toBeNull();
    expect(originVerified(null)).toBeNull();
  });
});

// -----------------------------------------------------------------------------
// end to end over the document beats
// -----------------------------------------------------------------------------

describe('assessDocument', () => {
  it('verifies a well-formed carriage document end to end', async () => {
    const out = await assessDocument({ kind: 'ok', document: demoApp() });
    expect(out.kind).toBe('verified');
    if (out.kind === 'verified') expect(out.did).toBe(demoApp().client_did);
  });

  // ruling: a schema-valid document with no chain is its own honest sub-state,
  // never green and never laundered into one of the failure states
  it('reports a chain-less document as no-carriage', async () => {
    const out = await assessDocument({
      kind: 'ok',
      document: readJson('schemas/dfos-app.v1.fixtures/valid/minimal-identity-scope.json'),
    });
    expect(out.kind).toBe('no-carriage');
  });

  it('reports a client_did without carriage as no-carriage too', async () => {
    const out = await assessDocument({
      kind: 'ok',
      document: readJson('schemas/dfos-app.v1.fixtures/valid/client-did-no-chain.json'),
    });
    expect(out.kind).toBe('no-carriage');
  });

  it('reports a structurally bad document as malformed', async () => {
    const out = await assessDocument({ kind: 'ok', document: { name: 'x' } });
    expect(out.kind).toBe('malformed');
  });

  it('reports an unverifiable chain as malformed', async () => {
    const out = await assessDocument({
      kind: 'ok',
      document: readJson('schemas/dfos-app.v1.fixtures/valid/full-carriage.json'),
    });
    // structurally valid placeholder JWS strings — they cannot fold
    expect(out.kind).toBe('malformed');
  });

  it('passes transport outcomes through, flagging our own route separately', async () => {
    const down = await assessDocument({ kind: 'proxy-unavailable', reason: 'no route' });
    expect(down).toMatchObject({ kind: 'unreachable', proxyDown: true });

    const origin = await assessDocument({
      kind: 'unreachable',
      status: 'timeout',
      reason: 'slow',
      httpStatus: null,
    });
    expect(origin).toMatchObject({ kind: 'unreachable', proxyDown: false });

    const absent = await assessDocument({ kind: 'no-app-description', httpStatus: 404 });
    expect(absent).toMatchObject({ kind: 'no-app-description', httpStatus: 404 });
  });
});
