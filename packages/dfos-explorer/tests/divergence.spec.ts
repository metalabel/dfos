import { IDBFactory } from 'fake-indexeddb';
import { describe, expect, it } from 'vitest';
import type { ChainRollup } from '../src/lib/db';
import { openExplorerDb } from '../src/lib/db';
import {
  bodyNamesOperation,
  checkDivergence,
  classifyAnswers,
  sampleChainHeads,
  summarize,
  type ProbeOutcome,
  type RelayAnswer,
} from '../src/lib/divergence';

const chain = (
  chainId: string,
  firstCreatedAt: string,
  headCid = `head-${chainId}`,
): ChainRollup => ({
  chainId,
  kind: 'content-op',
  opCount: 1,
  firstCreatedAt,
  lastCreatedAt: firstCreatedAt,
  headCid,
});

// A relay's answer is a status AND, on a 2xx, whether the body was the operation
// asked for. Both halves have to be definitive: an absence only from an answered
// 404, a presence only from a body that names the op.
const answered = (status: number, namesOp = status >= 200 && status < 300): RelayAnswer => ({
  status,
  namesOp,
});

describe('bodyNamesOperation — a 200 is a response, not the operation', () => {
  it('accepts the body both relay twins serve for this route', () => {
    expect(
      bodyNamesOperation(
        { cid: 'bafy-a', jwsToken: 'eyJ…', chainType: 'identity', chainId: 'did:dfos:aaa' },
        'bafy-a',
      ),
    ).toBe(true);
  });

  it('rejects a body that names a DIFFERENT operation', () => {
    expect(bodyNamesOperation({ cid: 'bafy-b' }, 'bafy-a')).toBe(false);
  });

  it('rejects everything that names nothing at all', () => {
    // the catch-all host: an SPA serving index.html parses to null, or to JSON
    // with no cid — either way it has told us nothing about this operation
    expect(bodyNamesOperation(null, 'bafy-a')).toBe(false);
    expect(bodyNamesOperation(undefined, 'bafy-a')).toBe(false);
    expect(bodyNamesOperation({}, 'bafy-a')).toBe(false);
    expect(bodyNamesOperation({ cid: 42 }, 'bafy-a')).toBe(false);
    expect(bodyNamesOperation('<!doctype html>', 'bafy-a')).toBe(false);
  });
});

describe('classifyAnswers — only an ANSWERED absence and a NAMED presence count', () => {
  it('a 2xx naming the op is present, whatever the other relays said', () => {
    expect(classifyAnswers([answered(200)])).toBe('present');
    expect(classifyAnswers([answered(404), answered(200)])).toBe('present');
    expect(classifyAnswers([answered(0), answered(500), answered(204)])).toBe('present');
  });

  // THE CATCH-ALL 200. A host answering index.html for every path used to make
  // every sampled op 'present' and the whole check read ALIGNED — divergence
  // detection switched off, silently, by a misconfiguration.
  it('a 2xx whose body does not name the op is UNKNOWN, never present', () => {
    expect(classifyAnswers([{ status: 200, namesOp: false }])).toBe('unknown');
    expect(
      classifyAnswers([
        { status: 200, namesOp: false },
        { status: 200, namesOp: false },
      ]),
    ).toBe('unknown');
  });

  // …and never ABSENT either: the host answered, it just answered nothing about
  // this operation. Reading that as a definite absence would flip the failure
  // from a false 'aligned' to a false 'diverged'.
  it('a catch-all 200 beside a real 404 is unknown, not absence', () => {
    expect(classifyAnswers([answered(404), { status: 200, namesOp: false }])).toBe('unknown');
  });

  it('a 404/410 from every relay is a definite absence', () => {
    expect(classifyAnswers([answered(404)])).toBe('absent');
    expect(classifyAnswers([answered(404), answered(410)])).toBe('absent');
  });

  it('a network failure is UNKNOWN, never divergence', () => {
    expect(classifyAnswers([answered(0)])).toBe('unknown');
    expect(classifyAnswers([answered(0), answered(0)])).toBe('unknown');
    // one relay says gone, the other never answered — we did not look everywhere
    expect(classifyAnswers([answered(404), answered(0)])).toBe('unknown');
  });

  it('server errors and gating are inconclusive, not absence', () => {
    expect(classifyAnswers([answered(500)])).toBe('unknown');
    expect(classifyAnswers([answered(503), answered(404)])).toBe('unknown');
    expect(classifyAnswers([answered(401)])).toBe('unknown');
    expect(classifyAnswers([answered(403), answered(404)])).toBe('unknown');
    expect(classifyAnswers([answered(429)])).toBe('unknown');
  });

  it('no relays probed at all is inconclusive', () => {
    expect(classifyAnswers([])).toBe('unknown');
  });
});

describe('summarize — the advisory verdict', () => {
  const at = 1_700_000_000_000;
  const report = (outcomes: ProbeOutcome[]) => summarize(outcomes, at);

  it('nothing sampled is empty, not aligned', () => {
    expect(report([]).verdict).toBe('empty');
  });

  it('all present is aligned', () => {
    expect(report(['present', 'present', 'present']).verdict).toBe('aligned');
  });

  it('one definite absence diverges the whole verdict', () => {
    expect(report(['present', 'present', 'absent']).verdict).toBe('diverged');
  });

  it('an absence outranks an inconclusive probe', () => {
    expect(report(['unknown', 'absent']).verdict).toBe('diverged');
  });

  it('any inconclusive probe with no absence makes the CHECK inconclusive', () => {
    // the honest failure mode: an unreachable relay must never read as clean
    expect(report(['present', 'present', 'unknown']).verdict).toBe('unknown');
    expect(report(['unknown']).verdict).toBe('unknown');
  });

  it('carries the tallies and the clock', () => {
    expect(report(['present', 'absent', 'unknown'])).toEqual({
      verdict: 'diverged',
      sampled: 3,
      present: 1,
      absent: 1,
      unknown: 1,
      checkedAt: at,
    });
  });
});

describe('sampleChainHeads — an even spread, oldest first', () => {
  it('returns every head when the corpus is smaller than the sample', () => {
    const chains = [chain('c', '2026-03-01'), chain('a', '2026-01-01'), chain('b', '2026-02-01')];
    expect(sampleChainHeads(chains, 12)).toEqual(['head-a', 'head-b', 'head-c']);
  });

  it('spans oldest to newest rather than crowding one end', () => {
    const chains = Array.from({ length: 100 }, (_, i) =>
      chain(`c${String(i).padStart(3, '0')}`, `2026-01-01T00:00:${String(i).padStart(2, '0')}Z`),
    );
    const picked = sampleChainHeads(chains, 5);
    expect(picked).toHaveLength(5);
    // the extremes are always included — a re-mint replaces the OLD history, so a
    // sample that never reaches the first chain would miss it entirely
    expect(picked[0]).toBe('head-c000');
    expect(picked[4]).toBe('head-c099');
  });

  it('is deterministic — a re-check samples the same operations', () => {
    const chains = Array.from({ length: 40 }, (_, i) => chain(`c${i}`, `2026-01-0${i % 9}`));
    expect(sampleChainHeads(chains, 6)).toEqual(sampleChainHeads(chains, 6));
  });

  it('skips chains with no head and degenerate sizes', () => {
    expect(sampleChainHeads([chain('a', '2026-01-01', '')], 4)).toEqual([]);
    expect(sampleChainHeads([], 4)).toEqual([]);
    expect(sampleChainHeads([chain('a', '2026-01-01')], 0)).toEqual([]);
  });
});

describe('checkDivergence — over a real store', () => {
  const freshDb = () => openExplorerDb(`divergence-${Math.random()}`, new IDBFactory());

  /** A stub relay. A 2xx serves the operation body the real route serves — echoing
   *  back the CID in the URL — unless `body` overrides it, which is how the
   *  catch-all host is expressed. */
  const withFetch = async (
    handler: (url: string) => { status: number; body?: unknown } | 'throw',
    run: () => Promise<void>,
  ): Promise<void> => {
    const original = globalThis.fetch;
    globalThis.fetch = ((input: RequestInfo | URL) => {
      const url = String(input);
      const out = handler(url);
      if (out === 'throw') return Promise.reject(new Error('network'));
      const cid = decodeURIComponent(url.slice(url.lastIndexOf('/') + 1));
      const body = 'body' in out ? out.body : { cid, jwsToken: 'eyJ…' };
      return Promise.resolve({
        status: out.status,
        json: () =>
          body === undefined ? Promise.reject(new Error('not json')) : Promise.resolve(body),
      } as Response);
    }) as typeof fetch;
    try {
      await run();
    } finally {
      globalThis.fetch = original;
    }
  };

  it('an empty local index has nothing to compare', async () => {
    const db = await freshDb();
    await withFetch(
      () => ({ status: 200 }),
      async () => {
        expect((await checkDivergence({ db, relays: ['http://r'] })).verdict).toBe('empty');
      },
    );
    db.close();
  });

  it('flags a corpus the relay no longer serves', async () => {
    const db = await freshDb();
    await db.putBatch([], [chain('old', '2022-02-18'), chain('new', '2026-08-28')]);
    await withFetch(
      (url) => ({ status: url.includes('head-old') ? 404 : 200 }),
      async () => {
        const report = await checkDivergence({ db, relays: ['http://r'] });
        expect(report.verdict).toBe('diverged');
        expect(report.absent).toBe(1);
        expect(report.present).toBe(1);
      },
    );
    db.close();
  });

  it('an unreachable relay reports unknown, not divergence', async () => {
    const db = await freshDb();
    await db.putBatch([], [chain('old', '2022-02-18')]);
    await withFetch(
      () => 'throw',
      async () => {
        const report = await checkDivergence({ db, relays: ['http://r'] });
        expect(report.verdict).toBe('unknown');
        expect(report.absent).toBe(0);
      },
    );
    db.close();
  });

  it('a host answering 200 to everything reads UNKNOWN, not aligned', async () => {
    // the whole point: a misconfigured host must not be able to certify the
    // mirror. Nothing it said was evidence, so the check says it could not look.
    const db = await freshDb();
    await db.putBatch([], [chain('a', '2026-01-01'), chain('b', '2026-02-01')]);
    await withFetch(
      () => ({ status: 200, body: undefined }), // index.html — parses to nothing
      async () => {
        const report = await checkDivergence({ db, relays: ['http://r'] });
        expect(report.verdict).toBe('unknown');
        expect(report.present).toBe(0);
        expect(report.absent).toBe(0);
      },
    );
    db.close();
  });

  it('a 200 naming a DIFFERENT operation is not evidence this one is here', async () => {
    const db = await freshDb();
    await db.putBatch([], [chain('a', '2026-01-01')]);
    await withFetch(
      () => ({ status: 200, body: { cid: 'bafy-someone-else' } }),
      async () => {
        expect((await checkDivergence({ db, relays: ['http://r'] })).verdict).toBe('unknown');
      },
    );
    db.close();
  });

  it('a relay that still serves everything reads aligned', async () => {
    const db = await freshDb();
    await db.putBatch([], [chain('a', '2026-01-01'), chain('b', '2026-02-01')]);
    await withFetch(
      () => ({ status: 200 }),
      async () => {
        const report = await checkDivergence({ db, relays: ['http://r'] });
        expect(report.verdict).toBe('aligned');
        expect(report.sampled).toBe(2);
      },
    );
    db.close();
  });
});
