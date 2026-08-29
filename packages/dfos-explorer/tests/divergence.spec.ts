import { IDBFactory } from 'fake-indexeddb';
import { describe, expect, it } from 'vitest';
import type { ChainRollup } from '../src/lib/db';
import { openExplorerDb } from '../src/lib/db';
import {
  checkDivergence,
  classifyStatuses,
  sampleChainHeads,
  summarize,
  type ProbeOutcome,
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

describe('classifyStatuses — only an ANSWERED absence counts', () => {
  it('any 2xx is present, whatever the other relays said', () => {
    expect(classifyStatuses([200])).toBe('present');
    expect(classifyStatuses([404, 200])).toBe('present');
    expect(classifyStatuses([0, 500, 204])).toBe('present');
  });

  it('a 404/410 from every relay is a definite absence', () => {
    expect(classifyStatuses([404])).toBe('absent');
    expect(classifyStatuses([404, 410])).toBe('absent');
  });

  it('a network failure is UNKNOWN, never divergence', () => {
    expect(classifyStatuses([0])).toBe('unknown');
    expect(classifyStatuses([0, 0])).toBe('unknown');
    // one relay says gone, the other never answered — we did not look everywhere
    expect(classifyStatuses([404, 0])).toBe('unknown');
  });

  it('server errors and gating are inconclusive, not absence', () => {
    expect(classifyStatuses([500])).toBe('unknown');
    expect(classifyStatuses([503, 404])).toBe('unknown');
    expect(classifyStatuses([401])).toBe('unknown');
    expect(classifyStatuses([403, 404])).toBe('unknown');
    expect(classifyStatuses([429])).toBe('unknown');
  });

  it('no relays probed at all is inconclusive', () => {
    expect(classifyStatuses([])).toBe('unknown');
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

  const withFetch = async (
    handler: (url: string) => { status: number } | 'throw',
    run: () => Promise<void>,
  ): Promise<void> => {
    const original = globalThis.fetch;
    globalThis.fetch = ((input: RequestInfo | URL) => {
      const out = handler(String(input));
      if (out === 'throw') return Promise.reject(new Error('network'));
      return Promise.resolve({ status: out.status } as Response);
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
