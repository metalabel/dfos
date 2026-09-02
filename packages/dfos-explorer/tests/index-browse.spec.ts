import { describe, expect, it } from 'vitest';
import {
  decideGatedContentPresent,
  decideIter2,
  gatedContentFromProbe,
  indexBrowseMode,
  indexCredSource,
  indexListState,
  indexListStateFor,
  isRouteAbsent,
  iter2FromProbeStatus,
  ROUTE_ABSENT,
  routeAbsentFromStatuses,
} from '../src/lib/index-light';

describe('indexBrowseMode — enumeration source decision', () => {
  it('index-capable + no error → the live relay index (incl. a genuinely-empty index)', () => {
    expect(indexBrowseMode(true, false, false)).toBe('index');
    expect(indexBrowseMode(true, false, true)).toBe('index');
  });

  it('index-capable + errored + a local corpus exists → fall back to local, noted', () => {
    expect(indexBrowseMode(true, true, true)).toBe('index-fell-back');
  });

  it('index-capable + errored + no local corpus → honest unavailable (never false-empty)', () => {
    expect(indexBrowseMode(true, true, false)).toBe('index-unavailable');
  });

  it('no index-capable relay (false/null) → the local path, regardless of index error', () => {
    expect(indexBrowseMode(false, false, true)).toBe('local');
    expect(indexBrowseMode(false, true, false)).toBe('local');
    expect(indexBrowseMode(null, false, false)).toBe('local');
  });
});

describe('indexListState — list render state (rows > error > loading > empty)', () => {
  it('rows present wins over loading/error flags', () => {
    expect(indexListState(true, true, 5)).toBe('rows');
  });

  it('empty + errored → error, never a false empty', () => {
    expect(indexListState(false, true, 0)).toBe('error');
  });

  it('empty + still loading → loading', () => {
    expect(indexListState(true, false, 0)).toBe('loading');
  });

  it('settled + empty → empty', () => {
    expect(indexListState(false, false, 0)).toBe('empty');
  });
});

describe('indexListStateFor — a pending capability probe is LOADING, never empty', () => {
  it('indexed === null reads loading even though the disabled pager is not loading', () => {
    // the exact false-empty this exists to prevent: nothing has been asked yet,
    // so "the relay returned no rows" would be a claim about a request that
    // never went out
    expect(indexListStateFor(null, false, false, 0)).toBe('loading');
  });

  it('once the probe settles it is the plain list state again', () => {
    expect(indexListStateFor(true, false, false, 0)).toBe('empty');
    expect(indexListStateFor(false, false, false, 0)).toBe('empty');
    expect(indexListStateFor(true, true, false, 0)).toBe('loading');
  });

  it('rows and errors still outrank a pending probe', () => {
    expect(indexListStateFor(null, false, false, 3)).toBe('rows');
    expect(indexListStateFor(null, false, true, 0)).toBe('error');
  });
});

describe('routeAbsentFromStatuses — durable route-absence vs a transient failure', () => {
  it('every relay answering 404/501 is the durable verdict', () => {
    expect(routeAbsentFromStatuses([404])).toBe(true);
    expect(routeAbsentFromStatuses([501])).toBe(true);
    expect(routeAbsentFromStatuses([404, 501, 404])).toBe(true);
  });

  it('one unreachable relay makes the whole failure transient', () => {
    // a relay we could not reach says NOTHING about what it serves — condemning
    // the route on that basis would hide a working feed for the session
    expect(routeAbsentFromStatuses([0])).toBe(false);
    expect(routeAbsentFromStatuses([404, 0])).toBe(false);
  });

  it('a 5xx or a rejected cursor (400) is transient, not a verdict about the route', () => {
    expect(routeAbsentFromStatuses([500])).toBe(false);
    expect(routeAbsentFromStatuses([400])).toBe(false);
    expect(routeAbsentFromStatuses([404, 400])).toBe(false);
  });

  it('an empty set is no verdict — nothing was asked', () => {
    expect(routeAbsentFromStatuses([])).toBe(false);
  });
});

describe('isRouteAbsent — reading the verdict off a rejection', () => {
  it('recognizes the tagged rejection and nothing else', () => {
    expect(isRouteAbsent(new Error('gone', { cause: ROUTE_ABSENT }))).toBe(true);
    expect(isRouteAbsent(new Error('gone'))).toBe(false);
    expect(isRouteAbsent(new Error('gone', { cause: 'something else' }))).toBe(false);
    expect(isRouteAbsent('not an error')).toBe(false);
    expect(isRouteAbsent(null)).toBe(false);
  });
});

describe('iter2FromProbeStatus — one relay’s order-probe verdict', () => {
  it('400 (unknown order rejected) → validates order → iteration-2', () => {
    expect(iter2FromProbeStatus(400)).toBe(true);
  });

  it('2xx (order silently ignored) → pre-iteration-2', () => {
    expect(iter2FromProbeStatus(200)).toBe(false);
    expect(iter2FromProbeStatus(204)).toBe(false);
  });

  it('501/5xx/unreachable(0) → indeterminate (defer to the next relay)', () => {
    expect(iter2FromProbeStatus(501)).toBeNull();
    expect(iter2FromProbeStatus(500)).toBeNull();
    expect(iter2FromProbeStatus(404)).toBeNull();
    expect(iter2FromProbeStatus(0)).toBeNull();
  });
});

describe('decideIter2 — support across the ordered relay set', () => {
  it('a single 400 relay → supported; a single 200 relay → unsupported', () => {
    expect(decideIter2([400])).toBe(true);
    expect(decideIter2([200])).toBe(false);
  });

  it('the first DEFINITIVE relay wins (mirrors query failover order)', () => {
    // indeterminate relays are skipped until one answers definitively
    expect(decideIter2([501, 0, 400])).toBe(true);
    // a reachable pre-iter2 relay ahead of an iter2 one → unsupported (it serves)
    expect(decideIter2([200, 400])).toBe(false);
  });

  it('all-indeterminate (or empty) → unsupported — the SAFE default', () => {
    expect(decideIter2([501, 0, 500])).toBe(false);
    expect(decideIter2([])).toBe(false);
  });
});

describe('gatedContentFromProbe — does this relay hold non-public content?', () => {
  it('a served page with rows → yes; a served empty page → no', () => {
    expect(gatedContentFromProbe(200, 1)).toBe(true);
    expect(gatedContentFromProbe(200, 0)).toBe(false);
  });

  it('a relay that IGNORES publicRead= answers with rows → reads as yes (the safe direction)', () => {
    // an unfiltered corpus page comes back non-empty, so the control is kept
    expect(gatedContentFromProbe(200, 25)).toBe(true);
  });

  it('non-2xx and network failures are no verdict at all', () => {
    expect(gatedContentFromProbe(501, 0)).toBeNull();
    expect(gatedContentFromProbe(500, 0)).toBeNull();
    expect(gatedContentFromProbe(0, 0)).toBeNull();
  });
});

describe('decideGatedContentPresent — whether a public-only control is worth showing', () => {
  const probe = (status: number, rows: number) => ({ relay: 'https://r.example', status, rows });

  it('any relay definitively holding non-public rows shows the control', () => {
    expect(decideGatedContentPresent([probe(200, 1)])).toBe(true);
    expect(decideGatedContentPresent([probe(200, 0), probe(200, 3)])).toBe(true);
    expect(decideGatedContentPresent([probe(0, 0), probe(200, 2)])).toBe(true);
  });

  it('a definitive empty answer and nothing to the contrary hides it', () => {
    expect(decideGatedContentPresent([probe(200, 0)])).toBe(false);
    expect(decideGatedContentPresent([probe(200, 0), probe(501, 0)])).toBe(false);
  });

  it('ALL-indeterminate (or empty) keeps the control — never withdraw on not having looked', () => {
    expect(decideGatedContentPresent([probe(501, 0), probe(0, 0)])).toBe(true);
    expect(decideGatedContentPresent([])).toBe(true);
  });
});

describe('indexCredSource — credential lane: live index vs local fold', () => {
  it('index-capable + route answered → read from the live relay index', () => {
    expect(indexCredSource(true, false)).toBe(true);
  });

  it('index-capable + route errored → fall back to the local fold (never false-empty)', () => {
    // the whole point of B: a relay advertising capability.index but lacking the
    // /index/v0/credentials sub-route must NOT blank the panel.
    expect(indexCredSource(true, true)).toBe(false);
  });

  it('not index-capable (false/null) → local fold, regardless of the error flag', () => {
    expect(indexCredSource(false, false)).toBe(false);
    expect(indexCredSource(false, true)).toBe(false);
    expect(indexCredSource(null, false)).toBe(false);
    expect(indexCredSource(null, true)).toBe(false);
  });
});
