import { describe, expect, it } from 'vitest';
import {
  decideIter2,
  indexBrowseMode,
  indexCredSource,
  indexListState,
  iter2FromProbeStatus,
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
