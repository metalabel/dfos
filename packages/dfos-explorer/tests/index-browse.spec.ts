import { describe, expect, it } from 'vitest';
import { indexBrowseMode, indexCredSource, indexListState } from '../src/lib/index-light';

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
