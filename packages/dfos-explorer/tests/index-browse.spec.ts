import { describe, expect, it } from 'vitest';
import { indexBrowseMode, indexListState } from '../src/lib/index-light';

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
