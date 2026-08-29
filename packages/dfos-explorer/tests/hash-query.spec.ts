import { describe, expect, it } from 'vitest';
import { parseRoute, readHashParam, splitHash, writeHashParam } from '../src/router';

describe('splitHash — path vs query', () => {
  it('splits at the first ?', () => {
    expect(splitHash('#/documents?after=abc&order=headAt.desc')).toEqual({
      path: '/documents',
      query: 'after=abc&order=headAt.desc',
    });
  });

  it('a bare route has an empty query', () => {
    expect(splitHash('#/identities')).toEqual({ path: '/identities', query: '' });
    expect(splitHash('')).toEqual({ path: '', query: '' });
  });
});

describe('parseRoute — query is not part of the path', () => {
  it('routes a hash carrying query state to the same view', () => {
    expect(parseRoute('#/documents?after=abc')).toEqual({ view: 'documents' });
    expect(parseRoute('#/?ops=bafy1&pub=0')).toEqual({ view: 'home' });
    expect(parseRoute('#/search?q=ada')).toEqual({ view: 'search' });
  });

  it('an id route keeps its id and ignores the query', () => {
    expect(parseRoute('#/did/did:dfos:abc?x=1')).toEqual({ view: 'did', id: 'did:dfos:abc' });
  });

  it('artifacts routes again — the browse surface returned with /index/v0/artifacts', () => {
    expect(parseRoute('#/artifacts')).toEqual({ view: 'artifacts' });
    expect(parseRoute('#/artifacts?order=ingestedAt.desc&after=bafy1')).toEqual({
      view: 'artifacts',
    });
  });

  it('local sync is a route, not a sidebar', () => {
    expect(parseRoute('#/sync')).toEqual({ view: 'sync' });
    expect(parseRoute('#sync')).toEqual({ view: 'sync' });
  });

  it('an unknown route still falls back to home', () => {
    expect(parseRoute('#/nope')).toEqual({ view: 'home' });
  });
});

describe('readHashParam / writeHashParam', () => {
  it('reads a param, or empty when absent', () => {
    expect(readHashParam('#/documents?after=abc', 'after')).toBe('abc');
    expect(readHashParam('#/documents?after=abc', 'order')).toBe('');
    expect(readHashParam('#/documents', 'after')).toBe('');
  });

  it('sets a param without disturbing the path or the others', () => {
    expect(writeHashParam('#/documents?order=headAt.desc', 'after', 'abc')).toBe(
      '#/documents?order=headAt.desc&after=abc',
    );
  });

  it('an empty value DROPS the param, so a default view links as the bare route', () => {
    expect(writeHashParam('#/documents?after=abc', 'after', '')).toBe('#/documents');
    expect(writeHashParam('#/documents?after=abc&order=x', 'after', '')).toBe(
      '#/documents?order=x',
    );
  });

  it('replaces rather than appends an existing param', () => {
    expect(writeHashParam('#/documents?after=abc', 'after', 'def')).toBe('#/documents?after=def');
  });

  it('round-trips a value needing encoding', () => {
    const hash = writeHashParam('#/search', 'q', 'ada lovelace & co');
    expect(readHashParam(hash, 'q')).toBe('ada lovelace & co');
  });
});
