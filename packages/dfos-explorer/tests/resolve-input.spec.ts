import { encodeEd25519Multikey } from '@metalabel/dfos-protocol/chain';
import { describe, expect, it } from 'vitest';
import { dispatchInput, normalizeHost, routeFor } from '../src/lib/resolve-input';

/** The two multikeys PROTOCOL.md's deterministic vectors mint. */
const SPEC_KEYS = [
  'z6MkfUd65JrAhfdgFuMCccU9ThQvjB2fJAMUHkuuajF992gK',
  'z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb',
];

describe('dispatchInput', () => {
  it('routes DIDs to identity', () => {
    expect(dispatchInput('did:dfos:tn7kkfz7ehzvv6fzvate9rz2874nc3e')).toEqual({
      kind: 'identity',
      id: 'did:dfos:tn7kkfz7ehzvv6fzvate9rz2874nc3e',
    });
  });

  it('routes base32 CIDv1 to op', () => {
    expect(dispatchInput('bafyreib36cg2bevmfjcgoqbcjqugmqvmvpu4wxy2sqxq3jc4c3ez6enp7q')).toEqual({
      kind: 'op',
      id: 'bafyreib36cg2bevmfjcgoqbcjqugmqvmvpu4wxy2sqxq3jc4c3ez6enp7q',
    });
    // raw-codec CIDs (bafk…) are ops too — dispatch is syntactic
    expect(dispatchInput('bafkreib36cg2bevmfjcgoqbcjqugmqvmvpu4wxy2sqxq3jc4c3ez6enp7q')?.kind).toBe(
      'op',
    );
  });

  it('routes 31-char ids to content', () => {
    expect(dispatchInput('dn2nc79k7z6ekzfhd43he4v8tr6h236')).toEqual({
      kind: 'content',
      id: 'dn2nc79k7z6ekzfhd43he4v8tr6h236',
    });
  });

  it('routes publicKeyMultibase to key', () => {
    for (const key of SPEC_KEYS) {
      expect(dispatchInput(key)).toEqual({ kind: 'key', key });
    }
  });

  it('accepts every key the protocol encoder can mint', () => {
    // the pattern is EXACT (48 chars, `z6Mk` head), so it must hold across the
    // whole value space, not just the two spec fixtures
    for (const seed of [0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff]) {
      const key = encodeEd25519Multikey(new Uint8Array(32).fill(seed));
      expect(dispatchInput(key)).toEqual({ kind: 'key', key });
    }
  });

  it('trims whitespace', () => {
    expect(dispatchInput('  dn2nc79k7z6ekzfhd43he4v8tr6h236\n')?.kind).toBe('content');
  });

  it('routes hostnames to domain', () => {
    expect(dispatchInput('3p.com')).toEqual({ kind: 'domain', host: '3p.com' });
    expect(dispatchInput('app.example.co.uk')).toEqual({
      kind: 'domain',
      host: 'app.example.co.uk',
    });
  });

  it('rejects garbage', () => {
    expect(dispatchInput('')).toBeNull();
    expect(dispatchInput('   ')).toBeNull();
    expect(dispatchInput('hello world')).toBeNull();
    expect(dispatchInput('did:web:example.com')).toBeNull();
  });

  it('builds routes', () => {
    expect(routeFor({ kind: 'identity', id: 'did:dfos:x' })).toBe('#/did/did:dfos:x');
    expect(routeFor({ kind: 'content', id: 'abc' })).toBe('#/content/abc');
    expect(routeFor({ kind: 'op', id: 'bafy1' })).toBe('#/op/bafy1');
    expect(routeFor({ kind: 'key', key: SPEC_KEYS[0]! })).toBe(`#/key/${SPEC_KEYS[0]}`);
    expect(routeFor({ kind: 'domain', host: '3p.com' })).toBe('#/domain/3p.com');
  });
});

// The key pattern is the one EXACT pattern in the dispatcher, and it is exact for
// a reason: a key has no view that can render an honest not-found. The key page
// asks a relay "which identities has this been proved into", and a relay answers
// a garbage string with an empty page — indistinguishable from a real key nobody
// used. So a near-miss must fall through to the name search, not become a page
// that quietly states a false absence.
describe('key dispatch is strict', () => {
  const KEY = SPEC_KEYS[0]!;

  it('never swallows another identifier', () => {
    expect(dispatchInput('dn2nc79k7z6ekzfhd43he4v8tr6h236')?.kind).toBe('content');
    expect(dispatchInput('bafyreib36cg2bevmfjcgoqbcjqugmqvmvpu4wxy2sqxq3jc4c3ez6enp7q')?.kind).toBe(
      'op',
    );
    expect(dispatchInput('did:dfos:tn7kkfz7ehzvv6fzvate9rz2874nc3e')?.kind).toBe('identity');
    expect(dispatchInput('z6mk.example.com')?.kind).toBe('domain');
  });

  it('rejects a near-miss rather than guessing', () => {
    expect(dispatchInput(KEY.slice(0, -1))).toBeNull(); // one short
    expect(dispatchInput(`${KEY}a`)).toBeNull(); // one long
    expect(dispatchInput(KEY.replace(/^z6Mk/, 'z6Mj'))).toBeNull(); // wrong multicodec head
    expect(dispatchInput(KEY.replace(/^z/, ''))).toBeNull(); // no multibase prefix
    expect(dispatchInput(KEY.toLowerCase())).toBeNull(); // case is load-bearing
    // base58btc excludes 0, O, I and l — a string carrying one is not a key
    expect(dispatchInput(`z6Mk0${KEY.slice(5)}`)).toBeNull();
    expect(dispatchInput(`z6MkO${KEY.slice(5)}`)).toBeNull();
    expect(dispatchInput(`z6MkI${KEY.slice(5)}`)).toBeNull();
    expect(dispatchInput(`z6Mkl${KEY.slice(5)}`)).toBeNull();
  });

  it('still trims and still leaves ordinary searches alone', () => {
    expect(dispatchInput(`  ${KEY}\n`)).toEqual({ kind: 'key', key: KEY });
    expect(dispatchInput('z6Mk')).toBeNull();
    expect(dispatchInput('multikey')).toBeNull();
  });
});

describe('domain dispatch ordering', () => {
  // the domain branch runs LAST — an identifier that could be read either way is
  // always the identifier. A regression here silently breaks id lookup.
  it('never steals an id pattern', () => {
    expect(dispatchInput('dn2nc79k7z6ekzfhd43he4v8tr6h236')?.kind).toBe('content');
    expect(dispatchInput('bafyreib36cg2bevmfjcgoqbcjqugmqvmvpu4wxy2sqxq3jc4c3ez6enp7q')?.kind).toBe(
      'op',
    );
    expect(dispatchInput('did:dfos:tn7kkfz7ehzvv6fzvate9rz2874nc3e')?.kind).toBe('identity');
  });

  // a URL pasted into the box used to be a dead end; it now resolves, and the
  // previously-null `https://relay.dfos.com` case is the regression witness
  it('normalizes a pasted URL down to its host', () => {
    expect(dispatchInput('https://relay.dfos.com')).toEqual({
      kind: 'domain',
      host: 'relay.dfos.com',
    });
    expect(dispatchInput('https://3p.com/callback?x=1#frag')).toEqual({
      kind: 'domain',
      host: '3p.com',
    });
  });

  // ordinary searches MUST still reach the name index — the search fallback
  // cannot rescue an input the dispatcher has already claimed
  it('leaves ordinary name searches to search', () => {
    expect(dispatchInput('brian eno')).toBeNull();
    expect(dispatchInput('metalabel')).toBeNull();
    expect(dispatchInput('v0.1')).toBeNull(); // numeric TLD
    expect(dispatchInput('...')).toBeNull();
    expect(dispatchInput('.com')).toBeNull();
    expect(dispatchInput('a.b')).toBeNull(); // single-char TLD
  });
});

describe('normalizeHost', () => {
  it('lowercases and strips scheme, path, port, userinfo, trailing dot', () => {
    expect(normalizeHost('HTTPS://3P.com')).toBe('3p.com');
    expect(normalizeHost('3p.com/callback')).toBe('3p.com');
    expect(normalizeHost('https://3p.com:8443/x')).toBe('3p.com');
    expect(normalizeHost('https://user@3p.com/x')).toBe('3p.com');
    expect(normalizeHost('3p.com.')).toBe('3p.com');
    expect(normalizeHost('  3p.com  ')).toBe('3p.com');
  });

  it('returns empty for anything not plausibly a host', () => {
    expect(normalizeHost('')).toBe('');
    expect(normalizeHost('hello world')).toBe('');
    expect(normalizeHost('localhost')).toBe(''); // no dot, no TLD
    expect(normalizeHost('-lead.com')).toBe('');
    expect(normalizeHost('trail-.com')).toBe('');
  });
});
