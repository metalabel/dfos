import { describe, expect, it } from 'vitest';
import { dispatchInput, routeFor } from '../src/lib/resolve-input';

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

  it('trims whitespace', () => {
    expect(dispatchInput('  dn2nc79k7z6ekzfhd43he4v8tr6h236\n')?.kind).toBe('content');
  });

  it('rejects garbage', () => {
    expect(dispatchInput('')).toBeNull();
    expect(dispatchInput('   ')).toBeNull();
    expect(dispatchInput('hello world')).toBeNull();
    expect(dispatchInput('https://relay.dfos.com')).toBeNull();
    expect(dispatchInput('did:web:example.com')).toBeNull();
  });

  it('builds routes', () => {
    expect(routeFor({ kind: 'identity', id: 'did:dfos:x' })).toBe('#/did/did:dfos:x');
    expect(routeFor({ kind: 'content', id: 'abc' })).toBe('#/content/abc');
    expect(routeFor({ kind: 'op', id: 'bafy1' })).toBe('#/op/bafy1');
  });
});
