import { describe, expect, it } from 'vitest';
import { isForbiddenAddress, validateHostname } from '../api/wellknown';

// The proxy's whole security story is these two pure functions: what may be
// asked for, and what a resolved answer may point at.
describe('wellknown proxy hostname validation', () => {
  it('accepts bare public hostnames, normalized', () => {
    expect(validateHostname('Example.COM')).toBe('example.com');
    expect(validateHostname('sub.example.co.uk')).toBe('sub.example.co.uk');
    expect(validateHostname('example.com.')).toBe('example.com');
  });

  it('rejects everything that is not a bare public DNS name', () => {
    for (const bad of [
      undefined,
      42,
      '',
      'localhost', // no dot, no TLD
      'example', // no dot
      '10.0.0.1', // IP literal
      '127.0.0.1',
      '[::1]',
      'example.com:8443', // port
      'user@example.com', // userinfo
      'example.com/path', // path
      'https://example.com', // scheme
      'exa mple.com',
      'example.c0m', // numeric TLD
      '-bad.example.com',
    ]) {
      expect(validateHostname(bad as never)).toBeNull();
    }
  });
});

describe('wellknown proxy address policy', () => {
  it('refuses private, loopback, link-local, CGNAT, and unique-local ranges', () => {
    for (const addr of [
      '0.0.0.0',
      '10.1.2.3',
      '100.64.0.1',
      '100.127.255.255',
      '127.0.0.1',
      '169.254.10.10',
      '172.16.0.1',
      '172.31.255.255',
      '192.168.1.1',
      '::1',
      '::',
      'fe80::1',
      'fc00::1',
      'fd12:3456::1',
      '::ffff:10.0.0.1',
      '::ffff:192.168.1.1',
    ]) {
      expect(isForbiddenAddress(addr), addr).toBe(true);
    }
  });

  it('allows public addresses', () => {
    for (const addr of [
      '1.1.1.1',
      '8.8.8.8',
      '100.128.0.1',
      '172.32.0.1',
      '2606:4700:4700::1111',
      '::ffff:8.8.8.8',
    ]) {
      expect(isForbiddenAddress(addr), addr).toBe(false);
    }
  });
});
