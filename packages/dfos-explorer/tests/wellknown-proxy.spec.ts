import { describe, expect, it } from 'vitest';
import { classifyStatus, isForbiddenAddress, validateHostname } from '../api/wellknown';

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

// The route's one judgement about the origin's answer. The line it holds is the
// same one api/binding.ts holds on the other well-known: a REDIRECT is a
// non-answer, distinct from the ABSENCE a 404 affirmatively demonstrates and
// distinct from an error status — three different things a domain's server did.
describe('wellknown proxy status classification', () => {
  it('reads every redirect as its own answer, carrying the status', () => {
    for (const status of [301, 302, 303, 307, 308]) {
      expect(classifyStatus(status), String(status)).toEqual({
        status: 'redirected',
        httpStatus: status,
        reason: 'the origin redirected; redirects are not followed',
      });
    }
  });

  // the apex-to-www shape the explorer met in the wild: a permanent redirect at
  // the fixed path, which used to fold all the way to "couldn't reach host"
  it('never reports a redirect as an error or as an absence', () => {
    for (const status of [301, 308]) {
      expect(classifyStatus(status)?.status).not.toBe('http-error');
      expect(classifyStatus(status)?.status).not.toBe('no-app-description');
    }
  });

  it('reads a 404 or a 410 as an absence the origin demonstrated', () => {
    expect(classifyStatus(404)).toEqual({ status: 'no-app-description', httpStatus: 404 });
    expect(classifyStatus(410)).toEqual({ status: 'no-app-description', httpStatus: 410 });
  });

  it('reads every other non-2xx status as an error', () => {
    for (const status of [400, 403, 429, 500, 503]) {
      expect(classifyStatus(status), String(status)).toEqual({
        status: 'http-error',
        httpStatus: status,
      });
    }
  });

  // a 2xx settles nothing on its own — the document is in the body
  it('leaves a success status to the body', () => {
    expect(classifyStatus(200)).toBeNull();
    expect(classifyStatus(204)).toBeNull();
  });
});
