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

// The policy is an ALLOWLIST of public unicast, so these tables are the whole
// of it: what a resolved address must NOT be, and the handful of forms that
// must keep working. The denylist this replaced passed everything it had not
// been told about — 192.0.0.0/24, 198.18.0.0/15, 240.0.0.0/4, fec0::/10, the
// v6 transition prefixes with a private v4 inside — so each case below names a
// range an attacker could have pointed a public hostname at.
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

  // one representative per IANA special-purpose v4 range the old denylist did
  // not name. 169.254.169.254 is called out separately because it is the
  // address an SSRF is usually AIMED at, not merely one that leaks.
  it('refuses every IPv4 special-purpose range, not just the private ones', () => {
    for (const addr of [
      '169.254.169.254', // link-local metadata endpoint
      '192.0.0.1', // IETF protocol assignments 192.0.0.0/24
      '192.0.2.5', // TEST-NET-1
      '192.88.99.1', // 6to4 relay anycast
      '198.18.0.1', // benchmarking 198.18.0.0/15
      '198.19.255.254', // the far end of the same /15
      '198.51.100.7', // TEST-NET-2
      '203.0.113.9', // TEST-NET-3
      '224.0.0.1', // multicast
      '239.255.255.250', // the far end of 224.0.0.0/4
      '240.0.0.1', // reserved
      '255.255.255.255', // broadcast, inside 240.0.0.0/4
    ]) {
      expect(isForbiddenAddress(addr), addr).toBe(true);
    }
  });

  // outside 2000::/3 there is no globally routable unicast at all, so the gate
  // catches these whether or not anyone thought to name them
  it('refuses every IPv6 address outside global unicast', () => {
    for (const addr of [
      'fec0::1', // site-local (deprecated)
      'ff02::1', // link-local all-nodes multicast
      'ff00::1', // multicast
      '100::1', // discard-only 100::/64
      '::2', // IPv4-compatible, deprecated
    ]) {
      expect(isForbiddenAddress(addr), addr).toBe(true);
    }
  });

  // 2000::/3 is necessary, not sufficient: these prefixes sit inside it and are
  // still not destinations
  it('refuses the reserved prefixes inside global unicast', () => {
    for (const addr of [
      '2001::1', // Teredo 2001::/32
      '2001:2::1', // benchmarking 2001:2::/48
      '2001:10::1', // ORCHID
      '2001:20::1', // ORCHIDv2
      '2001:db8::1', // documentation
      '2002:c0a8:0101::1', // 6to4 wrapping 192.168.1.1
      '2002:0808:0808::1', // 6to4 at all, public v4 inside or not
    ]) {
      expect(isForbiddenAddress(addr), addr).toBe(true);
    }
  });

  // the three v6 forms that carry a v4 inside them. A private v4 must not be
  // reachable by wrapping it, in any of the three spellings or either notation.
  it('refuses a private IPv4 smuggled inside a v6 transition form', () => {
    for (const addr of [
      '::ffff:169.254.169.254', // v4-mapped, dotted
      '::ffff:a9fe:a9fe', // the same address in hex
      '::ffff:127.0.0.1',
      '::ffff:172.16.0.1',
      '64:ff9b::10.0.0.1', // NAT64 well-known prefix
      '64:ff9b::a9fe:a9fe',
      '::10.0.0.1', // IPv4-compatible, deprecated
      '::169.254.169.254',
    ]) {
      expect(isForbiddenAddress(addr), addr).toBe(true);
    }
  });

  // anything that is not an IP literal cannot be shown to be safe
  it('refuses malformed addresses', () => {
    for (const addr of [
      '',
      'not-an-address',
      '10.0.0',
      '1.2.3.4.5',
      '999.1.1.1',
      '010.0.0.1', // octal-looking, not a valid literal
      '1.2.3.4 ',
      'fe80::1%eth0', // zone id
      '::ffff:10.0.0.1/8',
      '2606:4700::gggg',
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

  // the allowlist has to stay an allowlist and not become a ban: these are the
  // addresses the route exists to reach, including the v4-mapped form
  // `dns.lookup` hands back for an A record on a dual-stack resolve
  it('still allows the public addresses the route exists to fetch from', () => {
    for (const addr of [
      '8.8.8.8',
      '1.1.1.1',
      '93.184.216.34',
      '2606:4700::1111',
      '2001:4860:4860::8888', // inside 2000::/3, outside every 2001:: carve-out
      '2a00:1450:4001:800::200e',
      '::ffff:1.1.1.1', // v4-mapped public v4
      '::ffff:0808:0808', // the same, in hex
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
