import { describe, expect, it } from 'vitest';
import { short } from '../src/lib/format';
import { safeHttpUrl } from '../src/lib/media';

describe('short() tail guard', () => {
  it('does NOT append the whole string when tail is 0', () => {
    const v = 'did:dfos:tn7kkfz7ehzvv6fzvate9rz2874nc3e';
    const out = short(v, 12, 0);
    // slice(-0) === slice(0) bug would produce '<head>…<entire value>'
    expect(out).toBe('did:dfos:tn7…');
    expect(out).not.toContain('nc3e');
  });

  it('still ellipsizes with a real tail', () => {
    expect(short('abcdefghijklmnop', 4, 4)).toBe('abcd…mnop');
  });

  it('returns short strings unchanged', () => {
    expect(short('abc', 10, 6)).toBe('abc');
  });
});

describe('safeHttpUrl — XSS/scheme guard', () => {
  it('accepts http and https', () => {
    expect(safeHttpUrl('https://relay.dfos.com/x')).toBe('https://relay.dfos.com/x');
    expect(safeHttpUrl('http://localhost:4444/y')).toBe('http://localhost:4444/y');
  });

  it('rejects javascript:, data:, and other schemes', () => {
    expect(safeHttpUrl('javascript:alert(1)')).toBeNull();
    expect(safeHttpUrl('data:text/html,<script>alert(1)</script>')).toBeNull();
    expect(safeHttpUrl('file:///etc/passwd')).toBeNull();
    expect(safeHttpUrl('vbscript:msgbox')).toBeNull();
  });

  it('rejects garbage and empty', () => {
    expect(safeHttpUrl('not a url')).toBeNull();
    expect(safeHttpUrl('')).toBeNull();
    expect(safeHttpUrl(undefined)).toBeNull();
  });
});
