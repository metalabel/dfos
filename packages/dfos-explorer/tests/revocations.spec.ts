import { describe, expect, it } from 'vitest';
import type { ExplorerOp } from '../src/lib/db';
import { revokedByCredential } from '../src/lib/revocations';

const b64url = (v: unknown): string => Buffer.from(JSON.stringify(v)).toString('base64url');
const revocationOp = (cid: string, payload: Record<string, unknown>): ExplorerOp => ({
  cid,
  jwsToken: `${b64url({ typ: 'did:dfos:revocation' })}.${b64url(payload)}.sig`,
  kind: 'revocation',
  chainId: cid,
  type: 'revocation',
  createdAt: '2026-01-01T00:00:00.000Z',
  kid: '',
  seq: 0,
});

describe('revokedByCredential', () => {
  it('maps each revoked credential CID to its revoking op CID', () => {
    const ops = [
      revocationOp('rev-1', { credentialCID: 'cred-A', did: 'did:dfos:iss' }),
      revocationOp('rev-2', { credentialCID: 'cred-B', did: 'did:dfos:iss' }),
    ];
    const map = revokedByCredential(ops);
    expect(map.get('cred-A')).toBe('rev-1');
    expect(map.get('cred-B')).toBe('rev-2');
    expect(map.get('cred-C')).toBeUndefined();
  });

  it('keeps the first revocation when a credential is revoked more than once', () => {
    const ops = [
      revocationOp('rev-first', { credentialCID: 'cred-A' }),
      revocationOp('rev-second', { credentialCID: 'cred-A' }),
    ];
    expect(revokedByCredential(ops).get('cred-A')).toBe('rev-first');
  });

  it('ignores ops with no credentialCID or an unparseable token', () => {
    const ops = [
      revocationOp('rev-nocid', { did: 'did:dfos:iss' }),
      { ...revocationOp('rev-garbage', { credentialCID: 'cred-X' }), jwsToken: 'garbage' },
    ];
    expect(revokedByCredential(ops).size).toBe(0);
  });

  it('returns an empty map for no ops', () => {
    expect(revokedByCredential([]).size).toBe(0);
  });
});
