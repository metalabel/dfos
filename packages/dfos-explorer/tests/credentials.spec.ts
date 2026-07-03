import { describe, expect, it } from 'vitest';
import { grantsForChain } from '../src/lib/credentials';
import type { ExplorerOp } from '../src/lib/db';

const b64url = (v: unknown): string => Buffer.from(JSON.stringify(v)).toString('base64url');
const credOp = (cid: string, payload: Record<string, unknown>): ExplorerOp => ({
  cid,
  jwsToken: `${b64url({ typ: 'did:dfos:credential' })}.${b64url(payload)}.sig`,
  kind: 'credential',
  chainId: 'did:dfos:issuer',
  type: '',
  createdAt: '2026-01-01T00:00:00.000Z',
  kid: '',
  seq: 0,
});

const CHAIN = 'abc123content';

describe('grantsForChain', () => {
  it('matches public and scoped grants naming the chain, public first', () => {
    const ops = [
      credOp('cr-public', {
        aud: '*',
        exp: 4900000000,
        att: [{ resource: `chain:${CHAIN}`, action: 'read' }],
      }),
      credOp('cr-scoped', {
        aud: 'did:dfos:bob',
        att: [{ resource: `chain:${CHAIN}`, action: 'read' }],
      }),
      credOp('cr-other', { aud: '*', att: [{ resource: 'chain:somethingelse', action: 'read' }] }),
    ];
    const grants = grantsForChain(ops, CHAIN);
    expect(grants.map((g) => g.cid)).toEqual(['cr-public', 'cr-scoped']); // public sorted first
    expect(grants[0]).toMatchObject({ isPublic: true, actions: ['read'], exp: 4900000000 });
    expect(grants[1]).toMatchObject({ isPublic: false, aud: 'did:dfos:bob' });
  });

  it('ignores ops that do not name the chain, and dedupes by cid', () => {
    const ops = [
      credOp('c1', { aud: '*', att: [{ resource: `chain:${CHAIN}`, action: 'read' }] }),
      credOp('c1', { aud: '*', att: [{ resource: `chain:${CHAIN}`, action: 'read' }] }), // dup cid
      credOp('c2', { aud: '*', att: [{ resource: 'chain:nope', action: 'read' }] }),
    ];
    expect(grantsForChain(ops, CHAIN).map((g) => g.cid)).toEqual(['c1']);
  });

  it('requires an action on the matching resource (no bare resource match)', () => {
    const ops = [credOp('c1', { aud: '*', att: [{ resource: `chain:${CHAIN}` }] })];
    expect(grantsForChain(ops, CHAIN)).toEqual([]);
  });

  it('returns nothing for an empty chain id or empty ops', () => {
    expect(grantsForChain([credOp('c1', { aud: '*', att: [] })], '')).toEqual([]);
    expect(grantsForChain([], CHAIN)).toEqual([]);
  });
});
