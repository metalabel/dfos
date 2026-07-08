import type { IndexCredentialRow } from '@metalabel/dfos-client';
import { describe, expect, it } from 'vitest';
import {
  deriveCredentialCid,
  grantsForChain,
  grantsFromIndex,
  summarizeAuthorization,
} from '../src/lib/credentials';
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

const idxRow = (
  cid: string,
  att: { resource: string; action: string }[],
  aud = '*',
  exp = 4900000000,
): IndexCredentialRow => ({
  cid,
  issuerDID: 'did:dfos:issuer',
  att,
  exp,
  jwsToken: `${b64url({ typ: 'did:dfos:credential' })}.${b64url({ aud, att, exp })}.sig`,
});

describe('grantsFromIndex', () => {
  it('unions exact chain:<id> and chain:* wildcard candidates, flagging wildcards', () => {
    const rows = [
      idxRow('cr-exact', [{ resource: `chain:${CHAIN}`, action: 'read' }]),
      idxRow('cr-wild', [{ resource: 'chain:*', action: 'read' }]),
      idxRow('cr-other', [{ resource: 'chain:somethingelse', action: 'read' }]),
    ];
    const byCid = Object.fromEntries(grantsFromIndex(rows, CHAIN).map((g) => [g.cid, g]));
    expect(Object.keys(byCid).sort()).toEqual(['cr-exact', 'cr-wild']); // cr-other excluded
    expect(byCid['cr-exact']).toMatchObject({ wildcard: false, isPublic: true, actions: ['read'] });
    expect(byCid['cr-wild']).toMatchObject({ wildcard: true, isPublic: true, actions: ['read'] });
  });

  it('prefers the exact-resource actions over the wildcard when a cred names both', () => {
    const rows = [
      idxRow('c1', [
        { resource: `chain:${CHAIN}`, action: 'read' },
        { resource: 'chain:*', action: 'write' },
      ]),
    ];
    const [g] = grantsFromIndex(rows, CHAIN);
    expect(g).toMatchObject({ wildcard: false, actions: ['read'] });
  });

  it('dedupes by cid and sorts public grants first', () => {
    const rows = [
      idxRow('c-scoped', [{ resource: `chain:${CHAIN}`, action: 'read' }], 'did:dfos:bob'),
      idxRow('c-public', [{ resource: `chain:${CHAIN}`, action: 'read' }], '*'),
      idxRow('c-public', [{ resource: `chain:${CHAIN}`, action: 'read' }], '*'), // dup cid
    ];
    const grants = grantsFromIndex(rows, CHAIN);
    expect(grants.map((g) => g.cid)).toEqual(['c-public', 'c-scoped']);
    expect(grants[0]!.isPublic).toBe(true);
  });

  it('excludes a cred naming neither the chain nor chain:*, and handles an empty chain id', () => {
    expect(
      grantsFromIndex([idxRow('c1', [{ resource: `chain:${CHAIN}`, action: 'read' }])], ''),
    ).toEqual([]);
    expect(
      grantsFromIndex([idxRow('c1', [{ resource: 'chain:other', action: 'read' }])], CHAIN),
    ).toEqual([]);
  });
});

const authToken = (payload: Record<string, unknown>): string =>
  `${b64url({ typ: 'did:dfos:credential' })}.${b64url(payload)}.sig`;

describe('summarizeAuthorization', () => {
  it('decodes a well-formed embedded credential into a compact summary', () => {
    const token = authToken({
      version: 1,
      type: 'DFOSCredential',
      iss: 'did:dfos:creator',
      aud: 'did:dfos:delegate',
      att: [{ resource: `chain:${CHAIN}`, action: 'write' }],
      prf: [],
      iat: 1_700_000_000,
      exp: 1_800_000_000,
    });
    expect(summarizeAuthorization(token)).toEqual({
      iss: 'did:dfos:creator',
      aud: 'did:dfos:delegate',
      att: [{ resource: `chain:${CHAIN}`, action: 'write' }],
      iat: 1_700_000_000,
      exp: 1_800_000_000,
    });
  });

  it('returns null for a token that is not a valid DFOS credential', () => {
    // missing required att / iss — fails the payload schema
    expect(summarizeAuthorization(authToken({ version: 1, type: 'DFOSCredential' }))).toBeNull();
    expect(summarizeAuthorization('not-a-jws')).toBeNull();
  });
});

describe('deriveCredentialCid', () => {
  const valid = authToken({
    version: 1,
    type: 'DFOSCredential',
    iss: 'did:dfos:creator',
    aud: '*',
    att: [{ resource: `chain:${CHAIN}`, action: 'read' }],
    prf: [],
    iat: 1_700_000_000,
    exp: 1_800_000_000,
  });

  it('re-derives a CID from a well-formed credential payload', async () => {
    const cid = await deriveCredentialCid(valid);
    expect(cid).toMatch(/^baf[a-z2-7]+$/); // a dag-cbor CIDv1
  });

  it('is deterministic — same payload, same CID', async () => {
    expect(await deriveCredentialCid(valid)).toBe(await deriveCredentialCid(valid));
  });

  it('returns null when the token cannot be decoded (drives the visible error)', async () => {
    expect(await deriveCredentialCid('not-a-jws')).toBeNull();
    expect(await deriveCredentialCid(authToken({ version: 1, type: 'DFOSCredential' }))).toBeNull();
  });
});
