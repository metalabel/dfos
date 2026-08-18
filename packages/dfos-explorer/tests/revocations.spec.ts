import { describe, expect, it } from 'vitest';
import type { ExplorerOp } from '../src/lib/db';
import {
  emptyRevocations,
  localRevocations,
  mergeRevocations,
  revocationStatus,
  revokedByCredential,
  type RevocationView,
} from '../src/lib/revocations';

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

// -----------------------------------------------------------------------------
// The three-state verdict. These tests exist to pin ONE rule: a credential whose
// status could not be established must never render as active.
// -----------------------------------------------------------------------------

const view = (partial: Partial<RevocationView>): RevocationView => ({
  revoked: new Map(),
  established: false,
  unknown: new Set(),
  ...partial,
});

describe('revocationStatus — absence is never authoritative', () => {
  it('a positive proof is revoked, whatever else the view says', () => {
    const v = view({ revoked: new Map([['cred-A', 'rev-1']]), established: false });
    expect(revocationStatus(v, 'cred-A')).toBe('revoked');
  });

  it('green requires an ESTABLISHED sweep — an unswept credential is unknown', () => {
    expect(revocationStatus(view({ established: true }), 'cred-A')).toBe('active');
    // the whole point: nothing answered, so we do not know — and must not say active
    expect(revocationStatus(view({ established: false }), 'cred-A')).toBe('unknown');
  });

  it('a credential the sweep could not cover stays unknown even when it ran', () => {
    // an unreachable relay for this one CID, or one past the query cap
    const v = view({ established: true, unknown: new Set(['cred-B']) });
    expect(revocationStatus(v, 'cred-A')).toBe('active');
    expect(revocationStatus(v, 'cred-B')).toBe('unknown');
  });

  it('an empty view is all-unknown, never all-active', () => {
    expect(revocationStatus(emptyRevocations(), 'cred-A')).toBe('unknown');
  });
});

describe('localRevocations — the offline fold adds positives, never licenses green', () => {
  it('carries the fold’s positives', () => {
    const v = localRevocations([revocationOp('rev-1', { credentialCID: 'cred-A' })]);
    expect(revocationStatus(v, 'cred-A')).toBe('revoked');
  });

  it('never establishes absence — an un-synced index proves nothing it does not hold', () => {
    const v = localRevocations([revocationOp('rev-1', { credentialCID: 'cred-A' })]);
    expect(v.established).toBe(false);
    expect(revocationStatus(v, 'cred-OTHER')).toBe('unknown');
  });
});

describe('mergeRevocations — union of sources', () => {
  it('a positive from EITHER source wins', () => {
    const relay = view({ established: true });
    const local = view({ revoked: new Map([['cred-A', 'rev-1']]) });
    expect(revocationStatus(mergeRevocations(relay, local), 'cred-A')).toBe('revoked');
    expect(revocationStatus(mergeRevocations(local, relay), 'cred-A')).toBe('revoked');
  });

  it('the local fold rescues a credential the relays could not answer for', () => {
    // the regression this merge exists for: relays all silent on cred-A, but this
    // tab already holds the revocation op — it must show red, not green or unknown
    const relay = view({ established: true, unknown: new Set(['cred-A']) });
    const local = view({ revoked: new Map([['cred-A', 'rev-1']]) });
    const merged = mergeRevocations(relay, local);
    expect(revocationStatus(merged, 'cred-A')).toBe('revoked');
    expect(merged.unknown.has('cred-A')).toBe(false);
  });

  it('one established sweep is enough to license green for what it covered', () => {
    expect(mergeRevocations(view({ established: true }), view({})).established).toBe(true);
    expect(mergeRevocations(view({}), view({ established: true })).established).toBe(true);
  });

  it('neither source established → still unknown, not active', () => {
    const merged = mergeRevocations(view({}), view({}));
    expect(merged.established).toBe(false);
    expect(revocationStatus(merged, 'cred-A')).toBe('unknown');
  });

  it('an unknown from either side survives the merge', () => {
    const merged = mergeRevocations(
      view({ established: true }),
      view({ unknown: new Set(['cred-B']) }),
    );
    expect(revocationStatus(merged, 'cred-B')).toBe('unknown');
  });
});
