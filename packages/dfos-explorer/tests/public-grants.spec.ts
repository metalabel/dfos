import { describe, expect, it } from 'vitest';
import type { ExplorerOp } from '../src/lib/db';
import { isFetchEligible, publicGrantSet } from '../src/lib/public-grants';

const b64url = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
const mkJws = (header: Record<string, unknown>, payload: Record<string, unknown>): string =>
  `${b64url(header)}.${b64url(payload)}.sig`;

let seq = 0;
const credOp = (payload: Record<string, unknown>): ExplorerOp => {
  seq += 1;
  return {
    cid: `cred-${seq}`,
    jwsToken: mkJws({ typ: 'did:dfos:credential', kid: 'did:dfos:i#k' }, payload),
    kind: 'credential',
    chainId: 'did:dfos:i',
    type: 'grant',
    createdAt: '2026-01-01T00:00:00.000Z',
    kid: 'did:dfos:i#k',
    seq,
  };
};

const revOp = (credentialCID: string): ExplorerOp => ({
  cid: `rev-${credentialCID}`,
  jwsToken: mkJws({ typ: 'did:dfos:revocation', kid: 'did:dfos:i#k' }, { credentialCID }),
  kind: 'revocation',
  chainId: 'did:dfos:i',
  type: 'revocation',
  createdAt: '2026-02-01T00:00:00.000Z',
  kid: 'did:dfos:i#k',
  seq: 0,
});

const NOW = 1_800_000_000; // any fixed unix-seconds instant

describe('publicGrantSet', () => {
  it('collects chains named by aud-* read grants', () => {
    const grants = publicGrantSet(
      [credOp({ aud: '*', att: [{ resource: 'chain:abc', action: 'read' }] })],
      [],
      NOW,
    );
    expect(grants.all).toBe(false);
    expect(isFetchEligible(grants, 'abc')).toBe(true);
    expect(isFetchEligible(grants, 'other')).toBe(false);
  });

  it('honors the chain:* wildcard — everything becomes fetch-eligible', () => {
    const grants = publicGrantSet(
      [credOp({ aud: '*', att: [{ resource: 'chain:*', action: 'read' }] })],
      [],
      NOW,
    );
    expect(grants.all).toBe(true);
    expect(isFetchEligible(grants, 'anything')).toBe(true);
  });

  it('matches read inside a comma action set, per matchesResource semantics', () => {
    const grants = publicGrantSet(
      [credOp({ aud: '*', att: [{ resource: 'chain:abc', action: ' read , write ' }] })],
      [],
      NOW,
    );
    expect(isFetchEligible(grants, 'abc')).toBe(true);
  });

  it('ignores non-public audiences, non-read actions, and non-chain resources', () => {
    const grants = publicGrantSet(
      [
        credOp({ aud: 'did:dfos:someone', att: [{ resource: 'chain:a', action: 'read' }] }),
        credOp({ aud: '*', att: [{ resource: 'chain:b', action: 'write' }] }),
        credOp({ aud: '*', att: [{ resource: 'artifact:c', action: 'read' }] }),
      ],
      [],
      NOW,
    );
    expect(grants.all).toBe(false);
    expect(grants.chains.size).toBe(0);
  });

  it('drops expired grants but keeps unexpired and exp-less ones', () => {
    const grants = publicGrantSet(
      [
        credOp({ aud: '*', exp: NOW - 1, att: [{ resource: 'chain:old', action: 'read' }] }),
        credOp({ aud: '*', exp: NOW + 60, att: [{ resource: 'chain:live', action: 'read' }] }),
        credOp({ aud: '*', att: [{ resource: 'chain:forever', action: 'read' }] }),
      ],
      [],
      NOW,
    );
    expect(isFetchEligible(grants, 'old')).toBe(false);
    expect(isFetchEligible(grants, 'live')).toBe(true);
    expect(isFetchEligible(grants, 'forever')).toBe(true);
  });

  it('drops revoked grants', () => {
    const grant = credOp({ aud: '*', att: [{ resource: 'chain:z', action: 'read' }] });
    const grants = publicGrantSet([grant], [revOp(grant.cid)], NOW);
    expect(isFetchEligible(grants, 'z')).toBe(false);
  });
});
