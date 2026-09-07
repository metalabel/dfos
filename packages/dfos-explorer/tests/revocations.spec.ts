import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ExplorerOp } from '../src/lib/db';
import {
  emptyRevocations,
  fetchCredentialRevocations,
  fetchIssuerRevocations,
  localRevocations,
  mergeRevocations,
  revocationStatus,
  revokedByCredential,
  type RevocationView,
} from '../src/lib/revocations';
import { mockJws } from './fixtures/mock-jws';

const revocationOp = (cid: string, payload: Record<string, unknown>): ExplorerOp => ({
  cid,
  jwsToken: mockJws({ typ: 'did:dfos:revocation' }, payload),
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

// -----------------------------------------------------------------------------
// the network sweeps — where "unknown" is actually decided
// -----------------------------------------------------------------------------

const RELAY_A = 'https://a.example';
const RELAY_B = 'https://b.example';

/** Route the stubbed fetch by URL; a handler returning null is an unreachable
 *  relay (the transport throws, exactly as `getJson` sees it). */
const stubRelays = (route: (url: string) => unknown): void => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const body = route(url);
      if (body === null) throw new Error('network down');
      return Response.json(body);
    }),
  );
};

describe('fetchCredentialRevocations — one silent relay is not a clean sweep', () => {
  afterEach(() => vi.unstubAllGlobals());

  // M39: `answered` used to flip true on the FIRST relay that replied, so a set
  // where relay A answered `revoked: false` and relay B never answered returned
  // 'unrevoked' — green — though B may be the one holding the revocation.
  it('a credential one relay answered clean while another stayed silent is UNKNOWN', async () => {
    stubRelays((url) => (url.startsWith(RELAY_A) ? { revoked: false } : null));
    const swept = await fetchCredentialRevocations(['cred-A'], [RELAY_A, RELAY_B]);
    expect(swept.unknown.has('cred-A')).toBe(true);
    expect(revocationStatus(swept, 'cred-A')).toBe('unknown');
  });

  it('every relay answering clean is the only thing that licenses active', async () => {
    stubRelays(() => ({ revoked: false }));
    const swept = await fetchCredentialRevocations(['cred-A'], [RELAY_A, RELAY_B]);
    expect(swept.unknown.has('cred-A')).toBe(false);
    expect(revocationStatus(swept, 'cred-A')).toBe('active');
  });

  it('a positive from any relay still wins immediately, silent neighbours or not', async () => {
    stubRelays((url) =>
      url.startsWith(RELAY_A) ? null : { revoked: true, revocation: 'not-a-jws' },
    );
    const swept = await fetchCredentialRevocations(['cred-A'], [RELAY_A, RELAY_B]);
    expect(revocationStatus(swept, 'cred-A')).toBe('revoked');
  });
});

describe('fetchIssuerRevocations — a capped walk cannot establish absence', () => {
  afterEach(() => vi.unstubAllGlobals());

  // M40: the page cap used to exit the loop in the same observable state as an
  // exhausted feed, so a revocation past the cap rendered its credential active.
  it('a feed still paging at the cap contributes positives but establishes nothing', async () => {
    // every page hands back another cursor — the walk is cut off, never exhausted
    stubRelays(() => ({
      revocations: [{ credentialCID: 'cred-A', revocation: 'not-a-jws' }],
      next: 'more',
    }));
    const swept = await fetchIssuerRevocations('did:dfos:iss', [RELAY_A]);
    expect(swept.revoked.has('cred-A')).toBe(true);
    expect(swept.established).toBe(false);
    expect(revocationStatus(swept, 'cred-B')).toBe('unknown');
  });

  it('a feed that ends within the cap establishes absence for what it swept', async () => {
    stubRelays(() => ({ revocations: [{ credentialCID: 'cred-A', revocation: 'not-a-jws' }] }));
    const swept = await fetchIssuerRevocations('did:dfos:iss', [RELAY_A]);
    expect(swept.established).toBe(true);
    expect(revocationStatus(swept, 'cred-B')).toBe('active');
  });
});
