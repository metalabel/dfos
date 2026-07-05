import { createClient } from '@metalabel/dfos-client';
import type { PeerClient } from '@metalabel/dfos-web-relay/peer-client';
import { IDBFactory } from 'fake-indexeddb';
import { describe, expect, it } from 'vitest';
import { openExplorerDb } from '../src/lib/db';
import { syncAll, syncFromRelay } from '../src/lib/sync';

// unsigned JWS-shaped token — decodeJwsUnsafe only decodes, never verifies
const b64url = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');

const mkJws = (header: Record<string, unknown>, payload: Record<string, unknown>): string =>
  `${b64url(header)}.${b64url(payload)}.sig`;

interface FakeEntry {
  cid: string;
  jwsToken: string;
  kind: string;
  chainId: string;
}

const entry = (
  cid: string,
  chainId: string,
  kind: string,
  createdAt: string,
  type = 'create',
): FakeEntry => ({
  cid,
  jwsToken: mkJws({ typ: `did:dfos:${kind}`, kid: `${chainId}#key1` }, { type, createdAt }),
  kind,
  chainId,
});

/** A fake relay: serves `pages` from /log, cursor chains page indices. */
const fakePeer = (pages: FakeEntry[][]): PeerClient => ({
  getIdentityLog: async () => null,
  getContentLog: async () => null,
  getOperationLog: async (_url, params) => {
    const index = params?.after ? Number(params.after) : 0;
    const page = pages[index] ?? [];
    const next = index + 1 < pages.length ? String(index + 1) : null;
    return { entries: page as unknown as { cid: string; jwsToken: string }[], cursor: next };
  },
  submitOperations: async () => {},
});

const freshDb = () => openExplorerDb('sync-test', new IDBFactory());

describe('sync engine', () => {
  it('lands pages in the index and maintains rollups', async () => {
    const pages = [
      [
        entry('bafy-a1', 'did:dfos:aaa', 'identity-op', '2026-01-01T00:00:00.000Z'),
        entry('bafy-a2', 'did:dfos:aaa', 'identity-op', '2026-01-02T00:00:00.000Z', 'update'),
      ],
      [
        entry('bafy-c1', 'content1', 'content-op', '2026-01-03T00:00:00.000Z'),
        entry('bafy-cred', 'did:dfos:aaa', 'credential', '2026-01-04T00:00:00.000Z', ''),
      ],
    ];
    const client = createClient({ relays: ['http://fake'], peerClient: fakePeer(pages) });
    const db = await freshDb();

    const result = await syncFromRelay({ db, client, relay: 'http://fake' });
    expect(result.added).toBe(4);

    const counts = await db.counts();
    expect(counts.ops).toBe(4);
    expect(counts.chains).toBe(2);

    const identity = await db.getChain('did:dfos:aaa');
    // the credential shares the identity's chainId but must NOT relabel the
    // rollup, inflate its opCount, or (despite a later createdAt) steal its head:
    // the rollup is the IDENTITY chain (2 ops), the credential is counted apart
    expect(identity?.kind).toBe('identity-op');
    expect(identity?.opCount).toBe(2);
    expect(identity?.headCid).toBe('bafy-a2');

    // the credential is still stored and counted from the ops index
    expect(counts.byKind['credential']).toBe(1);
    expect(counts.byKind['identity-op']).toBe(1);

    const identityOps = await db.chainOps('did:dfos:aaa', 'identity-op');
    expect(identityOps.map((o) => o.cid)).toEqual(['bafy-a1', 'bafy-a2']);
    expect(identityOps[0]?.type).toBe('create');
    expect(identityOps[0]?.kid).toBe('did:dfos:aaa#key1');
  });

  it('a credential landing BEFORE its issuer identity op does not inflate the rollup', async () => {
    // pathological arrival order: the credential rides the issuer chainId and is
    // seen first; when the identity op arrives it reclaims the rollup as a chain
    const pages = [
      [
        entry('bafy-cred', 'did:dfos:zzz', 'credential', '2026-01-05T00:00:00.000Z', ''),
        entry('bafy-z1', 'did:dfos:zzz', 'identity-op', '2026-01-01T00:00:00.000Z'),
        entry('bafy-z2', 'did:dfos:zzz', 'identity-op', '2026-01-02T00:00:00.000Z', 'update'),
      ],
    ];
    const client = createClient({ relays: ['http://fake'], peerClient: fakePeer(pages) });
    const db = await freshDb();
    await syncFromRelay({ db, client, relay: 'http://fake' });

    const identity = await db.getChain('did:dfos:zzz');
    expect(identity?.kind).toBe('identity-op');
    expect(identity?.opCount).toBe(2);
    expect(identity?.headCid).toBe('bafy-z2');
  });

  it('is idempotent across re-syncs (union pool, no rollup double-count)', async () => {
    const pages = [[entry('bafy-a1', 'did:dfos:aaa', 'identity-op', '2026-01-01T00:00:00.000Z')]];
    const client = createClient({ relays: ['http://fake'], peerClient: fakePeer(pages) });
    const db = await freshDb();

    await syncFromRelay({ db, client, relay: 'http://fake' });
    // second relay serving the same op — union by cid, count stays 1
    const again = await syncFromRelay({ db, client, relay: 'http://fake-2' });
    expect(again.added).toBe(0);
    expect((await db.getChain('did:dfos:aaa'))?.opCount).toBe(1);
  });

  it('resumes from the stored cursor', async () => {
    const pageOne = [entry('bafy-a1', 'did:dfos:aaa', 'identity-op', '2026-01-01T00:00:00.000Z')];
    const pageTwo = [entry('bafy-a2', 'did:dfos:aaa', 'identity-op', '2026-01-02T00:00:00.000Z')];

    const db = await freshDb();
    const first = createClient({
      relays: ['http://fake'],
      // serve only page one, cursor pointing at page two
      peerClient: fakePeer([pageOne, []]),
    });
    await syncFromRelay({ db, client: first, relay: 'http://fake' });
    expect((await db.getCursor('http://fake'))?.cursor).toBe('1');

    const second = createClient({
      relays: ['http://fake'],
      peerClient: fakePeer([pageOne, pageTwo]),
    });
    const result = await syncFromRelay({ db, client: second, relay: 'http://fake' });
    expect(result.added).toBe(1);
    expect((await db.counts()).ops).toBe(2);
  });

  it('throws when the relay is unreachable, and syncAll isolates the failure', async () => {
    const db = await freshDb();
    const dead = createClient({ relays: ['http://dead'], peerClient: fakePeer([]) });
    // globalLog answers empty-with-blank-provenance when no relay responds; a
    // relay that answers zero entries is just "caught up", so simulate death
    // via a peer client that throws
    const throwing: PeerClient = {
      getIdentityLog: async () => null,
      getContentLog: async () => null,
      getOperationLog: async () => {
        throw new Error('boom');
      },
      submitOperations: async () => {},
    };
    const deadClient = createClient({ relays: ['http://dead'], peerClient: throwing });
    await expect(syncFromRelay({ db, client: deadClient, relay: 'http://dead' })).rejects.toThrow(
      /unreachable/,
    );

    const result = await syncAll({ db, client: deadClient, relays: ['http://dead'] });
    expect(result.errors).toHaveLength(1);
    expect(result.added).toBe(0);
    void dead;
  });

  it('skips malformed entries without dying', async () => {
    const good = entry('bafy-ok', 'did:dfos:aaa', 'identity-op', '2026-01-01T00:00:00.000Z');
    const noChain = { cid: 'bafy-nochain', jwsToken: 'x.y.z', kind: 'identity-op', chainId: '' };
    const badJws = {
      ...entry('bafy-badjws', 'did:dfos:bbb', 'identity-op', ''),
      jwsToken: 'garbage',
    };
    const client = createClient({
      relays: ['http://fake'],
      peerClient: fakePeer([[good, noChain as FakeEntry, badJws]]),
    });
    const db = await freshDb();
    const result = await syncFromRelay({ db, client, relay: 'http://fake' });
    // bad-JWS op still lands (kind/chainId route it); chainless op is dropped
    expect(result.added).toBe(2);
    expect(await db.getOp('bafy-nochain')).toBeUndefined();
    expect((await db.getOp('bafy-badjws'))?.createdAt).toBe('');
  });
});
