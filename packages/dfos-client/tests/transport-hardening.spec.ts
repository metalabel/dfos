/*

  TRANSPORT HARDENING

  Transport success is not trust. These tests pin the failure-mode behavior:
  a truncated drain is no answer at all; a reachable-but-lying relay is failed
  over at VERIFICATION time, not just transport time; a failed-quorum minority
  answer never becomes the trusted cache prefix; a duplicated relay URL cannot
  satisfy a quorum by itself; and a hung relay times out instead of stalling
  the read loop forever.

*/

import type { PeerClient } from '@metalabel/dfos-web-relay/peer-client';
import { describe, expect, it } from 'vitest';
import { createClient } from '../src/client';
import { memoryStore } from '../src/store/memory';
import { digestOps, fanOutLog, normalizeRelays } from '../src/transport';
import type { LogOp } from '../src/types';
import { buildIdentity, fakePeerClient, toEntries } from './fixtures';

const A = 'https://a.test';
const B = 'https://b.test';

/** Flip a mid-signature character of a JWS — decodes fine, verifies never.
 * (The LAST base64url char hides in padding bits, so tamper the middle.) */
const tamperSignature = (jws: string): string => {
  const parts = jws.split('.');
  const sig = parts[2]!;
  const mid = Math.floor(sig.length / 2);
  const flipped = sig[mid] === 'A' ? 'B' : 'A';
  return `${parts[0]}.${parts[1]}.${sig.slice(0, mid)}${flipped}${sig.slice(mid + 1)}`;
};

describe('normalizeRelays', () => {
  it('dedupes trailing-slash and duplicate relay URLs, preserving order', () => {
    expect(normalizeRelays([`${A}/`, A, ` ${B} `, B, ''])).toEqual([A, B]);
  });
});

describe('fanOutLog', () => {
  const op = (cid: string): LogOp => ({ cid, jwsToken: `${cid}.payload.sig` });

  it('treats a truncated drain (page failure mid-log) as NO answer, not a short log', async () => {
    const full = [op('op1'), op('op2')];
    const calls: Record<string, number> = { [A]: 0, [B]: 0 };
    const fetchPage = async (url: string, params: { after?: string; limit: number }) => {
      calls[url] = (calls[url] ?? 0) + 1;
      if (url === A) {
        // page 1 succeeds with a resume cursor, page 2 fails — the drained
        // prefix must be voided, never digested as A's complete answer
        if (!params.after) return { entries: [full[0]!], cursor: 'op1' };
        return null;
      }
      return params.after ? { entries: [], cursor: null } : { entries: full, cursor: null };
    };

    const result = await fanOutLog(fetchPage, [A, B], 1, undefined, async (entries) => entries);
    expect(result.outcome).toBe('verified');
    expect(result.entries).toHaveLength(2);
    expect(result.provenance.answeredBy).toBe(B);
    const aResponse = result.provenance.responses.find((r) => r.url === A);
    expect(aResponse?.ok).toBe(false);
  });

  it('throws (not silently degrades) when candidates exist but ALL fail verification', async () => {
    const fetchPage = async () => ({ entries: [op('bad')], cursor: null });
    await expect(
      fanOutLog(fetchPage, [A, B], 1, undefined, async () => {
        throw new Error('invalid signature');
      }),
    ).rejects.toThrow(/failed verification.*invalid signature/);
  });

  it('reports unreachable when no relay answers at all', async () => {
    const result = await fanOutLog(
      async () => null,
      [A, B],
      1,
      undefined,
      async (e) => e,
    );
    expect(result.outcome).toBe('unreachable');
    expect(result.provenance.responses.every((r) => !r.ok)).toBe(true);
  });

  it('digestOps distinguishes op sets and is stable', () => {
    expect(digestOps([op('x')])).toBe(digestOps([op('x')]));
    expect(digestOps([op('x')])).not.toBe(digestOps([op('x'), op('y')]));
  });
});

describe('verification-level failover', () => {
  it('fails over past a relay serving a forged log to a healthy relay behind it', async () => {
    const id = await buildIdentity();
    const forgedLog = id.log.map(tamperSignature);
    const peerClient = fakePeerClient({
      [A]: { identities: { [id.did]: forgedLog } }, // reachable, lying
      [B]: { identities: { [id.did]: id.log } }, // healthy
    });
    const client = createClient({ relays: [A, B], peerClient });

    const res = await client.identity(id.did);
    expect(res.value.did).toBe(id.did);
    expect(res.provenance.answeredBy).toBe(B);
    // both relays answered at the transport level — A's answer failed VERIFICATION
    expect(res.provenance.responses).toHaveLength(2);
    expect(res.provenance.responses.every((r) => r.ok)).toBe(true);
  });

  it('throws only when every candidate fails verification', async () => {
    const id = await buildIdentity();
    const forgedLog = id.log.map(tamperSignature);
    const peerClient = fakePeerClient({
      [A]: { identities: { [id.did]: forgedLog } },
      [B]: { identities: { [id.did]: forgedLog } },
    });
    const client = createClient({ relays: [A, B], peerClient });

    await expect(client.identity(id.did)).rejects.toThrow(/failed verification/);
  });
});

describe('cache-write gating', () => {
  it('does not cache a failed-quorum minority answer as the trusted prefix', async () => {
    const id = await buildIdentity({ rotate: true });
    const store = memoryStore();
    const peerClient = fakePeerClient({
      [A]: { identities: { [id.did]: id.log } }, // full chain
      [B]: { identities: { [id.did]: id.genesisLog } }, // divergent (behind)
    });
    const client = createClient({ relays: [A, B], quorum: 2, store, peerClient });

    const res = await client.identity(id.did);
    expect(res.provenance.agreed).toBe(false); // no quorum
    // the answer surfaced (verified) — but it must NOT have become cache truth
    expect(await store.get(`identity:${id.did}`)).toBeUndefined();
  });

  it('caches once quorum is met', async () => {
    const id = await buildIdentity();
    const store = memoryStore();
    const peerClient = fakePeerClient({
      [A]: { identities: { [id.did]: id.log } },
      [B]: { identities: { [id.did]: id.log } },
    });
    const client = createClient({ relays: [A, B], quorum: 2, store, peerClient });

    const res = await client.identity(id.did);
    expect(res.provenance.agreed).toBe(true);
    expect(await store.get(`identity:${id.did}`)).toBeDefined();
  });
});

describe('relay dedupe at the client', () => {
  it('one relay listed twice cannot satisfy quorum 2', async () => {
    const id = await buildIdentity();
    const peerClient = fakePeerClient({ [A]: { identities: { [id.did]: id.log } } });
    const client = createClient({ relays: [A, `${A}/`], quorum: 2, peerClient });

    const res = await client.identity(id.did);
    // after normalization only ONE distinct relay exists — quorum 2 unmeetable
    expect(res.provenance.responses).toHaveLength(1);
    expect(res.provenance.agreed).toBe(false);
  });
});

describe('timeouts', () => {
  /** A fetch that hangs forever unless its AbortSignal fires. */
  const hangingFetch: typeof fetch = (_input, init) =>
    new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () =>
        reject(new DOMException('aborted', 'AbortError')),
      );
    });

  it('a hung relay times out instead of stalling health() forever', async () => {
    const client = createClient({ relays: [A], timeoutMs: 30, fetch: hangingFetch });
    const started = Date.now();
    const health = await client.health();
    expect(Date.now() - started).toBeLessThan(2000);
    expect(health).toEqual([{ url: A, ok: false }]);
  });

  it('the default peer-client transport inherits the timeout policy', async () => {
    // no peerClient injected — the default createHttpPeerClient must run on the
    // policy-wrapped fetch, so a hung relay fails the read instead of hanging it
    const client = createClient({ relays: [A], timeoutMs: 30, fetch: hangingFetch });
    const started = Date.now();
    await expect(client.identity('did:dfos:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).rejects.toThrow(
      /not found on any relay/,
    );
    expect(Date.now() - started).toBeLessThan(2000);
  });
});

describe('globalLog resilience', () => {
  it('degrades to an empty page when the pager throws', async () => {
    const throwing: PeerClient = {
      ...fakePeerClient({}),
      async getOperationLog() {
        throw new Error('boom');
      },
    };
    const client = createClient({ relays: [A], peerClient: throwing });
    const page = await client.globalLog();
    expect(page.entries).toEqual([]);
    expect(page.provenance.answeredBy).toBe('');
  });

  it('serves a page from the first reachable relay', async () => {
    const id = await buildIdentity();
    const peerClient = fakePeerClient({
      [A]: { operations: id.log },
    });
    const client = createClient({ relays: [B, A], peerClient });
    const page = await client.globalLog();
    expect(page.entries).toEqual(toEntries(id.log));
    expect(page.provenance.answeredBy).toBe(A);
  });
});
