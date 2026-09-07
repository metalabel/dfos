import { describe, expect, it } from 'vitest';
import { createHttpPeerClient, MAX_PEER_LOG_PAGE_BYTES } from '../src/peer-client';

describe('HTTP peer client cursor errors', () => {
  it.each(['identity', 'content'] as const)(
    'returns invalid-cursor for a 400 on a paged %s-chain walk',
    async (kind) => {
      const client = createHttpPeerClient({
        fetch: async () =>
          new Response(JSON.stringify({ error: 'invalid cursor' }), { status: 400 }),
      });
      const result =
        kind === 'identity'
          ? await client.getIdentityLog('http://peer.example', 'did:dfos:test', {
              after: 'peer-cursor',
            })
          : await client.getContentLog('http://peer.example', 'content-id', {
              after: 'peer-cursor',
            });
      expect(result).toBe('invalid-cursor');
    },
  );
});

describe('HTTP peer client request timeout', () => {
  // `fetch` has no default timeout, so a peer that accepts the connection and
  // then says nothing holds the caller forever. Read-through can only check its
  // own deadline BETWEEN pages, so an unbounded single page outlives every bound
  // above it.
  it('carries an abort signal on every read', async () => {
    const signals: (AbortSignal | null | undefined)[] = [];
    const client = createHttpPeerClient({
      fetch: async (_input, init) => {
        signals.push(init?.signal);
        return new Response(JSON.stringify({ entries: [], next: null }), { status: 200 });
      },
    });

    await client.getIdentityLog('http://peer.example', 'did:dfos:test', {});
    await client.getContentLog('http://peer.example', 'content-id', {});
    await client.getOperationLog('http://peer.example', {});

    expect(signals).toHaveLength(3);
    for (const signal of signals) {
      expect(signal).toBeInstanceOf(AbortSignal);
      expect(signal?.aborted).toBe(false);
    }
  });

  it('lets a caller opt out with timeoutMs: 0', async () => {
    let seen: AbortSignal | null | undefined = null;
    const client = createHttpPeerClient({
      timeoutMs: 0,
      fetch: async (_input, init) => {
        seen = init?.signal;
        return new Response(JSON.stringify({ entries: [], next: null }), { status: 200 });
      },
    });
    await client.getOperationLog('http://peer.example', {});
    expect(seen).toBeUndefined();
  });
});

describe('HTTP peer client page bounds', () => {
  // The timeout bounds wall time, not memory, and read-through's op budget is
  // only consulted AFTER a page has been decoded and ingested. A page that is
  // not bounded here is unbounded work no later check can undo.
  const pageOf = (count: number) =>
    JSON.stringify({
      entries: Array.from({ length: count }, (_, i) => ({ cid: `cid-${i}`, jwsToken: 'x' })),
      next: null,
    });

  const clientReturning = (body: string, init?: ResponseInit) =>
    createHttpPeerClient({ fetch: async () => new Response(body, { status: 200, ...init }) });

  it.each(['identity', 'content', 'operation'] as const)(
    'refuses a %s page with more entries than were requested',
    async (kind) => {
      const client = clientReturning(pageOf(50));
      const result =
        kind === 'identity'
          ? await client.getIdentityLog('http://peer.example', 'did:dfos:test', { limit: 10 })
          : kind === 'content'
            ? await client.getContentLog('http://peer.example', 'content-id', { limit: 10 })
            : await client.getOperationLog('http://peer.example', { limit: 10 });
      expect(result).toBeNull();
    },
  );

  it('accepts a page at exactly the requested limit', async () => {
    const client = clientReturning(pageOf(10));
    const result = await client.getOperationLog('http://peer.example', { limit: 10 });
    expect(result).not.toBeNull();
    expect(result).not.toBe('invalid-cursor');
    expect((result as { entries: unknown[] }).entries).toHaveLength(10);
  });

  it('refuses a body past the byte cap', async () => {
    const oversized = JSON.stringify({
      entries: [{ cid: 'cid-0', jwsToken: 'x'.repeat(MAX_PEER_LOG_PAGE_BYTES) }],
      next: null,
    });
    const client = clientReturning(oversized);
    expect(await client.getOperationLog('http://peer.example', { limit: 10 })).toBeNull();
  });

  it('refuses a declared content-length past the byte cap', async () => {
    const client = clientReturning(pageOf(1), {
      headers: { 'content-length': String(MAX_PEER_LOG_PAGE_BYTES + 1) },
    });
    expect(await client.getOperationLog('http://peer.example', { limit: 10 })).toBeNull();
  });

  it('refuses a page whose entries are not an array', async () => {
    const client = clientReturning(JSON.stringify({ entries: 'nope', next: null }));
    expect(await client.getOperationLog('http://peer.example', { limit: 10 })).toBeNull();
  });
});
