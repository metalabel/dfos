import { describe, expect, it } from 'vitest';
import { createHttpPeerClient } from '../src/peer-client';

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
