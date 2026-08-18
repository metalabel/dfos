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
