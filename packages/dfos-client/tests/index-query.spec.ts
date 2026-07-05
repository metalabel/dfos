/*

  INDEX (v0) SEAM — hints, fetched with failover

  The index methods are a thin, non-authoritative fetch surface: build the query,
  take the first index-capable relay's 200, fail over past 501/unreachable relays,
  and parse the page verbatim (rows are claims the caller verifies by folding).
  These tests pin the query-param wiring, the failover, and the capability gate —
  against an injected fetch fake, no live network.

*/

import { describe, expect, it } from 'vitest';
import { createClient } from '../src/client';

const A = 'https://a.test';
const B = 'https://b.test';

const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

/** A fetch fake dispatching on (origin, pathname) to a per-relay handler map. */
const indexFetch =
  (byUrl: Record<string, (path: string, url: URL) => Response>): typeof fetch =>
  async (input) => {
    const url = new URL(String(input));
    const handler = byUrl[url.origin];
    if (!handler) return new Response('unreachable', { status: 502 });
    return handler(url.pathname, url);
  };

const IDENTITY_ROW = {
  did: 'did:dfos:hd34z9a4tf6h62864nh4f7at6hr36r4',
  headCID: 'bafyreiidentity',
  opCount: 4,
  genesisAt: '2026-03-25T00:00:00.000Z',
  headAt: '2026-04-02T00:00:00.000Z',
  isDeleted: false,
  profile: {
    anchor: 'a3n7r3nde8e4keeak92rr3aeztftvc2',
    publicRead: true,
    docSchema: 'https://schemas.dfos.com/profile/v1',
    name: 'asha',
  },
};

describe('index (v0) client seam', () => {
  it('fetches an identities page and passes hasPublicProfile/limit through', async () => {
    let seen: URL | undefined;
    const client = createClient({
      relays: [A],
      fetch: indexFetch({
        [A]: (path, url) => {
          seen = url;
          if (path === '/index/v0/identities')
            return json({ identities: [IDENTITY_ROW], next: null });
          return new Response('nope', { status: 404 });
        },
      }),
    });
    const page = await client.indexIdentities({ hasPublicProfile: true, limit: 50 });
    expect(page.identities).toHaveLength(1);
    expect(page.identities[0]?.profile?.name).toBe('asha');
    expect(page.next).toBeNull();
    expect(seen?.searchParams.get('hasPublicProfile')).toBe('true');
    expect(seen?.searchParams.get('limit')).toBe('50');
  });

  it('fails over past a 501 relay to an index-capable one', async () => {
    const client = createClient({
      relays: [A, B],
      fetch: indexFetch({
        [A]: () => new Response('index not supported', { status: 501 }),
        [B]: (path) =>
          path === '/index/v0/content'
            ? json({ content: [{ contentId: 'c1' }], next: 'c1' })
            : new Response('nope', { status: 404 }),
      }),
    });
    const page = await client.indexContent({ creator: 'did:dfos:x' });
    expect(page.content).toHaveLength(1);
    expect(page.next).toBe('c1');
  });

  it('returns an empty page when every relay declines (501 / unreachable)', async () => {
    const client = createClient({
      relays: [A, B],
      fetch: indexFetch({
        [A]: () => new Response('index not supported', { status: 501 }),
        // B absent from the map — the fake answers 502 (unreachable)
      }),
    });
    const page = await client.indexIdentities();
    expect(page.identities).toEqual([]);
    expect(page.next).toBeNull();
  });

  it('countersignatures-by-witness sets the required witness param and echoes it', async () => {
    let seen: URL | undefined;
    const client = createClient({
      relays: [A],
      fetch: indexFetch({
        [A]: (path, url) => {
          seen = url;
          return json({ witness: 'did:dfos:w', countersignatures: [], next: null });
        },
      }),
    });
    const page = await client.indexCountersignatures('did:dfos:w', { limit: 10 });
    expect(page.witness).toBe('did:dfos:w');
    expect(seen?.pathname).toBe('/index/v0/countersignatures');
    expect(seen?.searchParams.get('witness')).toBe('did:dfos:w');
    expect(seen?.searchParams.get('limit')).toBe('10');
  });

  it('capabilities() reports index true when any relay advertises it', async () => {
    const wellKnown = (index: boolean) => (path: string) =>
      path === '/.well-known/dfos-relay'
        ? json({ capabilities: { proof: true, index } })
        : new Response('nope', { status: 404 });
    const client = createClient({
      relays: [A, B],
      fetch: indexFetch({ [A]: wellKnown(false), [B]: wellKnown(true) }),
    });
    expect(await client.capabilities()).toEqual({ index: true });
  });

  it('capabilities() reports index false when no relay advertises it', async () => {
    const client = createClient({
      relays: [A],
      fetch: indexFetch({
        [A]: (path) =>
          path === '/.well-known/dfos-relay'
            ? json({ capabilities: { proof: true, index: false } })
            : new Response('nope', { status: 404 }),
      }),
    });
    expect(await client.capabilities()).toEqual({ index: false });
  });
});
