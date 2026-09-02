import { describe, expect, it } from 'vitest';
import { bootstrapRelayIdentity, createRelay, MemoryRelayStore } from '../src';

/*

  CORS — the browser-reader policy, and the one header that is not decoration

  The permissive Allow-* policy is what lets any browser client read the proof
  plane cross-origin. EXPOSE-HEADERS is the part worth a test: a cross-origin
  reader can see only the CORS-safelisted response headers unless the server
  names the rest, so an unexposed `X-Document-Cid` is invisible to exactly the
  clients that need it most.

  What that header is FOR: it is the blob route's own statement of which
  document it believes it is sending. A client that can read it can check served
  bytes against the SERVING relay's claim, and catch a relay contradicting
  itself. A client that cannot read it can only check them against a chain
  lookup that may have come from a DIFFERENT relay — which downgrades a
  hostile-relay signal into ordinary cross-relay skew. Nothing about the bytes
  changes; the reader just loses the ability to say who is wrong.

  This policy is kept byte-for-byte in sync with the Go twin
  (`TestCORSHeadersOnProofPlane` in packages/dfos-web-relay-go), so these
  expectations are the same strings on both sides on purpose.

*/

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, PUT, OPTIONS',
  'access-control-allow-headers': 'Content-Type, Authorization',
  'access-control-expose-headers': 'X-Document-Cid',
};

const relay = async () => {
  const store = new MemoryRelayStore();
  const identity = await bootstrapRelayIdentity(store);
  return createRelay({ store, identity });
};

describe('CORS policy', () => {
  it('carries every CORS header on an ordinary read', async () => {
    const app = await relay();
    const res = await app.app.request('/.well-known/dfos-relay');
    expect(res.status).toBe(200);
    for (const [header, value] of Object.entries(CORS)) {
      expect([header, res.headers.get(header)]).toEqual([header, value]);
    }
  });

  it('answers a preflight with 204 and the same headers', async () => {
    const app = await relay();
    const res = await app.app.request('/proof/v1/operations', { method: 'OPTIONS' });
    expect(res.status).toBe(204);
    for (const [header, value] of Object.entries(CORS)) {
      expect([header, res.headers.get(header)]).toEqual([header, value]);
    }
  });

  it('exposes X-Document-Cid, so a browser can read the blob route’s own claim', async () => {
    // the assertion that fails when someone adds a custom response header and
    // forgets that a cross-origin reader cannot see it
    const app = await relay();
    const res = await app.app.request('/.well-known/dfos-relay');
    expect(res.headers.get('access-control-expose-headers')).toContain('X-Document-Cid');
  });
});
