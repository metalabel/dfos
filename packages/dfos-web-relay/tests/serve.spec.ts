import { connect } from 'node:net';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { bootstrapRelayIdentity, createRelay, MemoryRelayStore } from '../src';
import { serve } from '../src/serve';

// =============================================================================
// Node server streaming body cap
//
// The serve() bridge buffers the ENTIRE request body before app.fetch runs any
// auth/routing. A huge POST/PUT would OOM Node before any per-route guard fires,
// so serve() caps the streamed body just ABOVE the 16MB route cap (~17MB). This
// is the ONLY guard that protects the unauthenticated path.
//
// We drive a raw socket so we can declare a large Content-Length and observe the
// pre-read 413 directly, without the fetch client EPIPE-ing on the early close.
// =============================================================================

describe('node server body cap', () => {
  let server: ReturnType<typeof serve>;
  let port: number;

  beforeAll(async () => {
    const store = new MemoryRelayStore();
    const identity = await bootstrapRelayIdentity(store);
    const app = await createRelay({ store, identity });
    server = serve(app.app, { port: 0 }); // ephemeral port
    await new Promise<void>((resolve) => server.once('listening', resolve));
    port = (server.address() as AddressInfo).port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('rejects an oversized body by Content-Length with 413 (pre-read)', async () => {
    // Declare a 20MB body (over the ~17MB stream cap) but send no payload — the
    // server's Content-Length check fires before reading a byte and returns 413.
    const status = await new Promise<number>((resolve, reject) => {
      const sock = connect(port, '127.0.0.1', () => {
        const req =
          'POST /operations HTTP/1.1\r\n' +
          'Host: 127.0.0.1\r\n' +
          'Content-Type: application/json\r\n' +
          `Content-Length: ${20 * 1024 * 1024}\r\n` +
          'Connection: close\r\n' +
          '\r\n';
        sock.write(req);
      });
      let data = '';
      sock.on('data', (chunk) => {
        data += chunk.toString('utf8');
      });
      sock.on('end', () => {
        const match = data.match(/^HTTP\/1\.1 (\d{3})/);
        if (match) resolve(Number(match[1]));
        else reject(new Error(`no status line in response: ${data.slice(0, 80)}`));
      });
      sock.on('error', reject);
      sock.setTimeout(5000, () => {
        sock.destroy();
        reject(new Error('timeout waiting for 413'));
      });
    });
    expect(status).toBe(413);
  });

  it('still serves a small request normally', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/.well-known/dfos-relay`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { protocol: string };
    expect(body.protocol).toBe('dfos-web-relay');
  });
});
