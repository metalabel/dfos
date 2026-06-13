/*

  NODE SERVER

  Bridges a Hono relay app to Node's http.createServer. Separate entry
  point so the core library stays runtime-agnostic.

*/

import { createServer, type Server } from 'node:http';
import type { Hono } from 'hono';

export interface ServeOptions {
  port?: number;
  hostname?: string;
}

/**
 * Hard streaming body cap for the Node server. This sits just ABOVE the relay's
 * 16MB per-route cap so it protects the UNAUTHENTICATED path (the for-await loop
 * below buffers the entire body before app.fetch runs any auth/route) without
 * shadowing the route's own 413 for legitimate near-cap bodies. A huge POST/PUT
 * would otherwise OOM Node before any guard fires. 1MB of headroom over the
 * route cap.
 */
const MAX_STREAM_BODY_BYTES = (16 << 20) + (1 << 20); // 17MB

/**
 * Start a Node HTTP server for a DFOS web relay.
 *
 * ```ts
 * import { createRelay, MemoryRelayStore } from '@metalabel/dfos-web-relay';
 * import { serve } from '@metalabel/dfos-web-relay/node';
 *
 * const relay = await createRelay({ store: new MemoryRelayStore() });
 * serve(relay, { port: 4444 });
 * ```
 */
export const serve = (app: Hono, options: ServeOptions = {}): Server => {
  const { port = 4444, hostname } = options;

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', `http://${hostname ?? 'localhost'}:${port}`);

    // 413 helper: respond and force the connection closed. We do NOT
    // req.destroy() first — that can tear the socket down before the response
    // flushes (leaving the client with an empty/EPIPE'd read). Instead we send
    // the response with `Connection: close`, which closes the socket cleanly
    // after the body drains, abandoning the rest of the (unread) request.
    const reject413 = () => {
      if (res.headersSent) return;
      res.writeHead(413, {
        'content-type': 'application/json',
        connection: 'close',
      });
      res.end(JSON.stringify({ error: 'request body too large' }));
    };

    // Reject by Content-Length before reading a byte, when the header is present.
    const declaredLength = Number(req.headers['content-length']);
    if (Number.isFinite(declaredLength) && declaredLength > MAX_STREAM_BODY_BYTES) {
      reject413();
      return;
    }

    // Stream-cap the body so a Content-Length-absent (chunked) flood can't OOM
    // Node before app.fetch runs auth/routing. Abort the moment the running
    // total crosses the cap.
    const chunks: Buffer[] = [];
    let total = 0;
    let aborted = false;
    for await (const chunk of req) {
      total += (chunk as Buffer).length;
      if (total > MAX_STREAM_BODY_BYTES) {
        aborted = true;
        break;
      }
      chunks.push(chunk as Buffer);
    }
    if (aborted) {
      reject413();
      return;
    }
    const body = Buffer.concat(chunks);

    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
      if (v) headers.set(k, Array.isArray(v) ? v.join(', ') : v);
    }

    const method = req.method ?? 'GET';
    const init: RequestInit = { method, headers };
    if (!['GET', 'HEAD'].includes(method)) {
      init.body = body;
    }

    const response = await app.fetch(new Request(url.toString(), init));

    res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
    const buf = Buffer.from(await response.arrayBuffer());
    res.end(buf);
  });

  server.listen(port, hostname, () => {
    console.log(`DFOS web relay listening on http://${hostname ?? 'localhost'}:${port}`);
  });

  return server;
};
