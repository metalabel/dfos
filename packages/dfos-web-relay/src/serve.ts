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

    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
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
