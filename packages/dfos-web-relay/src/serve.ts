/*

  NODE SERVER

  Bridges a Hono relay app to Node's http.createServer. Separate entry
  point so the core library stays runtime-agnostic.

*/

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
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

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? '/', `http://${hostname ?? 'localhost'}:${port}`);

    // Terminal error response in the uniform `{ "error": ... }` shape, written
    // defensively: every caller below is on a path where the socket may already
    // be gone (an aborted request, a half-written response), and a throw from
    // writeHead/end would be exactly the escaping rejection this file guards
    // against. A dead socket has nobody to tell, so there is nothing to do.
    const respond = (status: number, error: string, extraHeaders: Record<string, string> = {}) => {
      try {
        if (res.headersSent || res.writableEnded || res.destroyed) return;
        res.writeHead(status, { 'content-type': 'application/json', ...extraHeaders });
        res.end(JSON.stringify({ error }));
      } catch {
        // socket already torn down — no response to send
      }
    };

    // 413 helper: respond and force the connection closed. We do NOT
    // req.destroy() first — that can tear the socket down before the response
    // flushes (leaving the client with an empty/EPIPE'd read). Instead we send
    // the response with `Connection: close`, which closes the socket cleanly
    // after the body drains, abandoning the rest of the (unread) request.
    const reject413 = () => respond(413, 'request body too large', { connection: 'close' });

    // Reject by Content-Length before reading a byte, when the header is present.
    const declaredLength = Number(req.headers['content-length']);
    if (Number.isFinite(declaredLength) && declaredLength > MAX_STREAM_BODY_BYTES) {
      reject413();
      return;
    }

    // Stream-cap the body so a Content-Length-absent (chunked) flood can't OOM
    // Node before app.fetch runs auth/routing. Abort the moment the running
    // total crosses the cap.
    //
    // The loop THROWS when the client disappears mid-body (ECONNRESET /
    // "aborted"), so it is guarded: a vanished client is not an error the relay
    // reports, it is a request that no longer exists. We answer 400 for the
    // benefit of a socket that somehow survives, and otherwise drop it.
    const chunks: Buffer[] = [];
    let total = 0;
    let aborted = false;
    try {
      for await (const chunk of req) {
        total += (chunk as Buffer).length;
        if (total > MAX_STREAM_BODY_BYTES) {
          aborted = true;
          break;
        }
        chunks.push(chunk as Buffer);
      }
    } catch {
      respond(400, 'request body could not be read');
      return;
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
  };

  // The handler is async, and createServer does nothing with a returned
  // promise: an unhandled rejection here is a PROCESS-LEVEL event, and Node's
  // default for one is to exit. So nothing may escape. The read loop and the
  // response writes have their own guards above; this is the backstop that
  // makes "the relay stays up" a property of the server rather than of the
  // handler getting every case right.
  const server = createServer((req, res) => {
    void handle(req, res).catch((error: unknown) => {
      console.error(
        JSON.stringify({
          event: 'relay.request.failed',
          method: req.method ?? '',
          error: error instanceof Error ? error.message : String(error),
        }),
      );
      try {
        if (!res.headersSent && !res.writableEnded && !res.destroyed) {
          res.writeHead(500, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'internal error' }));
        } else if (!res.writableEnded) {
          res.end();
        }
      } catch {
        // socket already torn down — no response to send
      }
    });
  });

  server.listen(port, hostname, () => {
    console.log(`DFOS web relay listening on http://${hostname ?? 'localhost'}:${port}`);
  });

  return server;
};
