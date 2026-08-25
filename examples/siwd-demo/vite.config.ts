/*

  `npm run dev` — the static page AND the four api routes, no vercel CLI.

  Vercel's Node runtime adds exactly two things to Node's own
  `IncomingMessage` / `ServerResponse` pair: a pre-parsed JSON `body` on the
  request, and Express-style `status()` / `send()` on the response (see
  `api/_types.ts`). Both are shimmed below, and this plugin mounts the SAME
  handler files as connect middleware on vite's dev server, so the whole login
  flow runs locally against the live platform under the loopback tier.

  `api/login.ts` and friends are imported here, not reimplemented, so there is
  no second implementation to drift.

*/

import { Buffer } from 'node:buffer';
import type { IncomingMessage } from 'node:http';
import { defineConfig, type Plugin } from 'vite';
import type { VercelRequest, VercelResponse } from './api/_types.js';
import config from './api/config.js';
import login from './api/login.js';
import logout from './api/logout.js';
import me from './api/me.js';
import profile from './api/profile.js';
import verify from './api/verify.js';

type Handler = (req: VercelRequest, res: VercelResponse) => void | Promise<void>;

/** Vercel routes by filename; in dev the same map is written out by hand. */
const ROUTES: Record<string, Handler> = {
  '/api/config': config,
  '/api/login': login,
  '/api/logout': logout,
  '/api/me': me,
  '/api/profile': profile,
  '/api/verify': verify,
};

const readBody = async (req: IncomingMessage): Promise<string> => {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
};

const devApi = (): Plugin => ({
  name: 'siwd-demo-dev-api',
  configureServer(server) {
    server.middlewares.use((req, res, next) => {
      const handler = ROUTES[(req.url ?? '').split('?')[0] ?? ''];
      if (handler === undefined) {
        next();
        return;
      }

      void (async () => {
        const request = req as VercelRequest;
        const raw = await readBody(req);
        if (raw !== '') {
          // the runtime parses JSON and leaves anything else a string; the
          // handlers accept both, so mirroring it here keeps them on one path
          try {
            request.body = JSON.parse(raw);
          } catch {
            request.body = raw;
          }
        }

        const response = res as VercelResponse;
        response.status = (code) => {
          res.statusCode = code;
          return response;
        };
        response.send = (body) => {
          res.end(body);
          return response;
        };

        try {
          await handler(request, response);
        } catch (err) {
          // a thrown handler is a bug, not a verdict — report it in the same
          // JSON shape the routes use rather than hang the request
          response.status(500).send(
            JSON.stringify({
              ok: false,
              reason: err instanceof Error ? err.message : String(err),
            }),
          );
        }
      })();
    });
  },
});

export default defineConfig({ plugins: [devApi()] });
