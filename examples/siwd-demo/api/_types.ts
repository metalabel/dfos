/*

  Minimal types for a Vercel Node serverless function.

  Vercel's Node runtime hands a handler the same `IncomingMessage` /
  `ServerResponse` pair Node's own `http` server does, plus a parsed `body` on
  the request and Express-style `status()` / `send()` on the response. Those two
  additions are all this demo uses, so it declares them here rather than depend
  on `@vercel/node`, a build tool that drags a large tree (and its own
  advisories) into a small demo. Nothing here changes behavior; it only names
  what Vercel passes.

  Two additions is also a small enough surface to shim, which is what
  `vite.config.ts` does so `npm run dev` serves these same handlers with no
  vercel CLI in the loop.

  The leading underscore is load-bearing: Vercel does not deploy `api/_*` as
  routes, so shared modules live here and endpoints are the files without one.

*/

import type { IncomingMessage, ServerResponse } from 'node:http';

export type VercelRequest = IncomingMessage & {
  /** JSON bodies are pre-parsed by the runtime; a raw string otherwise. */
  body?: unknown;
};

export type VercelResponse = ServerResponse & {
  status(code: number): VercelResponse;
  send(body: string): VercelResponse;
};
