/*

  Minimal types for a Vercel Node serverless function.

  Vercel's Node runtime hands a handler the same `IncomingMessage` /
  `ServerResponse` pair Node's own `http` server does, augmented with a parsed
  `body` on the request and Express-style `status()` / `send()` on the response.
  Those augmentations are all this demo uses, so it declares exactly them rather
  than depending on `@vercel/node` — that package is a build tool that drags a
  large tree (and its own advisories) into a demo whose whole point is to be
  small enough to read in one sitting. The shapes below are accurate to the
  runtime; nothing here changes behaviour, it only names what Vercel passes.

  Two augmentations is also a small enough surface to SHIM, which is what
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
