import fs from 'node:fs';
import type { APIRoute } from 'astro';

export const GET: APIRoute = () => {
  const content = fs.readFileSync('../dfos-protocol/PROTOCOL.md', 'utf-8');

  return new Response(content, {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
};
