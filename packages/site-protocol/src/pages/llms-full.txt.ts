import fs from 'node:fs';
import type { APIRoute } from 'astro';

export const GET: APIRoute = () => {
  const protocol = fs.readFileSync('../dfos-protocol/PROTOCOL.md', 'utf-8');
  const didMethod = fs.readFileSync('../dfos-protocol/DID-METHOD.md', 'utf-8');
  const contentModel = fs.readFileSync('../dfos-protocol/CONTENT-MODEL.md', 'utf-8');
  const content = [protocol, '---', '', didMethod, '---', '', contentModel].join('\n');

  return new Response(content, {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
};
