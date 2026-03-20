import fs from 'node:fs';
import type { APIRoute } from 'astro';
import { faqs, faqsToMarkdown } from '../content/faq';
import { overviewMarkdown } from '../content/overview';

export const GET: APIRoute = () => {
  // Spec markdown files — read at build time from the protocol package
  const protocol = fs.readFileSync('../dfos-protocol/PROTOCOL.md', 'utf-8');
  const didMethod = fs.readFileSync('../dfos-protocol/DID-METHOD.md', 'utf-8');
  const contentModel = fs.readFileSync('../dfos-protocol/CONTENT-MODEL.md', 'utf-8');

  // Site content — sourced from shared modules (same data renders the pages)
  const overview = overviewMarkdown.trim();
  const faq = faqsToMarkdown(faqs);

  const content = [
    '# DFOS Protocol — Full Content Dump',
    '',
    '> All protocol site content as plain text. Specifications, overview, and FAQ.',
    '> Source: https://protocol.dfos.com',
    '',
    '---',
    '',
    overview,
    '',
    '---',
    '',
    protocol,
    '',
    '---',
    '',
    didMethod,
    '',
    '---',
    '',
    contentModel,
    '',
    '---',
    '',
    faq,
  ].join('\n');

  return new Response(content, {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
};
