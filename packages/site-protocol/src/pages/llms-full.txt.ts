import fs from 'node:fs';
import type { APIRoute } from 'astro';
import { faqs, faqsToMarkdown } from '../content/faq';
import { overviewMarkdown } from '../content/overview';

export const GET: APIRoute = () => {
  // Spec markdown files — read at build time from the specs directory
  const protocol = fs.readFileSync('../../specs/PROTOCOL.md', 'utf-8');
  const didMethod = fs.readFileSync('../../specs/DID-METHOD.md', 'utf-8');
  const contentModel = fs.readFileSync('../../specs/CONTENT-MODEL.md', 'utf-8');

  // Specs — web relay
  const webRelay = fs.readFileSync('../../specs/WEB-RELAY.md', 'utf-8');
  const cli = fs.readFileSync('../dfos-cli/CLI.md', 'utf-8');

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
    webRelay,
    '',
    '---',
    '',
    cli,
    '',
    '---',
    '',
    faq,
  ].join('\n');

  return new Response(content, {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
};
