import fs from 'node:fs';
import type { APIRoute } from 'astro';
import { faqs, faqsToMarkdown } from '../content/faq';
import { overviewMarkdown } from '../content/overview';
import { specs, type SpecEntry } from '../content/specs';

export const GET: APIRoute = () => {
  // Spec markdown files — read at build time from the specs directory
  const specContent = specs
    .filter((spec): spec is SpecEntry & { source: string } => spec.source !== undefined)
    .map((spec) => fs.readFileSync(spec.source, 'utf-8'));

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
    [overview, ...specContent, faq].join('\n\n---\n\n'),
  ].join('\n');

  return new Response(content, {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
};
