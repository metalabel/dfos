import type { APIRoute } from 'astro';
import { specs } from '../content/specs';

export const GET: APIRoute = () => {
  const specLink = ({ title, listTitle, slug, llms }: (typeof specs)[number]) =>
    `- [${listTitle ?? title}](https://protocol.dfos.com${slug}): ${llms}`;

  const content = [
    '# DFOS Protocol',
    '',
    '> An open protocol for cryptographic identity and verifiable content.',
    '> The proof is public; the content is access-controlled. The protocol commits to content hashes, never plaintext — it does not encrypt, and confidentiality is enforced at the application layer (no end-to-end encryption).',
    '',
    '## About',
    '',
    '- [Why](https://protocol.dfos.com/overview): Why the protocol exists — the structural condition, dark forest topology, design principles',
    '- [FAQ](https://protocol.dfos.com/faq): Common questions about the protocol, its design, and how it compares to alternatives',
    '',
    '## Specifications',
    '',
    ...specs.filter((spec) => spec.llmsSection === 'specifications').map(specLink),
    '',
    '## Implementation',
    '',
    ...specs.filter((spec) => spec.llmsSection === 'implementation').map(specLink),
    '',
    '## Full Content',
    '',
    '- [llms-full.txt](https://protocol.dfos.com/llms-full.txt): Complete markdown dump — all specifications, overview, and FAQ as plain text',
    '',
    '## Related',
    '',
    '- [Content Schemas](https://schemas.dfos.com): Hosted JSON Schema definitions',
    '- [npm Package](https://www.npmjs.com/package/@metalabel/dfos-protocol): @metalabel/dfos-protocol',
    '- [GitHub](https://github.com/metalabel/dfos): Source code',
    '- [DFOS](https://dfos.com): The platform',
  ].join('\n');

  return new Response(content, {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
};
