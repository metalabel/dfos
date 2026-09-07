import type { APIRoute } from 'astro';
import { specs } from '../content/specs';

export const GET: APIRoute = () => {
  const specLink = ({ title, listTitle, slug, llms }: (typeof specs)[number]) =>
    `- [${listTitle ?? title}](https://protocol.dfos.com${slug}): ${llms}`;

  const content = [
    '# DFOS Protocol',
    '',
    '> DFOS is an open protocol for identities, signed records, and delegated permissions that any compatible application can verify for itself.',
    '> Identity derives from Ed25519 signed operations, and an identifier derives from its genesis operation. Proofs verify offline, in any language, from any copy. Content chains reference documents by hash. The protocol does not encrypt, and whoever serves a document can read it. Which view of an identity you follow is a choice of relay.',
    '',
    '## About',
    '',
    '- [Why](https://protocol.dfos.com/overview): Why the protocol exists — verifiability without publication, identity continuity, delegated permissions, and where the guarantee stops',
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
