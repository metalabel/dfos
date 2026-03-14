import type { APIRoute } from 'astro';

export const GET: APIRoute = () => {
  const content = [
    '# DFOS Protocol',
    '',
    '> Ed25519 signed chain primitives, content-addressed proofs, W3C DIDs.',
    '> Verifiable identity and content without trusting the platform.',
    '',
    '## Pages',
    '',
    '- [Home](https://protocol.dfos.com/): Protocol overview and links',
    '- [Specification](https://protocol.dfos.com/spec): Complete protocol specification with worked examples and test vectors',
    '',
    '## Full Content',
    '',
    '- [llms-full.txt](https://protocol.dfos.com/llms-full.txt): Complete protocol specification as plain text',
    '',
    '## Related',
    '',
    '- [Content Schemas](https://schemas.dfos.com): JSON Schema definitions for DFOS content types',
    '- [npm Package](https://www.npmjs.com/package/@metalabel/dfos-protocol): @metalabel/dfos-protocol',
    '- [GitHub](https://github.com/metalabel/dfos): Source code',
    '- [DFOS](https://dfos.com): The platform',
  ].join('\n');

  return new Response(content, {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
};
