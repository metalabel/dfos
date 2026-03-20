import type { APIRoute } from 'astro';

export const GET: APIRoute = () => {
  const content = [
    '# DFOS Protocol',
    '',
    '> Ed25519 signed chain primitives, content-addressed proofs, W3C DIDs.',
    '> Verifiable identity and content without trusting the platform.',
    '',
    '## Specifications',
    '',
    '- [Protocol Specification](https://protocol.dfos.com/spec): Core protocol — identity chains, content chains, beacons, merkle trees, countersignatures, verification rules, and test vectors',
    '- [DID Method](https://protocol.dfos.com/did-method): W3C DID method specification for did:dfos',
    '- [Content Model](https://protocol.dfos.com/content-model): Standard JSON Schema content types (post, profile, manifest)',
    '',
    '## Full Content',
    '',
    '- [llms-full.txt](https://protocol.dfos.com/llms-full.txt): All specifications as plain text',
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
