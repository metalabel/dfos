import type { APIRoute } from 'astro';

export const GET: APIRoute = () => {
  const content = [
    '# DFOS Protocol',
    '',
    '> An open protocol for cryptographic identity and verifiable content.',
    '> The proof is public. The content is private.',
    '',
    '## About',
    '',
    '- [Why](https://protocol.dfos.com/overview): Why the protocol exists — the structural condition, dark forest topology, design principles',
    '- [FAQ](https://protocol.dfos.com/faq): Common questions about the protocol, its design, and how it compares to alternatives',
    '',
    '## Specifications',
    '',
    '- [Protocol Specification](https://protocol.dfos.com/spec): Core protocol — identity chains, content chains, beacons, credentials, countersignatures, verification rules, and test vectors',
    '- [DID Method](https://protocol.dfos.com/did-method): W3C DID method specification for did:dfos',
    '- [Content Model](https://protocol.dfos.com/content-model): Standard JSON Schema content types (post, profile, manifest)',
    '',
    '## Implementation',
    '',
    '- [Web Relay](https://protocol.dfos.com/web-relay): Verifying HTTP relay for identity chains, content chains, beacons, countersignatures, and content blobs',
    '- [CLI](https://protocol.dfos.com/cli): Go command-line interface for managing identities, signing operations, and interacting with relays',
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
