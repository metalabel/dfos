import type { APIRoute } from 'astro';

export const GET: APIRoute = () => {
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
    '- [Protocol Specification](https://protocol.dfos.com/spec): Core protocol — identity chains, content chains, services discovery vocabulary, credentials, countersignatures, verification rules, and test vectors',
    '- [DID Method](https://protocol.dfos.com/did-method): W3C DID method specification for did:dfos',
    '- [Content Model](https://protocol.dfos.com/content-model): Standard JSON Schema content types (post, profile)',
    '- [Credentials](https://protocol.dfos.com/credentials): Authorization credentials, delegation chains, and revocation',
    '- [Sign-In With DID](https://protocol.dfos.com/siwd): SIWD authentication flow for did:dfos',
    '- [Threat Model](https://protocol.dfos.com/threat-model): Adversary model, trust boundaries between the public proof plane and the access-controlled content plane, and what the protocol defends against',
    '- [Conformance](https://protocol.dfos.com/conformance): Conformance tiers (signer, verifier, relay), the normative MUST sets per tier, and the deterministic test vectors that prove them',
    '',
    '## Implementation',
    '',
    '- [Web Relay](https://protocol.dfos.com/web-relay): Verifying HTTP relay for identity chains, content chains, services, countersignatures, and content blobs',
    '- [Document Gateway](https://protocol.dfos.com/document-gateway): Stateless content-addressed blob store (0.1) — the content plane, with authorization re-derived live from the proof plane',
    '- [CLI](https://protocol.dfos.com/cli): Go command-line interface for managing identities, signing operations, and interacting with relays',
    '- [Deploy](https://protocol.dfos.com/deploy): Run a relay with Docker Compose, Caddy auto-TLS, peering, and container images',
    '- [Agent Skill](https://protocol.dfos.com/skill): Drive the DFOS CLI from a coding agent — install into Claude Code or any agent (plugin, npx skills, or the embedded `dfos skill` command)',
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
