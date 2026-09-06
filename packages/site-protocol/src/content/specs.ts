// Single source of truth for the spec/doc corpus this site serves.
// Every list surface derives from this array — the landing grid, the nav's
// spec block, llms.txt, llms-full.txt, and each page's title/meta description.
// Array order is THE canonical order for every derived list.

/** The CLI's build targets, stated once (.goreleaser.yml: 3 OS x 2 arch). */
export const CLI_PLATFORMS = 'Linux, macOS, and Windows (x64 and arm64)';

export interface SpecEntry {
  /** Route slug with leading slash: '/relay'. */
  slug: string;
  /** Page title and tile title. */
  title: string;
  /** List-surface label (grid tile, llms.txt) when it differs from the page title. */
  listTitle?: string;
  /** Landing-grid one-liner. HTML allowed (&mdash;, <code>). */
  tile: string;
  /** llms.txt one-liner. Plain text; may be richer than the tile. */
  llms: string;
  /** The page's <meta name="description">. */
  metaDescription: string;
  /**
   * Markdown source path for the llms-full.txt dump, relative to the site
   * package root. Absent for pages whose content is site-local.
   */
  source?: string;
  /** Landing-grid tier; null = not on the grid. */
  grid: 'core' | 'reference' | 'companions' | 'use' | null;
  /** Per-tile status chip on the landing grid; absent = no chip. */
  chip?: string;
  /** llms.txt grouping. */
  llmsSection: 'specifications' | 'implementation';
  /** Nav presence/labels (every registry entry appears in the nav). */
  nav: { label?: string; shortLabel?: string; tier: 'primary' | 'secondary' };
}

export const specs: SpecEntry[] = [
  {
    slug: '/spec',
    title: 'Specification',
    listTitle: 'Protocol Specification',
    tile: 'Chains, services, credentials, CID derivation, verification rules, test vectors',
    llms: 'Core protocol — identity chains, content chains, services discovery vocabulary, credentials, countersignatures, verification rules, and test vectors',
    metaDescription:
      'Complete DFOS protocol specification — Ed25519 signed chain primitives, services, credentials, countersignatures, identity and content verification, with worked examples and test vectors.',
    source: '../../specs/PROTOCOL.md',
    grid: 'core',
    llmsSection: 'specifications',
    nav: { shortLabel: 'Spec', tier: 'primary' },
  },
  {
    slug: '/did-method',
    title: 'DID Method: did:dfos',
    listTitle: 'DID Method',
    tile: 'W3C <code>did:dfos</code> &mdash; self-certifying, transport-agnostic identifiers',
    llms: 'W3C DID method specification for did:dfos',
    metaDescription:
      'W3C DID Method specification for did:dfos — self-certifying, transport-agnostic decentralized identifiers built on Ed25519 identity chains.',
    source: '../../specs/DID-METHOD.md',
    grid: 'core',
    llmsSection: 'specifications',
    nav: { label: 'DID Method', tier: 'secondary' },
  },
  {
    slug: '/credentials',
    title: 'Credentials',
    tile: 'Delegated authorization, revocation, standing access, and attenuation',
    llms: 'Authorization credentials, delegation chains, and revocation',
    metaDescription:
      'DFOS Credentials — UCAN-style authorization tokens for delegated content access, revocation, and standing authorization.',
    source: '../../specs/CREDENTIALS.md',
    grid: 'core',
    llmsSection: 'specifications',
    nav: { tier: 'secondary' },
  },
  {
    slug: '/content-model',
    title: 'Content Model',
    tile: 'JSON Schema content types committed via content-addressed CIDs',
    llms: 'Standard JSON Schema content types (post, profile)',
    metaDescription:
      'DFOS Content Model — standard JSON Schema content types (post, profile) committed via content-addressed CIDs.',
    source: '../../specs/CONTENT-MODEL.md',
    grid: 'core',
    llmsSection: 'specifications',
    nav: { tier: 'secondary' },
  },
  {
    slug: '/relay',
    title: 'Relay',
    tile: 'The relay HTTP surface &mdash; read and write contracts, ingestion, profiles, content plane',
    llms: 'The relay HTTP surface — the read contract and its routes, the write contract and its ingestion rules, the index / signing-mailbox / peering profiles, and the content plane',
    metaDescription:
      'DFOS Relay — the HTTP wire and ingest rules for a DFOS relay: read and write contracts, capability-gated profiles, peering, and the content plane.',
    source: '../../specs/RELAY.md',
    grid: 'reference',
    llmsSection: 'specifications',
    nav: { shortLabel: 'Relay', tier: 'primary' },
  },
  {
    slug: '/integrations',
    title: 'Integrations',
    tile: 'Sign in, API authentication, origin binding, and key ceremonies',
    llms: 'Integrating with DFOS — sign in (SIWD), proof-of-possession API authentication, bidirectional origin binding, and the key-possession ceremony surface',
    metaDescription:
      'DFOS Integrations — sign in with DFOS, proof-of-possession API request authentication, identity-to-domain origin binding, and key ceremonies.',
    source: '../../specs/INTEGRATIONS.md',
    grid: 'reference',
    llmsSection: 'specifications',
    nav: { tier: 'secondary' },
  },
  {
    slug: '/conformance',
    title: 'Conformance',
    tile: 'Signer, verifier, and relay tiers with the test vectors that prove them',
    llms: 'Conformance tiers (signer, verifier, relay), the normative MUST sets per tier, and the deterministic test vectors that prove them',
    metaDescription:
      'DFOS Protocol conformance — what it means to be a conformant signer, verifier, or relay, the normative MUST sets per tier, and the deterministic test vectors that prove it.',
    source: '../../specs/CONFORMANCE.md',
    grid: 'companions',
    chip: 'companion',
    llmsSection: 'specifications',
    nav: { tier: 'secondary' },
  },
  {
    slug: '/threat-model',
    title: 'Threat Model',
    tile: 'Adversaries, trust boundaries, and what the proof/content separation defends',
    llms: 'Adversary model, trust boundaries between the public proof plane and the access-controlled content plane, and what the protocol defends against',
    metaDescription:
      'DFOS Protocol threat model — adversaries, trust boundaries between the public proof plane and the access-controlled content plane, and what the protocol does and does not defend against.',
    source: '../../specs/THREAT-MODEL.md',
    grid: 'companions',
    chip: 'companion',
    llmsSection: 'specifications',
    nav: { tier: 'secondary' },
  },
  {
    slug: '/cli',
    title: 'CLI',
    tile: `Identities, content chains, credentials, relays &mdash; ${CLI_PLATFORMS}`,
    llms: 'Go command-line interface for managing identities, signing operations, and interacting with relays',
    metaDescription:
      'DFOS CLI — Go command-line interface for managing identities, content chains, services, and credentials against protocol relays.',
    source: '../dfos-cli/CLI.md',
    grid: 'use',
    llmsSection: 'implementation',
    nav: { tier: 'primary' },
  },
  {
    slug: '/deploy',
    title: 'Deploy',
    tile: 'Run a relay with Docker, Caddy auto-TLS, peering, and container images',
    llms: 'Run a relay with Docker Compose, Caddy auto-TLS, peering, and container images',
    metaDescription:
      'Running a DFOS relay — Docker Compose with Caddy auto-TLS, configuration, peering, and container images.',
    grid: 'use',
    llmsSection: 'implementation',
    nav: { tier: 'secondary' },
  },
  {
    slug: '/skill',
    title: 'Agent Skill',
    tile: 'Drive the CLI from your AI coding agent &mdash; Claude Code, or any agent via npx skills',
    llms: 'Drive the DFOS CLI from a coding agent — install into Claude Code or any agent (plugin, npx skills, or the embedded `dfos skill` command)',
    metaDescription:
      'Agent skill for the DFOS CLI — install into Claude Code or any coding agent to create identities, publish content, issue credentials, and manage relays.',
    grid: 'use',
    llmsSection: 'implementation',
    nav: { label: 'Skill', tier: 'primary' },
  },
];

export function specEntry(slug: string): SpecEntry {
  const entry = specs.find((candidate) => candidate.slug === slug);
  if (!entry) throw new Error(`Unknown spec slug: ${slug}`);
  return entry;
}
