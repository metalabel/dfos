export interface FaqEntry {
  question: string;
  /** Plain text answer — used in markdown dump and structured data. */
  answer: string;
  /** Optional HTML answer — used in page rendering. Falls back to answer. */
  answerHtml?: string;
}

export const faqs: FaqEntry[] = [
  {
    question: 'What is the DFOS Protocol?',
    answer:
      'An open protocol for cryptographic identity and verifiable content. Ed25519 signed chains establish identity, commit content, and produce proofs that anyone can verify — offline, in any language, from any source. No platform, no blockchain, no trust assumption. Chains are directed acyclic graphs (DAGs) that converge deterministically across implementations without consensus.',
    answerHtml:
      'An open protocol for cryptographic identity and verifiable content. <a href="/spec">Ed25519 signed chains</a> establish identity, commit content, and produce proofs that anyone can verify — offline, in any language, from any source. No platform, no blockchain, no trust assumption. Chains are directed acyclic graphs (DAGs) that converge deterministically across implementations without consensus.',
  },
  {
    question: 'What problem does it solve?',
    answer:
      'Your identity and content are rented back to you by the platforms that own it. If a service shuts down or locks your account, everything disappears. The DFOS Protocol makes identity and content provenance self-sovereign — derived from cryptographic keys you control, verifiable by anyone with your public key and any standard EdDSA library.',
  },
  {
    question: 'What does "dark forest" mean in this context?',
    answer:
      'The internet is a dark forest — most meaningful creative and social activity happens in private spaces, not on the public web. DFOS is designed for this reality. Content lives in private, member-governed spaces. The cryptographic proof layer is the only public surface: signed commitments that anyone can verify, without revealing the content itself. The proof is public. The content is private.',
  },
  {
    question: 'How do chains handle forks and conflicts?',
    answer:
      'Chains are DAGs, not linear sequences. Forks are valid — two operations referencing the same predecessor both get accepted. All implementations converge to the same head via a deterministic rule: highest createdAt timestamp among tips, with lexicographic CID as tiebreaker. Given the same set of operations, any relay computes the same head regardless of ingestion order. This is convergence without consensus — no coordination protocol, no leader election, no global ordering.',
    answerHtml:
      'Chains are DAGs, not linear sequences. Forks are valid — two operations referencing the same predecessor both get accepted. All implementations converge to the same head via a deterministic rule: highest <code>createdAt</code> timestamp among tips, with lexicographic CID as tiebreaker. Given the same set of operations, any relay computes the same head regardless of ingestion order. This is convergence without consensus — no coordination protocol, no leader election, no global ordering.',
  },
  {
    question: 'How does the relay network work?',
    answer:
      'Web relays are verifying HTTP endpoints that store and serve chains. Every relay independently verifies every operation on ingestion — there is no trust relationship between relays. Three peering behaviors compose to form the network: gossip (push new operations to peers), read-through (fetch from peers on cache miss), and sync (periodic pull via cursor-based polling). There are no relay roles or hierarchy. Topology is emergent from per-peer configuration.',
    answerHtml:
      '<a href="/web-relay">Web relays</a> are verifying HTTP endpoints that store and serve chains. Every relay independently verifies every operation on ingestion — there is no trust relationship between relays. Three peering behaviors compose to form the network: gossip (push new operations to peers), read-through (fetch from peers on cache miss), and sync (periodic pull via cursor-based polling). There are no relay roles or hierarchy. Topology is emergent from per-peer configuration.',
  },
  {
    question: 'Do I need to run a server or connect to a network?',
    answer:
      'No. Verification is offline and self-contained. A signed chain carries everything needed to verify it — public keys, signatures, content-addressed hashes. There is no registry to query, no blockchain to sync, no API to call. Given a chain and a public key, any standard Ed25519 library in any language can verify it. Relays are useful for storage and distribution, but verification never depends on them.',
  },
  {
    question: 'What languages are supported?',
    answer:
      'The reference implementation is in TypeScript (available as @metalabel/dfos-protocol on npm). Cross-language verification implementations exist in Go, Python, Rust, and Swift — all verifying the same deterministic test vectors from the protocol specification. The CLI is written in Go with pre-built binaries for Linux, macOS, and Windows — installable via Homebrew, curl, or Docker.',
    answerHtml:
      'The reference implementation is in TypeScript (available as <a href="https://www.npmjs.com/package/@metalabel/dfos-protocol">@metalabel/dfos-protocol</a> on npm). Cross-language verification implementations exist in Go, Python, Rust, and Swift — all verifying the same deterministic test vectors from the <a href="/spec">protocol specification</a>. The <a href="/cli">CLI</a> is written in Go with pre-built binaries for Linux, macOS, and Windows — installable via Homebrew, curl, or Docker.',
  },
  {
    question: 'How is this different from blockchain-based identity?',
    answer:
      'Blockchain identity systems anchor trust in a shared ledger — you need to sync with or query the chain to verify identity. The DFOS Protocol anchors trust in cryptographic signatures alone. There is no consensus layer, no gas fees, no chain state to maintain. Verification is a pure function: public key + signed chain = valid or invalid. Forks converge deterministically without coordination. This makes it simpler, faster, and fully transport-agnostic.',
  },
  {
    question: 'How does this compare to AT Protocol (Bluesky)?',
    answer:
      'AT Protocol and DFOS Protocol share foundations — self-sovereign identity, signed data, content-addressed storage, DIDs — but differ in topology. AT Protocol is public-by-default: your data repository is a public document, posts are visible to the network, and federation relays ingest content openly. The DFOS Protocol inverts this. Content is private — it lives in member-governed spaces, visible only to participants. The cryptographic proof layer is the only public surface. This is an architectural choice, not a privacy setting. AT Protocol is also a full social networking protocol (federation, data repositories, application schemas). The DFOS Protocol is narrower by design — cryptographic primitives only, agnostic to transport, federation, and application semantics.',
    answerHtml:
      'AT Protocol and DFOS Protocol share foundations — self-sovereign identity, signed data, content-addressed storage, DIDs — but differ in topology. AT Protocol is public-by-default: your data repository is a public document, posts are visible to the network, and federation relays ingest content openly. The DFOS Protocol inverts this. Content is private — it lives in member-governed spaces, visible only to participants. The cryptographic proof layer is the only public surface. This is an architectural choice, not a privacy setting. AT Protocol is also a full social networking protocol (federation, data repositories, application schemas). The DFOS Protocol is narrower by design — cryptographic primitives only, agnostic to transport, federation, and application semantics.',
  },
  {
    question: 'How do identity chains relate to DIDs?',
    answer:
      "Every identity chain is also a DID. The DID (did:dfos:<hash>) is derived deterministically from the hash of the chain's genesis operation — making it self-certifying. Given the chain, anyone can verify that it belongs to the claimed DID without trusting the source. The DID method specification defines how did:dfos identifiers conform to the W3C DID standard.",
    answerHtml:
      'Every identity chain is also a DID. The DID (did:dfos:&lt;hash&gt;) is derived deterministically from the hash of the chain\'s genesis operation — making it self-certifying. Given the chain, anyone can verify that it belongs to the claimed DID without trusting the source. The <a href="/did-method">DID method specification</a> defines how did:dfos identifiers conform to the W3C DID standard.',
  },
  {
    question: 'Is the protocol coupled to the DFOS platform?',
    answer:
      'No. The protocol is independent. DFOS (the platform) is one implementation, but any system that implements the same chain primitives produces interoperable, cross-verifiable proofs. An identity created on one system can sign content on another. The protocol is MIT-licensed open source.',
    answerHtml:
      'No. The protocol is independent. <a href="https://dfos.com">DFOS</a> (the platform) is one implementation, but any system that implements the same chain primitives produces interoperable, cross-verifiable proofs. An identity created on one system can sign content on another. The protocol is <a href="https://github.com/metalabel/dfos/blob/main/LICENSE">MIT-licensed</a> open source.',
  },
  {
    question: 'Is this production-ready?',
    answer:
      'The protocol specification is under active review and development. The TypeScript reference implementation is published and tested, with deterministic test vectors verified across five languages. The CLI ships pre-built binaries for 6 platforms via Homebrew, Docker, and direct download. The DFOS platform runs on this protocol in production. The specification has not been submitted to any formal standards body.',
    answerHtml:
      'The <a href="/spec">protocol specification</a> is under active review and development. The TypeScript <a href="https://www.npmjs.com/package/@metalabel/dfos-protocol">reference implementation</a> is published and tested, with deterministic test vectors verified across five languages. The <a href="/cli">CLI</a> ships pre-built binaries for 6 platforms via Homebrew, Docker, and direct download. The <a href="https://dfos.com">DFOS platform</a> runs on this protocol in production. The specification has not been submitted to any formal standards body.',
  },
  {
    question: 'Where can I discuss the protocol?',
    answer:
      'The specification is open source on GitHub (metalabel/dfos). Protocol discussion happens in the clear.txt space on DFOS.',
    answerHtml:
      'The specification is open source on <a href="https://github.com/metalabel/dfos">GitHub</a>. Protocol discussion happens in the <a href="https://clear.dfos.com">clear.txt</a> space on <a href="https://dfos.com">DFOS</a>.',
  },
];

/** Serialize FAQ entries as markdown. */
export function faqsToMarkdown(entries: FaqEntry[]): string {
  const sections = entries.map((faq) => `## ${faq.question}\n\n${faq.answer}`);
  return ['# Frequently Asked Questions', '', ...sections].join('\n\n');
}
