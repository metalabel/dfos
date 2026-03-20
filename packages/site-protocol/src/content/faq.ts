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
      'A specification for cryptographic identity and content proof. It defines how Ed25519 signed chains, content-addressed CIDs, and W3C DIDs work together to create verifiable identity and content — independent of any particular platform, infrastructure, or trust assumption.',
  },
  {
    question: 'What problem does it solve?',
    answer:
      'Platform identity is platform-controlled. If a service shuts down or locks your account, your identity and content history disappear with it. The DFOS Protocol makes identity and content provenance self-sovereign — derived from cryptographic keys you control, verifiable by anyone with your public key and any standard EdDSA library.',
  },
  {
    question: 'What does "dark forest" mean in this context?',
    answer:
      'The internet is a dark forest — most meaningful creative and social activity happens in private spaces, not on the public web. DFOS is designed for this reality. Content lives in private, member-governed spaces. The cryptographic proof layer is the only public surface: signed commitments that anyone can verify, without revealing the content itself. The proof is public. The content is private.',
  },
  {
    question: 'Do I need to run a server or connect to a network?',
    answer:
      'No. Verification is offline and self-contained. A signed chain carries everything needed to verify it — public keys, signatures, content-addressed hashes. There is no registry to query, no blockchain to sync, no API to call. Given a chain and a public key, any standard Ed25519 library in any language can verify it.',
  },
  {
    question: 'What languages are supported?',
    answer:
      'The reference implementation is in TypeScript (available as @metalabel/dfos-protocol on npm). Cross-language verification implementations exist in Go, Python, Rust, and Swift — all verifying the same deterministic test vectors from the protocol specification.',
  },
  {
    question: 'How is this different from blockchain-based identity?',
    answer:
      'Blockchain identity systems anchor trust in a shared ledger — you need to sync with or query the chain to verify identity. The DFOS Protocol anchors trust in cryptographic signatures alone. There is no consensus layer, no gas fees, no chain state to maintain. Verification is a pure function: public key + signed chain → valid or invalid. This makes it simpler, faster, and fully transport-agnostic.',
  },
  {
    question: 'How does this compare to AT Protocol (Bluesky)?',
    answer:
      'AT Protocol and DFOS Protocol share some goals — self-sovereign identity, signed data, content-addressed storage — but differ in scope and architecture. AT Protocol is a full social networking protocol: it specifies data repositories, federation (BGS/PDS), application-level schemas (Lexicon), and the social graph. The DFOS Protocol is narrower by design — it specifies only the cryptographic primitives: signed chains, CID derivation, DID resolution, and verification rules. It is agnostic to transport, federation, and application semantics. Content semantics are a separate layer (see the Content Model).',
  },
  {
    question: 'How do identity chains relate to DIDs?',
    answer:
      'Every identity chain is also a DID. The DID (did:dfos:<hash>) is derived deterministically from the hash of the chain\'s genesis operation — making it self-certifying. Given the chain, anyone can verify that it belongs to the claimed DID without trusting the source. The DID method specification defines how did:dfos identifiers conform to the W3C DID standard.',
    answerHtml:
      'Every identity chain is also a DID. The DID (did:dfos:&lt;hash&gt;) is derived deterministically from the hash of the chain\'s genesis operation — making it self-certifying. Given the chain, anyone can verify that it belongs to the claimed DID without trusting the source. The DID method specification defines how did:dfos identifiers conform to the W3C DID standard.',
  },
  {
    question: 'Is the protocol coupled to the DFOS platform?',
    answer:
      'No. The protocol is independent. DFOS (the platform) is one implementation, but any system that implements the same chain primitives produces interoperable, cross-verifiable proofs. An identity created on one system can sign content on another. The protocol is MIT-licensed open source.',
  },
  {
    question: 'Is this production-ready?',
    answer:
      'The protocol specification is under active review and development. The TypeScript reference implementation is published and tested, with deterministic test vectors verified across five languages. The DFOS platform runs on this protocol in production. The specification has not been submitted to any formal standards body.',
  },
  {
    question: 'Where can I discuss the protocol?',
    answer:
      'The specification is open source on GitHub (metalabel/dfos). Protocol discussion happens in the clear.txt space on DFOS.',
  },
];

/** Serialize FAQ entries as markdown. */
export function faqsToMarkdown(entries: FaqEntry[]): string {
  const sections = entries.map((faq) => `## ${faq.question}\n\n${faq.answer}`);
  return ['# Frequently Asked Questions', '', ...sections].join('\n\n');
}
