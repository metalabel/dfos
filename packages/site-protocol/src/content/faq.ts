import { CLI_PLATFORMS } from './specs';

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
      'An open protocol for cryptographic identity and verifiable content. Ed25519 signed chains establish identity, commit content, and produce proofs that anyone can verify — offline, in any language, from any source. No platform, no blockchain, no trust assumption. Identity chains are strictly linear logs; content chains are directed acyclic graphs (DAGs) that converge deterministically across implementations without consensus.',
    answerHtml:
      'An open protocol for cryptographic identity and verifiable content. <a href="/spec">Ed25519 signed chains</a> establish identity, commit content, and produce proofs that anyone can verify — offline, in any language, from any source. No platform, no blockchain, no trust assumption. Identity chains are strictly linear logs; content chains are directed acyclic graphs (DAGs) that converge deterministically across implementations without consensus.',
  },
  {
    question: 'What problem does it solve?',
    answer:
      'Your identity and content are rented back to you by the platforms that own them. If a service shuts down or locks your account, everything disappears. The DFOS Protocol makes identity and content provenance self-sovereign — derived from cryptographic keys you control, verifiable by anyone with your public key and any standard EdDSA library.',
  },
  {
    question: 'What does "dark forest" mean in this context?',
    answer:
      'The internet is a dark forest — most meaningful creative and social activity happens in access-controlled spaces, not on the public web. DFOS is designed for this reality: content lives in member-governed spaces, undisclosed by default, and the cryptographic proof layer is the only public surface. The proof is public; the content is access-controlled. The design and its limits — the protocol commits to content hashes and does not encrypt — are covered in Why and the Threat Model.',
    answerHtml:
      'The internet is a dark forest — most meaningful creative and social activity happens in access-controlled spaces, not on the public web. DFOS is designed for this reality: content lives in member-governed spaces, undisclosed by default, and the cryptographic proof layer is the only public surface. The proof is public; the content is access-controlled. The design and its limits — the protocol commits to content hashes and does not encrypt — are covered in <a href="/overview">Why</a> and the <a href="/threat-model">Threat Model</a>.',
  },
  {
    question: 'How do chains handle forks and conflicts?',
    answer:
      'It depends on the chain kind, and forks are permitted exactly where a merge function exists. Content chains are DAGs that converge to the same head deterministically on every implementation, with no consensus protocol; identity chains are strictly linear, and a conflicting extension is refused rather than arbitrated. The Protocol Specification defines the convergence rule, and Web Relay defines order authority for identity chains.',
    answerHtml:
      'It depends on the chain kind, and forks are permitted exactly where a merge function exists. Content chains are DAGs that converge to the same head deterministically on every implementation, with no consensus protocol; identity chains are strictly linear, and a conflicting extension is refused rather than arbitrated. The <a href="/spec">Protocol Specification</a> defines the convergence rule, and <a href="/web-relay">Web Relay</a> defines order authority for identity chains.',
  },
  {
    question: 'How does the relay network work?',
    answer:
      'Web relays are verifying HTTP endpoints that store and serve chains: every relay independently re-verifies every operation, no relay trusts another, and topology emerges from per-peer configuration rather than roles or hierarchy. The Web Relay specification defines the peering behaviors, the routes, and the DID resolver.',
    answerHtml:
      'Web relays are verifying HTTP endpoints that store and serve chains: every relay independently re-verifies every operation, no relay trusts another, and topology emerges from per-peer configuration rather than roles or hierarchy. The <a href="/web-relay">Web Relay specification</a> defines the peering behaviors, the routes, and the DID resolver.',
  },
  {
    question: 'Do I need to run a server or connect to a network?',
    answer:
      'No. Verification is offline and self-contained. A signed chain carries everything needed to verify it — public keys, signatures, content-addressed hashes. There is no registry to query, no blockchain to sync, no API to call. Given a chain and a public key, any standard Ed25519 library in any language can verify it. Relays are useful for storage and distribution, but verification never depends on them.',
  },
  {
    question: 'What languages are supported?',
    answer: `The reference implementation is in TypeScript (available as @metalabel/dfos-protocol on npm). Cross-language verification implementations exist in Go, Python, Rust, and Swift — all verifying the same deterministic test vectors from the protocol specification. The CLI is written in Go with pre-built binaries for ${CLI_PLATFORMS} — installable via Homebrew, curl, or Docker.`,
    answerHtml: `The reference implementation is in TypeScript (available as <a href="https://www.npmjs.com/package/@metalabel/dfos-protocol">@metalabel/dfos-protocol</a> on npm). Cross-language verification implementations exist in Go, Python, Rust, and Swift — all verifying the same deterministic test vectors from the <a href="/spec">protocol specification</a>. The <a href="/cli">CLI</a> is written in Go with pre-built binaries for ${CLI_PLATFORMS} — installable via Homebrew, curl, or Docker.`,
  },
  {
    question: 'How is this different from blockchain-based identity?',
    answer:
      'Blockchain identity systems anchor trust in a shared ledger — you need to sync with or query the chain to verify identity. The DFOS Protocol anchors trust in cryptographic signatures alone. There is no consensus layer, no gas fees, no chain state to maintain. Verification is a pure function: public key + signed chain = valid or invalid. Content-chain forks converge deterministically without coordination. This makes it simpler, faster, and fully transport-agnostic.',
  },
  {
    question: 'How does this compare to AT Protocol (Bluesky)?',
    answer:
      'AT Protocol and DFOS Protocol share foundations — self-sovereign identity, signed data, content-addressed storage, DIDs — but differ in topology. AT Protocol is public-by-default: your data repository is a public document, posts are visible to the network, and federation relays ingest content openly. The DFOS Protocol inverts this. Content is access-controlled — it lives in member-governed spaces, undisclosed by default and served only to participants. The cryptographic proof layer is the only public surface. This is an architectural choice, not a privacy setting (the protocol does not encrypt; confidentiality is enforced by whoever serves the space). Identity resolution also differs: an AT Protocol did:plc is resolved through plc.directory, a registry Bluesky operates, whereas a did:dfos derives from its genesis operation and needs no external directory to resolve. AT Protocol is also a full social networking protocol (federation, data repositories, application schemas); the DFOS Protocol is narrower by design — cryptographic primitives only, agnostic to transport, federation, and application semantics.',
    answerHtml:
      'AT Protocol and DFOS Protocol share foundations — self-sovereign identity, signed data, content-addressed storage, DIDs — but differ in topology. AT Protocol is public-by-default: your data repository is a public document, posts are visible to the network, and federation relays ingest content openly. The DFOS Protocol inverts this. Content is access-controlled — it lives in member-governed spaces, undisclosed by default and served only to participants. The cryptographic proof layer is the only public surface. This is an architectural choice, not a privacy setting (the protocol does not encrypt; confidentiality is enforced by whoever serves the space). Identity resolution also differs: an AT Protocol <code>did:plc</code> is resolved through plc.directory, a registry Bluesky operates, whereas a <code>did:dfos</code> derives from its genesis operation and needs no external directory to resolve. AT Protocol is also a full social networking protocol (federation, data repositories, application schemas); the DFOS Protocol is narrower by design — cryptographic primitives only, agnostic to transport, federation, and application semantics.',
  },
  {
    question: 'How do identity chains relate to DIDs?',
    answer:
      "Every identity chain is also a DID. The DID (did:dfos:<hash>) is derived deterministically from the hash of the chain's genesis operation — making it self-certifying. Given the chain, anyone can verify that it belongs to the claimed DID without trusting the source. The DID method specification defines how did:dfos identifiers conform to the W3C DID standard.",
    answerHtml:
      'Every identity chain is also a DID. The DID (did:dfos:&lt;hash&gt;) is derived deterministically from the hash of the chain\'s genesis operation — making it self-certifying. Given the chain, anyone can verify that it belongs to the claimed DID without trusting the source. The <a href="/did-method">DID method specification</a> defines how did:dfos identifiers conform to the W3C DID standard.',
  },
  {
    question: 'Can a third-party application log people in with their DFOS identity?',
    answer:
      "Yes — that is Sign In With DFOS: the application mints a challenge, a key from the user's identity chain signs it, and the application verifies the signature against the chain resolved from any relay — pure crypto for that check, no DFOS server in the loop. Scopes that return a credential add a second, explicitly server-side surface: the credential gates requests to the issuing platform's API. The SIWD specification defines the challenge, the two couriers, and the verification rules; API Authentication defines the gated-request side.",
    answerHtml:
      'Yes — that is <a href="/siwd">Sign In With DFOS</a>: the application mints a challenge, a key from the user\'s identity chain signs it, and the application verifies the signature against the chain resolved from any relay — pure crypto for that check, no DFOS server in the loop. Scopes that return a credential add a second, explicitly server-side surface: the credential gates requests to the issuing platform\'s API. The SIWD specification defines the challenge, the two couriers, and the verification rules; <a href="/api-auth">API Authentication</a> defines the gated-request side.',
  },
  {
    question: "Can an application call a DFOS API on the user's behalf?",
    answer:
      "Yes — with a credential issued at Sign In With DFOS consent and a per-request proof of possession signed by the application's own key. A captured credential is useless as a bearer token, and the resource form api:<host> lets any deployment gate itself the same way. API Authentication defines the proof envelope and the verification algorithm.",
    answerHtml:
      'Yes — with a credential issued at <a href="/siwd">Sign In With DFOS</a> consent and a per-request proof of possession signed by the application\'s own key. A captured credential is useless as a bearer token, and the resource form <code>api:&lt;host&gt;</code> lets any deployment gate itself the same way. <a href="/api-auth">API Authentication</a> defines the proof envelope and the verification algorithm.',
  },
  {
    question: 'Is the protocol coupled to the DFOS platform?',
    answer:
      'No. The protocol is independent. DFOS (the platform) is one implementation, but any system that implements the same chain primitives produces interoperable, cross-verifiable proofs. An identity created on one system can sign content on another. The protocol is MIT-licensed open source.',
    answerHtml:
      'No. The protocol is independent. <a href="https://dfos.com">DFOS</a> (the platform) is one implementation, but any system that implements the same chain primitives produces interoperable, cross-verifiable proofs. An identity created on one system can sign content on another. The protocol is <a href="https://github.com/metalabel/dfos/blob/main/LICENSE">MIT-licensed</a> open source.',
  },
  {
    question: 'How do I inspect a chain without installing anything?',
    answer:
      'explore.dfos.com is a chain explorer that runs entirely in the browser tab. It reads from relays but trusts none of them: every operation it displays is re-verified client-side — CIDs re-derived, signatures re-checked, the chain re-folded — so what you see is what your own browser proved, not what a relay asserted. The explorer is MIT-licensed and in this repository; it is deployed rather than published to npm.',
    answerHtml:
      '<a href="https://explore.dfos.com">explore.dfos.com</a> is a chain explorer that runs entirely in the browser tab. It reads from relays but trusts none of them: every operation it displays is re-verified client-side — CIDs re-derived, signatures re-checked, the chain re-folded — so what you see is what your own browser proved, not what a relay asserted. The explorer is <a href="https://github.com/metalabel/dfos/tree/main/packages/dfos-explorer">MIT-licensed and in this repository</a>; it is deployed rather than published to npm.',
  },
  {
    question: 'What do I use to read and verify chains from my own application?',
    answer:
      '@metalabel/dfos-client, the client-side kit for participating in the protocol — resolve, verify, prove — over an untrusted set of relays, with every cryptographic proof coming from @metalabel/dfos-protocol. It holds no keys: signing is always a callback the caller supplies. Its /siwd subpath carries the relying-party login kit, and its /api-auth subpath signs and verifies the per-request proofs for credential-gated APIs.',
    answerHtml:
      '<a href="https://www.npmjs.com/package/@metalabel/dfos-client">@metalabel/dfos-client</a>, the client-side kit for participating in the protocol — resolve, verify, prove — over an untrusted set of relays, with every cryptographic proof coming from @metalabel/dfos-protocol. It holds no keys: signing is always a callback the caller supplies. Its <code>/siwd</code> subpath carries the <a href="/siwd">relying-party login kit</a>, and its <code>/api-auth</code> subpath signs and verifies the per-request proofs for <a href="/api-auth">credential-gated APIs</a>.',
  },
  {
    question: 'Is this production-ready?',
    answer: `The protocol's v1 surface is feature-complete and frozen: the core wire is settled and will not change in shape, while the reference packages remain on their own 0.x release line. The TypeScript reference implementation is published and tested, with deterministic test vectors verified across five languages. The CLI ships pre-built binaries for ${CLI_PLATFORMS} via Homebrew, Docker, and direct download. The DFOS platform runs on this protocol in production. The specification has not been submitted to any formal standards body.`,
    answerHtml: `The <a href="/spec">protocol's v1 surface</a> is feature-complete and frozen: the core wire is settled and will not change in shape, while the reference <a href="https://www.npmjs.com/package/@metalabel/dfos-protocol">packages</a> remain on their own 0.x release line. The TypeScript reference implementation is published and tested, with deterministic test vectors verified across five languages. The <a href="/cli">CLI</a> ships pre-built binaries for ${CLI_PLATFORMS} via Homebrew, Docker, and direct download. The <a href="https://dfos.com">DFOS platform</a> runs on this protocol in production. The specification has not been submitted to any formal standards body.`,
  },
  {
    question: 'Where can I discuss the protocol?',
    answer:
      'The specification is open source on GitHub (metalabel/dfos). Protocol discussion happens in the DFOS space.',
    answerHtml:
      'The specification is open source on <a href="https://github.com/metalabel/dfos">GitHub</a>. Protocol discussion happens in the <a href="https://nce.dfos.com">DFOS</a> space.',
  },
];

/** Serialize FAQ entries as markdown. */
export function faqsToMarkdown(entries: FaqEntry[]): string {
  const sections = entries.map((faq) => `## ${faq.question}\n\n${faq.answer}`);
  return ['# Frequently Asked Questions', '', ...sections].join('\n\n');
}
