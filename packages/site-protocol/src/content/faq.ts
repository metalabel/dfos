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
