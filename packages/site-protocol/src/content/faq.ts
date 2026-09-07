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
      'An open protocol for identities, signed records, and delegated permissions that any compatible application can verify for itself. Signed chains establish identity, commit documents, and produce proofs anyone can verify offline, in any language, from any source. Authorship is verifiable without trusting any server. Which view of an identity you follow is a choice of relay.',
    answerHtml:
      'An open protocol for identities, signed records, and delegated permissions that any compatible application can verify for itself. <a href="/spec">Signed chains</a> establish identity, commit documents, and produce proofs anyone can verify offline, in any language, from any source. Authorship is verifiable without trusting any server. Which view of an identity you follow is a choice of relay.',
  },
  {
    question: 'Who holds my keys?',
    answer:
      "On the DFOS platform, the platform holds a signing key for your account by default. You can add keys it never holds, from Settings. The platform's default key is a controller key: it can change the key set, and every change is written to the chain where anyone can see it. Nothing the platform does can forge a signature from a key it does not hold. Guarantees states what custody buys and what it does not.",
    answerHtml:
      'On the <a href="https://dfos.com">DFOS platform</a>, the platform holds a signing key for your account by default. You can add keys it never holds, from Settings. The platform\'s default key is a controller key: it can change the key set, and every change is written to the chain where anyone can see it. Nothing the platform does can forge a signature from a key it does not hold. <a href="/guarantees">Guarantees</a> states what custody buys and what it does not.',
  },
  {
    question: 'What happens if the platform I use goes away?',
    answer:
      'Your identity chain and every proof in it are public and can be mirrored by anyone. With a controller key you hold, you continue the chain on another relay from the last operation that key controlled. Documents do not replicate with the proofs, and proofs survive only where a copy was kept: keep your own copies of your chain and your documents. Guarantees states the bounds of that continuity.',
    answerHtml:
      'Your identity chain and every proof in it are public and can be mirrored by anyone. With a controller key you hold, you continue the chain on another relay from the last operation that key controlled. Documents do not replicate with the proofs, and proofs survive only where a copy was kept: keep your own copies of your chain and your documents. <a href="/guarantees">Guarantees</a> states the bounds of that continuity.',
  },
  {
    question: 'How do chains handle forks and conflicts?',
    answer:
      'It depends on the chain kind, and forks are permitted exactly where a merge function exists. Content chains are DAGs that converge to the same head deterministically on every implementation, with no consensus protocol. An identity chain is linear per view: a relay admits the first successor it sees at a position and refuses later ones rather than arbitrating between them, so two relays can serve two views of one identity. The Protocol Specification defines the convergence rule and the view model, and the Relay specification defines relay admission.',
    answerHtml:
      'It depends on the chain kind, and forks are permitted exactly where a merge function exists. Content chains are DAGs that converge to the same head deterministically on every implementation, with no consensus protocol. An identity chain is linear per view: a relay admits the first successor it sees at a position and refuses later ones rather than arbitrating between them, so two relays can serve two views of one identity. The <a href="/spec">Protocol Specification</a> defines the convergence rule and the view model, and <a href="/relay">Relay</a> defines relay admission.',
  },
  {
    question: 'How does the relay network work?',
    answer:
      "A relay stores and serves chains and verifies every operation it admits. It keeps each identity's log linear by admitting the first successor it sees. Two relays that admitted different operations hold two views of the same identity, and which relay you read is which view you get. Peers exchange logs; nothing arbitrates between them. The Relay specification defines the routes, the admission rules, and the profiles a relay may serve.",
    answerHtml:
      'A relay stores and serves chains and verifies every operation it admits. It keeps each identity\'s log linear by admitting the first successor it sees. Two relays that admitted different operations hold two views of the same identity, and which relay you read is which view you get. Peers exchange logs; nothing arbitrates between them. The <a href="/relay">Relay specification</a> defines the routes, the admission rules, and the profiles a relay may serve.',
  },
  {
    question: 'Do I need to run a server or connect to a network?',
    answer:
      "No. Verification is offline and self-contained. A signed chain carries everything needed to verify it: public keys, signatures, content-addressed hashes. There is no registry to query, no blockchain to sync, no API to call. A verifier needs standard cryptographic components — an Ed25519 implementation, a dag-cbor encoder, and SHA-256 — plus the identifier derivation and the chain rules, and no DFOS software. Relays are useful for storage and distribution, and recovery is the one operation that needs one: recovering the identities a seed phrase controls asks a relay's key index which identities each derived key has been proved into.",
    answerHtml:
      'No. Verification is offline and self-contained. A signed chain carries everything needed to verify it: public keys, signatures, content-addressed hashes. There is no registry to query, no blockchain to sync, no API to call. A verifier needs standard cryptographic components — an Ed25519 implementation, a dag-cbor encoder, and SHA-256 — plus the identifier derivation and the chain rules, and no DFOS software. Relays are useful for storage and distribution, and recovery is the one operation that needs one: recovering the identities a seed phrase controls asks a <a href="/relay#index-capability-index">relay\'s key index</a> which identities each derived key has been proved into.',
  },
  {
    question: 'What languages are supported?',
    answer: `The reference implementation is in TypeScript (available as @metalabel/dfos-protocol on npm). Cross-language verification implementations exist in Go, Python, Rust, and Swift, all verifying the same deterministic test vectors from the protocol specification. The CLI is written in Go with pre-built binaries for ${CLI_PLATFORMS}, installable via Homebrew, curl, or Docker.`,
    answerHtml: `The reference implementation is in TypeScript (available as <a href="https://www.npmjs.com/package/@metalabel/dfos-protocol">@metalabel/dfos-protocol</a> on npm). Cross-language verification implementations exist in Go, Python, Rust, and Swift, all verifying the same deterministic test vectors from the <a href="/spec">protocol specification</a>. The <a href="/cli">CLI</a> is written in Go with pre-built binaries for ${CLI_PLATFORMS}, installable via Homebrew, curl, or Docker.`,
  },
  {
    question: 'How do identity chains relate to DIDs?',
    answer:
      "Every identity chain is also a DID. The DID (did:dfos:<hash>) is derived deterministically from the hash of the chain's genesis operation, which is what makes it self-certifying. Given the chain, anyone can verify that it belongs to the claimed DID without trusting the source. The DID method specification defines how did:dfos identifiers conform to the W3C DID standard.",
    answerHtml:
      'Every identity chain is also a DID. The DID (did:dfos:&lt;hash&gt;) is derived deterministically from the hash of the chain\'s genesis operation, which is what makes it self-certifying. Given the chain, anyone can verify that it belongs to the claimed DID without trusting the source. The <a href="/did-method">DID method specification</a> defines how did:dfos identifiers conform to the W3C DID standard.',
  },
  {
    question: 'Can a third-party application log people in with their DFOS identity?',
    answer:
      "Yes. That is Sign In With DFOS: the application mints a challenge, a key from the user's identity chain signs it, and the application verifies the signature against the chain resolved from any relay, which is pure cryptography with no DFOS server in that check. The signing side is a hosted authorization server: the application sends the person to the authorize endpoint their identity names, and that host signs the challenge with the key it holds for them. Scopes that return a credential add a second, explicitly server-side surface, where the credential gates requests to the issuing platform's API. The Integrations specification defines the challenge, the authorize path, the verification rules, and the gated-request side.",
    answerHtml:
      'Yes. That is <a href="/integrations#sign-in">Sign In With DFOS</a>: the application mints a challenge, a key from the user\'s identity chain signs it, and the application verifies the signature against the chain resolved from any relay, which is pure cryptography with no DFOS server in that check. The signing side is a hosted authorization server: the application sends the person to the <a href="/integrations#finding-the-authorize-endpoint">authorize endpoint their identity names</a>, and that host signs the challenge with the key it holds for them. Scopes that return a credential add a second, explicitly server-side surface, where the credential gates requests to the issuing platform\'s API. The <a href="/integrations">Integrations specification</a> defines the challenge, the authorize path, the verification rules, and the gated-request side.',
  },
  {
    question: "Can an application call a DFOS API on the user's behalf?",
    answer:
      "Yes, with a credential issued at Sign In With DFOS consent and a per-request proof of possession signed by the application's own key. A captured credential is useless as a bearer token, and the resource form api:<host> lets any deployment gate itself the same way. Integrations defines the proof envelope and the verification algorithm.",
    answerHtml:
      'Yes, with a credential issued at <a href="/integrations#sign-in">Sign In With DFOS</a> consent and a per-request proof of possession signed by the application\'s own key. A captured credential is useless as a bearer token, and the resource form <code>api:&lt;host&gt;</code> lets any deployment gate itself the same way. <a href="/integrations#api-authentication">API authentication</a> defines the proof envelope and the verification algorithm.',
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
      "explore.dfos.com is a chain explorer that runs entirely in the browser tab. Every operation it displays is re-verified client-side, with CIDs re-derived, signatures re-checked, and the chain re-folded, so the signatures and the commitments over the bytes a relay served are proved by your own browser rather than asserted. Which view is current is still the relay's: the head, the effective keys, and whether an identity is deleted are what the relay you read serves. The explorer is MIT-licensed and in this repository; it is deployed rather than published to npm.",
    answerHtml:
      '<a href="https://explore.dfos.com">explore.dfos.com</a> is a chain explorer that runs entirely in the browser tab. Every operation it displays is re-verified client-side, with CIDs re-derived, signatures re-checked, and the chain re-folded, so the signatures and the commitments over the bytes a relay served are proved by your own browser rather than asserted. Which view is current is still the relay\'s: the head, the effective keys, and whether an identity is deleted are what the relay you read serves. The explorer is <a href="https://github.com/metalabel/dfos/tree/main/packages/dfos-explorer">MIT-licensed and in this repository</a>; it is deployed rather than published to npm.',
  },
  {
    question: 'What do I use to read and verify chains from my own application?',
    answer:
      '@metalabel/dfos-client, the client-side kit for participating in the protocol (resolve, verify, prove) over an untrusted set of relays, with every cryptographic proof coming from @metalabel/dfos-protocol. It holds no keys: signing is always a callback the caller supplies. Its /siwd subpath carries the relying-party login kit, and its /api-auth subpath signs and verifies the per-request proofs for credential-gated APIs.',
    answerHtml:
      '<a href="https://www.npmjs.com/package/@metalabel/dfos-client">@metalabel/dfos-client</a>, the client-side kit for participating in the protocol (resolve, verify, prove) over an untrusted set of relays, with every cryptographic proof coming from @metalabel/dfos-protocol. It holds no keys: signing is always a callback the caller supplies. Its <code>/siwd</code> subpath carries the <a href="/integrations#sign-in">relying-party login kit</a>, and its <code>/api-auth</code> subpath signs and verifies the per-request proofs for <a href="/integrations#api-authentication">credential-gated APIs</a>.',
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
