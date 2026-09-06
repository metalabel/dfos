export const overviewMarkdown = `# Why This Exists

Identity on the internet is granted by a platform. Your account, your content history, and your social graph live inside a service, and they are that service's to change or end. This is structural, not a policy failure: when the platform holds the only keys, it holds the identity.

The DFOS Protocol changes what the keys are. Identity derives from cryptographic keys, authorship is verifiable without trusting the source, and the proofs outlive the service that carried them. A platform can host your identity. It cannot own it.

## The Dark Forest

The internet is not a public square. The most meaningful creative and social coordination happens in private groups, closed communities, and invite-only spaces. That is where real work gets done, real relationships form, and real culture develops. The topology is private-first.

The major social protocols (AT Protocol, nostr, Farcaster) are public-by-default: posts and profiles are public documents, and to verify a piece of content you generally have to be able to read it. The proof and the content travel together.

DFOS separates them.

The reference platform holds a signing key for every account by default, so ordinary use needs no key management. You can add keys the platform never holds. A controller key you hold is a fork right: from the last operation it controlled, you can continue the same identity on another relay, and who follows you there is a choice of relay. The platform's default key is a controller key: it can change the key set, and every change is written to the chain where anyone can see it. What continues is the proof of your history, for anyone who kept a copy. The documents live wherever they were served.

The proof surface is public: signed chains of cryptographic commitments, verifiable by anyone with a public key and any standard Ed25519 library, offline, in any language. The content surface is access-controlled: documents live in member-governed spaces, undisclosed by default and served only to participants. The protocol defines the proof surface. It commits to content hashes, never the documents themselves.

**For high-entropy content, you can prove you authored something without revealing what it is.** The public chain carries only the CID, and the CID is the only thing the protocol exposes.

This separation is architectural, not a privacy setting. It is an engineering response to the structural condition of where the internet actually lives.

### Privacy Considerations

The protocol commits to content via an unsalted \`dag-cbor\` → SHA-256 CID. It does not encrypt documents and does not hide low-entropy content: anyone who can guess the document can recompute its CID and confirm the match, so the "prove without revealing" property holds only for content with enough entropy to be unguessable. Confidentiality of the underlying documents is enforced at the application layer by whoever serves the space. A relay operator can read what it stores, and there is no end-to-end encryption. The proof surface is undisclosed-by-default access control, not cryptographic secrecy. [Guarantees](https://protocol.dfos.com/guarantees) states the full boundary in one page.

## What the Protocol Is

The DFOS Protocol specifies how [Ed25519 signed chains](https://protocol.dfos.com/spec) establish identity, commit content, and produce proofs. It defines [self-certifying identifiers](https://protocol.dfos.com/did-method) (\`did:dfos\`) derived from genesis operations, [content-addressed commitments](https://protocol.dfos.com/content-model) via CID, and a [relay network](https://protocol.dfos.com/relay) of verifying HTTP endpoints that each re-verify what they distribute. Authorship is verifiable without trusting any server. Which view of an identity you follow is a choice of relay.

Identity chains carry an optional discovery vocabulary: controller-signed \`services\` that say where to reach an identity and what stable content it anchors, projected into verified identity state alongside its keys. Witnesses can attach a standalone countersignature to any CID-addressable operation, carrying an optional open-namespace \`relation\` tag (\`endorses\`, \`coauthors\`, \`witnessed\`) that names the nature of the attestation.

Verification is a pure function. Given a chain and a public key, any Ed25519 implementation returns valid or invalid. The chain carries everything needed: public keys, signatures, content-addressed hashes. There is no registry to query and no blockchain to sync.

The reference implementation is in [TypeScript](https://www.npmjs.com/package/@metalabel/dfos-protocol). Cross-language verification exists in Go, Python, Rust, and Swift, all running against the same [deterministic test vectors](https://protocol.dfos.com/spec#reference-vectors) from the specification.

## What It Isn't

- **Not a social protocol.** No federation model, no feeds, no application semantics. The protocol operates on keys and document hashes. [Application semantics](https://protocol.dfos.com/content-model) are a separate concern, free to evolve without protocol changes.
- **Not a blockchain.** No consensus layer, no gas fees, no chain state to sync. Content-chain forks are valid, and convergence is deterministic without coordination: highest \`createdAt\` timestamp among tips, with lexicographic CID as tiebreaker.
- **Not an encryption system.** Privacy comes from separation, not obscurity. The proof surface is fully public. The content surface is governed by application-layer access control. The protocol does not encrypt anything.
- **Not coupled to the DFOS platform.** [DFOS](https://dfos.com) is one implementation. Any system implementing the same chain primitives produces interoperable, cross-verifiable proofs.

## How It Compares

**Blockchain identity** systems anchor trust in a shared ledger: verifying an identity means syncing with or querying the chain. The DFOS Protocol anchors trust in cryptographic signatures alone, with no consensus layer, no gas fees, and no chain state to maintain. Verification is a pure function, public key plus signed chain yields valid or invalid, and content-chain forks converge deterministically without coordination, which makes the protocol simpler, faster, and fully transport-agnostic.

**AT Protocol** (Bluesky) shares foundations with DFOS (self-sovereign identity, signed data, content-addressed storage, DIDs) but differs in topology. AT Protocol is public-by-default: a data repository is a public document, posts are visible to the network, and federation relays ingest content openly. The DFOS Protocol inverts this, as described above: the proof surface is the only public surface, and that separation is an architectural choice, not a privacy setting. Identity resolution also differs. An AT Protocol \`did:plc\` resolves through plc.directory, a registry Bluesky operates, whereas a \`did:dfos\` derives from its genesis operation and needs no external directory to resolve. AT Protocol is also a full social networking protocol, with federation, data repositories, and application schemas, where the DFOS Protocol is narrower by design: cryptographic primitives only, agnostic to transport, federation, and application semantics.

## Design Principles

- **Self-certifying.** Identity derives from cryptographic operations. The DID is a deterministic hash of the genesis operation. No external authority needed.
- **Forks exactly where a merge exists.** Content chains are directed acyclic graphs, so forks are valid and convergence is deterministic without consensus: given the same set of operations, any relay computes the same head regardless of ingestion order. Identity chains are linear per view. Key state has no merge function, so a relay keeps its own log linear by first-seen admission, and two relays that admitted different operations at one position hold two views of the same identity.
- **Transport-agnostic.** No privileged registry, blockchain, or API. A proof obtained from an API, a USB drive, or a peer-to-peer exchange verifies the same way.
- **Offline-first.** Verification requires no network. The chain carries everything needed.
- **Protocol-only.** Signed chains, CID derivation, [DID resolution](https://protocol.dfos.com/did-method), credentials, countersignatures. Application semantics are a [separate concern](https://protocol.dfos.com/content-model).

## Status

The specification iterates in place and carries the version of the release it ships with. It is open source under the [MIT license](https://github.com/metalabel/dfos/blob/main/LICENSE). The DFOS platform runs on it in production. It has not been submitted to a standards body.

The executable suites in [\`packages/protocol-verify\`](https://github.com/metalabel/dfos/tree/main/packages/protocol-verify) and [\`packages/relay-conformance\`](https://github.com/metalabel/dfos/tree/main/packages/relay-conformance) are the conformance definition. The [CLI](https://protocol.dfos.com/cli) ships pre-built binaries for Linux, macOS, and Windows, installable via Homebrew, Docker, or a single curl command.

Discussion happens in the [DFOS](https://nce.dfos.com) space. Read the [full specification](https://protocol.dfos.com/spec), read what the protocol [guarantees and does not](https://protocol.dfos.com/guarantees), explore the [FAQ](https://protocol.dfos.com/faq), or browse the [source on GitHub](https://github.com/metalabel/dfos).
`;
