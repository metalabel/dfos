export const overviewMarkdown = `# Why This Exists

Not everything needs to be public to be verifiable.

Some work is published for everyone. Some is shared with a few collaborators, a membership, or a private group. That choice should not decide whether the work's signed history can be checked independently.

The DFOS Protocol separates the record from its delivery. A signed commitment circulates without the document it names. An application checks a signature without asking the original host to vouch for it. A reader who does receive the document checks that the bytes match the commitment.

The purpose is not to eliminate hosting. It is to make hosting a service rather than the only place the evidence can be examined.

## Identity That Continues

A DFOS identity begins with a signed operation, not a registration in a directory. The [\`did:dfos\`](https://protocol.dfos.com/did-method) identifier derives from that genesis operation, so re-deriving it from the chain is the check: a chain that does not derive the identifier it claims is rejected, whatever served it. Later operations change the identity's keys and services without changing the identifier, and every key that resolves proves possession of itself, bound to its role and its position in the chain.

An application verifies a [sign-in](https://protocol.dfos.com/integrations) against that signed history rather than against an account at one host. A domain you control can point to the identity, with a matching claim recorded on the identity itself.

The reference platform holds a signing key for every account by default, so ordinary use needs no key management. You can add keys the platform never holds. A controller key you hold is a fork right: from the last operation it controlled, you can continue the same identity on another relay, and who follows you there is a choice of relay. Any controller key can change the key set, the platform's included, and every change is a signed operation on the chain where anyone reading it can see it.

## Permissions You Can Delegate

Authorization is a signed [credential](https://protocol.dfos.com/credentials), not a session at one service. A credential names the identity it authorizes and the resources and actions it covers. Delegation is linear and narrowing: each hop can drop resources, drop actions, and shorten expiry, and it can never widen what it was given.

For credential-gated API calls, the recipient proves possession of its own key and binds that proof to the particular request, so a captured credential authorizes nothing without the audience key. A credential expires at the time it names and can be revoked before then, and a verifier enforces a revocation once it holds it.

## Where the Guarantee Stops

Verification establishes who signed a record and whether a document matches its commitment. It does not establish that a signed claim is true: the chain shows what was signed, never who was at the keyboard.

An identity chain is linear per view. A relay admits the first successor it sees at a position and refuses later ones, nothing in this corpus arbitrates between relays that admitted different successors, and which relay you read is which view you get. A signature proves who signed, forever, from anywhere. Whether a key is still effective, and what the head is, are statements about the freshest state a relay has.

The protocol does not encrypt. A relay operator reads every blob it stores, and nothing obliges any relay to keep your chain: keep your own copies of your chain and your documents. [Guarantees](https://protocol.dfos.com/guarantees) states the full boundary in one page.

### Privacy Considerations

The public record contains signed commitments and identity metadata. It does not need to contain the underlying document.

The protocol commits to a document via an unsalted \`dag-cbor\` → SHA-256 CID. The commitment binds; it does not hide. Anyone holding the CID can test a candidate document against it and learn whether the guess was right, so a document drawn from a small or guessable space is not confidential against a party that holds its CID, and two chains that committed the same bytes are visibly the same bytes. Confidentiality of the documents themselves is enforced above the protocol, by whoever serves them. There is no end-to-end encryption here, and the security posture of a document is the security posture of the party serving it.

## The Dark Forest

The internet is not a public square. Much of the creative and social coordination that matters happens in private groups, closed communities, and invite-only spaces. That is where real work gets done, real relationships form, and real culture develops. The topology is private-first.

A design in which proof and content travel together does not serve that topology: to check a piece of content you generally have to be able to read it. DFOS separates them. The proof plane is public — signed chains carrying identity, signed attribution, and the hash of every document committed, verifiable by anyone holding a copy. The content plane is the documents, served by whoever holds the bytes under that host's own access control, and they do not travel with the proofs.

This separation is architectural, not a privacy setting. It is an engineering response to the structural condition of where the internet actually lives.

## What the Protocol Is

The DFOS Protocol specifies how [Ed25519 signed chains](https://protocol.dfos.com/spec) establish identity, commit documents, and produce proofs. It defines [identifiers derived from a genesis operation](https://protocol.dfos.com/did-method) (\`did:dfos\`), [content-addressed commitments](https://protocol.dfos.com/content-model) via CID, and a [relay network](https://protocol.dfos.com/relay) of verifying HTTP endpoints that each re-verify what they distribute. Which view of an identity you follow is a choice of relay.

Identity chains carry an optional discovery vocabulary: controller-signed \`services\` that say where to reach an identity and what stable content it anchors, projected into verified identity state alongside its keys. Witnesses can attach a standalone countersignature to any CID-addressable operation, carrying an optional open-namespace \`relation\` tag (\`endorses\`, \`coauthors\`, \`witnessed\`) that names the nature of the attestation.

Verification is a function of the chains. A signed chain, the identity chains it names, and the revocations the verifier holds give valid or invalid. The signature check is one step of that: a verifier also needs canonical \`dag-cbor\` encoding, SHA-256, the identifier derivation, the chain rules, and, where authorization applies, the delegation walk. Standard cryptographic components are enough, and no DFOS software is required. There is no registry to query and no blockchain to sync.

The reference implementation is in [TypeScript](https://www.npmjs.com/package/@metalabel/dfos-protocol). Cross-language verification exists in Go, Python, Rust, and Swift, all running against the same [deterministic test vectors](https://protocol.dfos.com/spec#reference-vectors) from the specification.

## What It Isn't

- **Not a social protocol.** No federation model, no feeds, no application semantics. The protocol operates on keys and document hashes. [Application semantics](https://protocol.dfos.com/content-model) are a separate concern, free to evolve without protocol changes.
- **Not a blockchain.** No consensus layer, no gas fees, no chain state to sync. Content-chain forks are valid, and convergence is deterministic without coordination: highest \`createdAt\` timestamp among tips, with lexicographic CID as tiebreaker.
- **Not an encryption system.** Privacy comes from separation, not obscurity. The proof plane is fully public. The content plane is governed by application-layer access control. The protocol does not encrypt anything.
- **Not coupled to the DFOS platform.** [DFOS](https://dfos.com) is one implementation. Any system implementing the same chain primitives produces interoperable, cross-verifiable proofs.

## Design Principles

- **The identifier derives from the chain.** A DID is a deterministic hash of the genesis operation, so re-deriving it is the check. No external authority is needed to resolve it.
- **Forks exactly where a merge exists.** Content chains are directed acyclic graphs, so forks are valid and convergence is deterministic without consensus: given the same set of operations, any relay computes the same head regardless of ingestion order. Identity chains are linear per view. Key state has no merge function, so a relay keeps its own log linear by first-seen admission, and two relays that admitted different operations at one position hold two views of the same identity.
- **Transport-agnostic.** No privileged registry, blockchain, or API. A proof obtained from an API, a USB drive, or a peer-to-peer exchange verifies the same way.
- **Offline-first.** Verification requires no network. The chain carries everything needed.
- **Protocol-only.** Signed chains, CID derivation, [DID resolution](https://protocol.dfos.com/did-method), credentials, countersignatures. Application semantics are a [separate concern](https://protocol.dfos.com/content-model).

## Status

The specification iterates in place and carries the version of the release it ships with. The cross-language test vectors ship with each release, and every implementation is checked against them. It is open source under the [MIT license](https://github.com/metalabel/dfos/blob/main/LICENSE). The DFOS platform runs on it in production. It has not been submitted to a standards body.

The executable suites in [\`packages/protocol-verify\`](https://github.com/metalabel/dfos/tree/main/packages/protocol-verify) and [\`packages/relay-conformance\`](https://github.com/metalabel/dfos/tree/main/packages/relay-conformance) are the conformance definition. The [CLI](https://protocol.dfos.com/cli) ships pre-built binaries for Linux, macOS, and Windows, installable via Homebrew, Docker, or a single curl command.

Discussion happens in the [DFOS](https://nce.dfos.com) space. Read the [full specification](https://protocol.dfos.com/spec), read what the protocol [guarantees and does not](https://protocol.dfos.com/guarantees), explore the [FAQ](https://protocol.dfos.com/faq), or browse the [source on GitHub](https://github.com/metalabel/dfos).

## How It Compares

**Blockchain identity** systems anchor trust in a shared ledger: verifying an identity means syncing with or querying the chain. The DFOS Protocol anchors trust in cryptographic signatures alone, with no consensus layer, no gas fees, and no chain state to maintain. Verification is a function of the chains rather than of ledger state, and content-chain forks converge deterministically without coordination, which makes the protocol simpler, faster, and fully transport-agnostic.

**Public-by-default social protocols** (AT Protocol, nostr, Farcaster) publish posts and profiles as public documents, and to verify a piece of content you generally have to be able to read it. The proof and the content travel together. The DFOS Protocol inverts this: the proof plane is the only public surface, and the documents are served by whoever holds the bytes, under that host's own access control.

**AT Protocol** (Bluesky) shares foundations with DFOS — signed data, content-addressed storage, DIDs — but differs in topology, as above, and in identity resolution. An AT Protocol \`did:plc\` resolves through plc.directory, a registry Bluesky operates, whereas a \`did:dfos\` derives from its genesis operation and needs no external directory to resolve. AT Protocol is also a full social networking protocol, with federation, data repositories, and application schemas, where the DFOS Protocol is narrower by design: cryptographic primitives only, agnostic to transport, federation, and application semantics.
`;
