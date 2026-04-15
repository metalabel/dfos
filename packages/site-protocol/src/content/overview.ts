export const overviewMarkdown = `# Why This Exists

Identity on the internet is platform-granted. Your account, your content history, your social graph — all exist at the discretion of the service you're using. If the platform changes its rules, locks your account, or shuts down, your identity goes with it. This is structural, not a policy failure. The architecture of platform identity means someone else always holds the keys.

The DFOS Protocol inverts this. Identity derives from cryptographic keys you control. Content authorship is verifiable without trusting the source. Proofs survive the platform.

## The Dark Forest

The internet is not a public square. The most meaningful creative and social coordination happens in private groups, closed communities, invite-only spaces. This is where real work gets done, real relationships form, real culture develops. The topology is private-first.

Every existing protocol collapses proof and content into the same surface. If you can access the content, you can verify it. If you can't access the content, you can't verify anything about it. The proof and the content are the same artifact, served from the same place, gated by the same access control.

DFOS separates them.

The proof surface is public — signed chains of cryptographic commitments, verifiable by anyone with a public key and any standard Ed25519 library, offline, in any language. The content surface is private — documents live in member-governed spaces, visible only to participants. The protocol defines the proof surface. It sees hashes, never documents.

**You can prove you authored something without revealing what it is.**

This separation is architectural, not a privacy setting. It is an engineering response to the structural condition of where the internet actually lives.

## What the Protocol Is

The DFOS Protocol specifies how [Ed25519 signed chains](https://protocol.dfos.com/spec) establish identity, commit content, and produce proofs. It defines [self-certifying identifiers](https://protocol.dfos.com/did-method) (\`did:dfos\`) derived from genesis operations, [content-addressed commitments](https://protocol.dfos.com/content-model) via CID, and a [relay network](https://protocol.dfos.com/web-relay) of verifying HTTP endpoints that distribute proofs without trusting each other.

Verification is a pure function. Given a chain and a public key, any Ed25519 implementation returns valid or invalid. The chain carries everything needed — public keys, signatures, content-addressed hashes. There is no registry to query, no blockchain to sync. A proof exported today is verifiable by code that doesn't exist yet.

The reference implementation is in [TypeScript](https://www.npmjs.com/package/@metalabel/dfos-protocol). Cross-language verification exists in Go, Python, Rust, and Swift — all running against the same [deterministic test vectors](https://protocol.dfos.com/spec#deterministic-reference-artifacts) from the specification.

## What It Isn't

- **Not a social protocol.** No federation model, no feeds, no application semantics. The protocol operates on keys and document hashes. [Application semantics](https://protocol.dfos.com/content-model) are a separate concern, free to evolve without protocol changes.
- **Not a blockchain.** No consensus layer, no gas fees, no chain state to sync. Forks are valid. Convergence is deterministic without coordination — highest \`createdAt\` timestamp among tips, with lexicographic CID as tiebreaker.
- **Not an encryption system.** Privacy comes from separation, not obscurity. The proof surface is fully public. The content surface is governed by application-layer access control. The protocol doesn't encrypt anything.
- **Not coupled to the DFOS platform.** [DFOS](https://dfos.com) is one implementation. Any system implementing the same chain primitives produces interoperable, cross-verifiable proofs.

## Design Principles

- **Self-certifying.** Identity derives from cryptographic operations. The DID is a deterministic hash of the genesis operation. No external authority needed.
- **DAG-native.** Chains are directed acyclic graphs. Forks are valid. Convergence is deterministic without consensus. Given the same set of operations, any relay computes the same head regardless of ingestion order.
- **Transport-agnostic.** No privileged registry, blockchain, or API. A proof obtained from an API, a USB drive, or a peer-to-peer exchange verifies the same way.
- **Offline-first.** Verification requires no network. The chain carries everything needed.
- **Protocol-only.** Signed chains, CID derivation, [DID resolution](https://protocol.dfos.com/did-method), credentials, beacons. Application semantics are a [separate concern](https://protocol.dfos.com/content-model).

## Status

The specification is under active development. It is open source under the [MIT license](https://github.com/metalabel/dfos/blob/main/LICENSE). The [CLI](https://protocol.dfos.com/cli) ships pre-built binaries for Linux, macOS, and Windows — installable via Homebrew, Docker, or a single curl command. The [DFOS platform](https://dfos.com) runs on this protocol in production.

Discussion happens in the [clear.txt](https://clear.dfos.com) space on DFOS. Read the [full specification](https://protocol.dfos.com/spec), explore the [FAQ](https://protocol.dfos.com/faq), or browse the [source on GitHub](https://github.com/metalabel/dfos).
`;
