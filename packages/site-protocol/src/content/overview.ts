export const overviewMarkdown = `# Overview

The DFOS Protocol is a system for proving identity and content authorship using cryptography alone — no platform trust, no network dependency, no shared ledger.

It specifies how Ed25519 signed chains establish identity, commit content, and produce proofs that anyone can verify with a public key and any standard signature library. The protocol is transport-agnostic: a proof obtained from an API, a file on a USB drive, or a peer-to-peer exchange all verify the same way.

## The Problem

Identity on the internet is platform-granted. Your account, your content history, your social graph — all exist at the discretion of the service you're using. If the platform changes its rules, locks your account, or shuts down, your identity goes with it.

This is a structural problem, not a policy problem. The architecture of platform identity means someone else always holds the keys.

## The Approach

The DFOS Protocol inverts this. Identity derives from cryptographic keys you control — not from a username on someone else's server. An identity is an append-only chain of signed operations: key rotations, content commitments, and state transitions. The chain is self-certifying — given the chain data, anyone can verify it belongs to the claimed \`did:dfos\` identifier without trusting the source.

Content works the same way. A content chain is a signed sequence of commitments to content-addressed documents. The protocol sees document hashes, not documents — it doesn't know what a "post" or "profile" is. Application semantics live in a separate content layer, free to evolve without protocol changes.

## The Dark Forest

The internet is a dark forest. The most meaningful creative and social activity doesn't happen on the public web — it happens in private groups, closed communities, invite-only spaces. DFOS is built for this topology.

Content lives in private, member-governed spaces — visible only to participants. The cryptographic proof layer is the only public surface: signed chains of commitments that anyone can independently verify. You can prove you authored something without revealing what it is.

*The proof is public. The content is private.*

## Verification Model

Verification is a pure function. Given a chain and a public key, any Ed25519 implementation in any language returns valid or invalid. No network call. No consensus check. No registry lookup. The chain carries everything needed to verify it.

The reference implementation is in TypeScript. Cross-language verification implementations exist in Go, Python, Rust, and Swift — all verifying the same deterministic test vectors from the protocol specification.

## Design Principles

- **Self-certifying.** Identity is derived from cryptographic operations, not granted by an authority. The DID is a deterministic hash of the genesis operation.
- **Transport-agnostic.** No privileged registry, blockchain, or API. Chains can be obtained and verified from any source.
- **Offline-first.** Verification requires no network. A chain exported today is verifiable by code that doesn't exist yet.
- **Protocol-only.** The spec defines cryptographic primitives — signed chains, CID derivation, DID resolution, merkle trees, beacons. Application semantics are a separate concern.
- **Platform-independent.** Not coupled to the DFOS platform. Any system implementing the same primitives produces interoperable, cross-verifiable proofs.

## Status

The protocol specification is under active review and development. It is open source under the MIT license. Discussion happens in the [clear.txt](https://clear.dfos.com) space on DFOS.

Read the [full specification](https://protocol.dfos.com/spec), explore the [FAQ](https://protocol.dfos.com/faq), or browse the [source on GitHub](https://github.com/metalabel/dfos).
`;
