export const overviewMarkdown = `# Overview

The DFOS Protocol specifies how [Ed25519 signed chains](https://protocol.dfos.com/spec) establish identity, commit content, and produce proofs that anyone can verify — with a public key and any standard signature library, offline, in any language. It is transport-agnostic: a proof obtained from an API, a USB drive, or a peer-to-peer exchange verifies the same way.

## Why This Exists

Identity on the internet is platform-granted. Your account, your content history, your social graph — all exist at the discretion of the service you're using. If the platform changes its rules, locks your account, or shuts down, your identity goes with it. This is structural, not a policy failure. The architecture of platform identity means someone else always holds the keys.

## Chain Topology

The protocol inverts this by deriving identity from cryptographic keys you control. An identity is a directed acyclic graph (DAG) of signed operations — key rotations, content commitments, recoveries, deletions — rooted at a genesis. Each operation links to its predecessor via content-addressed CID ([\`did:dfos\`](https://protocol.dfos.com/did-method) derives from the genesis hash, making it self-certifying).

Forks are valid. Two operations referencing the same predecessor both get accepted. All implementations converge to the same head via a deterministic rule: highest \`createdAt\` timestamp among tips, with lexicographic CID as tiebreaker. Given the same set of operations, any relay computes the same head regardless of ingestion order. Convergence without consensus.

Content chains use the same mechanics — signed commitments to content-addressed documents. The protocol sees document hashes, never documents. It doesn't know what a "post" or "profile" is. Application semantics live in a [separate content layer](https://protocol.dfos.com/content-model), free to evolve without protocol changes.

## Proof and Content

The internet is a dark forest — the most meaningful creative and social activity happens in private groups, closed communities, invite-only spaces. The protocol is designed for this topology.

Two surfaces: the proof surface is public — signed chains that anyone can verify. The content surface is private — documents live in member-governed spaces, visible only to participants. The protocol defines the proof surface. You can prove you authored something without revealing what it is.

## Relay Network

[Web relays](https://protocol.dfos.com/web-relay) are verifying HTTP endpoints that store and serve chains. Every relay independently verifies every operation on ingestion — relays don't trust each other or any central authority.

Three peering behaviors compose to form the network:

- **Gossip** — push new operations to peers when ingested (fire-and-forget, only on first ingestion to prevent storms)
- **Read-through** — fetch chains from peers on local cache miss
- **Sync** — periodically pull operations from peers via cursor-based polling

There are no relay roles, tiers, or hierarchy. Topology is emergent from per-peer configuration. A relay with only gossip enabled is a write-only edge node. One with only read-through is a read cache. Full peering creates a convergent mesh.

## Verification

Verification is a pure function. Given a chain and a public key, any Ed25519 implementation returns valid or invalid. The chain carries everything needed — public keys, signatures, content-addressed hashes. There is no registry to query, no blockchain to sync.

The reference implementation is in [TypeScript](https://www.npmjs.com/package/@metalabel/dfos-protocol). Cross-language verification exists in Go, Python, Rust, and Swift — all running against the same [deterministic test vectors](https://protocol.dfos.com/spec#deterministic-reference-artifacts) from the specification.

## Design Principles

- **Self-certifying.** Identity derives from cryptographic operations. The DID is a deterministic hash of the genesis operation.
- **DAG-native.** Chains are directed acyclic graphs. Forks are valid. Convergence is deterministic without consensus.
- **Transport-agnostic.** No privileged registry, blockchain, or API. Chains verify from any source.
- **Offline-first.** Verification requires no network. A chain exported today is verifiable by code that doesn't exist yet.
- **Protocol-only.** Signed chains, CID derivation, [DID resolution](https://protocol.dfos.com/did-method), merkle trees, beacons. Application semantics are a [separate concern](https://protocol.dfos.com/content-model).
- **Platform-independent.** Not coupled to the [DFOS platform](https://dfos.com). Any system implementing the same primitives produces interoperable proofs.

## Status

The specification is under active development. It is open source under the MIT license. The [CLI](https://protocol.dfos.com/cli) ships pre-built binaries for Linux, macOS, and Windows — installable via Homebrew, Docker, or a single curl command. Discussion happens in the [clear.txt](https://clear.dfos.com) space on DFOS.

Install the [CLI](https://protocol.dfos.com/cli) to create identities, sign content, and run relays locally. Read the [full specification](https://protocol.dfos.com/spec), explore the [FAQ](https://protocol.dfos.com/faq), or browse the [source on GitHub](https://github.com/metalabel/dfos).
`;
