# DFOS

DFOS is a private internet for creative groups — groupcore infrastructure to cooperate, create, and coordinate. Spaces, posts, chat, governance, identity, payments — built for groups that want to own their context and operate on their own terms.

The platform is closed. The math is open.

Underneath the social layer is a cryptographic protocol for verifiable identity and content. Ed25519 signed chains, content-addressed proofs, W3C DIDs. Every post, every profile, every piece of content on DFOS is backed by a chain of signed operations that can be verified offline, without trusting the platform, without accessing the database, without DFOS-specific tooling.

The inversion that makes this work: **the proof is public, the content is private.** The protocol layer only knows about keys and hashes. It doesn't see content. It proves that _this identity_ committed to _this exact content_ at _this time_, and that the commitment is part of an ordered, unforgeable sequence. The content stays in the dark forest. The math is in the light.

This repository contains the open-source protocol implementation and supporting packages.

## Packages

| Package                                                | Description                                                                         |
| ------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| [`@metalabel/dfos-protocol`](./packages/dfos-protocol) | Ed25519 signed chain primitives, identity and content verification, registry server |

## Links

- [clear.txt](https://clear.dfos.com) — the builder and cryptography space on DFOS
- [DFOS](https://dfos.com)

## License

[MIT](./LICENSE)
