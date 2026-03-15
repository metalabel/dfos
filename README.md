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
| [`site-protocol`](./packages/site-protocol)            | Astro site for [protocol.dfos.com](https://protocol.dfos.com)                       |
| [`site-schemas`](./packages/site-schemas)              | Hono worker for [schemas.dfos.com](https://schemas.dfos.com)                        |

## Links

- [Protocol specification](https://protocol.dfos.com/spec) — core protocol with worked examples and test vectors
- [DID Method](https://protocol.dfos.com/did-method) — W3C DID method specification for `did:dfos`
- [Content Model](https://protocol.dfos.com/content-model) — standard JSON Schema content types
- [Registry API](https://protocol.dfos.com/registry-api) — HTTP API for chain storage and resolution
- [JSON Schemas](https://schemas.dfos.com) — hosted schema definitions for DFOS documents
- [Chain verifier](https://verify.dfos.com) — browser-based chain verification tool
- [DFOS app](https://app.dfos.com) — the platform
- [npm package](https://www.npmjs.com/package/@metalabel/dfos-protocol) — `@metalabel/dfos-protocol`
- [clear.txt](https://clear.dfos.com) — the builder and cryptography space on DFOS
- [dfos.com](https://dfos.com)

## License

[MIT](./LICENSE)
