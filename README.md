# DFOS

The DFOS Protocol is a system for cryptographic identity and content proof. It specifies how identity chains, content chains, beacons, merkle trees, and verification work — independent of any particular platform, implementation, or infrastructure.

Identity derives from signed operations, not platform accounts. Proofs are self-contained — they verify offline, in any language, with no network dependency. A chain exported today is verifiable by code that may not even exist yet.

In the dark forest, identity and content authority derive from math alone. The proof is public. The content is private.

This repository contains the open-source protocol implementation and supporting packages.

## Packages

| Package                                                  | Language   | Description                                                              |
| -------------------------------------------------------- | ---------- | ------------------------------------------------------------------------ |
| [`@metalabel/dfos-protocol`](./packages/dfos-protocol)   | TypeScript | Ed25519 signed chain primitives, beacons, merkle trees, and verification |
| [`dfos-protocol-go`](./packages/dfos-protocol-go)        | Go         | Go protocol library — signing, verification, CID derivation, credentials |
| [`@metalabel/dfos-web-relay`](./packages/dfos-web-relay) | TypeScript | Portable HTTP relay with Go conformance test suite                       |
| [`dfos-cli`](./packages/dfos-cli)                        | Go         | CLI for managing identities, content, beacons, and relay interactions    |
| [`site-protocol`](./packages/site-protocol)              | Astro      | Static site for [protocol.dfos.com](https://protocol.dfos.com)           |
| [`site-schemas`](./packages/site-schemas)                | Hono       | Worker for [schemas.dfos.com](https://schemas.dfos.com)                  |

## Links

- [Protocol specification](https://protocol.dfos.com/spec) — core protocol with worked examples and test vectors
- [DID Method](https://protocol.dfos.com/did-method) — W3C DID method specification for `did:dfos`
- [Content Model](https://protocol.dfos.com/content-model) — standard JSON Schema content types
- [Architecture Poster](https://protocol.dfos.com/poster) — visual protocol architecture reference
- [JSON Schemas](https://schemas.dfos.com) — hosted schema definitions for DFOS documents
- [Chain verifier](https://verify.dfos.com) — browser-based chain verification tool
- [DFOS app](https://app.dfos.com) — the platform
- [npm package](https://www.npmjs.com/package/@metalabel/dfos-protocol) — `@metalabel/dfos-protocol`
- [clear.txt](https://clear.dfos.com) — the builder and cryptography space on DFOS
- [dfos.com](https://dfos.com)

## License

[MIT](./LICENSE)
