# DFOS

Your identity and content are rented back to you by the platforms that own it. The DFOS Protocol gives you back the keys.

An open protocol for cryptographic identity and verifiable content. Identity derives from Ed25519 signed operations, not platform accounts. Proofs verify offline, in any language, from any source. The proof is public. The content is private.

This repository contains the protocol specification, reference implementations in TypeScript and Go, cross-language verification suites, and the CLI.

## Packages

| Package                                                  | Language            | Description                                                              |
| -------------------------------------------------------- | ------------------- | ------------------------------------------------------------------------ |
| [`@metalabel/dfos-protocol`](./packages/dfos-protocol)   | TypeScript          | Ed25519 signed chain primitives, beacons, credentials, and verification  |
| [`dfos-protocol-go`](./packages/dfos-protocol-go)        | Go                  | Go protocol library — signing, verification, CID derivation, credentials |
| [`@metalabel/dfos-web-relay`](./packages/dfos-web-relay) | TypeScript          | Portable HTTP relay — Hono app, any runtime                              |
| [`dfos-web-relay-go`](./packages/dfos-web-relay-go)      | Go                  | Go relay — single binary, SQLite, built-in peering                       |
| [`dfos-cli`](./packages/dfos-cli)                        | Go                  | The sovereign actor — keys, signing, relay interaction                   |
| [`protocol-verify`](./packages/protocol-verify)          | TS/Go/Py/Rust/Swift | Cross-language verification against shared test vectors                  |
| [`relay-conformance`](./packages/relay-conformance)      | Go                  | Integration tests against any live relay                                 |
| [`site-protocol`](./packages/site-protocol)              | Astro               | Static site for [protocol.dfos.com](https://protocol.dfos.com)           |
| [`site-schemas`](./packages/site-schemas)                | Hono                | Worker for [schemas.dfos.com](https://schemas.dfos.com)                  |

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
