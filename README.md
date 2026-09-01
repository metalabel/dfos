# DFOS

Your identity and content are rented back to you by the platforms that own it. The DFOS Protocol gives you back the keys.

An open protocol for cryptographic identity and verifiable content. Identity derives from Ed25519 signed operations, not platform accounts. Proofs verify offline, in any language, from any source. The proof is public; the content is access-controlled. The protocol commits to content hashes, never plaintext — it does not encrypt, and document confidentiality is enforced at the application layer (the relay operator that serves a space can read it; there is no end-to-end encryption).

The first thing it cleanly solves: a portable, rotation-capable signing identity for AI agents and devices — a `did:dfos` derives from a genesis operation and needs no external directory to resolve.

This repository contains the protocol specification, reference implementations in TypeScript and Go, cross-language verification suites, and the CLI.

## Packages

| Package                                                  | Language            | Description                                                                                                          |
| -------------------------------------------------------- | ------------------- | -------------------------------------------------------------------------------------------------------------------- |
| [`@metalabel/dfos-protocol`](./packages/dfos-protocol)   | TypeScript          | Ed25519 signed chain primitives, services, credentials, and verification                                             |
| [`dfos-protocol-go`](./packages/dfos-protocol-go)        | Go                  | Go protocol library — signing, verification, CID derivation, credentials                                             |
| [`@metalabel/dfos-web-relay`](./packages/dfos-web-relay) | TypeScript          | Portable HTTP relay — Hono app, any runtime                                                                          |
| [`@metalabel/dfos-client`](./packages/dfos-client)       | TypeScript          | High-level read client — resolve + verify orchestration over relays                                                  |
| [`dfos-web-relay-go`](./packages/dfos-web-relay-go)      | Go                  | Go relay — single binary, SQLite, built-in peering                                                                   |
| [`dfos-cli`](./packages/dfos-cli)                        | Go                  | The sovereign actor — keys, signing, relay interaction                                                               |
| [`protocol-verify`](./packages/protocol-verify)          | TS/Go/Py/Rust/Swift | Cross-language verification against shared test vectors                                                              |
| [`relay-conformance`](./packages/relay-conformance)      | Go                  | Integration tests against any live relay                                                                             |
| [`site-protocol`](./packages/site-protocol)              | Astro               | Static site for [protocol.dfos.com](https://protocol.dfos.com)                                                       |
| [`site-schemas`](./packages/site-schemas)                | Hono                | Worker for [schemas.dfos.com](https://schemas.dfos.com)                                                              |
| [`dfos-explorer`](./packages/dfos-explorer)              | TypeScript          | Client-side chain explorer at [explore.dfos.com](https://explore.dfos.com) — re-verifies untrusted relays in the tab |
| [`siwd-demo`](./examples/siwd-demo)                      | TypeScript          | Complete Sign In With DFOS relying party — live at [dfos-siwd-demo.vercel.app](https://dfos-siwd-demo.vercel.app)    |

## Links

- [Set up Sign In With DFOS](https://docs.dfos.com/docs/developers/sign-in-with-dfos/setup) — task-oriented guide to adding DFOS sign-in to your app; the specs below are the normative layer
- [Protocol specification](https://protocol.dfos.com/spec) — core protocol with worked examples and test vectors
- [DID Method](https://protocol.dfos.com/did-method) — W3C DID method specification for `did:dfos`
- [Content Model](https://protocol.dfos.com/content-model) — standard JSON Schema content types
- [Credentials](https://protocol.dfos.com/credentials) — UCAN-style authorization, linear delegation, revocation
- [Credits](https://protocol.dfos.com/credits) — verifiable attribution: signed credit claims bound to the content they credit
- [Sign In With DFOS](https://protocol.dfos.com/siwd) — cryptographic identity verification for third-party applications
- [Signing](https://protocol.dfos.com/signing) — transport-agnostic requests for DFOS signatures
- [API Authentication](https://protocol.dfos.com/api-auth) — proof-of-possession authentication for credential-gated HTTP APIs
- [Origin Binding](https://protocol.dfos.com/origin-binding) — bidirectional binding between a `did:dfos` and a web domain
- [Relay Contract](https://protocol.dfos.com/relay-contract) — the frozen relay wire surface: routes, shapes, pagination
- [Web Relay](https://protocol.dfos.com/web-relay) — reference relay behavior: ingestion, peering, and the content plane
- [Extension Registry](https://protocol.dfos.com/extensions) — the index of registered service types and JWS `typ` values
- [Threat Model](https://protocol.dfos.com/threat-model) — adversary classes and the trustless-proof / honest-host split
- [Conformance](https://protocol.dfos.com/conformance) — tiered conformance definition and self-certification
- [JSON Schemas](https://schemas.dfos.com) — hosted schema definitions for DFOS documents

## Specification status

Each spec declares its own clock in its header; this table is the index, not the authority.

| Spec                                        | Clock / status                                                     |
| ------------------------------------------- | ------------------------------------------------------------------ |
| [PROTOCOL](./specs/PROTOCOL.md)             | **v1 — frozen**, not yet final                                     |
| [RELAY-CONTRACT](./specs/RELAY-CONTRACT.md) | **Frozen with v1** — the relay wire surface                        |
| [WEB-RELAY](./specs/WEB-RELAY.md)           | Reference relay behavior, own `0.x` clock                          |
| [DID-METHOD](./specs/DID-METHOD.md)         | **v1 — frozen**                                                    |
| [CREDENTIALS](./specs/CREDENTIALS.md)       | **v1 — frozen**                                                    |
| [CONTENT-MODEL](./specs/CONTENT-MODEL.md)   | Encoding rule frozen with v1; schema vocabulary on its own `0.x`   |
| [CREDITS](./specs/CREDITS.md)               | Settled — additive capability on v1                                |
| [SIGNING](./specs/SIGNING.md)               | `0.1` — optional capability, own `0.x` clock                       |
| [SIWD](./specs/SIWD.md)                     | `0.1` — optional authentication seam, own `0.x` clock              |
| [API-AUTH](./specs/API-AUTH.md)             | `0.1` — optional capability, own `0.x` clock                       |
| [ORIGIN-BINDING](./specs/ORIGIN-BINDING.md) | `0.1` — optional capability, own `0.x` clock                       |
| [KEY-PROOF](./specs/KEY-PROOF.md)           | Envelope shares the protocol's v1 clock; ceremony on its own `0.x` |
| [EXTENSIONS](./specs/EXTENSIONS.md)         | Companion — indexes registered names, defines no rules             |
| [THREAT-MODEL](./specs/THREAT-MODEL.md)     | Companion — assembles specified surface, defines no rules          |
| [CONFORMANCE](./specs/CONFORMANCE.md)       | Companion — tiers over the normative MUST sets, defines no rules   |

- [Chain verifier](https://verify.dfos.com) — browser-based chain verification tool
- [Chain explorer](https://explore.dfos.com) — client-side, verify-in-tab
- [DFOS app](https://app.dfos.com) — the platform
- [npm packages](https://www.npmjs.com/package/@metalabel/dfos-protocol) — `@metalabel/dfos-protocol`, [`@metalabel/dfos-web-relay`](https://www.npmjs.com/package/@metalabel/dfos-web-relay), [`@metalabel/dfos-client`](https://www.npmjs.com/package/@metalabel/dfos-client)
- [`@metalabel/dfos-api`](https://github.com/metalabel/dfos-api) — typed TypeScript SDK for [api.dfos.com](https://api.dfos.com), generated from the live OpenAPI spec (separate repository)
- [DFOS](https://nce.dfos.com) — the builder and cryptography space
- [dfos.com](https://dfos.com)

## License

[MIT](./LICENSE)
