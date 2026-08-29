# DFOS Extension Registry

> **Status — companion document, no clock of its own.** This document defines no protocol rules; it is the single index of the names the specs register — service types under the core's open [services namespace](https://protocol.dfos.com/spec#services), and JWS `typ` values under the core's [`typ` convention](https://protocol.dfos.com/spec#typ-header). Each name's semantics live in its owner spec, which remains normative wherever the two could be read to disagree. A new name lands by adding its row here in the same PR that specifies it, never by minting locally ([CONTRIBUTING](https://github.com/metalabel/dfos/blob/main/CONTRIBUTING.md), item 2). Discuss in the [DFOS](https://nce.dfos.com) space.

## Service Types

The [services namespace](https://protocol.dfos.com/spec#services) is open: the two core types are structurally validated by every conformant verifier, and every other registered type is an opaque extension the core preserves verbatim and ignores — registering one requires no protocol or cross-language change. One row per type:

| Service `type`            | Owner spec                                                                                               | Validation | Semantics                                                                                                                              |
| ------------------------- | -------------------------------------------------------------------------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `DfosRelay`               | [PROTOCOL](https://protocol.dfos.com/spec#services)                                                      | core       | Transport locator — where to reach a relay serving this identity.                                                                      |
| `ContentAnchor`           | [PROTOCOL](https://protocol.dfos.com/spec#services)                                                      | core       | Stable content reference — a contentId or artifact CID under a client-defined semantic label.                                          |
| `DfosAuthorizationServer` | [SIWD](https://protocol.dfos.com/siwd#finding-the-authorize-endpoint--the-dfosauthorizationserver-entry) | consumer   | The canonical authorize origin able to produce this subject's signature under SIWD profile A.                                          |
| `DfosOrigin`              | [ORIGIN-BINDING](https://protocol.dfos.com/origin-binding)                                               | consumer   | The identity's claimed web domain — the chain half of the bidirectional origin binding.                                                |
| `DfosDocumentGateway`     | [WEB-RELAY](https://protocol.dfos.com/web-relay#discovery)                                               | consumer   | Base URL of a document gateway serving this identity's content.                                                                        |
| `DfosProfile`             | [WEB-RELAY](https://protocol.dfos.com/web-relay#discovery)                                               | consumer   | The identity's profile document — a contentId (living chain) or artifact CID (immutable snapshot), dispatched by shape as anchors are. |

**Validation** — `core`: structurally validated by every conformant verifier, and a malformed entry rejects at verification. `consumer`: opaque to the core (preserved verbatim, ignored); structural validation is an obligation of the owner spec's consumers. Everything else — ambiguity rules (`DfosOrigin` and `DfosAuthorizationServer`: one entry or none), field grammar, display discipline — is the owner spec's.

## JWS `typ` Values

Every DFOS JWS envelope is typ-scoped: the protected header names exactly one registered value, and a verifier rejects any `typ` other than the one the presented context requires — the gate that keeps a JWS signed for one purpose from ever being presented as another. The `cid` column marks whether the envelope carries the protocol's [`cid` header](https://protocol.dfos.com/spec#cid-header).

| `typ` value               | Owner spec                                            | `cid` | Semantics                                                                                                                     |
| ------------------------- | ----------------------------------------------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------- |
| `did:dfos:identity-op`    | [PROTOCOL](https://protocol.dfos.com/spec#typ-header) | yes   | Identity chain operations.                                                                                                    |
| `did:dfos:content-op`     | [PROTOCOL](https://protocol.dfos.com/spec#typ-header) | yes   | Content chain operations.                                                                                                     |
| `did:dfos:artifact`       | [PROTOCOL](https://protocol.dfos.com/spec#typ-header) | yes   | Standalone signed inline documents.                                                                                           |
| `did:dfos:countersign`    | [PROTOCOL](https://protocol.dfos.com/spec#typ-header) | yes   | Standalone witness attestations.                                                                                              |
| `did:dfos:credential`     | [CREDENTIALS](https://protocol.dfos.com/credentials)  | yes   | Authorization credentials — the `cid` is their revocation address.                                                            |
| `did:dfos:revocation`     | [CREDENTIALS](https://protocol.dfos.com/credentials)  | yes   | Credential revocation artifacts.                                                                                              |
| `did:dfos:credit-claim`   | [CREDITS](https://protocol.dfos.com/credits)          | yes   | Document-plane credit claims — registered for `typ` routing; never relay-ingested.                                            |
| `did:dfos:sign-request`   | [SIGNING](https://protocol.dfos.com/signing)          | yes   | Sign-request envelopes — travel the signing-mailbox courier, never `POST /proof/v1/operations`.                               |
| `did:dfos:siwd`           | [SIWD](https://protocol.dfos.com/siwd)                | no    | Sign In With DFOS challenge proofs — delivered by web redirect or the signing mailbox; never relay-ingested.                  |
| `did:dfos:siwd-ask`       | [SIWD](https://protocol.dfos.com/siwd#the-ask-proof)  | no    | Loopback client ask proofs — the client's key-control proof over its own authorize request.                                   |
| `did:dfos:request-proof`  | [API-AUTH](https://protocol.dfos.com/api-auth)        | no    | API request proofs — ride the `Authorization` header of a credential-gated API request and die with the freshness window.     |
| `did:dfos:identity-proof` | [API-AUTH](https://protocol.dfos.com/api-auth)        | no    | API identity proofs — the request proof's credential-less sibling: bind one exact request to a bare DID, authentication only. |
| `did:dfos:key-add`        | [KEY-PROOF](https://protocol.dfos.com/key-proof)      | no    | Key-add ceremony proofs — the candidate key's single-shot possession-and-consent proof; self-signed, never relay-ingested.    |

## Registries That Live in Their Owner Spec

Names whose grammar is inseparable from their owner's machinery register there, not here — this section only says where:

- **Credential resource forms** (`chain:<contentId>`, `mailbox:<id>`, `api:<host>`) — [CREDENTIALS → Resource Types](https://protocol.dfos.com/credentials).
- **API action tokens** (`read:profile`, `read:email`, `read:memberships`) — [API-AUTH's action registry](https://protocol.dfos.com/api-auth).
- **SIWD scope tokens** — [SIWD → Scopes and Credentials](https://protocol.dfos.com/siwd).
- **Sign-request `payloadTyp` families** — [SIGNING](https://protocol.dfos.com/signing).
- **Key-proof ceremony purposes** — [KEY-PROOF → Purpose Registry](https://protocol.dfos.com/key-proof#purpose-registry) (each purpose `typ` also lands a row above).
- **App description members** — [SIWD → The App Description Document](https://protocol.dfos.com/siwd) (the member table is the registry).
- **Content schemas** (`$schema` vocabulary) — [CONTENT-MODEL](https://protocol.dfos.com/content-model), hosted at [schemas.dfos.com](https://schemas.dfos.com).
