# @metalabel/dfos-protocol

Ed25519 signed chain primitives for cryptographic identity and verifiable content. Self-certifying DIDs, content-addressed CIDs, offline verification. The protocol operates on keys and document hashes — application semantics are a separate concern, free to evolve without protocol changes.

## Install

```bash
npm install @metalabel/dfos-protocol zod
```

`zod` is a peer dependency. The package exports Zod schema objects directly
(`IdentityOperation`, `ContentOperation`, `MultikeyPublicKey`, …) so you can
compose them into your own schemas — which only works if your app and this
package share one Zod install.

## Usage

```ts
// Chain verification
import { verifyContentChain, verifyIdentityChain } from '@metalabel/dfos-protocol/chain';
// Credentials (auth tokens + DFOS credentials)
import { createAuthToken, createDFOSCredential } from '@metalabel/dfos-protocol/credentials';
// Crypto primitives
import { createJws, dagCborCanonicalEncode, verifyJws } from '@metalabel/dfos-protocol/crypto';
```

## Subpath Exports

| Export                                 | Description                                                                                             |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `@metalabel/dfos-protocol/chain`       | Identity & content chains, services, artifacts, countersigns, revocations, credit claims, sign requests |
| `@metalabel/dfos-protocol/credentials` | Auth tokens (DID-signed JWT) and DFOS credentials for authorization                                     |
| `@metalabel/dfos-protocol/crypto`      | Ed25519, JWS, JWT, dag-cbor, base64url, ID generation                                                   |
| `@metalabel/dfos-protocol/fold`        | Canonical linearization and LWW-map folds for index documents                                           |

## Specifications

| Document                                         | Description                                                                       |
| ------------------------------------------------ | --------------------------------------------------------------------------------- |
| [PROTOCOL.md](../../specs/PROTOCOL.md)           | Core protocol — chains, signatures, verification, test vectors                    |
| [DID-METHOD.md](../../specs/DID-METHOD.md)       | W3C DID method specification for `did:dfos`                                       |
| [CONTENT-MODEL.md](../../specs/CONTENT-MODEL.md) | Standard content schemas (post, profile)                                          |
| [CREDENTIALS.md](../../specs/CREDENTIALS.md)     | UCAN-style authorization credentials for the DFOS protocol                        |
| [CREDITS.md](../../specs/CREDITS.md)             | Verifiable attribution for DFOS content                                           |
| [SIGNING.md](../../specs/SIGNING.md)             | A transport-agnostic way for one party to ask another to produce a DFOS signature |

Release history lives at https://github.com/metalabel/dfos/releases.

## Examples

The `examples/` directory contains deterministic reference fixtures that can be independently verified by any Ed25519 + dag-cbor implementation:

- `identity-genesis.json` — single create operation
- `identity-rotation.json` — genesis + key rotation
- `identity-delete.json` — genesis + delete (terminal)
- `content-lifecycle.json` — create + update (with both documents)
- `content-delete.json` — create + delete
- `content-delegated.json` — creator genesis + delegated update with DFOS write credential
- `credential-write.json` — DFOS write credential (broad + content-narrowed)
- `credential-read.json` — DFOS read credential
- `identity-services.json` — genesis publishing a services set (relay locator + content/artifact anchors)

## License

MIT
