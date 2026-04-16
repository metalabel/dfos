# @metalabel/dfos-protocol

Ed25519 signed chain primitives for cryptographic identity and verifiable content. Self-certifying DIDs, content-addressed CIDs, offline verification. The protocol operates on keys and document hashes — application semantics are a separate concern, free to evolve without protocol changes.

## Install

```bash
npm install @metalabel/dfos-protocol
```

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

| Export                                 | Description                                                             |
| -------------------------------------- | ----------------------------------------------------------------------- |
| `@metalabel/dfos-protocol/chain`       | Identity and content chain signing, verification, beacons, countersigns |
| `@metalabel/dfos-protocol/credentials` | Auth tokens (DID-signed JWT) and DFOS credentials for authorization     |
| `@metalabel/dfos-protocol/crypto`      | Ed25519, JWS, JWT, dag-cbor, base64url, ID generation                   |

## Specifications

| Document                                         | Description                                                    |
| ------------------------------------------------ | -------------------------------------------------------------- |
| [PROTOCOL.md](../../specs/PROTOCOL.md)           | Core protocol — chains, signatures, verification, test vectors |
| [DID-METHOD.md](../../specs/DID-METHOD.md)       | W3C DID method specification for `did:dfos`                    |
| [CONTENT-MODEL.md](../../specs/CONTENT-MODEL.md) | Standard content schemas (post, profile, manifest)             |

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
- `beacon.json` — signed manifest pointer announcement with witness countersignature

## License

MIT
