# @metalabel/dfos-protocol

Cryptographic identity and content proof — Ed25519 signed chains, content-addressed CIDs, W3C DIDs. The protocol knows about keys and document hashes. It doesn't know about posts, profiles, or any application concept.

## Install

```bash
npm install @metalabel/dfos-protocol
```

## Usage

```ts
// Chain verification
import { verifyContentChain, verifyIdentityChain } from '@metalabel/dfos-protocol/chain';
// Crypto primitives
import { createJws, dagCborCanonicalEncode, verifyJws } from '@metalabel/dfos-protocol/crypto';
// Reference registry server
import { createRegistryServer } from '@metalabel/dfos-protocol/registry';
```

## Subpath Exports

| Export                              | Description                                                         |
| ----------------------------------- | ------------------------------------------------------------------- |
| `@metalabel/dfos-protocol/chain`    | Identity and content chain signing, verification, multikey encoding |
| `@metalabel/dfos-protocol/crypto`   | Ed25519, JWS, JWT, dag-cbor, base64url, ID generation               |
| `@metalabel/dfos-protocol/registry` | Hono-based registry server, in-memory store, Zod schemas            |

## Specifications

| Document                               | Description                                                    |
| -------------------------------------- | -------------------------------------------------------------- |
| [PROTOCOL.md](./PROTOCOL.md)           | Core protocol — chains, signatures, verification, test vectors |
| [DID-METHOD.md](./DID-METHOD.md)       | W3C DID method specification for `did:dfos`                    |
| [CONTENT-MODEL.md](./CONTENT-MODEL.md) | Standard content schemas (post, profile, media)                |
| [REGISTRY-API.md](./REGISTRY-API.md)   | HTTP API for chain storage and resolution                      |
| [openapi.yaml](./openapi.yaml)         | OpenAPI 3.1 machine-readable registry spec                     |

## Examples

The `examples/` directory contains deterministic reference chain fixtures that can be independently verified by any Ed25519 + dag-cbor implementation:

- `identity-genesis.json` — single create operation
- `identity-rotation.json` — genesis + key rotation
- `identity-delete.json` — genesis + delete (terminal)
- `content-lifecycle.json` — create + update (with both documents)
- `content-delete.json` — create + delete

## License

MIT
