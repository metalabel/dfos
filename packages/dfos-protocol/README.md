# @metalabel/dfos-protocol

Ed25519 signed chain primitives, verifiable content, and registry for the DFOS Protocol.

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

## Protocol Specification

See [PROTOCOL.md](./PROTOCOL.md) for the complete protocol specification with worked examples and test vectors.

## Examples

The `examples/` directory contains deterministic reference chain fixtures that can be independently verified by any Ed25519 + dag-cbor implementation:

- `identity-genesis.json` — single create operation
- `identity-rotation.json` — genesis + key rotation
- `identity-delete.json` — genesis + delete (terminal)
- `content-lifecycle.json` — create + update (with both documents)
- `content-delete.json` — create + delete

## API Documentation

See [openapi.yaml](./openapi.yaml) for the registry API specification.

## License

MIT
