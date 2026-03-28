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
// Credentials (auth tokens + VC-JWT)
import { createAuthToken, verifyCredential } from '@metalabel/dfos-protocol/credentials';
// Crypto primitives
import { createJws, dagCborCanonicalEncode, verifyJws } from '@metalabel/dfos-protocol/crypto';
// Merkle trees
import { buildMerkleTree, verifyMerkleProof } from '@metalabel/dfos-protocol/merkle';
```

## Subpath Exports

| Export                                 | Description                                                             |
| -------------------------------------- | ----------------------------------------------------------------------- |
| `@metalabel/dfos-protocol/chain`       | Identity and content chain signing, verification, beacons, countersigns |
| `@metalabel/dfos-protocol/credentials` | Auth tokens (DID-signed JWT) and VC-JWT credentials for authorization   |
| `@metalabel/dfos-protocol/crypto`      | Ed25519, JWS, JWT, dag-cbor, base64url, ID generation                   |
| `@metalabel/dfos-protocol/merkle`      | SHA-256 binary merkle tree, inclusion proofs                            |

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
- `content-delegated.json` — creator genesis + delegated update with DFOSContentWrite VC-JWT
- `credential-write.json` — DFOSContentWrite VC-JWT (broad + content-narrowed)
- `credential-read.json` — DFOSContentRead VC-JWT
- `merkle-tree.json` — 5 content IDs → sorted tree → root, with inclusion proof
- `beacon.json` — signed merkle root announcement with witness countersignature

## Cross-Language Verification

The `verify/` directory contains independent verification suites that re-derive CIDs and verify signatures from the reference fixtures — proving protocol correctness across implementations:

| Language | Path             | Status  |
| -------- | ---------------- | ------- |
| Go       | `verify/go/`     | Passing |
| Python   | `verify/python/` | Passing |
| Rust     | `verify/rust/`   | Passing |
| Swift    | `verify/swift/`  | Passing |

Each suite uses only its language's native Ed25519, dag-cbor, and multihash implementations — no shared code with the TypeScript reference.

## License

MIT
