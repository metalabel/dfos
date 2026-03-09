# @metalabel/dfos-protocol

Cryptographic identity and verifiable content for DFOS. Ed25519 signed chains, content-addressed CIDs, a DID method, JSON Schema content types, and a reference registry server.

The protocol is not a library — it's a formalized specification for combining standards that already exist: Ed25519 (RFC 8032), JWS (RFC 7515), CIDv1 with dag-cbor, W3C Multikey, JSON Schema, W3C DIDs. This package is the canonical TypeScript implementation. Cross-language implementations exist in [Go and Python](./verify/).

## The protocol

Two chain types, three operations each.

**Identity chains** manage keys — create, update, delete. An identity is born with a genesis operation that declares its initial key set. The DID is derived deterministically from the genesis operation's content address. No root authority, no issuer hierarchy. The math bootstraps itself.

**Content chains** manage document commitments — create, update, delete. Each operation commits to a `documentCID`, a content-addressed hash of whatever the document contains. The protocol doesn't look inside. The chain proves that _this identity_ committed to _this exact content_ at _this time_.

Both are signed linked lists using the same mechanics — Ed25519 signatures, JWS compact tokens, content-addressed CID links. Take any DFOS proof token, decode it with any JWT library that supports EdDSA, and you have the operation payload and a verified signature.

See [`PROTOCOL.md`](./PROTOCOL.md) for the full specification and the [protocol reference](https://gist.github.com/bvalosek/ed4c96fd4b841302de544ffaee871648) for worked examples with byte-level test vectors.

## Install

```
npm install @metalabel/dfos-protocol
```

## Exports

```typescript
// Everything
import { ... } from '@metalabel/dfos-protocol';

// Ed25519, JWS, JWT, dag-cbor, base64url, ID generation
import { ... } from '@metalabel/dfos-protocol/crypto';

// Identity chains, content chains, multikey, schemas
import { ... } from '@metalabel/dfos-protocol/chain';

// Reference Hono registry server, store, wire types
import { ... } from '@metalabel/dfos-protocol/registry';
```

## Test

```
pnpm test
```

93 tests covering crypto primitives, chain verification, content schemas, registry HTTP surface, and a deterministic protocol reference that generates all test vectors from the spec.

## License

[MIT](../../LICENSE)
