# @metalabel/dfos-web-relay

Portable HTTP relay for the [DFOS protocol](https://protocol.dfos.com). Receives, verifies, stores, and serves identity chains, content chains, beacons, countersignatures, and content blobs.

See [RELAY.md](./RELAY.md) for the full relay specification.

## Install

```bash
npm install @metalabel/dfos-web-relay @metalabel/dfos-protocol
```

## Usage

### Embedded (Hono app)

```typescript
import { createRelay, MemoryRelayStore } from '@metalabel/dfos-web-relay';

const relay = await createRelay({
  store: new MemoryRelayStore(),
});

// relay.app  — Hono application
// relay.did  — the relay's auto-generated DID
// relay.syncFromPeers() — pull operations from configured peers

export default relay.app;
```

### Standalone (Node.js)

```typescript
import { serve } from '@metalabel/dfos-web-relay/node';

serve({ port: 4444 });
```

## Routes

| Method | Path                                     | Description                                                      |
| ------ | ---------------------------------------- | ---------------------------------------------------------------- |
| `GET`  | `/.well-known/dfos-relay`                | Relay metadata (DID, protocol version)                           |
| `POST` | `/operations`                            | Submit signed operations (identity, content, beacon, countersig) |
| `GET`  | `/identities/:did`                       | Get identity chain state and operation log                       |
| `GET`  | `/content/:contentId`                    | Get content chain state and operation log                        |
| `GET`  | `/operations/:cid`                       | Get a single operation by CID                                    |
| `GET`  | `/beacons/:did`                          | Get beacon for an identity                                       |
| `GET`  | `/countersignatures/:cid`                | Get countersignatures for an operation                           |
| `GET`  | `/operations/:cid/countersignatures`     | Same as above (alias)                                            |
| `PUT`  | `/content/:contentId/blob/:operationCID` | Upload blob (auth required)                                      |
| `GET`  | `/content/:contentId/blob`               | Download blob at head (auth + credential)                        |
| `GET`  | `/content/:contentId/blob/:ref`          | Download blob at specific operation ref                          |

## Blob Authorization

**Upload**: Auth token required. Caller must be the chain creator or the signer of the referenced operation (enables delegated upload).

**Download**: Auth token required. Chain creator can download directly. Other identities must present a `DFOSContentRead` VC-JWT credential (issued by the creator) in the `X-Credential` header.

## Conformance Test Suite

The `conformance/` directory contains a Go integration test suite that exercises the full relay HTTP surface. It runs against any live relay via the `RELAY_URL` environment variable.

```bash
# Run against a local relay
RELAY_URL=http://localhost:4444 go test -v -count=1 ./conformance/

# Run against a remote relay
RELAY_URL=https://registry.imajin.ai/relay go test -v -count=1 ./conformance/
```

77 tests covering:

- Well-known discovery
- Identity lifecycle (create, update, delete, batch, idempotency, controller key rotation)
- Content lifecycle (create, update, delete, fork acceptance, DAG logs, deterministic head selection, post-delete rejection, notes, long chains)
- Content update after auth key rotation, multiple independent chains
- Operations by CID
- Beacons (create, replacement, not-found, unknown/deleted identity)
- Countersignatures (dedup, empty result, multi-witness, self-countersign, non-existent operation)
- Blob upload/download (CID verification, auth, credential-based access, multi-version, idempotent upload)
- Delegated content operations (write credentials, delegated blob upload, delegated delete)
- Credentials (expiry, scope mismatch, type enforcement, deleted issuer behavior)
- Signature verification (tampered signature, wrong signing key)
- Auth edge cases (wrong audience, expired token, rotated-out key)
- Batch processing (3-step dependency sort, content-identity sort, large batch, dedup, mixed valid/invalid, multi-chain)
- Input validation (malformed JSON, empty operations, invalid JWS)
- Future timestamp guard (reject identity/content ops >24h ahead)

The conformance suite depends on [`dfos-protocol-go`](../dfos-protocol-go) for protocol operations.

## Peering

Relays can replicate operations via three composable behaviors configured per-peer:

- **Gossip-out**: push new operations to peers (fire-and-forget)
- **Read-through**: fetch from peers on local 404
- **Sync-in**: cursor-based log polling from peers

```typescript
import { createHttpPeerClient, createRelay, MemoryRelayStore } from '@metalabel/dfos-web-relay';

const relay = await createRelay({
  store: new MemoryRelayStore(),
  peerClient: createHttpPeerClient(),
  peers: [{ url: 'https://other-relay.example.com' }],
});
```

See [RELAY.md](./RELAY.md) for the full peering specification.

## Custom Store

Implement the `RelayStore` interface to use any persistence backend:

```typescript
import type { RelayStore } from '@metalabel/dfos-web-relay';
```

`MemoryRelayStore` is provided as a reference implementation and for testing.

## License

MIT
