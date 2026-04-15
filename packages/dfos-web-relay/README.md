# @metalabel/dfos-web-relay

Relays verify everything they receive and serve everything they've verified. No trust between relays, no hierarchy, no central authority. Topology is emergent. Portable HTTP relay for the [DFOS protocol](https://protocol.dfos.com).

See [WEB-RELAY.md](../../specs/WEB-RELAY.md) for the full relay specification.

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
| `GET`  | `/content/:contentId/blob`               | Download blob at head (standing auth, or auth + credential)      |
| `GET`  | `/content/:contentId/blob/:ref`          | Download blob at specific operation ref                          |

## Blob Authorization

**Upload**: Auth token required. Caller must be the chain creator or the signer of the referenced operation (enables delegated upload).

**Download**: If a public credential (`aud: *`) exists as a standing authorization, the blob is served without authentication. Otherwise, auth token required — chain creator can download directly, other identities must present a DFOS read credential (issued by the creator) in the `X-Credential` header.

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

See [WEB-RELAY.md](../../specs/WEB-RELAY.md) for the full peering specification.

## Custom Store

Implement the `RelayStore` interface to use any persistence backend:

```typescript
import type { RelayStore } from '@metalabel/dfos-web-relay';
```

`MemoryRelayStore` is provided as a reference implementation and for testing.

## License

MIT
