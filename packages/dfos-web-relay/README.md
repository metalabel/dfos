# @metalabel/dfos-web-relay

Relays verify everything they receive and serve everything they've verified. No trust between relays, no hierarchy, no central authority. Topology is emergent. Portable HTTP relay for the [DFOS protocol](https://protocol.dfos.com).

See [WEB-RELAY.md](../../specs/WEB-RELAY.md) for the full relay specification.

## Install

```bash
npm install @metalabel/dfos-web-relay @metalabel/dfos-protocol hono
```

`@metalabel/dfos-protocol` and `hono` are peer dependencies. Hono is peered
rather than bundled because the relay's public API is Hono-typed — `createRelay`
returns `{ app: Hono }` and `serve(app)` takes one — so the relay and your app
must resolve to the _same_ Hono install. A private copy yields two structurally
incompatible `Hono` types and the handoff fails to compile.

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

Set `signing: true` to enable the optional signing mailbox; it is disabled by default.
The store must implement the optional signing members or `createRelay` throws
`signing capability requires a store implementing the signing members`.

### Standalone (Node.js)

```typescript
import { serve } from '@metalabel/dfos-web-relay/node';

serve({ port: 4444 });
```

## Routes

| Method | Path                                        | Description                                                          |
| ------ | ------------------------------------------- | -------------------------------------------------------------------- |
| `GET`  | `/.well-known/dfos-relay`                   | Relay metadata (DID, capabilities, profile, peers, stats)            |
| `POST` | `/proof/v1/operations`                      | Submit signed operations (identity, content, countersig)             |
| `GET`  | `/proof/v1/identities/:did`                 | Get identity chain terminal state                                    |
| `GET`  | `/proof/v1/identities/:did/log`             | Paginated identity chain operation log                               |
| `GET`  | `/proof/v1/content/:contentId`              | Get content chain terminal state                                     |
| `GET`  | `/proof/v1/content/:contentId/log`          | Paginated content chain operation log                                |
| `GET`  | `/proof/v1/log`                             | Paginated global operation log (`log` capability)                    |
| `GET`  | `/proof/v1/operations/:cid`                 | Get a single operation by CID                                        |
| `GET`  | `/proof/v1/countersignatures/:cid`          | Paginated countersignatures for any CID (ops, artifacts)             |
| `GET`  | `/1.0/identifiers/:did`                     | Resolve a `did:dfos` to a W3C DID Document (DIF-compat)              |
| `GET`  | `/revocations/v1/credential/:credentialCID` | Revocation status for a credential (self-proving JWS)                |
| `GET`  | `/revocations/v1/issuer/:did`               | Paginated feed of all revocations ingested for an issuer             |
| `POST` | `/signing/v0/requests`                      | Deposit a sign request (`signing` capability; 501 when disabled)     |
| `GET`  | `/signing/v0/requests`                      | Poll pending sign requests (`signing` capability; 501 when disabled) |
| `POST` | `/signing/v0/requests/:cid/response`        | Submit a sign response (`signing` capability; 501 when disabled)     |
| `GET`  | `/signing/v0/requests/:cid/response`        | Poll sign response status (`signing` capability; 501 when disabled)  |
| `POST` | `/signing/v0/requests/:cid/decline`         | Decline a sign request (`signing` capability; 501 when disabled)     |
| `GET`  | `/index/v0/operations`                      | Browse operation metadata rows by recency (`index` capability)       |
| `GET`  | `/index/v0/identities`                      | Query materialized identity projections (`index` capability)         |
| `GET`  | `/index/v0/content`                         | Query materialized content projections (`index` capability)          |
| `GET`  | `/index/v0/artifacts`                       | Query standalone signed artifacts (`index` capability)               |
| `GET`  | `/index/v0/countersignatures`               | Query countersignatures by witness (`index` capability)              |
| `GET`  | `/index/v0/credentials`                     | Query credential projections (`index` capability)                    |
| `GET`  | `/index/v0/credits`                         | Query credits on public head documents (`index` capability)          |
| `PUT`  | `/content/:contentId/blob/:operationCID`    | Upload blob (auth required)                                          |
| `GET`  | `/content/:contentId/blob`                  | Download blob at head (standing auth, or auth + credential)          |
| `GET`  | `/content/:contentId/blob/:ref`             | Download blob at specific operation ref                              |

## Route Semantics

The route table above is the full surface this package serves; the semantics
behind it are the spec's to define, not this README's. DID resolution
(`/1.0/identifiers/:did`) follows the normative mapping in
[DID-METHOD.md](https://protocol.dfos.com/did-method) §4; revocation status
(`/revocations/v1/*`) is specified in
[Web Relay § Revocation Status](https://protocol.dfos.com/web-relay#revocation-status-v1);
blob upload/download authorization is
[Web Relay § Content Plane Access](https://protocol.dfos.com/web-relay#content-plane-access).

## Peering

Relays replicate operations via three composable per-peer behaviors —
gossip-out, read-through, sync-in — specified in
[Web Relay § Peering](https://protocol.dfos.com/web-relay#peering); operator
guidance for running a peered relay is at
[protocol.dfos.com/deploy](https://protocol.dfos.com/deploy).

```typescript
import { createHttpPeerClient, createRelay, MemoryRelayStore } from '@metalabel/dfos-web-relay';

const relay = await createRelay({
  store: new MemoryRelayStore(),
  peerClient: createHttpPeerClient(),
  peers: [{ url: 'https://other-relay.example.com' }],
});
```

## Custom Store

Implement the `RelayStore` interface to use any persistence backend:

```typescript
import type { RelayStore } from '@metalabel/dfos-web-relay';
```

`MemoryRelayStore` is provided as a reference implementation and for testing.

## License

MIT
