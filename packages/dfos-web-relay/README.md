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

Set `authority` to the `host[:port]` callers reach this relay at. It is what every
[API-AUTH](https://protocol.dfos.com/api-auth) identity proof is checked against, and
it is configuration, never read from a request header — without it the authenticated
routes answer 503. `ingestion` (`open` | `proof-required` | `closed`) and an injectable
`admissionPolicy` set who may submit operations
([Web Relay § Ingestion Admission](https://protocol.dfos.com/web-relay#ingestion-admission)).

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
| `PUT`  | `/content/:contentId/blob/:operationCID`    | Upload blob (identity proof required)                                |
| `GET`  | `/content/:contentId/blob`                  | Download blob at head (public grant, or identity proof + credential) |
| `GET`  | `/content/:contentId/blob/:ref`             | Download blob at specific operation ref                              |

## Route Semantics

The route table above is the full surface this package serves; the semantics
behind it are the spec's to define, not this README's. DID resolution
(`/1.0/identifiers/:did`) follows the normative mapping in
[DID-METHOD.md](https://protocol.dfos.com/did-method) §4; revocation status
(`/revocations/v1/*`) is specified in
[Relay Contract § Revocation Status](https://protocol.dfos.com/relay-contract#revocation-status);
blob upload/download authorization is
[Web Relay § Access](https://protocol.dfos.com/web-relay#access).

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

The `PeerClient` is injected like the store — semantic per-resource methods,
not raw HTTP. The default (`createHttpPeerClient`) uses HTTP; tests inject
mocks that route directly to another relay's API in-process:

```typescript
interface PeerClient {
  getIdentityLog(
    peerUrl: string,
    did: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; next: string | null } | 'invalid-cursor' | null>;

  getContentLog(
    peerUrl: string,
    contentId: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; next: string | null } | 'invalid-cursor' | null>;

  // `null` = transport/peer failure; `'invalid-cursor'` = the peer explicitly
  // rejected `after` (400) — the distinguished value the sync loop's self-heal
  // requires. A client that collapses the 400 into `null` leaves the puller
  // retrying a dead cursor forever after a peer wipes or rebuilds its log.
  getOperationLog(
    peerUrl: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; next: string | null } | 'invalid-cursor' | null>;

  submitOperations(peerUrl: string, operations: string[]): Promise<void>;
}
```

A `PeerLogEntry` is `{ cid: string; jwsToken: string }`. The
`'invalid-cursor'` outcome (a peer's 400 cursor rejection, distinct from
transport failure) is load-bearing for the sync loop's self-heal — see
[Web Relay § Peering](https://protocol.dfos.com/web-relay#peering).

## Custom Store

Implement the `RelayStore` interface to use any persistence backend. The relay
handles what to store and when; the store handles how:

```typescript
interface RelayStore {
  getOperation(cid: string): Promise<StoredOperation | undefined>;
  putOperation(op: StoredOperation): Promise<void>;

  getIdentityChain(did: string): Promise<StoredIdentityChain | undefined>;
  putIdentityChain(chain: StoredIdentityChain): Promise<void>;

  getContentChain(contentId: string): Promise<StoredContentChain | undefined>;
  putContentChain(chain: StoredContentChain): Promise<void>;

  getBlob(key: BlobKey): Promise<Uint8Array | undefined>;
  putBlob(key: BlobKey, data: Uint8Array): Promise<void>;

  getCountersignatures(operationCID: string): Promise<string[]>;
  addCountersignature(operationCID: string, jwsToken: string): Promise<void>;

  appendToLog(entry: LogEntry): Promise<void>;
  // `null` (the whole result, not the `next` field) = the store does not
  // recognize `after` — the relay MUST answer 400, never an empty page. A
  // store that cannot signal this would silently mask foreign cursors as
  // caught-up, permanently stalling any peer that trusted the answer.
  readLog(params: {
    after?: string;
    limit: number;
  }): Promise<{ entries: LogEntry[]; next: string | null } | null>;

  // chain state at arbitrary CID (content fork verification; identity historical state)
  getIdentityStateAtCID(
    did: string,
    cid: string,
  ): Promise<{ state: VerifiedIdentity; lastCreatedAt: string } | null>;
  getContentStateAtCID(
    contentId: string,
    cid: string,
  ): Promise<{ state: VerifiedContentChain; lastCreatedAt: string } | null>;

  // peer sync cursors
  getPeerCursor(peerUrl: string): Promise<string | undefined>;
  setPeerCursor(peerUrl: string, cursor: string): Promise<void>;
}
```

The `getIdentityStateAtCID` / `getContentStateAtCID` methods compute
materialized chain state at an arbitrary operation CID — content-fork
verification is the driving use. Implementations decide how: `MemoryRelayStore`
replays from genesis; a SQL-backed store can use snapshot tables.

Convergence (store-then-verify — [Web Relay § Convergence](https://protocol.dfos.com/web-relay#convergence))
extends the interface with a content-addressed raw-operation buffer:

```typescript
// raw ops — content-addressed store for all received operations
putRawOp(cid: string, jwsToken: string): Promise<void>;
getUnsequencedOps(limit: number): Promise<string[]>;
markOpsSequenced(cids: string[]): Promise<void>;
markOpRejected(cid: string, reason: string): Promise<void>;
countUnsequenced(): Promise<number>;
resetSequencer(): Promise<void>;
```

`MemoryRelayStore` is provided as a reference implementation and for testing.

## License

MIT
