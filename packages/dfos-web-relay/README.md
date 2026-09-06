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
// relay.projectIndex()  — advance the /index/v0 projection by one budget

export default relay.app;
```

Set `signing: true` to enable the optional signing mailbox; it is disabled by default.
The store must implement `SigningStore` or `createRelay` throws
`signing capability requires a store implementing SigningStore`.

Set `authority` to the `host[:port]` callers reach this relay at. It is what every
[API-AUTH](https://protocol.dfos.com/api-auth) identity proof is checked against, and
it is configuration, never read from a request header — without it the authenticated
routes answer 503. `ingestion` (`open` | `proof-required` | `closed`) and an injectable
`admissionPolicy` set who may submit operations
([Web Relay § Ingestion Admission](https://protocol.dfos.com/web-relay#ingestion-admission)).

### Advertising an OpenAPI document

Serving an OpenAPI document is a SHOULD, so it is opt-in. `openapi: { document }`
serves the document at `/openapi.json` (override with `route`) and advertises that
path in the well-known's `openapi` field; `openapi: { url }` advertises a document
hosted elsewhere without registering a route. Absent the option the relay serves
none and omits the field. This package's own document — the one describing the
route table below — ships as an importable JSON artifact generated from
`openapi.yaml`:

```typescript
import document from '@metalabel/dfos-web-relay/openapi.json';

const relay = await createRelay({ store, openapi: { document } });
```

The document is discovery, never authority: the routes, capability gates, and auth
rules the spec fixes govern regardless of what an advertised document says.

### Standalone (Node.js)

```typescript
import { serve } from '@metalabel/dfos-web-relay/node';

serve({ port: 4444 });
```

## Routes

| Method | Path                                        | Description                                                          |
| ------ | ------------------------------------------- | -------------------------------------------------------------------- |
| `GET`  | `/.well-known/dfos-relay`                   | Relay metadata (DID, capabilities, profile, peers, stats)            |
| `GET`  | `/openapi.json`                             | The configured OpenAPI document (registered only when configured)    |
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

## Implementing a store

A store implements one required contract and, optionally, up to three more. Which
ones it implements is what the relay reads its capabilities from — there is no
capability flag that can promise something the store cannot do, and no member
that exists only to throw.

```typescript
import { createRelay } from '@metalabel/dfos-web-relay';

// a read-only relay: serves the proof plane, the content plane, the log and the
// revocation routes. `write` is false, `index` is false, and it says so.
const relay = await createRelay({ store: myReadStore, identity: myIdentity });
```

### `RelayReadStore` — required

Every read a route performs: operations, identity and content chains, chain state
at an arbitrary CID, blobs, countersignatures, the paginated global log, stats,
revocations, and held public credentials. A relay over nothing but this serves
every GET the spec defines.

Reads FAIL CLOSED. A read that cannot be answered throws; it never returns
`undefined` to mean "the store is unwell". Absence and failure are different
answers, and ingestion classifies them differently — absence is a verdict, a
throw is retryable.

### `RelayWriteStore` — one method

```typescript
interface RelayWriteStore extends RelayReadStore {
  commit(batch: CommitBatch): Promise<CommitResult>;
}
```

`CommitBatch` is a typed, exhaustive description of everything ONE accepted
operation implies — the operation row, the identity or content chain's new head
and log, the global-log append, a countersignature, a revocation, a standing
credential added or (issuer-scoped) dropped — or one document blob. The store
persists all of it or none of it, and answers `new` or `duplicate`.

Atomicity is the contract. A partial commit is a corrupt relay: an operation in
the operation table but not in the log is invisible to every puller forever, and
a chain head advanced without its operation row breaks fork verification. If the
commit throws, the store MUST have persisted nothing; the relay treats a throw as
retryable and keeps the raw operation for a later pass.

A writing relay also holds writer-internal bookkeeping — the raw-operation
buffer the sequencer drains, and per-peer sync cursors (`RelayWriterState`). That
is this package's own state, not part of the store contract a read-only
integration has to care about.

### `IndexReadStore` / `IndexWriteStore` — the index profile

`IndexReadStore` is the nine queries behind `/index/v0`, pushed down so a page
costs O(page). `IndexWriteStore` is the projection side: `applyIndexRows` plus a
persisted cursor.

They are separate because a store can implement one without the other. A store
whose index rows are maintained by an external worker implements the queries,
advertises `index: true`, and the relay does no projection work for it. A store
that implements both lets this package run the projection:

```typescript
import { projectIndex } from '@metalabel/dfos-web-relay';

// inline (default): the relay drains the projection after each accepted batch
await createRelay({ store });

// external: nothing runs it but you
const relay = await createRelay({ store, indexProjection: 'external' });
setInterval(() => void relay.projectIndex(), 5_000);
```

The projection walks the operation log from its cursor, maps each entry to the
rows it dirties, and applies them. It is never inside a commit, every pass is
bounded by a budget, and a full-corpus fan-out (a `chain:*` grant, an identity
delete or restore) is carried on the cursor as a resumable sweep rather than
drained in one pass.

### `SigningStore` — the optional mailbox

The ephemeral courier state behind `/signing/v0`. `signing: true` over a store
that does not implement it is a configuration that lies, so `createRelay` throws.

`MemoryRelayStore` implements all of them, and is the reference implementation.

### Migrating a store written against the old interface

This is a breaking change to the package's store API (`0.x`, so a minor bump).
A store written against the single `RelayStore` interface needs three edits:

1. **Replace the ~14 write members with `commit`.** `putOperation`,
   `putIdentityChain`, `putContentChain`, `putBlob`, `addCountersignature`,
   `appendToLog`, `addRevocation`, `addPublicCredential` and
   `removePublicCredential` are gone. One `commit` carries what all of them
   carried, and the store decides how to make it atomic. `removePublicCredential`
   is now issuer-scoped: drop the held credential only when its `issuerDID`
   matches the one on the batch.
2. **Replace the `putIndex*` members with `applyIndexRows`, and add the cursor.**
   `getIndexCursor` / `setIndexCursor` persist where the projection got to. If
   your index is maintained elsewhere, implement neither and keep the queries.
3. **Return `ingestedAt` on log entries, and delete `getIndexOperationRow`.** A
   `LogEntry` now carries the relay's receipt stamp for that operation. It is the
   single clock read per operation and the projection's only source for it, which
   is what the optional `getIndexOperationRow` used to be for. It is store state,
   not wire state: `GET /proof/v1/log` still serves
   `{cid, jwsToken, kind, chainId}`.

Members that were optional and are now simply absent (`getStats` is required;
`getRevocations` was unused and is deleted) and the members a read-only store
used to answer by throwing can all be removed.

## License

MIT
