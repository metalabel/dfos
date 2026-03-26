# DFOS Web Relay

An HTTP relay for the DFOS protocol — receives, verifies, stores, and serves identity chains, content chains, artifacts, beacons, countersignatures, and content blobs.

This spec is under active review. Discuss it in the [clear.txt](https://clear.dfos.com) space on DFOS.

[Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-web-relay) · [npm](https://www.npmjs.com/package/@metalabel/dfos-web-relay) · [Protocol](https://protocol.dfos.com)

---

## Philosophy

The DFOS protocol defines signed chain primitives — identity and content chains, beacons, credentials — but says nothing about transport. A web relay is the HTTP layer that carries these primitives between participants.

Relays are not authorities. They verify what they receive and serve what they've verified, but they don't issue identity, grant permissions, or define content semantics. Any relay implementing the same verification rules produces the same acceptance/rejection decisions for the same operations. Clients can replicate their data across multiple relays without coordination.

A relay is a library, not a service. `createRelay()` returns a portable Hono application that any runtime can host — Node.js, Cloudflare Workers, Deno, Bun, a Docker container, a Raspberry Pi. The consumer provides a storage backend and configuration. The relay handles verification and HTTP semantics.

---

## Two Planes

The relay serves two distinct planes of data with different access models:

### Proof Plane (public)

Signed chain operations, artifacts, beacons, and countersignatures. These are cryptographic proofs — anyone can verify them with a public key. The proof plane gossips freely: relays push operations to peers, peers verify and store independently.

All proof plane routes are unauthenticated. The operations themselves carry their own authentication (Ed25519 signatures).

### Content Plane (private)

Raw content blobs — the actual documents that content chains commit to via `documentCID`. The content plane never gossips. Blobs are stored by the relay that received them and served only to authorized readers.

Content plane access requires two credentials:

- **Auth token**: A DID-signed JWT proving the caller controls an identity (AuthN)
- **Read credential** (for non-creators): A `DFOSContentRead` VC-JWT issued by the content creator, granting the caller read access (AuthZ)

The content creator (the DID that signed the genesis content operation) can always read their own blobs with just an auth token.

Content plane support is optional per relay. When disabled (`content: false` in the well-known response), all content plane routes return **501 Not Implemented** — not 404 (resource doesn't exist), but 501 (capability not supported).

---

## Operation Ingestion

All proof plane operations enter through a single endpoint: `POST /operations`. The request body is an array of JWS tokens — identity operations, content operations, artifacts, beacons, and countersignatures can be mixed freely in the same batch.

### Classification

Each token is classified by its JWS `typ` header:

| `typ` header           | Classification           |
| ---------------------- | ------------------------ |
| `did:dfos:identity-op` | Identity chain operation |
| `did:dfos:content-op`  | Content chain operation  |
| `did:dfos:beacon`      | Beacon announcement      |
| `did:dfos:artifact`    | Artifact                 |
| `did:dfos:countersign` | Countersignature         |

Each operation type has its own `typ` header. Classification is unambiguous — no DID comparison needed.

### Dependency Sort

Within a batch, operations are sorted by dependency priority before processing:

1. **Identity operations** — must be processed first so their keys are available
2. **Beacons and artifacts** — reference identity keys for signature verification
3. **Content operations** — reference identity keys, may have chain dependencies
4. **Countersignatures** — reference identity keys and existing operations (target must exist)

Within each priority level, genesis operations (no `previousOperationCID`) are processed before extensions. This ensures that a single batch can bootstrap an entire identity-and-content lifecycle — including chained create + update operations — without multiple round trips.

### Verification

Each operation is verified against the relay's stored state:

- **Identity operations**: Extension operations are verified against the relay's current trusted state using O(1) extension verification — the trusted head state plus the new operation is sufficient. Genesis operations verify the single-operation chain. The relay uses `verifyIdentityChain()` / `verifyIdentityExtensionFromTrustedState()` from the protocol library
- **Content operations**: Extension operations are verified against trusted state with `enforceAuthorization: true`. Non-creator signers must include a `DFOSContentWrite` VC-JWT. The relay uses `verifyContentChain()` / `verifyContentExtensionFromTrustedState()` from the protocol library
- **Artifacts**: Signature is verified against the signing DID's current identity state. CID integrity is checked. Payload must conform to the declared `$schema`. CBOR-encoded payload must not exceed 16384 bytes
- **Beacons**: Signature, CID integrity, and clock skew are verified. Replace-on-newer: only the most recent beacon per DID is retained
- **Countersignatures**: Two-phase verification. Protocol-level (stateless): signature, CID integrity, payload schema. Relay-level (stateful): target CID must exist in the relay, witness DID must differ from the target's author DID, one countersign per witness per target

### Fork Policy

First-seen-wins. If a chain head has already advanced past the `previousOperationCID` referenced by an incoming operation, the new operation is rejected. The relay does not attempt to resolve forks — the first valid extension wins.

Duplicate submissions (same operation CID, same JWS token) are silently accepted (idempotent). Submissions with the same CID but a different JWS token are rejected — since Ed25519 is deterministic, a different token for the same payload means a different signing key, which is either a self-countersign attempt or an unauthorized re-sign.

Duplicate countersignatures (same witness DID, same target CID) MUST be deduplicated — one countersign per witness per target. The relay MUST NOT store multiple attestations from the same witness for the same target. Resubmission SHOULD return `accepted` (idempotent).

### Deletion Semantics

Deletion means the identity stops being an active participant. Historical operations remain verifiable — keys persist in state for signature verification — but no new acts flow from a deleted identity.

Specifically:

- **Identity operations after deletion**: Rejected. A deleted identity chain is sealed.
- **Content operations after deletion**: Rejected. A deleted content chain is sealed.
- **Beacons from deleted identities**: Rejected. A deleted identity MUST NOT publish new beacons.
- **Artifacts from deleted identities**: Rejected. A deleted identity MUST NOT publish new artifacts.
- **Credentials from deleted issuers**: Rejected. Identity deletion revokes all authority, including outstanding `DFOSContentRead` and `DFOSContentWrite` credentials issued by the deleted identity. Credentials that were valid at time of issuance cease to be honored once the issuer is deleted.
- **Countersignatures from deleted witnesses**: Rejected. A deleted identity MUST NOT publish new countersignatures. Countersignatures on operations by deleted authors are still accepted — deletion of the target's author does not prevent other identities from attesting.

Self-countersignatures — where the witness DID matches the target's author DID — are rejected at the relay level. A countersignature's semantic is "a distinct witness attests." The protocol-level verifier is stateless and does not enforce this; the relay resolves the target's author and rejects self-attestation.

### Result Ordering

Ingestion results are returned in the same order as the input `operations` array, regardless of internal processing order. `results[i]` corresponds to `operations[i]`.

---

## Artifacts

Artifacts are standalone signed inline documents — immutable, CID-addressable proof plane primitives. Unlike chain operations which extend a sequence, an artifact is a single signed statement with no predecessor or successor.

### Payload

```json
{
  "version": 1,
  "type": "artifact",
  "did": "did:dfos:...",
  "content": {
    "$schema": "https://schemas.dfos.com/profile/v1",
    "name": "My Relay",
    "description": "A relay for the dark forest"
  },
  "createdAt": "2026-03-25T00:00:00.000Z"
}
```

The `content` object MUST include a `$schema` string that identifies the artifact's schema. The schema acts as a discriminator — consumers use it to determine how to interpret the artifact's content. Schema names are free-form strings (no protocol-level registry). Communities may establish conventions for well-known schemas.

### Constraints

- **JWS `typ` header**: `did:dfos:artifact`
- **Max payload size**: 16384 bytes CBOR-encoded. This is a protocol constant — not configurable per relay
- **Immutability**: Once ingested, an artifact is never updated or replaced. To "update" an artifact's content, publish a new artifact
- **CID-addressable**: Each artifact is addressed by the CID of its CBOR-encoded payload

### Verification

1. JWS signature verification against the signing DID's current key state
2. CID integrity — the payload CID matches the computed CID from the raw payload bytes
3. Payload schema validation — the payload conforms to the artifact structure (`version`, `type`, `did`, `content` with `$schema`, `createdAt`)
4. Size limit — CBOR-encoded payload does not exceed 16384 bytes

---

## Countersignatures

A countersignature is a standalone witness attestation — a signed statement that references a target operation by CID. Unlike the original operation primitives (which carry the data itself), a countersign is pure attestation: "I, witness W, attest to operation X."

### Payload

```json
{
  "version": 1,
  "type": "countersign",
  "did": "did:dfos:witness...",
  "targetCID": "bafy...",
  "createdAt": "2026-03-25T00:00:00.000Z"
}
```

### Properties

- **JWS `typ` header**: `did:dfos:countersign`
- **Own CID**: Each countersign has its own CID, distinct from the target. This avoids the ambiguity of multiple JWS tokens sharing the same CID
- **Stateless verification**: Signature + CID integrity + payload schema. No relay state required to verify the cryptographic validity of a countersign
- **Composable**: The `targetCID` can reference any CID-addressable operation — content ops, beacons, artifacts, identity ops, even other countersigns
- **Immutable**: Once published, a countersign is permanent

### Relay-Level Checks

The relay enforces semantic rules beyond cryptographic validity:

1. **Target exists**: The `targetCID` must reference an operation already stored in the relay
2. **Witness ≠ author**: The countersign's `did` (witness) must differ from the target operation's author DID
3. **Deduplication**: One countersign per witness per target. If the same witness submits a second countersign for the same target, the relay accepts idempotently
4. **Deleted witness rejection**: Countersigns from deleted identities are rejected

---

## Relay Identity

Every relay has a DID that resolves on its own proof plane. The relay DID serves as:

- **Auth token audience**: Auth tokens are scoped to a specific relay via the JWT `aud` claim, preventing cross-relay token replay
- **Peer identity**: When relays gossip proof plane data to each other, the relay DID identifies the peer
- **Self-proof anchor**: The relay's identity chain lives in its own store, verifiable by anyone querying the relay

### Relay Profile

The relay MUST publish a profile artifact signed by its own DID using the HEAD key state. The profile artifact uses the `https://schemas.dfos.com/profile/v1` schema:

```json
{
  "$schema": "https://schemas.dfos.com/profile/v1",
  "name": "edge.relay.dfos.com",
  "description": "Cloudflare edge relay for the DFOS network",
  "image": { "id": "relay-avatar", "uri": "https://cdn.example.com/avatar.png" },
  "operator": "Metalabel",
  "motd": "Welcome to the dark forest"
}
```

All fields are optional except `name`, which SHOULD be present. The `image.uri` field is any valid URI (operator choice — CDN, content-plane reference, or any resolvable URL). The profile JWS token is inlined in the well-known response — self-proving, no extra fetch needed.

### Well-Known Endpoint (`GET /.well-known/dfos-relay`)

Returns relay metadata. All fields are required — `profile` is the relay's proof of DID controllership (an artifact JWS signed by the relay DID's controller key).

```json
{
  "did": "did:dfos:edgerelay0000000000000",
  "protocol": "dfos-web-relay",
  "version": "0.1.0",
  "proof": true,
  "content": false,
  "profile": "eyJhbGciOiJFZERTQSIs..."
}
```

| Field      | Type    | Description                                                                |
| ---------- | ------- | -------------------------------------------------------------------------- |
| `did`      | string  | The relay's DID, resolvable on this relay's proof plane                    |
| `protocol` | string  | Protocol identifier, always `"dfos-web-relay"`                             |
| `version`  | string  | Relay protocol version (semver)                                            |
| `proof`    | boolean | MUST be `true`. A relay without proof plane capability is not a relay      |
| `content`  | boolean | Whether the relay supports content plane (blob upload/download)            |
| `profile`  | string  | The relay's profile artifact as a compact JWS token — self-proving payload |

`proof: false` is not a valid value. A compliant relay always serves the proof plane.

---

## Operation Log

The relay maintains a global append-only operation log. Every successfully ingested operation (identity ops, content ops, artifacts, beacons, countersignatures) is appended to the log in ingestion order.

### Global Log (`GET /log?after={cid}&limit=N`)

Returns log entries starting after the given CID cursor.

```json
{
  "entries": [
    {
      "cid": "bafy...",
      "jwsToken": "eyJhbGciOiJFZERTQSIs...",
      "kind": "identity-op",
      "chainId": "did:dfos:..."
    },
    {
      "cid": "bafy...",
      "jwsToken": "eyJhbGciOiJFZERTQSIs...",
      "kind": "artifact",
      "chainId": "did:dfos:..."
    }
  ],
  "cursor": "bafy..."
}
```

| Field                | Type         | Description                                                                      |
| -------------------- | ------------ | -------------------------------------------------------------------------------- |
| `entries[].cid`      | string       | Operation CID                                                                    |
| `entries[].jwsToken` | string       | The full compact JWS token — makes the log self-contained for sync               |
| `entries[].kind`     | string       | Operation kind: `identity-op`, `content-op`, `beacon`, `artifact`, `countersign` |
| `entries[].chainId`  | string       | DID (identity/beacon/artifact), contentId (content), or targetCID (countersign)  |
| `cursor`             | string\|null | CID to pass as `after` for the next page. `null` means caught up                 |

Parameters:

- **`after`** (optional): CID cursor. Omit to start from the beginning of the log
- **`limit`** (optional): Max entries to return. Default: 100. Max: 1000

Pagination is forward-only. The log is ordered by ingestion time. JWS tokens are included in every entry because proof-plane JWS payloads are bounded (chain operations and artifacts have finite size), keeping the log self-contained — a syncing peer can replay the log without separate fetches.

### Per-Chain Logs

Identity and content chains expose their own log views with the same cursor-based pagination:

- `GET /identities/:did/log?after={cid}&limit=N`
- `GET /content/:contentId/log?after={cid}&limit=N`

Same cursor-based pagination parameters as the global log. Per-chain log entries include `{ cid, jwsToken }` — the chain-specific subset of the global log entry shape. Returns operations belonging to that chain in chain order.

---

## Identity and Content State

State endpoints return projected state — the computed result of replaying the chain — without embedding the full operation log.

### Identity State (`GET /identities/:did`)

```json
{
  "did": "did:dfos:abc123...",
  "headCID": "bafy...",
  "state": {
    "did": "did:dfos:abc123...",
    "isDeleted": false,
    "authKeys": [...],
    "assertKeys": [...],
    "controllerKeys": [...]
  }
}
```

### Content State (`GET /content/:contentId`)

```json
{
  "contentId": "abc123...",
  "genesisCID": "bafy...",
  "headCID": "bafy...",
  "state": {
    "contentId": "abc123...",
    "genesisCID": "bafy...",
    "headCID": "bafy...",
    "isDeleted": false,
    "currentDocumentCID": "bafy...",
    "length": 1,
    "creatorDID": "did:dfos:..."
  }
}
```

Chain history is available via the per-chain log routes described above.

---

## Content Plane Access

### Blob Upload (`PUT /content/:contentId/blob/:operationCID`)

The upload path mirrors the download path — the operation CID identifies which operation's document is being uploaded.

Requirements:

- Valid auth token (Bearer header)
- The operation CID must reference an operation in this content chain that has a `documentCID`
- The authenticated DID must be either the chain creator OR the signer of the referenced operation (enabling delegated uploads)
- The uploaded bytes must hash to the operation's `documentCID` (dag-cbor + sha-256 verification)

Blobs are stored by `(creatorDID, documentCID)` — always keyed to the chain creator regardless of who uploads. If multiple content chains by the same creator reference the same document, the blob is shared (deduplication).

### Blob Download (`GET /content/:contentId/blob[/:ref]`)

Requirements:

- Valid auth token (Bearer header)
- If the caller is the chain creator: no further credentials needed
- If the caller is not the creator: must present a `DFOSContentRead` VC-JWT in the `X-Credential` header, issued by the creator to the caller

The optional `:ref` parameter selects which operation's document to return:

- `head` (default): the current document at chain head
- An operation CID: the document committed by that specific operation

---

## Key Resolution

The relay uses two key resolution strategies:

- **Historical resolver** (for chain re-verification): searches all keys that have ever appeared in an identity chain's log, including rotated-out keys. This is necessary because re-verifying a full content chain from genesis must resolve keys from operations signed before a key rotation.
- **Current-state resolver** (for live authentication): only resolves keys in the identity's current state. After a key rotation, the old key immediately stops working for auth tokens and credentials. This prevents a compromised rotated-out key from being used to authenticate new requests.

---

## Storage Interface

The relay delegates persistence to a `RelayStore` interface. Implementations handle how data is stored — the relay handles what to store and when.

```typescript
interface RelayStore {
  getOperation(cid: string): Promise<StoredOperation | undefined>;
  putOperation(op: StoredOperation): Promise<void>;

  getIdentityChain(did: string): Promise<StoredIdentityChain | undefined>;
  putIdentityChain(chain: StoredIdentityChain): Promise<void>;

  getContentChain(contentId: string): Promise<StoredContentChain | undefined>;
  putContentChain(chain: StoredContentChain): Promise<void>;

  getBeacon(did: string): Promise<StoredBeacon | undefined>;
  putBeacon(beacon: StoredBeacon): Promise<void>;

  getBlob(key: BlobKey): Promise<Uint8Array | undefined>;
  putBlob(key: BlobKey, data: Uint8Array): Promise<void>;

  getCountersignatures(operationCID: string): Promise<string[]>;
  addCountersignature(operationCID: string, jwsToken: string): Promise<void>;

  appendToLog(entry: LogEntry): Promise<void>;
  readLog(params: { after?: string; limit: number }): Promise<LogPage>;
}
```

The `appendToLog` / `readLog` pair supports both the global log and per-chain log queries. The store implementation determines how to scope queries (e.g., by filtering on `chainId`).

The package includes `MemoryRelayStore` for development and testing. Production deployments would implement the interface over Postgres, SQLite, D1, or any durable store.

---

## Quick Start

```typescript
import { createRelay, MemoryRelayStore } from '@metalabel/dfos-web-relay';

// JIT mode — generates relay identity + profile artifact at startup
const relay = await createRelay({
  store: new MemoryRelayStore(),
});

// Or provide a pre-created identity (production)
const relay = await createRelay({
  store: new MemoryRelayStore(),
  identity: { did: 'did:dfos:myrelay...', profileArtifactJws: '...' },
});

// Mount on any Hono-compatible runtime
export default relay;
```

The returned Hono app exposes:

| Method | Path                                 | Plane   | Auth                    |
| ------ | ------------------------------------ | ------- | ----------------------- |
| `GET`  | `/.well-known/dfos-relay`            | meta    | none                    |
| `POST` | `/operations`                        | proof   | none                    |
| `GET`  | `/operations/:cid`                   | proof   | none                    |
| `GET`  | `/operations/:cid/countersignatures` | proof   | none                    |
| `GET`  | `/countersignatures/:cid`            | proof   | none                    |
| `GET`  | `/identities/:did`                   | proof   | none                    |
| `GET`  | `/identities/:did/log`               | proof   | none                    |
| `GET`  | `/content/:contentId`                | proof   | none                    |
| `GET`  | `/content/:contentId/log`            | proof   | none                    |
| `GET`  | `/beacons/:did`                      | proof   | none                    |
| `GET`  | `/log`                               | proof   | none                    |
| `PUT`  | `/content/:contentId/blob/:opCID`    | content | auth token              |
| `GET`  | `/content/:contentId/blob[/:ref]`    | content | auth token + credential |

---

## What's Deferred

- **Peer gossip**: Proactive push of proof plane operations to other relays
- **Rate limiting / anti-spam**: Operational concern, not protocol concern
- **Docker/CF reference deployments**: Focus on the core library first
- **Blob size limits**: No enforcement yet — production deployments should add limits at the middleware layer
- **Artifact `$schema` registry**: Schema names are free-form strings for now — no formal registry or validation beyond structural checks
