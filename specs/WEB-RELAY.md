# DFOS Web Relay

An HTTP relay for the DFOS protocol — receives, verifies, stores, and serves identity chains, content chains, artifacts, countersignatures, and content blobs.

The **proof plane** (`/proof/v1/*`) is **frozen with Protocol v1** — see the [core protocol status](https://protocol.dfos.com/spec). The relay's other surfaces — ingestion ergonomics, peering, and the content plane — are reference-implementation behavior on their own clock, not frozen. Discuss in the [DFOS](https://nce.dfos.com) space.

> **Wire stability.** The non-frozen relay surfaces — well-known, countersignature reads, `/revocations/v1`, and the content plane — went through one deliberate pre-adoption breaking amendment to close the window on breaking changes. Countersignature reads now use one route, `/revocations/v1` is frozen at v1 with a bounded issuer feed, the redundant documents route is removed, and every list route uses one `limit` + `after` + `next` cursor paradigm. Breaking once now, while there are no external adopters, protects future adopters from integrating against transient shapes.

[Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-web-relay) · [npm](https://www.npmjs.com/package/@metalabel/dfos-web-relay) · [Protocol](https://protocol.dfos.com)

---

## Philosophy

Relays verify everything they receive and serve everything they've verified. They don't issue identity, grant permissions, or define content semantics. Give any two relays the same operations and they produce the same deterministic head state. No trust between relays, no coordination required.

A relay is a library, not a service. `createRelay()` returns a portable Hono application — Node.js, Cloudflare Workers, Deno, Bun, Docker, a Raspberry Pi. You provide storage and peer configuration. The relay handles verification, peering, and HTTP semantics.

---

## Two Planes

The relay serves two distinct planes of data with different access models:

### Proof Plane (public)

Signed chain operations, artifacts, and countersignatures. These are cryptographic proofs — anyone can verify them with a public key. The proof plane gossips freely: relays push operations to peers, peers verify and store independently.

All proof plane routes are unauthenticated. The operations themselves carry their own authentication (Ed25519 signatures).

### Content Plane (private)

Raw content blobs — the actual documents that content chains commit to via `documentCID`. The content plane never **gossips**: blobs are never pushed on the operation log the way proof-plane operations are. A blob enters a relay one of two ways — it is uploaded to the relay that holds the chain, or it is **pulled** by a relay that is authorized to read it (content-addressed, behind a grant; see [Content Following](#content-following)). Either way a blob is served only to authorized readers, and its integrity is its `documentCID`, so a pulled blob is verified by hash regardless of where it came from.

A relay's content plane **is** a document gateway — the same surface named as a standalone service on its own `0.x` clock. See [DOCUMENT-GATEWAY.md](https://protocol.dfos.com/document-gateway) for the gateway contract: a stateless, content-addressed blob store whose authorization is re-derived live from the proof plane. The served blob is the document itself — whether terminal (the bytes _are_ the content) or referential (the document points at external bytes, e.g. `ipfs://` or a signed-CDN reference). The relay never resolves a referential pointer; delivery of referenced media is out of protocol.

Content plane access requires two credentials:

- **Auth token**: A DID-signed JWT proving the caller controls an identity (AuthN)
- **Read credential** (for non-creators): A DFOS credential with `action: "read"` attenuations, issued by the content creator (or delegated via chain), granting the caller read access (AuthZ). Can be presented per-request or ingested as a standing authorization (see [Standing Authorization](#standing-authorization) below)

The content creator (the DID that signed the genesis content operation) can always read their own blobs with just an auth token.

Content plane support is optional per relay. When disabled (`capabilities.content: false` in the well-known response), all content plane routes return **501 Not Implemented** — not 404 (resource doesn't exist), but 501 (capability not supported).

---

## Route Namespacing

Every proof plane route is namespaced under a single prefix, **`/proof/v1`**:

```
/proof/v1/operations
/proof/v1/operations/:cid
/proof/v1/countersignatures/:cid
/proof/v1/identities/:did
/proof/v1/identities/:did/log
/proof/v1/content/:contentId
/proof/v1/content/:contentId/log
/proof/v1/log
```

The prefix encodes the plane and its version (`{plane}/{version}`), so the proof plane's version clock is legible in the URL and the plane mounts or proxies as a unit by prefix. The proof routes are **frozen with protocol v1** — a relay MUST serve them at exactly these paths.

Four route families deliberately stay at the root, on their own clocks:

- **`GET /.well-known/dfos-relay`** — discovery (RFC 8615) lives at the root by convention; it announces the base and the relay's own release version.
- **Content plane routes** (`/content/:contentId/blob[/:ref]`) — these belong to the **[document gateway](https://protocol.dfos.com/document-gateway)**, an optional service on a `0.x` clock independent of the protocol freeze. They remain at the root under `/content/:contentId` because they belong to the gateway's `0.x` clock, not the frozen proof plane. Note the resulting split: the proof node owns the bare chain-state paths `GET /proof/v1/content/:contentId` and `/proof/v1/content/:contentId/log`; the document gateway owns the `/content/:contentId/blob*` sub-paths. They are distinct namespaces that a reverse proxy can fan by prefix when the planes are split across origins.
- **Universal resolver** (`GET /1.0/identifiers/:did`) — the DID-core / DIF Universal Resolver binding on its own `1.0` clock (the DIF driver interface version, [DID-METHOD.md](https://protocol.dfos.com/did-method) §5.2.4). It is an additive, read-only projection of the same self-certified terminal state the proof plane serves at `/proof/v1/identities/:did`, rendered as a W3C DID Document. It stays at the root because it tracks the DIF driver clock, not the frozen proof plane.
- **Revocation status** (`GET /revocations/v1/credential/:credentialCID`, `GET /revocations/v1/issuer/:did`) — an indexed, read-only projection of the relay's revocation set on its own frozen `v1` clock. Revocations still _enter_ through the frozen proof plane (`POST /proof/v1/operations`); this family only exposes a read over the index the relay already maintains for its own credential enforcement. See [Revocation Status](#revocation-status-v1).
- **Index** (`GET /index/v0/*`) — an optional, non-authoritative query surface over the current-state projections the relay already folds: enumerate identities, filter content chains, reverse-look-up countersignatures by witness. On its own unfrozen `0.x` clock, gated by `capabilities.index`. See [Index (v0)](#index-v0).

---

## Operation Ingestion

All proof plane operations enter through a single endpoint: `POST /proof/v1/operations`. The request body is an array of JWS tokens — identity operations, content operations, artifacts, and countersignatures can be mixed freely in the same batch.

### Classification

Each token is classified by its JWS `typ` header:

| `typ` header           | Classification           |
| ---------------------- | ------------------------ |
| `did:dfos:identity-op` | Identity chain operation |
| `did:dfos:content-op`  | Content chain operation  |
| `did:dfos:artifact`    | Artifact                 |
| `did:dfos:countersign` | Countersignature         |
| `did:dfos:credential`  | DFOS credential          |
| `did:dfos:revocation`  | Credential revocation    |

Each operation type has its own `typ` header. Classification is unambiguous — no DID comparison needed.

### Dependency Sort

Within a batch, operations are sorted by dependency priority before processing:

1. **Identity operations** — must be processed first so their keys are available
2. **Artifacts** — reference identity keys for signature verification
3. **Content operations** — reference identity keys, may have chain dependencies
4. **Countersignatures** — reference identity keys and existing operations (target must exist)

Within each priority level, genesis operations (no `previousOperationCID`) are processed before extensions. This ensures that a single batch can bootstrap an entire identity-and-content lifecycle — including chained create + update operations — without multiple round trips.

### Verification

Each operation is verified against the relay's stored state:

- **Identity operations**: Extension operations are verified against the relay's current trusted state using O(1) extension verification — the trusted head state plus the new operation is sufficient. Genesis operations verify the single-operation chain. The relay uses `verifyIdentityChain()` / `verifyIdentityExtensionFromTrustedState()` from the protocol library
- **Content operations**: Extension operations are verified against trusted state with `enforceAuthorization: true`. Non-creator signers must include a DFOS credential with `action: "write"` attenuations. The relay uses `verifyContentChain()` / `verifyContentExtensionFromTrustedState()` from the protocol library
- **Revocations**: Signature is verified against the revoking DID's current identity state. The revocation payload must reference a valid credential CID. Once ingested, the revoked credential is no longer honored for authorization or content plane access
- **Artifacts**: Signature is verified against the signing DID's current identity state. CID integrity is checked. Payload must conform to the declared `$schema`. CBOR-encoded payload must not exceed 16384 bytes
- **Countersignatures**: Two-phase verification. Protocol-level (stateless): signature, CID integrity, payload schema. Relay-level (stateful): target CID must exist in the relay, witness DID must differ from the target's author DID, one countersign per witness per target

### Chain Resolution

The relay must route each incoming operation to its chain. Resolution differs by type:

- **Identity genesis**: No prior chain — the relay verifies the single-operation chain and creates a new `StoredIdentityChain` keyed by the new DID
- **Identity extension**: The `kid` in the JWS header is a DID URL (`did:dfos:<id>#<keyId>`). The relay extracts the DID prefix (before `#`) and looks up the existing chain. A `kid` without `#` on a non-genesis operation is rejected — it cannot be routed
- **Content genesis**: No prior chain — creates a new `StoredContentChain` keyed by the content ID derived from verification
- **Content extension**: The `previousOperationCID` payload field is used to look up a `StoredOperation`, which carries the `chainId`. The relay then fetches the content chain by that `chainId`. If the previous operation doesn't exist or isn't a content operation, the extension is rejected
- **Countersignatures**: The `targetCID` payload field is used to look up the target operation. The target's author DID is resolved from the stored operation to enforce the witness ≠ author rule

This is relay-level machinery — the protocol library verifies chain integrity, but the relay decides how to locate the chain a given operation belongs to.

### Fork Acceptance

Forks are accepted. If an incoming operation's `previousOperationCID` references any operation in the chain (not just the current head), the relay verifies the extension against the chain state at that fork point and accepts it. The chain log accumulates all branches.

**Deterministic head selection**: after accepting a fork, the relay recomputes the head — highest `createdAt` among tips, lexicographic highest CID as tiebreaker. This is deterministic across relays given the same set of operations, regardless of ingestion order. As forks propagate via peering, all relays converge to the same head.

**State at fork point**: to verify a fork extension, the relay computes chain state at the parent CID. The Store interface abstracts this via `getIdentityStateAtCID` / `getContentStateAtCID` — implementations choose the strategy (full replay, snapshot-backed, etc.).

**Undeletion**: falls naturally from the fork model. An identity holder can fork from before a delete with a higher `createdAt`. The fork becomes the head. The delete remains visible in the log (auditable, gossiped) but is on a non-head branch.

**Future timestamp guard**: Identity and content operations with a `createdAt` more than 24 hours in the future are rejected. Since head selection favors the highest timestamp, a far-future `createdAt` would permanently dominate head selection — a temporal denial-of-service. The 24-hour window accommodates clock drift while preventing abuse.

### Ingestion Statuses

Three distinct outcomes from ingestion:

| Status      | Meaning                                          |
| ----------- | ------------------------------------------------ |
| `new`       | First time seen, verified, stored, state changed |
| `duplicate` | Already had it, no state change (see note below) |
| `rejected`  | Verification failed                              |

For chain operations, `duplicate` means the exact same CID and JWS token was already stored — a true idempotent resubmission. Submissions with the same CID but a different JWS token are rejected — since Ed25519 is deterministic, a different token for the same payload means a different signing key.

Duplicate countersignatures (same witness DID, same target CID) MUST be deduplicated — one countersign per witness per target. The relay MUST NOT store multiple attestations from the same witness for the same target. Resubmission SHOULD return `duplicate` (idempotent).

### Deletion Semantics

Deletion means the identity stops being an active participant. Historical operations remain verifiable — keys persist in state for signature verification — but no new acts flow from a deleted identity.

Specifically:

- **Identity operations after deletion (linear extension)**: Rejected. A `delete` seals the head against forward (linear) extension — appending a new operation from the deleted head is refused. This is the _linear_ path only: a current controller MAY still fork from a pre-delete operation with a higher `createdAt` to supersede the delete (see _Fork Acceptance → Undeletion_ above), in which case the resolved head reports `deactivated: false`. The `delete` remains permanently in the log on a non-head branch.
- **Content operations after deletion**: Rejected. Both paths are checked: (a) the signer's identity is deleted — no operations from that DID are accepted, and (b) the content chain's creator identity is deleted — the chain is sealed regardless of who signs.
- **Artifacts from deleted identities**: Rejected. A deleted identity MUST NOT publish new artifacts.
- **Credentials from deleted issuers**: Rejected. Identity deletion revokes all authority, including outstanding DFOS credentials issued by the deleted identity. Credentials that were valid at time of issuance cease to be honored once the issuer is deleted.
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
  "relation": "endorses",
  "createdAt": "2026-03-25T00:00:00.000Z"
}
```

The optional `relation` field is an open-namespace tag (1–64 chars) naming the nature of the attestation (e.g. `coauthors`, `endorses`, `witnessed`, `holds`, `received`). Recognized values carry social meaning; unrecognized values MUST be preserved and ignored. Omitting `relation` is CID-neutral — a bare witness encodes identically to one signed before this field existed.

### Properties

- **JWS `typ` header**: `did:dfos:countersign`
- **Own CID**: Each countersign has its own CID, distinct from the target. This avoids the ambiguity of multiple JWS tokens sharing the same CID
- **Stateless verification**: Signature + CID integrity + payload schema. No relay state required to verify the cryptographic validity of a countersign
- **Composable**: The `targetCID` can reference any CID-addressable operation — content ops, artifacts, identity ops, even other countersigns
- **Immutable**: Once published, a countersign is permanent

### Relay-Level Checks

The relay enforces semantic rules beyond cryptographic validity:

1. **Target exists**: The `targetCID` must reference an operation already stored in the relay
2. **Witness ≠ author**: The countersign's `did` (witness) must differ from the target operation's author DID
3. **Deduplication**: One countersign per witness per target. If the same witness submits a second countersign for the same target, the relay accepts idempotently
4. **Deleted witness rejection**: Countersigns from deleted identities are rejected

### Endpoints

One route serves countersignature data:

- **`GET /proof/v1/countersignatures/:cid?after={cid}&limit=N`** — Primary lookup. Returns `{ cid, countersignatures: string[], next }`, sorted by each countersignature's own CID ascending and forward-only cursor-paginated. `after` is a countersignature CID, `limit` defaults to 100 and maxes at 1000, and `next` is the countersignature CID to resume from or `null` when caught up. Works for any CID-addressable target (operations, artifacts). Returns 404 only when the CID is neither a known operation nor has stored countersignatures.

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
  "links": [{ "uri": "https://dfos.com", "label": "operator", "description": "Metalabel" }]
}
```

All fields are optional except `name`, which SHOULD be present. The optional `links` array carries up to 20 `{ uri, label?, description? }` entries (operator site, status page, contact). The profile JWS token is inlined in the well-known response — self-proving, no extra fetch needed.

### Well-Known Endpoint (`GET /.well-known/dfos-relay`)

Returns relay metadata. The core discovery contract (`did`, `protocol`, `version`, `capabilities`, `profile`) is required — `profile` is the relay's proof of DID controllership (an artifact JWS signed by the relay DID's controller key). `peers` and extended `stats` fields are optional additive telemetry.

```json
{
  "did": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
  "protocol": "dfos-web-relay",
  "version": "0.15.0",
  "capabilities": {
    "proof": true,
    "write": true,
    "content": true,
    "log": true,
    "revocations": true,
    "index": true
  },
  "profile": "eyJhbGciOiJFZERTQSIs...",
  "peers": [{ "endpoint": "https://peer.relay.example.com" }],
  "stats": {
    "pendingOps": 0,
    "opCount": 128,
    "countsByKind": {
      "identity": 12,
      "content": 30,
      "artifact": 5,
      "credential": 8,
      "countersign": 3,
      "revocation": 1
    },
    "oldestOpAt": "2026-03-25T00:00:00.000Z",
    "headCid": "bafy..."
  }
}
```

| Field                      | Type           | Description                                                                                                                                                          |
| -------------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `did`                      | string         | The relay's DID, resolvable on this relay's proof plane                                                                                                              |
| `protocol`                 | string         | Protocol identifier, always `"dfos-web-relay"`                                                                                                                       |
| `version`                  | string         | The relay's own release version (semver), independent of the frozen proof-plane clock — the proof version lives in the `/proof/v1` path prefix, not here             |
| `capabilities`             | object         | Capability flags for optional features                                                                                                                               |
| `capabilities.proof`       | boolean        | MUST be `true`. A relay without proof plane capability is not a relay                                                                                                |
| `capabilities.write`       | boolean        | Whether the relay accepts writes via `POST /proof/v1/operations`                                                                                                     |
| `capabilities.content`     | boolean        | Whether the relay supports the content plane (blob upload/download)                                                                                                  |
| `capabilities.log`         | boolean        | Whether the global operation log is available (`GET /proof/v1/log`)                                                                                                  |
| `capabilities.revocations` | boolean        | Whether the [revocation status](#revocation-status-v1) index is served (`GET /revocations/v1/*`). Both reference relays always serve it                              |
| `capabilities.index`       | boolean        | Whether the [index](#index-v0) query family is served (`GET /index/v0/*`). An absent flag (a relay predating the family) reads as `false`                            |
| `profile`                  | string         | The relay's profile artifact as a compact JWS token — self-proving payload                                                                                           |
| `peers`                    | array          | OPTIONAL additive telemetry. Configured peer relays surfaced for mesh discovery; reference relays emit `[]` when no peers are configured                             |
| `peers[].endpoint`         | string         | OPTIONAL additive telemetry. The peer relay's base URL. A future `peers[].did` MAY appear once a relay resolves peer DIDs                                            |
| `stats`                    | object         | Operational counters. `stats.pendingOps` is the count of operations pending processing (`-1` if unavailable)                                                         |
| `stats.opCount`            | number         | OPTIONAL additive telemetry. Total entries in the global operation log                                                                                               |
| `stats.countsByKind`       | object         | OPTIONAL additive telemetry. Global-log counts by primitive kind; reference relays emit `identity`, `content`, `artifact`, `credential`, `countersign`, `revocation` |
| `stats.oldestOpAt`         | string \| null | OPTIONAL additive telemetry. `createdAt` of the oldest-position global-log entry, or `null` when the log is empty                                                    |
| `stats.headCid`            | string \| null | OPTIONAL additive telemetry. CID of the global-log tip, or `null` when the log is empty                                                                              |

`capabilities.proof: false` is not a valid value. A compliant relay always serves the proof plane. When `capabilities.log: false`, `GET /proof/v1/log` returns **501 Not Implemented**. Per-chain logs are always available regardless of this setting. When `capabilities.content: false`, all content plane routes return **501 Not Implemented**. When `capabilities.revocations: false`, the `/revocations/v1/*` routes return **501 Not Implemented** — the same capability-not-supported semantics. When `capabilities.index` is `false` or absent, the `/index/v0/*` routes return **501 Not Implemented**. Credential and revocation ingestion are always enabled on the proof plane — they enter through `POST /proof/v1/operations` like all other operation types.

### Lite (pull-only) node — `capabilities.write: false`

A relay MAY run as a **lite pull-only proof node**: it verifies, stores, and serves the proof plane, but accepts **no writes**. When `capabilities.write: false`, `POST /proof/v1/operations` returns **501 Not Implemented**. Because that endpoint is _both_ the client-write and the peer-gossip-ingest path (a gossiping peer POSTs operations here, and nothing in the request distinguishes a first-party submission from a peer push), refusing it disables **gossip-in along with client writes**. Such a node stays current by **pulling**: `syncFromPeers` polls its peers' `/proof/v1/log` and ingests verified operations locally. This is the smallest, safest mesh citizen — a tiny attack surface (no untrusted write endpoint) that still contributes verification and availability. All read routes behave normally. `dfos serve --no-write` runs this mode.

`capabilities.write` governs the **proof-plane** write endpoint (`POST /proof/v1/operations`) only. Content-plane writes (blob upload, `PUT /content/:contentId/blob/:operationCID`) are governed independently by `capabilities.content`, which enables or disables the content plane as a whole. A node that should accept no writes of any kind runs with both `write: false` and `content: false`.

---

## Operation Log

The relay maintains a global append-only operation log. Every successfully ingested operation (identity ops, content ops, artifacts, countersignatures) is appended to the log in ingestion order.

### Global Log (`GET /proof/v1/log?after={cid}&limit=N`)

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

| Field                | Type         | Description                                                                                                                                                  |
| -------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `entries[].cid`      | string       | Operation CID                                                                                                                                                |
| `entries[].jwsToken` | string       | The full compact JWS token — makes the log self-contained for sync                                                                                           |
| `entries[].kind`     | string       | Operation kind: `identity-op`, `content-op`, `artifact`, `countersign`, `revocation`, `credential`                                                           |
| `entries[].chainId`  | string       | DID (`identity-op`, `artifact`, `credential`, and `revocation` — all keyed to the issuer/signer DID), contentId (`content-op`), or targetCID (`countersign`) |
| `cursor`             | string\|null | CID to pass as `after` for the next page. `null` means caught up                                                                                             |

Parameters:

- **`after`** (optional): CID cursor. Omit to start from the beginning of the log
- **`limit`** (optional): Max entries to return. Default: 100. Max: 1000

> **`chainId` is not a per-chain partition key.** Because `credential` and `revocation` entries carry `chainId` = the issuer DID — the **same** value as that DID's `identity-op` and `artifact` entries — folding the global log per-chain on `chainId` alone silently co-mingles credentials, revocations, artifacts, and identity ops under a single DID. An indexer reconstructing a specific chain MUST filter by `kind` first (e.g. `kind === 'identity-op'` to rebuild the identity chain) rather than grouping on `chainId` alone.

Pagination is forward-only. The log is ordered by ingestion time. JWS tokens are included in every entry because proof-plane JWS payloads are bounded (chain operations and artifacts have finite size), keeping the log self-contained — a syncing peer can replay the log without separate fetches.

### Per-Chain Logs

Identity and content chains expose their own log views with the same cursor-based pagination:

- `GET /proof/v1/identities/:did/log?after={cid}&limit=N`
- `GET /proof/v1/content/:contentId/log?after={cid}&limit=N`

Same cursor-based pagination parameters as the global log. Per-chain log entries include `{ cid, jwsToken }` — the chain-specific subset of the global log entry shape. Returns operations belonging to that chain in chain order.

---

## Identity and Content State

State endpoints return projected state — the computed result of replaying the chain — without embedding the full operation log.

### Identity State (`GET /proof/v1/identities/:did`)

```json
{
  "did": "did:dfos:abc123...",
  "headCID": "bafy...",
  "state": {
    "did": "did:dfos:abc123...",
    "isDeleted": false,
    "authKeys": [...],
    "assertKeys": [...],
    "controllerKeys": [...],
    "services": [...]
  }
}
```

Resolved identity state includes the identity's `services` — the controller-signed discovery vocabulary (relay locators and stable content anchors) projected from the winning head. See [Services](https://protocol.dfos.com/spec#services) in the protocol spec. Read-through and sync replicate the underlying identity operations, so a peer that fetches an identity chain recomputes the same `services` set deterministically.

### Content State (`GET /proof/v1/content/:contentId`)

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

This response is **frozen with protocol v1** and carries pure chain state — no derived authorization material. Public-read discovery (surfacing the `aud: "*"` credentials that currently authorize `read` on a chain) is a **document gateway** concern on the `0.x` clock, not a proof-plane field: keeping it off the frozen route lets that ergonomic evolve without touching the locked contract. See [DOCUMENT-GATEWAY.md → Public-read discovery](https://protocol.dfos.com/document-gateway#public-read-discovery-0x).

Chain history is available via the per-chain log routes described above.

---

## Content Plane Access

This section describes the content plane as the relay serves it today. The standalone gateway contract — the stateless, proof-plane-derived authorization model, where authority is re-derived live every request and any materialized public-credential index is a non-authoritative cache — is specified in [DOCUMENT-GATEWAY.md](https://protocol.dfos.com/document-gateway).

Content plane requests carry a self-signed **auth token** in the `Bearer` header to prove caller identity (verified against the issuer's _current_ identity state — a rotated-out key cannot mint one; see [Key Resolution](#key-resolution)).

**Auth-token lifetime ceiling**: the relay rejects an auth token whose declared lifetime (`exp − iat`) exceeds a configured maximum (default **24 hours**), returning `401`. Auth tokens are ephemeral by design (minutes); this ceiling stops a buggy or malicious signer from minting an effectively-permanent bearer token. It applies only to auth tokens — DFOS credentials (read/write/standing) are verified on a separate path and may carry hours-to-months lifetimes. Setting the maximum to `≤ 0` disables the ceiling.

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

- If a standing authorization exists for the content (a public credential with `aud: "*"` covering the resource): access is granted without any auth token or per-request credential
- Otherwise, a valid auth token (Bearer header) is required, plus:
  - If the caller is the chain creator: no further credentials needed
  - If the caller is not the creator: must present a DFOS credential with `action: "read"` in the `X-Credential` header, with a delegation chain rooting at the creator

The optional `:ref` parameter selects which operation's document to return:

- `head` (default): the current document at chain head
- An operation CID: the document committed by that specific operation

### Enumerating a Chain's Documents

The former relay-side list route was removed because it was only a relay-decoded convenience over state the client can re-derive verifiably. Fetch `GET /content/:contentId/blob` for the document at head, `GET /content/:contentId/blob/:opCID` for the document any specific operation committed (immutable), and `GET /proof/v1/content/:contentId/log` to enumerate the chain's operations, each carrying its `documentCID`. This composition is strictly more verifiable: every blob is checked against its committed `documentCID`, and the op log is the frozen proof-plane enumeration.

### Standing Authorization

Instead of presenting a read credential on every request, a DFOS credential with `aud: "*"` (public) can be ingested by the relay as a **standing authorization** — once ingested, matching content plane requests are authorized without an `X-Credential` header. Credential ingestion uses `POST /proof/v1/operations`: DFOS credentials are submitted as JWS tokens alongside other proof plane operations and stored in the op log like any other operation (addressable by CID, carried in the global log as `kind: "credential"`).

**Authority is re-derived live, not read from a stored flag.** On every content plane access the relay re-verifies the standing credential against current proof-plane state — signature, issuer-key resolution, temporal validity, **revocation**, and a delegation chain rooted at the content creator — through the **same verifier the per-request (`X-Credential`) path uses**. The two paths differ only in where the credential came from and an audience check that public (`aud: "*"`) credentials skip; revocation is checked **symmetrically** on both, at every link of the delegation chain. See [DOCUMENT-GATEWAY.md → The unified verifier](https://protocol.dfos.com/document-gateway#the-unified-verifier).

A relay MAY keep a materialized index of ingested public credentials (resource → candidate credentials) to make standing-auth lookup O(1). **That index is a performance optimization, not authority** — every candidate it yields is re-verified live before it can authorize, so a stale or revoked entry cannot grant access. It is a re-verified, non-authoritative cache over the op log, fully re-derivable from it.

A standing authorization stops granting access the moment any live check fails:

- The credential expires (temporal validity)
- The credential — or any parent in its delegation chain — is revoked
- The issuer's identity (or any delegating identity) is deleted

These are evaluated live per request, so the effect is immediate; no cache invalidation is required for correctness.

### Revocation Ingestion

Revocation artifacts (`typ: did:dfos:revocation`) are ingested via `POST /proof/v1/operations` alongside other proof plane operations. When a revocation is accepted:

1. The revoked credential's CID is recorded against its issuer
2. Standing authorization backed by that credential stops granting — the live per-request revocation check denies it on the next read (a relay that keeps a candidate index MAY also evict the entry eagerly, but the live check is what guarantees immediacy)
3. Future content chain operations embedding the revoked credential as `authorization` are rejected
4. Future content plane requests presenting the revoked credential are rejected

Revocation is permanent and immediate. See [CREDENTIALS.md](https://protocol.dfos.com/credentials) for the revocation payload format. A relay MAY additionally expose a read over the revocation index it keeps for this enforcement — see [Revocation Status](#revocation-status-v1).

### Content Following

The operation log federates the **proof plane**: identity chains, content chains, public-read credentials, and revocations are all pushed and gossiped between peers. The **content plane** — the document _bytes_ — is deliberately not on that wire. A relay MAY nonetheless make those bytes available locally by **following**: pulling the documents of the content chains it is authorized to read, content-addressed and gated by the grant. This turns a relay from a proof mirror into a true edge cache that serves public content **independently of the origin** that authored it.

Following is a per-relay, optional behavior on the content plane's own `0.x` clock; it adds **no wire surface** and changes nothing for a relay that does not opt in. The reference Go relay exposes it as `CONTENT_FOLLOW=eager` (default `none`). The shape, normatively:

- **Pull, not push.** A follower fetches blobs from its peers over the existing public blob route (`GET /content/:contentId/blob[/:ref]`). Blobs are never gossiped; there is no new endpoint.
- **The materialize gate is the serve gate.** A follower materializes a chain's bytes only while a standing public-read grant authorizes anonymous read of it — the same predicate (`hasPublicStandingAuth`) the serve path checks. So a chain that is private, revoked, or deleted is never followed.
- **Verified by hash, trustless in source.** Every pulled blob is checked against the `documentCID` the chain committed (its content address) before it is stored. A follower may therefore pull from any peer; a byte that does not hash to its committed CID is rejected.
- **Eventually consistent.** Authorization arrives instantly (the grant rides the log); the bytes arrive asynchronously. Between the two, a follower that is authorized but has not yet materialized a blob returns `404 blob not found` on `GET /content/:contentId/blob[/:ref]` — the **honest "authorized-but-not-yet-materialized" state**, not an error. A conforming follower converges to serving the bytes; it need not do so instantaneously. See [DOCUMENT-GATEWAY.md → Follower materialization](https://protocol.dfos.com/document-gateway#follower-materialization-0x).
- **Convergent, ordering-immune.** Following is driven by a sweep over the chains the follower already holds in local state, so it cannot be raced by op-ingest ordering (a credential op sequences before the content op it grants). The sweep is the correctness backbone; low-latency triggers, if any, are an optimization over it.
- **Revoke is correctness-free; GC is reclamation.** When a grant is revoked, the per-request serve gate immediately makes any cached bytes unreachable — correctness needs nothing more. Reclaiming the now-orphaned bytes (deleting them) is a separate, convergent garbage-collection pass keyed on the same gate, and is purely a storage concern.

---

## Revocation Status (v1)

A relay that enforces revocation already maintains an `(issuerDID, credentialCID)` revocation set (see [Revocation Ingestion](#revocation-ingestion)). The **revocation status** route family exposes an indexed, read-only projection of that set, so a client can ask "has this credential been revoked?" or "what has this issuer revoked?" with one GET instead of replaying the operation log.

Like the universal resolver, this family is a **frozen `v1` contract at the relay root** on its own v1 clock — it is NOT part of, and is not mounted under, the frozen `/proof/v1` proof plane. Nothing about ingestion changes: revocations remain ordinary proof-plane operations (`typ: did:dfos:revocation`), submitted via `POST /proof/v1/operations` and gossiped like everything else. A relay advertises support via `capabilities.revocations` in the well-known; when unsupported, the routes return **501 Not Implemented** (capability not supported, consistent with `content`/`log`). Both reference relays serve the index unconditionally.

### Credential Status (`GET /revocations/v1/credential/:credentialCID`)

```json
{
  "credentialCID": "bafyrei…",
  "revoked": true,
  "revocation": "eyJhbGciOiJFZERTQSIs…"
}
```

This credential-status route is frozen AS-IS.

- **`200` revoked** — includes `revocation`, the full revocation JWS token.
- **`200` not revoked** — `{ "credentialCID": "…", "revoked": false }`, no `revocation` key.
- **`400`** — the param is not a well-formed credential CID (CIDv1 dag-cbor + sha256, `bafyrei` + 52 base32 chars).

**The JWS is the proof; the boolean is a convenience.** A zero-trust caller does not take the relay's word for it: it re-verifies the returned revocation token itself — signature against the issuer's identity chain, CID integrity, kid-DID == payload `did`, and the issuer-only rule (only the credential's issuer can revoke it). The relay serves the index; the operation carries its own authority.

**Absence is NOT proof of non-revocation.** `revoked: false` is the honest known-nothing answer: it attests only that _this relay_ has not ingested a revocation for that CID. A relay can be behind, partitioned, or adversarially withholding. A caller that needs stronger assurance queries a quorum of independent relays (and gossip makes withholding progressively harder) — the same trust posture as every other read in the protocol.

If more than one issuer has revoked the same credential CID (possible, since the set is scoped per issuer and the issuer-only rule is enforced at credential verification rather than ingest), the relay MUST answer deterministically: the revocation with the lexicographically smallest `issuerDID`. Callers re-verifying the JWS against the credential's actual issuer are unaffected either way.

### Issuer Revocations (`GET /revocations/v1/issuer/:did?after={cid}&limit=N`)

```json
{
  "did": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
  "revocations": [{ "credentialCID": "bafyrei…", "revocation": "eyJhbGciOiJFZERTQSIs…" }],
  "next": null
}
```

- **`200`** — every revocation this relay has ingested for the issuer, sorted by revocation `createdAt` ascending (tiebreak `credentialCID`), forward-only cursor-paginated: `after` (a `credentialCID` cursor, omit to start from the first) and `limit` (default 100, max 1000); the response carries `next` — the `credentialCID` to pass as `after` for the next page, `null` when caught up. An issuer with none returns an empty array — same honest-absence semantics as above.
- **`400`** — the param is not a canonical 31-char `did:dfos` identifier.

---

## Index (v0)

A relay that verifies and folds chains already holds current-state projections — terminal states, standing public-read grants, per-chain logs. The **index** route family exposes read-only, cursor-paginated _queries_ over those projections: enumerate identities, filter content chains, reverse-look-up countersignatures by witness. It exists so a light client can browse and discover without replaying the global operation log — the same role the revocation status family plays for credential state, generalized.

The family lives at **`/index/v0/*`** on its own **`0.x` clock** — NOT part of the frozen `/proof/v1` proof plane, and (unlike `/revocations/v1`) not yet frozen itself. A relay advertises support via `capabilities.index` in the well-known; when unsupported (or when the flag is absent — relays predating this family), the routes return **501 Not Implemented**. Nothing about ingestion changes.

### Hints, Not Authority

Index responses are **discovery hints, never authority**. Every row carries the identifiers needed to re-derive its claims from the frozen proof plane — a client that cares fetches `GET /proof/v1/identities/:did` / `GET /proof/v1/content/:contentId` (and the per-chain logs) and folds the chain itself. The trust posture is asymmetric and worth stating precisely:

- **The index cannot lie by assertion.** Every claim in a row is verifiable against the proof plane. A fabricated row fails the client's fold.
- **The index CAN lie by omission.** A relay can be behind, partitioned, or adversarially withholding rows — and a light client cannot detect a recall gap. Absence of a row is NOT proof of absence. A caller that needs stronger recall queries a quorum of independent relays, or replays `GET /proof/v1/log` and folds locally — the full-log replay remains the audit posture that keeps every index honest.
- **Index output MUST NOT be used as an authorization input.** The `publicRead` field is a discovery hint; content plane access is always re-derived live by the gateway's unified verifier (see [DOCUMENT-GATEWAY.md](https://protocol.dfos.com/document-gateway)).

### The Structural Seam

The index is bounded by one invariant:

> **Every index field and filter MUST be computable from protocol-defined fields and verification outcomes alone. Document payloads are opaque**, except the [well-known projections](#well-known-projections) below.

Concretely, the index may serve:

- **Structural facts** the relay already computes to verify: chain kind, genesis/head CIDs, op counts, creator DIDs, deletion state, countersign witnesses and targets, credential issuer/subject/scope, revocation status, standing public-read grants, identity service entries.
- **Declared labels, matched as opaque strings**: an artifact or document `$schema`, a `ContentAnchor` `label`. The relay matches these byte-for-byte the way an HTTP server serves a `Content-Type` — it never interprets what they mean.

What the index MUST NOT do: interpret document payloads, join across application semantics, rank, or reify application concepts. There is no "posts" endpoint and never will be — an application-level notion like _post_ is a **client-composed filter expression** over structural parts (`docSchema=… & publicRead=true & creator=…`), not an index concept. This keeps the relay's query vocabulary closed while the application vocabulary composed on top stays open.

### Well-Known Projections

Exactly one exception to payload opacity exists, and it is enumerated here rather than left to implementations:

| #   | Projection          | Definition                                                                                                                                                                                                                                                                                                                                                                                         |
| --- | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `profile/v1 → name` | For an identity whose terminal `services` contain a `ContentAnchor` whose `label`, lowercased, equals `"profile"` and whose `anchor` is a content-chain identifier: if the relay holds the bytes of that chain's current head document, and the decoded document declares `$schema: "https://schemas.dfos.com/profile/v1"`, and its `name` is a non-empty string — the index surfaces that `name`. |

The projection carries structural **circuit breakers** — every escape hatch resolves to the honest unknown, never a guess:

- A document under any `$schema` NOT in this table is never field-extracted, no matter how tempting its shape.
- A listed schema whose document is malformed, whose extracted field is missing, empty, or not a string — `name: null`. No partial parses, no coercion.
- Bytes the relay does not hold — `docSchema: null`, `name: null` (see coverage, below).

Extracted values are **attribution-tier claims**: the anchor is controller-signed (strong), but the name is whatever the document says. Clients verify by fetching the chain and re-hashing the served bytes to the committed `documentCID`. Additions to this table require an amendment to this spec — a relay MUST NOT ship extraction rules that are not listed here.

### Determinism and Coverage

- **Deterministic enumeration.** Every index list is ordered lexicographically ascending by its cursor key (identity rows by `did`, content rows by `contentId`, countersign rows by countersignature `cid`). Two relays holding the same operations serve identical page ordering and identical structural fields — the same convergence property the proof plane guarantees for head state, extended to enumeration. Held-bytes-dependent fields (`docSchema`, projected values) additionally require the same held blobs to agree, per coverage below.
- **Keyset pagination.** `after` is a **strictly-greater** cursor: a page returns the rows whose (post-filter) cursor key is lexicographically **greater than** `after`, ascending, capped at `limit`; `next` is the last returned row's key, or `null` when the page was not full (caught up). The cursor need not be a currently-present key — a value that falls between keys, or names a row that was mutated out of the active filter between pages, resumes at the next greater key rather than truncating to an empty page. This makes enumeration stable under concurrent row changes: keys are immutable natural identifiers, so a row's filtered membership or projected values may change between pages without dropping or duplicating other rows.
- **Coverage is bounded by held bytes.** `docSchema` and projected fields are computable only for chains whose current head document bytes the relay holds (uploaded, or pulled via [content following](#content-following)). A chain whose bytes are absent reports `docSchema: null` — honest unknown, not a claim of schemalessness. A `docSchema` filter therefore matches only chains with held, decodable head bytes; callers MUST treat the result as a lower bound.
- **Timestamps are author-claimed.** `genesisAt` / `headAt` surface the `createdAt` fields signed inside the operations — the same values head selection uses — not relay receipt times.
- **Maintenance.** The index is fully re-derivable from the operation log plus held blobs. Reference implementations maintain it incrementally at ingestion and expose a rebuild path for pre-existing corpora; either way the serving contract is identical.
- **`publicRead` is a last-touch snapshot, and MAY lag time-based transitions.** A materialized `publicRead` reflects whether a standing public-read grant authorized anonymous read **at the moment the row was last recomputed** (its content's most recent op, or a rebuild). One input to that predicate — a grant credential's `exp` — is wall-clock-relative and crosses **without emitting any operation**, so incremental maintenance has no event to react to: a row can continue to advertise `publicRead: true` after the grant that made it public has expired, until the next op dirties that content or a rebuild reruns the projection. This is deliberately tolerated because the index is a discovery hint, never an authorization input (see [Hints, Not Authority](#hints-not-authority)) — the content plane re-derives `hasPublicStandingAuth` live on every read, where `exp` is always evaluated against the current clock. A relay MAY additionally re-sweep public rows near expiry to tighten the hint, but is not required to.

### Identities (`GET /index/v0/identities?hasPublicProfile=&after={did}&limit=N`)

Enumerates identity chains, `did` ascending.

```json
{
  "identities": [
    {
      "did": "did:dfos:hd34z9a4tf6h62864nh4f7at6hr36r4",
      "headCID": "bafyrei…",
      "opCount": 4,
      "genesisAt": "2026-03-25T00:00:00.000Z",
      "headAt": "2026-04-02T00:00:00.000Z",
      "isDeleted": false,
      "profile": {
        "anchor": "a3n7r3nde8e4keeak92rr3aeztftvc2",
        "publicRead": true,
        "docSchema": "https://schemas.dfos.com/profile/v1",
        "name": "asha"
      }
    }
  ],
  "next": null
}
```

| Field                  | Type           | Description                                                                                                                                              |
| ---------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opCount`              | number         | Operations stored for this chain, branch-inclusive (log length, not head-branch length)                                                                  |
| `genesisAt` / `headAt` | string         | Author-claimed `createdAt` of the genesis and current head operations                                                                                    |
| `profile`              | object \| null | The [well-known projection](#well-known-projections), or `null` when the identity declares no profile-labeled content-chain anchor                       |
| `profile.anchor`       | string         | The anchored contentId — the client's verification pointer                                                                                               |
| `profile.publicRead`   | boolean        | Whether a standing public-read grant currently authorizes anonymous read of the anchored chain, per this relay's fold — a hint, never an access decision |
| `profile.docSchema`    | string \| null | `$schema` declared by the held head document; `null` when bytes are not held or not decodable                                                            |
| `profile.name`         | string \| null | Extracted per the projection table; `null` on any circuit breaker                                                                                        |

Parameters: `hasPublicProfile` (optional boolean filter on the predicate "`profile` is non-null AND `profile.publicRead` is true" — `true` keeps only rows where it holds, `false` keeps only rows where it does not, absent applies no filter), `after` (a `did` keyset cursor — returns rows with `did` strictly greater), `limit` (default 100, max 1000). Multiple profile-labeled anchors resolve deterministically to the one with the lexicographically smallest service `id`.

### Content Chains (`GET /index/v0/content?creator={did}&docSchema=&documentCID=&publicRead=&after={contentId}&limit=N`)

Enumerates content chains, `contentId` ascending. All filters are ANDed exact matches.

```json
{
  "content": [
    {
      "contentId": "a3n7r3nde8e4keeak92rr3aeztftvc2",
      "genesisCID": "bafyrei…",
      "headCID": "bafyrei…",
      "creatorDID": "did:dfos:hd34z9a4tf6h62864nh4f7at6hr36r4",
      "isDeleted": false,
      "opCount": 3,
      "genesisAt": "2026-03-25T00:00:00.000Z",
      "headAt": "2026-04-02T00:00:00.000Z",
      "currentDocumentCID": "bafyrei…",
      "publicRead": true,
      "docSchema": "https://schemas.dfos.com/profile/v1"
    }
  ],
  "next": null
}
```

Parameters: `creator` (exact DID — the chain's genesis signer; `400` when malformed), `docSchema` (exact opaque string match against held head bytes — a lower bound, per coverage above), `documentCID` (exact match against the projected `currentDocumentCID` — the reverse lookup "who published this document"), `publicRead` (boolean), `after` (a `contentId` keyset cursor — returns rows with `contentId` strictly greater), `limit` (default 100, max 1000). This is the reverse lookup "what content does DID X own" plus the composition surface for application-level queries — e.g. a client's notion of _public posts by X_ is `creator=X&docSchema=<its post schema>&publicRead=true`, composed client-side.

### Countersignatures by Witness (`GET /index/v0/countersignatures?witness={did}&after={cid}&limit=N`)

The reverse of the proof plane's by-target route: every countersignature this relay has ingested **signed by** the given witness DID, ordered by countersignature CID ascending.

```json
{
  "witness": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
  "countersignatures": [
    {
      "cid": "bafyrei…",
      "targetCID": "bafyrei…",
      "relation": "endorses",
      "jwsToken": "eyJhbGciOiJFZERTQSIs…"
    }
  ],
  "next": null
}
```

`witness` is required (`400` when missing or malformed); `after` is a countersignature-`cid` keyset cursor (returns rows with `cid` strictly greater), `limit` defaults to 100 and maxes at 1000. `relation` is the countersign's open-namespace tag, `null` when omitted by the signer. Each entry carries the full JWS — self-proving, same posture as the issuer revocations feed: the caller re-verifies the token rather than trusting the row.

### Credentials (`GET /index/v0/credentials?issuer={did}&resource=&after={cid}&limit=N`)

Enumerates the relay's held public credentials, `cid` ascending.

```json
{
  "credentials": [
    {
      "cid": "bafyrei…",
      "issuerDID": "did:dfos:hd34z9a4tf6h62864nh4f7at6hr36r4",
      "att": [{ "resource": "chain:a3n7r3nde8e4keeak92rr3aeztftvc2", "action": "read" }],
      "exp": 1775088000,
      "jwsToken": "eyJhbGciOiJFZERTQSIs…"
    }
  ],
  "next": null
}
```

Parameters: `issuer` (optional exact DID — `400` when malformed), `resource` (optional exact match against an `att[].resource`; when the requested resource starts with `chain:`, the `chain:*` wildcard bucket is always unioned in because a `chain:*` grant may authorize the named chain), `after` (a credential-`cid` keyset cursor — returns rows with `cid` strictly greater), `limit` (default 100, max 1000). Filters are ANDed.

Only public credentials (`aud: "*"`) are ever held by the relay. Targeted bearer credentials never enter relay storage, so they are neither enumerable nor leakable here.

This route is amber and relay-asserted: `resource=chain:Y` returns a superset of candidates (exact `chain:Y` plus any `chain:*`). Each entry carries the full JWS — self-proving, same posture as the issuer revocations feed. The caller folds each token against the proof plane (delegation roots at Y's creator, revocation, expiry) before treating it as authorization; the relay makes no authorization claim in this index row.

### Deferred from v0

- **`/search`** — fuzzy or tokenized name search. Search semantics (normalization, ranking) are deliberately kept off this clock; if they ship, they ship as their own explicitly-unstable family, never frozen into the index contract.
- **Fork/tips visibility** — remains deferred at the proof-plane level (see [What's Deferred](#whats-deferred)).

---

## Key Resolution

The relay uses two key resolution strategies:

- **Historical resolver** (for chain re-verification): searches all keys that have ever appeared in an identity chain's log, including rotated-out keys. This is necessary because re-verifying a full content chain from genesis must resolve keys from operations signed before a key rotation.
- **Current-state resolver** (for live authentication): only resolves keys in the identity's current state. After a key rotation, the old key immediately stops working for auth tokens. This prevents a compromised rotated-out key from being used to authenticate new requests.

**Which primitive uses which resolver:**

- **Current-state resolver** — auth tokens. A rotated-out key cannot mint an auth token, preventing stale-key auth.
- **Historical resolver** — identity and content chain re-verification, artifacts, revocations, and countersignatures. These are historical facts whose signing key may since have rotated out, so they must resolve against every key that ever appeared in the chain; re-verifying them under current state would break sync of honest operations after any rotation. Their invalidation mechanism is revocation or deletion, not key rotation.
- **Credentials are the exception to the auth grouping.** Although a credential proves authorization, it uses the **historical** resolver and survives key rotation — a credential signed before a rotation remains valid afterward. Revocation (not key rotation) is the invalidation mechanism for credentials. See [CREDENTIALS.md](https://protocol.dfos.com/credentials).

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

  getBlob(key: BlobKey): Promise<Uint8Array | undefined>;
  putBlob(key: BlobKey, data: Uint8Array): Promise<void>;

  getCountersignatures(operationCID: string): Promise<string[]>;
  addCountersignature(operationCID: string, jwsToken: string): Promise<void>;

  appendToLog(entry: LogEntry): Promise<void>;
  readLog(params: {
    after?: string;
    limit: number;
  }): Promise<{ entries: LogEntry[]; cursor: string | null }>;

  // chain state at arbitrary CID (fork verification)
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

The `getIdentityStateAtCID` / `getContentStateAtCID` methods compute materialized chain state at an arbitrary operation CID. Used by fork verification — the ingestion pipeline needs state at the fork point to verify signer authority and timestamp ordering. Implementations decide how: `MemoryStore` replays from genesis, `SQLiteStore` can use snapshot tables.

The package includes `MemoryRelayStore` for development and testing. Production deployments would implement the interface over Postgres, SQLite, D1, or any durable store.

---

## Quick Start

```typescript
import { createHttpPeerClient, createRelay, MemoryRelayStore } from '@metalabel/dfos-web-relay';

// JIT mode — generates relay identity + profile artifact at startup
const relay = await createRelay({
  store: new MemoryRelayStore(),
});

// With peering
const relay = await createRelay({
  store: new MemoryRelayStore(),
  peers: [{ url: 'https://peer.relay.example.com' }],
  peerClient: createHttpPeerClient(),
});

// Mount on any Hono-compatible runtime
export default relay.app;

// Schedule sync polling
setInterval(() => relay.syncFromPeers(), 30_000);
```

The returned `CreatedRelay` includes `app` (Hono), `did` (string), and `syncFromPeers` (async function). The Hono app exposes:

| Method | Path                                        | Plane       | Auth                                      |
| ------ | ------------------------------------------- | ----------- | ----------------------------------------- |
| `GET`  | `/.well-known/dfos-relay`                   | meta        | none                                      |
| `POST` | `/proof/v1/operations`                      | proof       | none                                      |
| `GET`  | `/proof/v1/operations/:cid`                 | proof       | none                                      |
| `GET`  | `/proof/v1/countersignatures/:cid`          | proof       | none                                      |
| `GET`  | `/proof/v1/identities/:did`                 | proof       | none                                      |
| `GET`  | `/proof/v1/identities/:did/log`             | proof       | none                                      |
| `GET`  | `/proof/v1/content/:contentId`              | proof       | none                                      |
| `GET`  | `/proof/v1/content/:contentId/log`          | proof       | none                                      |
| `GET`  | `/proof/v1/log`                             | proof       | none                                      |
| `GET`  | `/1.0/identifiers/:did`                     | meta        | none                                      |
| `GET`  | `/revocations/v1/credential/:credentialCID` | revocations | none                                      |
| `GET`  | `/revocations/v1/issuer/:did`               | revocations | none                                      |
| `GET`  | `/index/v0/identities`                      | index       | none                                      |
| `GET`  | `/index/v0/content`                         | index       | none                                      |
| `GET`  | `/index/v0/countersignatures`               | index       | none                                      |
| `GET`  | `/index/v0/credentials`                     | index       | none                                      |
| `PUT`  | `/content/:contentId/blob/:opCID`           | content     | auth token                                |
| `GET`  | `/content/:contentId/blob[/:ref]`           | content     | standing auth, or auth token + credential |

---

## Peering

Relay-to-relay peering enables data replication across the network. The relay expresses peering intent through a `PeerClient` interface (injected like `Store`) and per-peer configuration flags.

### Three Behaviors

| Behavior         | Trigger          | Mechanism                                             |
| ---------------- | ---------------- | ----------------------------------------------------- |
| **Gossip-out**   | New op ingested  | Push to peers with `gossip: true`                     |
| **Read-through** | Local 404 on GET | Fetch from peers with `readThrough: true`             |
| **Sync-in**      | Scheduled poll   | Pull from peers with `sync: true` via `/proof/v1/log` |

Gossip fires on `new` status only — `duplicate` results are not re-gossiped, preventing gossip storms. Read-through applies to **identity chains** and **content chains** only — operations and countersignatures are not read-through targets. When triggered, the relay fetches the full chain log from a peer and ingests locally (full verification, no trust). Sync-in uses cursor-based pagination against the peer's global log.

### Peer Configuration

```typescript
interface PeerConfig {
  url: string;
  gossip?: boolean; // default: true
  readThrough?: boolean; // default: true
  sync?: boolean; // default: true
}
```

No relay roles or types. Topology is emergent from configuration. A relay with `gossip: true, readThrough: false, sync: false` is a write-only edge node. A relay with `gossip: false, readThrough: true, sync: false` is a read-only cache.

### PeerClient Interface

The `PeerClient` is injected like `Store` — semantic per-resource methods, not raw HTTP. The default implementation uses HTTP. Tests inject mocks that route directly to another relay's API in-process.

```typescript
interface PeerClient {
  getIdentityLog(
    peerUrl: string,
    did: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; cursor: string | null } | null>;

  getContentLog(
    peerUrl: string,
    contentId: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; cursor: string | null } | null>;

  getOperationLog(
    peerUrl: string,
    params?: { after?: string; limit?: number },
  ): Promise<{ entries: PeerLogEntry[]; cursor: string | null } | null>;

  submitOperations(peerUrl: string, operations: string[]): Promise<void>;
}
```

Each method corresponds to a peering behavior: `getIdentityLog` / `getContentLog` support read-through, `getOperationLog` supports sync-in, and `submitOperations` supports gossip-out. A `PeerLogEntry` is `{ cid: string; jwsToken: string }`.

---

## Convergence

The protocol guarantees: given the same set of operations, any relay computes the same deterministic head state. Peering (gossip, read-through, sync) replicates operations across relays. But operations may arrive before their causal dependencies — a content extension before its identity chain, a fork before the branch it forks from. A relay MUST eventually process any structurally valid operation whose causal dependencies have been processed. This is the convergence contract.

### Causal Dependencies

An operation's causal dependencies are the minimum state required for verification:

| Operation type     | Dependencies                                            |
| ------------------ | ------------------------------------------------------- |
| Identity genesis   | None                                                    |
| Identity extension | Previous identity operation (by `previousOperationCID`) |
| Content genesis    | Creator's identity chain (for key resolution)           |
| Content extension  | Previous content operation + creator's identity chain   |
| Artifact           | Signer's identity chain                                 |
| Countersignature   | Signer's identity chain + target operation              |

If all causal dependencies are present, the operation MUST be verifiable. If any dependency is missing, the operation cannot be verified yet — but it is not invalid. The relay MUST retain it and re-attempt verification when the missing dependency arrives.

### Store-Then-Verify

A relay MUST NOT discard a structurally well-formed operation because its dependencies are temporarily unavailable. The implementation strategy is store-then-verify:

1. **Store**: on receipt (via `POST /proof/v1/operations`, gossip, sync, or read-through), store the raw JWS token in a content-addressed buffer keyed by operation CID. This is idempotent — duplicate CIDs are ignored.

2. **Verify**: attempt full verification against current state. Three outcomes:
   - **Sequenced** — verification succeeded, operation committed to chain state and global log
   - **Dependency failure** — a causal dependency is missing, operation remains in the buffer
   - **Permanent rejection** — structurally invalid, bad signature, deleted identity, etc. — will never succeed regardless of what state arrives

3. **Sequence loop**: after each ingestion batch, re-attempt all buffered operations in dependency order until no further progress is made (fixed-point). This ensures cross-batch dependencies resolve immediately — when batch B provides the identity that batch A's content operation was waiting for, the sequencer resolves it within B's response cycle.

### Dependency Failures

A rejection is a dependency failure if and only if it is caused by missing state that may arrive later via peering. The set is small and stable:

- Previous operation not yet in store (`previousOperationCID` unknown)
- Identity chain not yet available (key resolution fails)
- Content chain not yet created (genesis not arrived)
- Fork state cannot be computed (ancestor in branch path not yet available)

All other rejections are permanent. Permanent rejections MUST NOT be retried.

### Serialization

All chain-state mutations (ingestion + sequencing) MUST be serialized. Concurrent ingestion of operations for the same chain produces a read-modify-write race: two goroutines read the chain log, both append their operation, and the second write clobbers the first. Raw operation storage (`putRawOp`) does not require serialization — it is idempotent and append-only.

### Convergence Bound

Given a fully connected peer mesh where every relay syncs from every other relay:

- After one sync cycle, every relay has every operation that any peer accepted (stored as raw)
- After one sequencer pass, every operation whose full dependency chain exists locally is sequenced
- Deterministic head selection ensures all relays agree on the canonical head

In practice, the dependency depth for fork operations is 1 (each op depends on its immediate predecessor). Convergence is typically achieved in a single sync + sequence cycle.

### Storage Interface (Convergence)

The `RelayStore` interface extends with methods for raw operation buffering:

```typescript
// raw ops — content-addressed store for all received operations
putRawOp(cid: string, jwsToken: string): Promise<void>;
getUnsequencedOps(limit: number): Promise<string[]>;
markOpsSequenced(cids: string[]): Promise<void>;
markOpRejected(cid: string, reason: string): Promise<void>;
countUnsequenced(): Promise<number>;
resetSequencer(): Promise<void>;
```

---

## What's Deferred

- **Peer discovery**: Static configuration only — no dynamic discovery
- **SSE/realtime push**: Polling `GET /proof/v1/log` for now, SSE in the future
- **Fork visibility API**: Dedicated endpoint to list tips/branches
- **Search**: fuzzy/tokenized name queries — deliberately excluded from the [index](#index-v0) contract; would ship as its own explicitly-unstable family
- **Branch termination op**: Protocol-level operation to explicitly kill fork branches
- **Rate limiting / anti-spam**: Operational concern, not protocol concern
- **Blob size limits**: No enforcement yet — production deployments should add limits at the middleware layer
- **Artifact `$schema` registry**: Schema names are free-form strings for now — no formal registry or validation beyond structural checks
