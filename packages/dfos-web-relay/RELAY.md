# DFOS Web Relay

> **Version 0.4.0** · _2026-03-24_

An HTTP relay for the DFOS protocol — receives, verifies, stores, and serves identity chains, content chains, beacons, countersignatures, and content blobs.

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

Signed chain operations, beacons, and countersignatures. These are cryptographic proofs — anyone can verify them with a public key. The proof plane gossips freely: relays push operations to peers, peers verify and store independently.

All proof plane routes are unauthenticated. The operations themselves carry their own authentication (Ed25519 signatures).

### Content Plane (private)

Raw content blobs — the actual documents that content chains commit to via `documentCID`. The content plane never gossips. Blobs are stored by the relay that received them and served only to authorized readers.

Content plane access requires two credentials:

- **Auth token**: A DID-signed JWT proving the caller controls an identity (AuthN)
- **Read credential** (for non-creators): A `DFOSContentRead` VC-JWT issued by the content creator, granting the caller read access (AuthZ)

The content creator (the DID that signed the genesis content operation) can always read their own blobs with just an auth token.

---

## Operation Ingestion

All proof plane artifacts enter through a single endpoint: `POST /operations`. The request body is an array of JWS tokens — identity operations, content operations, beacons, and countersignatures can be mixed freely in the same batch.

### Classification

Each token is classified by its JWS `typ` header:

| `typ` header           | kid DID == payload DID? | Classification           |
| ---------------------- | ----------------------- | ------------------------ |
| `did:dfos:identity-op` | —                       | Identity chain operation |
| `did:dfos:content-op`  | yes                     | Content chain operation  |
| `did:dfos:content-op`  | no                      | Countersignature         |
| `did:dfos:beacon`      | yes                     | Beacon announcement      |
| `did:dfos:beacon`      | no                      | Beacon countersignature  |

When the signing key's DID differs from the payload DID, the operation is classified as a countersignature (witness attestation) rather than a primary operation.

### Dependency Sort

Within a batch, operations are sorted by dependency priority before processing:

1. **Identity operations** — must be processed first so their keys are available
2. **Beacons** — reference identity keys
3. **Content operations** — reference identity keys for signature verification
4. **Countersignatures** — reference both identity keys and existing operations

Within each priority level, genesis operations (no `previousOperationCID`) are processed before extensions. This ensures that a single batch can bootstrap an entire identity-and-content lifecycle — including chained create + update operations — without multiple round trips.

### Verification

Each operation is verified against the relay's stored state:

- **Identity operations**: The full chain (stored log + new operation) is re-verified from genesis. The relay uses `verifyIdentityChain()` from the protocol library
- **Content operations**: The full chain is re-verified with `enforceAuthorization: true`. Non-creator signers must include a `DFOSContentWrite` VC-JWT
- **Beacons**: Signature, CID integrity, and clock skew are verified. Replace-on-newer: only the most recent beacon per DID is retained
- **Countersignatures**: The referenced operation or beacon must already exist. Signature is verified against the witness DID's identity chain
- **Beacon countersignatures**: The referenced beacon must exist and the countersignature CID must match the current beacon CID

### Fork Policy

First-seen-wins. If a chain head has already advanced past the `previousOperationCID` referenced by an incoming operation, the new operation is rejected. The relay does not attempt to resolve forks — the first valid extension wins.

Duplicate submissions (same operation CID, same JWS token) are silently accepted (idempotent). Submissions with the same CID but a different JWS token are rejected — since Ed25519 is deterministic, a different token for the same payload means a different signing key, which is either a self-countersign attempt or an unauthorized re-sign.

Duplicate countersignatures (same witness DID, same target CID) MUST be deduplicated. The relay MUST NOT increase the countersignature count on resubmission. Resubmission SHOULD return `accepted` (idempotent).

### Deletion Semantics

Deletion means the identity stops being an active participant. Historical operations remain verifiable — keys persist in state for signature verification — but no new acts flow from a deleted identity.

Specifically:

- **Identity operations after deletion**: Rejected. A deleted identity chain is sealed.
- **Content operations after deletion**: Rejected. A deleted content chain is sealed.
- **Beacons from deleted identities**: Rejected. A deleted identity MUST NOT publish new beacons.
- **Credentials from deleted issuers**: Rejected. Identity deletion revokes all authority, including outstanding `DFOSContentRead` and `DFOSContentWrite` credentials issued by the deleted identity. Credentials that were valid at time of issuance cease to be honored once the issuer is deleted.
- **Countersignatures on existing operations**: Still accepted. Deletion of the original author does not prevent other identities from attesting to operations that already exist in the relay.

Self-countersignatures — where the witness DID matches the operation author DID — are rejected. A countersignature's semantic is "a distinct witness attests." Signing your own operation is redundant with the original signature.

### Result Ordering

Ingestion results are returned in the same order as the input `operations` array, regardless of internal processing order. `results[i]` corresponds to `operations[i]`.

---

## Relay Identity

Every relay has a DID, published at `GET /.well-known/dfos-relay`. The relay DID serves as:

- **Auth token audience**: Auth tokens are scoped to a specific relay via the JWT `aud` claim, preventing cross-relay token replay
- **Peer identity**: When relays gossip proof plane data to each other, the relay DID identifies the peer

The relay does not currently sign operations or participate in the protocol as an identity. It's a passive verifier and store.

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
}
```

The package includes `MemoryRelayStore` for development and testing. Production deployments would implement the interface over Postgres, SQLite, S3, or any durable store.

---

## Quick Start

```typescript
import { createRelay, MemoryRelayStore } from '@metalabel/dfos-web-relay';

const relay = createRelay({
  relayDID: 'did:dfos:myrelay00000000000000',
  store: new MemoryRelayStore(),
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
| `GET`  | `/content/:contentId`                | proof   | none                    |
| `GET`  | `/beacons/:did`                      | proof   | none                    |
| `PUT`  | `/content/:contentId/blob/:opCID`    | content | auth token              |
| `GET`  | `/content/:contentId/blob[/:ref]`    | content | auth token + credential |

---

## What's Deferred

- **Peer gossip**: Proactive push of proof plane operations to other relays
- **Rate limiting / anti-spam**: Operational concern, not protocol concern
- **Docker/CF reference deployments**: Focus on the core library first
- **Pagination**: Chain logs are returned in full — fine for v1, needs pagination at scale
- **Blob size limits**: No enforcement yet — production deployments should add limits at the middleware layer
