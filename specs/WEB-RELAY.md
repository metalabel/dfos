# DFOS Web Relay

An HTTP relay for the DFOS protocol — receives, verifies, stores, and serves identity chains, content chains, artifacts, countersignatures, and content blobs.

> **Status — reference relay behavior, on its own `0.x` clock.** This document specifies how the reference relay behaves: ingestion, convergence, peering, key-resolution mechanics, the content plane, and the optional route families. None of it is frozen. The **frozen wire surface** — the `/proof/v1` routes, `/revocations/v1`, their request/response shapes, and the pagination envelope — is [RELAY-CONTRACT.md](https://protocol.dfos.com/relay-contract), frozen with Protocol v1; and the verification semantics a relay enforces are normative in the core specs ([PROTOCOL.md → Chain Validity](https://protocol.dfos.com/spec#chain-validity) and [Admission and Re-Verification](https://protocol.dfos.com/spec#admission-and-re-verification), [CREDENTIALS.md](https://protocol.dfos.com/credentials)). A courier holds no frozen guarantees of its own — everything frozen here lives in the contract or the core, and this document narrates the behavior around them. The non-frozen surfaces hold one uniform shape: every list route uses the contract's `limit` + `after` + `next` envelope, so adopters integrate against one pagination contract, never per-route variants. Discuss in the [DFOS](https://nce.dfos.com) space.

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

A relay's content plane **is** a document gateway — a stateless, content-addressed blob store whose authorization is re-derived live from the proof plane; the full contract is [below](#content-plane--document-gateway). The served blob is the document itself — whether terminal (the bytes _are_ the content) or referential (the document points at external bytes, e.g. `ipfs://` or a signed-CDN reference). The relay never resolves a referential pointer; delivery of referenced media is out of protocol.

Content plane access separates authentication from authorization:

- **Identity proof** ([API-AUTH](https://protocol.dfos.com/api-auth#the-identity-proof)): a request-bound `did:dfos:identity-proof` JWS proving the caller controls an identity (AuthN)
- **Read credential** (for non-creators): A DFOS credential with `action: "read"` attenuations, issued by the content creator (or delegated via chain), granting the caller read access (AuthZ). Can be presented per-request or ingested as a standing authorization (see [Standing Authorization](#standing-authorization) below)

The content creator (the DID that signed the genesis content operation) can always read their own blobs with just an identity proof.

Content plane support is optional per relay. When disabled (`capabilities.content: false` in the well-known response), all content plane routes return **501 Not Implemented** — not 404 (resource doesn't exist), but 501 (capability not supported).

---

## Route Namespacing

Every proof plane route is namespaced under a single prefix, **`/proof/v1`** — the routes, their shapes, and the freeze itself are [RELAY-CONTRACT.md](https://protocol.dfos.com/relay-contract)'s. The prefix encodes the plane and its version (`{plane}/{version}`), so the frozen clock is legible in the URL and the plane mounts or proxies as a unit by prefix.

Six route families deliberately stay at the root, on their own clocks:

- **`GET /.well-known/dfos-relay`** — discovery (RFC 8615) lives at the root by convention; it announces the base and the relay's own release version.
- **Content plane routes** (`/content/:contentId/blob[/:ref]`) — these belong to the **[content plane / document gateway](#content-plane--document-gateway)**, an optional surface on a `0.x` clock independent of the protocol freeze. They remain at the root under `/content/:contentId` because they belong to that clock, not the frozen proof plane. Note the resulting split: the proof node owns the bare chain-state paths `GET /proof/v1/content/:contentId` and `/proof/v1/content/:contentId/log`; the document gateway owns the `/content/:contentId/blob*` sub-paths. They are distinct namespaces that a reverse proxy can fan by prefix when the planes are split across origins.
- **Universal resolver** (`GET /1.0/identifiers/:did`) — the DID-core / DIF Universal Resolver binding on its own `1.0` clock (the DIF driver interface version, [DID-METHOD.md](https://protocol.dfos.com/did-method) §5.2.4). It is an additive, read-only projection of the same self-certified terminal state the proof plane serves at `/proof/v1/identities/:did`, rendered as a W3C DID Document. It stays at the root because it tracks the DIF driver clock, not the frozen proof plane.
- **Revocation status** (`GET /revocations/v1/credential/:credentialCID`, `GET /revocations/v1/issuer/:did`) — an indexed, read-only projection of the relay's revocation set on its own frozen `v1` clock. Revocations still _enter_ through the frozen proof plane (`POST /proof/v1/operations`); this family only exposes a read over the index the relay already maintains for its own credential enforcement. See [Revocation Status](#revocation-status).
- **Index** (`GET /index/v0/*`) — an optional, non-authoritative query surface over the current-state projections the relay already folds: enumerate identities, filter content chains, reverse-look-up countersignatures by witness. On its own unfrozen `0.x` clock, gated by `capabilities.index`. See [Index (v0)](#index-v0).
- **Signing mailbox** (`/signing/v0/*`) — an optional, opt-in courier for [sign requests](https://protocol.dfos.com/signing): deposit, poll, respond, decline. On the SIGNING spec's own unfrozen `0.x` clock — legible in the path exactly as `/index/v0`'s — gated by `capabilities.signing` (default off). Courier state is not proof plane — nothing deposited there is gossiped, indexed, or folded. Routes and semantics live entirely in [SIGNING.md](https://protocol.dfos.com/signing).

## Error Responses and Pagination

The uniform error body (`{ "error": "<prose>" }`, status codes contractual, message text never), the pagination envelope (`limit` + `after` + `next`), and the three cursor conducts — relay-local positional (400 on foreign cursors), transparent keyset (foreign cursors resume safely), opaque token (undecodable is 400) — are [RELAY-CONTRACT.md](https://protocol.dfos.com/relay-contract)'s. The unfrozen families adopt them unchanged: `/index/v0/*` is transparent-keyset in its lexical default and opaque-token in ordered mode, and the signing poll is opaque-token. No new route family invents another envelope.

---

## Authentication

The relay owns **no authentication grammar**. Every authenticated request consumes the [API-AUTH](https://protocol.dfos.com/api-auth) envelope family — the request-bound possession proofs any DFOS-gated HTTP surface uses — and every route sits in exactly one of three tiers:

| Tier               | Wire                                                       | Routes                                                                                                                                                                            |
| ------------------ | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Public**         | nothing                                                    | every [RELAY-CONTRACT](https://protocol.dfos.com/relay-contract) read, index and revocation reads, publicly-granted blob reads, sign-response collect (CID knowledge) and decline |
| **Identity proof** | `Authorization: DFOS <did:dfos:identity-proof JWS>`        | creator's own blob reads, blob upload, the mailbox poll, the AuthN half of non-public blob reads — and optionally [ingestion](#ingestion-admission), per admission policy         |
| **Credential**     | `X-Credential` presentation, or an ingested standing grant | non-creator blob reads (alongside the identity proof), mailbox deposit ([SIGNING](https://protocol.dfos.com/signing)) — the ordinary credential machinery, unchanged              |

Verification is API-AUTH's, verbatim: the relay's **own configured authority** is the `host` binding (a relay serving several hostnames selects the expected one from its own configuration, never from a request header), presenter resolution is current-state against the relay's local store, and the freshness window is the relay's to own. A route that requires a credential rejects an identity proof at the typ gate and vice versa; nothing here re-specifies the envelope.

**The `jti` replay cache is REQUIRED on every write-shaped proof.** An identity proof presented to a write-shaped surface — [ingestion](#ingestion-admission), blob upload — MUST carry the `jti` member, recorded by the relay with API-AUTH's atomic insert-if-absent discipline and expired with the freshness window. The reason is the [admission ladder](#ingestion-admission): policy runs **before** full verification, so the relay grants admission-layer effects (quota spend, reputation attribution) before it knows whether the payload is a harmless duplicate — a write-shaped surface never borrows its replay posture from downstream idempotency. Read-shaped proofs (blob reads, the mailbox poll) rely on the freshness window alone, per API-AUTH's accepted bound.

---

## Operation Ingestion

All proof plane operations enter through a single endpoint: `POST /proof/v1/operations` — request/response shapes, batch caps, and the three ingestion statuses are [RELAY-CONTRACT.md → Submission](https://protocol.dfos.com/relay-contract#submission-post-proofv1operations). Identity operations, content operations, artifacts, and countersignatures mix freely in one batch; gossiping peers chunk larger runs to stay within the caps. This section is the behavior behind the endpoint: how a relay classifies, sorts, verifies, and routes what arrives.

### Ingestion Admission

Who may ingest is a **policy axis**, not a fixed rule — and peers are not special: gossip-in, client submission, and open deposit are one door with one grammar. A submission arrives in one of two **admission modes** — **anonymous** (no proof) or **identity-proven** (an [identity proof](#authentication) signed by the submitting party's own DID, `jti` required) — and the relay evaluates a **relay-local admission policy** over what it now knows: a proven principal, or anonymity. Policy MAY refuse either mode. Policy _content_ is operator-defined and out of this spec: one relay admits only DIDs its operator recognizes, another is open-anonymous under quotas, another is allowlist-only; "my peers" is one possible policy set, not a separate authentication scheme.

**The evaluation ladder is normative, cheapest first:**

1. **Structural caps** — batch size, body size, token shape. Failures are **400**/**413**.
2. **Proof verification**, when a proof is presented — one signature plus a current-state key resolution. An invalid proof is **401**; an unresolvable presenter is **503**.
3. **Admission policy** over (principal | anonymous). A refusal is **403** with the ordinary error body — _policy-refused_, distinguishable from malformed (400), from an invalid proof (401), from unverifiable (503), and from capability-off (501). Refusal is request-level: nothing in the batch is examined further, and no per-item results are produced. A policy that cannot be evaluated fails **closed** (503 — the server's condition, not a judgment on the caller).
4. **Full verification** — the per-item chain and signature work of the sections below, only for admitted submissions. The expensive step is never spent on a submission policy refuses.

The well-known's [`ingestion` member](#well-known-endpoint-get-well-knowndfos-relay) advertises the mode so a client knows before attempting: `"open"` (anonymous submissions admitted, subject to policy), `"proof-required"` (anonymous refused at step 3), or `"closed"` (no external ingestion — `POST /proof/v1/operations` answers 501, as under `capabilities.write: false`). Advertisement is a hint; the policy decision is the authority.

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

**Content chains fork; identity chains do not.** This section is the content-chain rule; the identity-chain rule is [Identity Linearity and Order Authority](#identity-linearity-and-order-authority) below.

Content-chain forks are accepted. If an incoming content operation's `previousOperationCID` references any operation in the chain (not just the current head), the relay verifies the extension against the chain state at that fork point and accepts it. The chain log accumulates all branches.

**Deterministic head selection**: after accepting a fork, the relay recomputes the head — highest `createdAt` among tips, lexicographic highest CID as tiebreaker. This is deterministic across relays given the same set of operations, regardless of ingestion order. As forks propagate via peering, all relays converge to the same head.

**State at fork point**: to verify a fork extension, the relay computes chain state at the parent CID. The Store interface abstracts this via `getContentStateAtCID` — implementations choose the strategy (full replay, snapshot-backed, etc.).

**Content-chain deletes stay per-branch**: a content `delete` seals its own branch, forks rooted at a pre-delete operation remain valid, and head selection may make a non-deleted branch the head (PROTOCOL.md "Terminal States"). Identity undeletion is **not** a fork behavior — it is the explicit `restore` operation on the linear identity chain (see [Deletion Semantics](#deletion-semantics)).

**Future timestamp guard**: Identity and content operations with a `createdAt` more than 24 hours in the future are rejected. Since head selection favors the highest timestamp, a far-future `createdAt` would permanently dominate content-chain head selection — a temporal denial-of-service. The 24-hour window accommodates clock drift while preventing abuse. (Identity chains select no head, but the same bound applies to their operations — one admission rule, no per-kind exception.)

### Identity Linearity and Order Authority

Identity chains are strictly linear (PROTOCOL.md "Chain Validity"). The relay enforces this at ingest:

**Conflicting extension → permanent rejection.** An incoming identity operation whose `previousOperationCID` references an operation that already has a committed child is refused with the named error `identity chains are linear: conflicting extension refused`. This is a **permanent rejection**, not a dependency failure: it is not buffered, not retried, and never admitted later — first-seen wins locally, whatever the competing operation's `createdAt` claims. The rule holds on every path an identity operation arrives by — direct submission, gossip, sync, and read-through. A peer-log identity operation that conflicts with a locally-committed extension is refused identically: committed identity order is never auctioned or re-arbitrated. (Historical admission of committed logs is otherwise unchanged — see [Key Resolution](#key-resolution).)

**The home relay is the order authority.** The order-authority rule is core protocol, normative in [PROTOCOL.md → Chain Validity](https://protocol.dfos.com/spec#chain-validity): the subject's services-listed relay is the order authority for its identity chain, committed identity order is never auctioned or re-arbitrated by timestamp, what is single-writer is ordering (not read availability), an identity write during a home-relay outage is at-risk-until-retry, and an identity whose `services` names no relay is controller-attested end to end under [SIWD's carried-chain rules](https://protocol.dfos.com/siwd#carried-identity-chains). What this section adds is the relay's enforcement mechanics: first-seen is this relay's local admission mechanism, the permanent rejection above is how the rule lands at ingest, and what it closes is exactly the pathological case — an identity concurrently extended through multiple writers with the same controller key, settled by timestamp auction.

### Ingestion Statuses

The three statuses (`new` / `duplicate` / `rejected`) and their exact semantics — including the same-CID-different-token rejection — are the [contract's](https://protocol.dfos.com/relay-contract#submission-post-proofv1operations). One relay-behavior rule rides on top: duplicate countersignatures (same witness DID, same target CID) MUST be deduplicated — one countersign per witness per target, the relay MUST NOT store multiple attestations from the same witness for the same target, and resubmission SHOULD return `duplicate` (idempotent).

### Deletion Semantics

Deletion means the identity stops being an active participant. Historical operations remain verifiable — keys persist in state for signature verification — but no new acts flow from a deleted identity.

**The one exception, stated once for every gate below:** a **`restore`** identity operation in exactly the successor-of-delete position (`previousOperationCID` = the delete's CID, signed by a controller key of the deleted head state — PROTOCOL.md "Identity Operations") is the single operation a deleted identity's chain accepts. A valid restore returns the identity to active: resolution reports `deactivated: false`, and every deleted-identity gate below reopens for operations that follow it. No other operation, of any kind, passes any of these gates while the identity is deleted.

Specifically:

- **Identity operations after deletion**: Rejected, except a valid `restore` as the immediate linear successor of the `delete`. Anything else appended after a delete — including a `restore` anywhere but that position, or a `restore` signed by a key not in the deleted head state — is permanently rejected. The `delete`, and any `restore`, remain permanently in the linear log.
- **Content operations after deletion**: Rejected. Both paths are checked: (a) the signer's identity is deleted — no operations from that DID are accepted, and (b) the content chain's creator identity is deleted — the chain is sealed regardless of who signs.
- **Artifacts from deleted identities**: Rejected. A deleted identity MUST NOT publish new artifacts.
- **Credentials from deleted issuers**: Rejected. Identity deletion suspends all authority, including outstanding DFOS credentials issued by the deleted identity. Credentials that were valid at time of issuance cease to be honored while the issuer is deleted.
- **Countersignatures from deleted witnesses**: Rejected. A deleted identity MUST NOT publish new countersignatures. Countersignatures on operations by deleted authors are still accepted — deletion of the target's author does not prevent other identities from attesting.

**Restore resurrects, revocation terminates.** Deletion is a suspension of authority, reversible by `restore`; revocation is permanent. After a valid restore, credentials issued by the identity **before the delete are honored again** (they were never revoked — their issuer was suspended), the identity's chains accept operations again, and artifacts and countersignatures flow again. A credential the issuer actually revoked stays revoked forever, restore or not.

Self-countersignatures — where the witness DID matches the target's author DID — are rejected at the relay level. A countersignature's semantic is "a distinct witness attests." The protocol-level verifier is stateless and does not enforce this; the relay resolves the target's author and rejects self-attestation.

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

One route serves countersignature data — `GET /proof/v1/countersignatures/:cid`, shape and cursor conduct per [RELAY-CONTRACT.md → Countersignatures](https://protocol.dfos.com/relay-contract#countersignatures-get-proofv1countersignaturescidaftercidlimitn). The row shape matches per-chain log entries, so a generic client handles both identically.

---

## Relay Identity

Every relay has a DID that resolves on its own proof plane. The relay DID serves as:

- **Peer identity**: When relays gossip proof plane data to each other, the relay DID identifies the peer — on the wire, a gossiping peer authenticates like any client: anonymously, or with an identity proof signed by its own DID (see [Authentication](#authentication))
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
    "index": true,
    "signing": false
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

| Field                      | Type           | Description                                                                                                                                                                                                                                                       |
| -------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `did`                      | string         | The relay's DID, resolvable on this relay's proof plane                                                                                                                                                                                                           |
| `protocol`                 | string         | Protocol identifier, always `"dfos-web-relay"`                                                                                                                                                                                                                    |
| `version`                  | string         | The relay's own release version (semver), independent of the frozen proof-plane clock — the proof version lives in the `/proof/v1` path prefix, not here                                                                                                          |
| `capabilities`             | object         | Capability flags for optional features                                                                                                                                                                                                                            |
| `capabilities.proof`       | boolean        | MUST be `true`. A relay without proof plane capability is not a relay                                                                                                                                                                                             |
| `capabilities.write`       | boolean        | Whether the relay accepts writes via `POST /proof/v1/operations`                                                                                                                                                                                                  |
| `capabilities.content`     | boolean        | Whether the relay supports the content plane (blob upload/download)                                                                                                                                                                                               |
| `capabilities.log`         | boolean        | Whether the global operation log is available (`GET /proof/v1/log`)                                                                                                                                                                                               |
| `capabilities.revocations` | boolean        | Whether the [revocation status](#revocation-status) index is served (`GET /revocations/v1/*`). Reference relays serve it by default; a relay MAY disable it (501). An absent flag reads as `true` (the family predates the flag)                                  |
| `capabilities.index`       | boolean        | Whether the [index](#index-v0) query family is served (`GET /index/v0/*`). An absent flag (a relay predating the family) reads as `false`                                                                                                                         |
| `capabilities.signing`     | boolean        | Whether the [signing mailbox](https://protocol.dfos.com/signing) courier is served (`/signing/v0/*`). Opt-in: reference relays default it off, and an absent flag reads as `false`                                                                                |
| `ingestion`                | string         | [Admission-mode](#ingestion-admission) hint: `"open"` (anonymous submissions admitted, subject to policy), `"proof-required"` (identity proof required), or `"closed"`. Absent derives from `capabilities.write`: `true` reads as `"open"`, `false` as `"closed"` |
| `profile`                  | string         | The relay's profile artifact as a compact JWS token — self-proving payload                                                                                                                                                                                        |
| `peers`                    | array          | OPTIONAL additive telemetry. Configured peer relays surfaced for mesh discovery; reference relays emit `[]` when no peers are configured                                                                                                                          |
| `peers[].endpoint`         | string         | OPTIONAL additive telemetry. The peer relay's base URL. A future `peers[].did` MAY appear once a relay resolves peer DIDs                                                                                                                                         |
| `stats`                    | object         | Operational counters. `stats.pendingOps` is the count of operations pending processing (`-1` if unavailable)                                                                                                                                                      |
| `stats.opCount`            | number         | OPTIONAL additive telemetry. Total entries in the global operation log                                                                                                                                                                                            |
| `stats.countsByKind`       | object         | OPTIONAL additive telemetry. Global-log counts by primitive kind; reference relays emit `identity`, `content`, `artifact`, `credential`, `countersign`, `revocation`                                                                                              |
| `stats.oldestOpAt`         | string \| null | OPTIONAL additive telemetry. `createdAt` of the oldest-position global-log entry, or `null` when the log is empty                                                                                                                                                 |
| `stats.headCid`            | string \| null | OPTIONAL additive telemetry. CID of the global-log tip, or `null` when the log is empty                                                                                                                                                                           |
| `stats.peerSync`           | object         | OPTIONAL additive telemetry. Per-peer sync state keyed by endpoint: `lastAttemptAt`, `lastSuccessAt`, `lastReceived`, `lastInserted`, `caughtUp`, `consecutiveFailures`, `lastReconcile*`; absent when no sync peer is configured                                 |

`capabilities.proof: false` is not a valid value. A compliant relay always serves the proof plane. When `capabilities.log: false`, `GET /proof/v1/log` returns **501 Not Implemented**. Per-chain logs are always available regardless of this setting. When `capabilities.content: false`, all content plane routes return **501 Not Implemented**. When `capabilities.revocations: false`, the `/revocations/v1/*` routes return **501 Not Implemented** — the same capability-not-supported semantics. When `capabilities.index` is `false` or absent, the `/index/v0/*` routes return **501 Not Implemented**. When `capabilities.signing` is `false` or absent, the `/signing/v0/*` routes return **501 Not Implemented**. Credential and revocation ingestion are always enabled on the proof plane — they enter through `POST /proof/v1/operations` like all other operation types.

Capability gates fire **first** — before authentication, body parsing, or any store lookup — uniformly across every gated family. Where two gates stack (content-plane blob upload is gated by `content` and then `write`), the plane-existence gate fires before the write gate.

### Lite (pull-only) node — `capabilities.write: false`

A relay MAY run as a **lite pull-only proof node**: it verifies, stores, and serves the proof plane, but accepts **no writes**. When `capabilities.write: false`, `POST /proof/v1/operations` returns **501 Not Implemented**. Because that endpoint is _both_ the client-write and the peer-gossip-ingest path (a gossiping peer POSTs operations here, and nothing in the request distinguishes a first-party submission from a peer push), refusing it disables **gossip-in along with client writes**. Such a node stays current by **pulling**: `syncFromPeers` polls its peers' `/proof/v1/log` and ingests verified operations locally. This is the smallest, safest mesh citizen — a tiny attack surface (no untrusted write endpoint) that still contributes verification and availability. All read routes behave normally. `dfos serve --no-write` runs this mode.

**`capabilities.write: false` means the node accepts no writes of any kind.** It gates **every** write route, on both planes: `POST /proof/v1/operations` (proof plane) and `PUT /content/:contentId/blob/:ref` (content-plane blob upload; the ref MUST be the committing operation CID) both return **501 Not Implemented**. Blob upload is the one route that accepts a multi-megabyte body, so leaving it open on a node whose whole point is a minimal attack surface would contradict the advertised capability.

To be precise about what "writes" quantifies over: the two **replicated planes** — proof-plane ingestion and content-plane blob upload, the routes enumerated above. The optional [signing mailbox](https://protocol.dfos.com/signing) is on neither plane (courier state: never gossiped, never folded, retention bounded by each request's own expiry) and is governed solely by `capabilities.signing`. A `write: false` relay MAY therefore serve the mailbox; its no-ingest invariant is exactly "this relay never ingests proof-plane operations," and SIGNING.md's deposit gate — credential-authorized, byte-capped, verify-then-discard — is what keeps that invariant true on a node that couriers signing traffic.

The two flags gate different things and compose:

| Flags                          | Result                                                                                  |
| ------------------------------ | --------------------------------------------------------------------------------------- |
| `write: false`                 | No writes on either plane. Content-plane **reads** (blob download) still serve normally |
| `content: false`               | The content plane is absent entirely — all content routes 501, reads included           |
| `write: false, content: false` | A proof-plane-only, read-only node                                                      |

`capabilities.content` still governs the content plane **as a whole** (its reads included); `capabilities.write` governs only the act of writing.

---

## Operation Log

The relay maintains a global append-only operation log: every successfully ingested operation is appended in ingestion order, and identity and content chains expose per-chain log views in chain order. Routes, entry shapes, the `chainId`-is-not-a-partition-key caveat, and cursor conduct are [RELAY-CONTRACT.md → Logs](https://protocol.dfos.com/relay-contract#logs). The global log is what sync-in pulls (see [Peering](#peering)): self-contained JWS entries, forward-only, relay-local cursors.

---

## Identity and Content State

The state endpoints return projected state — the computed result of replaying the chain — without embedding the full operation log; shapes per [RELAY-CONTRACT.md](https://protocol.dfos.com/relay-contract#identity-state-get-proofv1identitiesdid). Two behavior notes: resolved identity state includes the identity's `services` projected from the winning head ([Services](https://protocol.dfos.com/spec#services)), and read-through and sync replicate the underlying operations, so a peer that fetches a chain recomputes the same projection deterministically. The content-state response deliberately carries no derived authorization material — public-read discovery (surfacing the `aud: "*"` credentials that currently authorize `read` on a chain) is a **document gateway** concern on the `0.x` clock, kept off the frozen route so the ergonomic can evolve without touching the locked contract (see [Public-read discovery](#public-read-discovery-0x)).

---

## Content Plane — Document Gateway

> A relay's content plane **is** the document gateway — one surface, one contract. This section is that contract (it absorbs the retired standalone DOCUMENT-GATEWAY spec; the old `/document-gateway` URL redirects here).

The content plane is the relay's read/write face for document bytes — the **preimages** of the `documentCID`s content chains commit to. It is deliberately dumber than the proof plane: no chains of its own, no signatures of its own, no gossip, no operation log. It does exactly two things — **stores bytes** addressed by a committed `documentCID`, and **serves bytes** to readers it can verify are authorized, where "authorized" is a judgment re-derived live from the proof plane on every request, never trusted from a stored flag. Everything that gives a document _meaning_ — which chain it belongs to, who committed it, who may read it — lives in the proof plane, and the governance invariant runs one way: capability flows up from frozen primitives; the protocol never reaches down to the content plane.

A reverse proxy can split the planes across origins — the proof node owns `GET /proof/v1/content/:contentId` and `/log`; the content plane owns the `/content/:contentId/blob*` sub-paths. Performance is a deployment question, not an architectural one: co-located, proof-plane reads are local; split across origins they ride the network, optionally fronted by a **TTL cache** with bounded, stated staleness — a performance optimization that is always re-verifiable and never authoritative state.

### Terminal and referential documents

A document the content plane serves is either **terminal** — the `{ $schema, … }` blob _is_ the content — or **referential** — a document that describes _how to fetch_ external bytes: an `ipfs://` CID, or an opaque `attachment://<id>` resolved by an out-of-protocol signed-CDN API, optionally carrying a hash of the target bytes so a consumer can re-bind delivery to the committed reference. The relay serves the document blob either way and **never resolves a referential pointer** — dereferencing is _delivery_, and delivery lives outside the protocol. There is no media server here: no range requests, no partial content, no streaming surface, no minting of CDN URLs. Media is a content-schema convention ([CONTENT-MODEL.md → Media object](https://protocol.dfos.com/content-model#media-object)), never a relay primitive.

### Discovery

A reader finds a content-plane host through the identity's `services` vocabulary ([PROTOCOL.md → Services](https://protocol.dfos.com/spec#services)). Two open-namespace service types serve it — additive, requiring no protocol or relay change, both indexed in the [extension registry](https://protocol.dfos.com/extensions):

| Service `type`        | Fields           | Meaning                                                                                         |
| --------------------- | ---------------- | ----------------------------------------------------------------------------------------------- |
| `DfosDocumentGateway` | `endpoint` (URL) | Base URL of a content-plane host serving this identity's content                                |
| `DfosProfile`         | `anchor`         | The identity's profile document — a 31-char contentId (living chain) or a `baf…` CID (artifact) |

A resolver replays the identity chain to current state, reads the `DfosDocumentGateway` endpoint, and requests the document. `DfosProfile` dispatches by shape exactly as `ContentAnchor` does: a contentId resolves to a content chain (a living, updatable profile), a CIDv1 resolves to an artifact (an immutable snapshot). Discovery and authorization stay orthogonal.

### Statelessness

The content plane holds **no authoritative authorization state**: every decision is re-derived live from the proof plane, so nothing it stores can be served stale. This is read-coupling, not state-coupling, and the coupling is correct — you cannot decouple a verifier from the source of the mutable, revocable keys it verifies against; decoupling would mean either caching authority (drift) or ignoring mutability (honoring rotated-out keys and revoked grants). A relay MAY keep a materialized index of ingested public grants as a **performance optimization** — an O(1) candidate lookup whose every candidate is re-verified live before it can authorize anything; a stale or revoked entry cannot grant access, because the live re-verify rejects it. The index is a cache over the proof-plane op log, fully re-derivable from it — never a source of truth.

### The unified verifier

Authorization is **one routine**. Both the public path and the delegated path reduce to the same verification — the only difference is _where the credential came from_:

```
verify(credential, resource, action):
  resolve issuer keys from the proof plane      # required for any signature check
  check the credential signature
  check the delegation chain roots at the content creator
  check not expired
  check not revoked — for EVERY link in the prf delegation chain
  → authorized iff all checks pass
```

- **Public path.** The reader presents no credential. The relay derives the public credentials (`aud: "*"`) covering the chain from the proof plane it already reads — public credentials are ordinary proof-plane operations, so no separate grant table is authority — and runs each through the verifier. A surviving public grant authorizes the read. Crucially, the relay works from the **credentials themselves**, never a pre-chewed `publiclyReadable: true`: the proof plane provides _data_; the verifier makes the _decision_.
- **Delegated path.** The reader presents a DFOS credential in the `X-Credential` header. The same verifier runs over it, including the same per-link revocation check.

A public grant may name `chain:<contentId>` (this chain) or `chain:*` (all of the issuer's chains); either way it MUST root at the content creator to authorize. Public credentials SHOULD be read-scoped — a public `write` grant is a world-writable bearer token ([CREDENTIALS.md](https://protocol.dfos.com/credentials#security-aud-quotquot--write--a-world-writable-bearer-grant)).

### Access

Non-public content plane requests carry an **identity proof** in the `Authorization: DFOS` header — the [API-AUTH](https://protocol.dfos.com/api-auth#the-identity-proof) request-bound possession proof, verified against the presenter's _current_ identity state (a rotated-out key cannot mint one) with the relay's own configured authority as the `host` binding; see [Authentication](#authentication). There is no lifetime knob to configure: a proof lives inside the verifier-owned freshness window, seconds not hours, and binds one exact request.

### Blob Upload (`PUT /content/:contentId/blob/:ref`)

The upload path mirrors the download path — the operation CID identifies which operation's document is being uploaded.

Requirements:

- A valid identity proof (`Authorization: DFOS` — see [Authentication](#authentication))
- The operation CID must reference an operation in this content chain that has a `documentCID`
- The authenticated DID must be either the chain creator OR the signer of the referenced operation (enabling delegated uploads)
- The uploaded bytes must hash to the operation's `documentCID` (dag-cbor + sha-256 verification)

Blobs are stored by `(creatorDID, documentCID)` — always keyed to the chain creator regardless of who uploads. If multiple content chains by the same creator reference the same document, the blob is shared (deduplication).

### Blob Download (`GET /content/:contentId/blob[/:ref]`)

Requirements:

- If a standing authorization exists for the content (a public credential with `aud: "*"` covering the resource): access is granted anonymously — no proof, no per-request credential
- Otherwise, a valid identity proof (`Authorization: DFOS`) is required, plus:
  - If the caller is the chain creator: no further credentials needed
  - If the caller is not the creator: must present a DFOS credential with `action: "read"` in the `X-Credential` header, with a delegation chain rooting at the creator

The optional `:ref` parameter selects which operation's document to return:

- `head` (default): the current document at chain head
- An operation CID: the document committed by that specific operation

### Enumerating a Chain's Documents

There is deliberately no relay-side document list route — it would only be a relay-decoded convenience over state the client can re-derive verifiably. Fetch `GET /content/:contentId/blob` for the document at head, `GET /content/:contentId/blob/:ref` for the document any specific operation committed (immutable), and `GET /proof/v1/content/:contentId/log` to enumerate the chain's operations, each carrying its `documentCID`. This composition is strictly more verifiable: every blob is checked against its committed `documentCID`, and the op log is the frozen proof-plane enumeration.

### Standing Authorization

Instead of presenting a read credential on every request, a DFOS credential with `aud: "*"` (public) can be ingested by the relay as a **standing authorization** — once ingested, matching content plane requests are authorized without an `X-Credential` header. Credential ingestion uses `POST /proof/v1/operations`: DFOS credentials are submitted as JWS tokens alongside other proof plane operations and stored in the op log like any other operation (addressable by CID, carried in the global log as `kind: "credential"`).

**Authority is re-derived live, not read from a stored flag.** On every content plane access the relay re-verifies the standing credential against current proof-plane state — signature, issuer-key resolution, temporal validity, **revocation**, and a delegation chain rooted at the content creator — through the **same verifier the per-request (`X-Credential`) path uses**. The two paths differ only in where the credential came from and an audience check that public (`aud: "*"`) credentials skip; revocation is checked **symmetrically** on both, at every link of the delegation chain. See [The unified verifier](#the-unified-verifier).

A relay MAY keep a materialized index of ingested public credentials (resource → candidate credentials) to make standing-auth lookup O(1). **That index is a performance optimization, not authority** — every candidate it yields is re-verified live before it can authorize, so a stale or revoked entry cannot grant access. It is a re-verified, non-authoritative cache over the op log, fully re-derivable from it.

A standing authorization stops granting access the moment any live check fails:

- The credential expires (temporal validity)
- The credential — or any parent in its delegation chain — is revoked
- The issuer's identity (or any delegating identity) is deleted

These are evaluated live per request, so the effect is immediate; no cache invalidation is required for correctness.

### Revocation Ingestion

Revocation artifacts (`typ: did:dfos:revocation`) are ingested via `POST /proof/v1/operations` alongside other proof plane operations. When a revocation is accepted:

1. The revoked credential's CID is recorded against its issuer, **together with the revocation's own signed `createdAt`** — the boundary the as-of rule compares against (see below)
2. Standing authorization backed by that credential stops granting — the live per-request revocation check denies it on the next read (a relay that keeps a candidate index MAY also evict the entry eagerly, but the live check is what guarantees immediacy)
3. Future content chain operations embedding the revoked credential as `authorization` are rejected
4. Future content plane requests presenting the revoked credential are rejected

Revocation is permanent and immediate. See [CREDENTIALS.md](https://protocol.dfos.com/credentials) for the revocation payload format. A relay MAY additionally expose a read over the revocation index it keeps for this enforcement — see [Revocation Status](#revocation-status).

**Ingest asks freshness; re-verification asks validity.** Points 2–4 are all **acceptance** decisions, answered from what the relay currently knows: a relay MUST refuse a new operation authorized by a credential it already holds a revocation for, **whatever that operation's `createdAt` claims** — otherwise backdating would buy a revoked delegate an indefinite write window. Re-verifying operations the relay has **already committed** is the other question, and it is answered **as of each operation's own `createdAt`** per CREDENTIALS.md ["Acceptance vs Validity"](https://protocol.dfos.com/credentials#acceptance-vs-validity-normative). Concretely, a relay replaying a chain's history (for example to compute content-chain state at a fork point, or to re-verify a synced log) MUST NOT reject an operation because a credential in its history was revoked **later** — that operation was authorized when it was signed, and rejecting it would make legitimately committed history fail re-verification. The two rules coexist without tension: acceptance is local and timely, and the ingest verdict never enters the replicated log; historical validity is deterministic and therefore identical on every relay, forever.

### Trust and security model

A `200` from the content plane is an **endorsement**: "I, a cooperating host, verified against the live proof plane that a grant authorizes this read." Every input to that decision is public and re-derivable — the chain head and `documentCID` from the proof plane, the grants as signed CID-addressable objects, revocation as a proof-plane query — so a zero-trust caller MAY re-run the unified verifier itself and arrive at the same yes independently.

| Property                | Guarantee                                                                                                                                                                                                                                                          |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Can't forge**         | A reader checks served bytes against the known `documentCID` by re-canonicalizing (decode-JSON → dag-cbor → sha-256), not by hashing the served bytes directly; wrong bytes fail content-addressing. Integrity is cryptographic **even against a malicious host**. |
| **Can withhold / leak** | The host holds plaintext. Content-plane access control is **host-cooperative** — it protects an _honest_ host from mis-serving. It is not a cryptographic vault.                                                                                                   |

What is not re-verifiable is the host's **serve discipline** — whether an honest host actually withholds bytes from an unauthorized reader. That is unprovable for _any_ content host, and it is the one place the model is host-cooperative rather than cryptographic. Anything that must stay confidential against a _hostile_ host is withheld or encrypted **above** the protocol ([THREAT-MODEL.md](https://protocol.dfos.com/threat-model)).

**Blobs are unsigned, and that is correct.** A blob's integrity _is_ its CID, and the CID is already signed in the proof plane — re-signing the bytes here would be redundant. The proof plane provides legitimacy and authorization; content-addressing provides integrity. Note the byte encoding: stored and served blob bytes are the bytes **as received** (canonically a JSON document), NOT a re-canonicalized form — a naive `sha256(servedBytes)` will NOT equal `documentCID`; a verifier re-canonicalizes through the same decode → dag-cbor path the upload check uses.

### Content Following

The operation log federates the **proof plane**: identity chains, content chains, public-read credentials, and revocations are all pushed and gossiped between peers. The **content plane** — the document _bytes_ — is deliberately not on that wire. A relay MAY nonetheless make those bytes available locally by **following**: pulling the documents of the content chains it is authorized to read, content-addressed and gated by the grant. This turns a relay from a proof mirror into a true edge cache that serves public content **independently of the origin** that authored it.

Following is a per-relay, optional behavior on the content plane's own `0.x` clock; it adds **no wire surface** and changes nothing for a relay that does not opt in. The reference Go relay exposes it as `CONTENT_FOLLOW=eager` (default `none`). The shape, normatively:

- **Pull, not push.** A follower fetches blobs from its peers over the existing public blob route (`GET /content/:contentId/blob[/:ref]`). Blobs are never gossiped; there is no new endpoint.
- **The materialize gate is the serve gate.** A follower materializes a chain's bytes only while a standing public-read grant authorizes anonymous read of it — the same predicate (`hasPublicStandingAuth`) the serve path checks. So a chain that is private, revoked, or deleted is never followed.
- **Verified by hash, trustless in source.** Every pulled blob is checked against the `documentCID` the chain committed (its content address) before it is stored. A follower may therefore pull from any peer; a byte that does not hash to its committed CID is rejected.
- **Eventually consistent.** Authorization arrives instantly (the grant rides the log); the bytes arrive asynchronously. Between the two, a follower that is authorized but has not yet materialized a blob returns `404 blob not found` on `GET /content/:contentId/blob[/:ref]` — the **honest "authorized-but-not-yet-materialized" state**, not an error. A conforming follower converges to serving the bytes; it need not do so instantaneously. A conformance test asserts eventual materialization (poll until served), never instantaneous.
- **Convergent, ordering-immune.** Following is driven by a sweep over the chains the follower already holds in local state, so it cannot be raced by op-ingest ordering (a credential op sequences before the content op it grants). The sweep is the correctness backbone; low-latency triggers, if any, are an optimization over it.
- **Revoke is correctness-free; GC is reclamation.** When a grant is revoked, the per-request serve gate immediately makes any cached bytes unreachable — correctness needs nothing more. Reclaiming the now-orphaned bytes (deleting them) is a separate, convergent garbage-collection pass keyed on the same gate, and is purely a storage concern.

### Public-read discovery (0.x)

> **Status: design — shape, not bytes.** This ergonomic is specified by shape only: it is **not** part of the reference relay and is deliberately under-specified at the wire level — the framing fixes the _shape_ of the answer; an implementor picks the exact bytes.

A zero-trust public-read caller wants two things at once: the document bytes, _and_ the `aud: "*"` credentials that authorized the read, so it can re-verify the grant itself instead of trusting "the relay let me in." The grants do **not** ride `GET /proof/v1/content/:contentId` — that route is [contract-frozen](https://protocol.dfos.com/relay-contract) and carries pure chain state — and they do not ride response headers (a delegation chain of credential JWS tokens can run to many kilobytes). The shape: on the public blob path, when a public grant authorized the read, the relay hands back — alongside or wrapping the blob — the **authorizing credentials themselves**, in a response envelope. Constraints that fix the shape: the inlined grant set is bounded at **≤ 256 KiB** of credential material (past that the relay MAY refuse to inline, and the caller falls back to fetching credentials by CID off the proof plane); only grants that survived the live verifier are inlined; revocation currency remains the caller's option (the envelope is a head-start, never a substitute for the caller's own proof-plane reads); and the exact wire shape — JSON wrapper, multipart, or a `Link`-discoverable sidecar — is the implementor's. This adds zero proof-plane surface, and the grants are public credentials, so surfacing them discloses nothing private.

---

## Revocation Status

A relay that enforces revocation already maintains an `(issuerDID, credentialCID)` revocation set (see [Revocation Ingestion](#revocation-ingestion)). The **revocation status** family (`/revocations/v1/*`) exposes an indexed, read-only projection of that set — routes, shapes, the honest-absence rule, and the deterministic multi-issuer answer are [RELAY-CONTRACT.md → Revocation Status](https://protocol.dfos.com/relay-contract#revocation-status). Behavior notes: nothing about ingestion changes (revocations remain ordinary proof-plane operations, submitted via `POST /proof/v1/operations` and gossiped like everything else); a relay advertises support via `capabilities.revocations` and answers **501** when unsupported — which a client MUST treat as "this relay does not answer revocation-status questions," never as a negative answer; and disabling the flag changes only these read routes — revocation **enforcement** (ingest, content-plane, deposit gates) runs regardless.

---

## Index (v0)

A relay that verifies and folds chains already holds current-state projections — terminal states, standing public-read grants, per-chain logs. The **index** route family exposes read-only, cursor-paginated _queries_ over those projections: enumerate identities, filter content chains, reverse-look-up countersignatures by witness, enumerate held public credentials. It exists so a light client can browse and discover without replaying the global operation log — the same role the revocation status family plays for credential state, generalized.

The family lives at **`/index/v0/*`** on its own **`0.x` clock** — NOT part of the frozen `/proof/v1` proof plane, and (unlike `/revocations/v1`) not frozen itself. A relay advertises support via `capabilities.index` in the well-known; when unsupported (or when the flag is absent — relays predating this family), the routes return **501 Not Implemented**. Nothing about ingestion changes.

### Hints, Not Authority

Index responses are **discovery hints, never authority**. Every row carries the identifiers needed to re-derive its claims from the frozen proof plane — a client that cares fetches `GET /proof/v1/identities/:did` / `GET /proof/v1/content/:contentId` (and the per-chain logs) and folds the chain itself. The trust posture is asymmetric and worth stating precisely:

- **The index cannot lie by assertion.** Every claim in a row is verifiable against the proof plane. A fabricated row fails the client's fold.
- **The index CAN lie by omission.** A relay can be behind, partitioned, or adversarially withholding rows — and a light client cannot detect a recall gap. Absence of a row is NOT proof of absence. A caller that needs stronger recall queries a quorum of independent relays, or replays `GET /proof/v1/log` and folds locally — the full-log replay remains the audit posture that keeps every index honest.
- **Index output MUST NOT be used as an authorization input.** The `publicRead` field is a discovery hint; content plane access is always re-derived live by [the unified verifier](#the-unified-verifier).

### The Structural Seam

The index is bounded by one invariant:

> **Every index field and filter MUST be computable from protocol-defined fields and verification outcomes alone. Document payloads are opaque**, except the [well-known projections](#well-known-projections) below.

The invariant has a semantic reading that bounds the query vocabulary itself:

> **The index knows who acted, when, and what things call themselves. Nothing else.**

Every index field and filter is an instance of one of three axes — **actor** (creator, signer, witness, issuer), **clock** (`genesisAt` / `headAt` / operation or artifact `createdAt` / relay `ingestedAt`), or **name** (the [display-name registry](#well-known-projections)). Artifacts occupy the actor and clock axes: their JWS signing DID and signed/observed timestamps make standalone documents enumerable without interpreting their content. The [credit projection](#credit-projection) is the one enumerated **assertion-tier** entry on the actor axis: who a _public_ head document says made it, projected under its own rule below and never conflated with the proof-tier actor filters. A query that cannot be phrased under these axes is not an index feature: it is a client-composed filter over them, a client-side fold over verified bytes, or `/search` (deferred, on its own clock).

Concretely, the index may serve:

- **Structural facts** the relay already computes to verify: chain kind, genesis/head CIDs, op counts, creator DIDs, operation signer sets, deletion state, countersign witnesses and targets, credential issuer/subject/scope, revocation status, standing public-read grants, identity service entries.
- **Declared labels, matched as opaque strings**: an artifact or document `$schema`, a `ContentAnchor` `label`. The relay matches these byte-for-byte the way an HTTP server serves a `Content-Type` — it never interprets what they mean.

What the index MUST NOT do: interpret document payloads, join across application semantics, rank, or reify application concepts. There is no "posts" endpoint and never will be — an application-level notion like _post_ is a **client-composed filter expression** over structural parts (`docSchema=… & publicRead=true & creator=…`), not an index concept. This keeps the relay's query vocabulary closed while the application vocabulary composed on top stays open.

### Well-Known Projections

The **display-name registry** is the sole exception to payload opacity, enumerated here rather than left to implementations. Its rule: **one display-name field per enumerated `$schema` — the index may know what a thing calls itself, never what it says.** A registry row names an exact `$schema`, the single payload field that schema uses as its display name, and the index surface where the projection appears. Nothing else is ever extracted — no descriptions, bodies, summaries, or payload timestamps; what a document _says_ is client-fold or `/search` territory, never an index axis. The single structured exception is the [credit projection](#credit-projection) below — its own enumerated rule with the same circuit-breaker posture, sanctioned by [CREDITS.md](https://protocol.dfos.com/credits)'s relay-awareness design pass.

| #   | Projection          | Definition                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| --- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `profile/v1 → name` | For an identity whose terminal `services` contain a `ContentAnchor` whose `label`, lowercased, equals `"profile"` and whose `anchor` is a content-chain identifier: if the relay holds the bytes of that chain's current head document, and the decoded document declares `$schema: "https://schemas.dfos.com/profile/v1"`, and its `name` is a non-empty string — the index surfaces that `name` on the identity row's `profile` projection. |
| 2   | `post/v1 → title`   | For a content chain whose current head document bytes the relay holds: if the decoded document declares `$schema: "https://schemas.dfos.com/post/v1"` and its `title` is a non-empty string — the index surfaces that `title` on the content row.                                                                                                                                                                                             |

Every registry row carries the same structural **circuit breakers** — every escape hatch resolves to the honest unknown, never a guess:

- A document under any `$schema` NOT in this table is never field-extracted, no matter how tempting its shape.
- A listed schema whose document is malformed, whose extracted field is missing, empty, or not a string — the projected field is `null`. No partial parses, no coercion.
- Bytes the relay does not hold — `docSchema: null` and the projected field `null` (see coverage, below).
- **A chain that is not publicly readable** — the projected `publicRead` is `false` — never surfaces its extracted display-name field: the projected value is `null`. Confidentiality of the underlying documents is enforced at the application layer by whoever serves them (see [PROTOCOL.md](https://protocol.dfos.com/spec)); the index MUST NOT project a non-public document's extracted fields onto its anonymous surface. Only the extracted display-name value is withheld — the structural `anchor` / `publicRead` / `docSchema` fields (a declared label matched as an opaque string, never document content) still project.

Extracted values are **attribution-tier claims**: the value is whatever the signed head document says (row 1 is additionally reached through a controller-signed anchor). Clients verify by fetching the chain and re-hashing the served bytes to the committed `documentCID`. Additions to this table require an amendment to this spec — one display-name field per schema, and a relay MUST NOT ship extraction rules that are not listed here.

### Credit Projection

The second and only other payload extraction, with its own rule: **the index may know who a public document says made it.** For a content chain whose current head document bytes the relay holds, whose decoded document declares `$schema: "https://schemas.dfos.com/post/v1"`, and whose `credits` is an array: each entry with a string `did` projects one row onto the [credits family](#credits-get-indexv0creditsdidcontentidroleaftercursorlimitn) carrying `(contentId, did, role, position, hasClaim)` — `role` is the entry's string `role` or `null`, `position` is the entry's array index (`0` is the primary author), and `hasClaim` is whether the entry carries a string `claim`. Nothing else in the entry is projected: `name` is a rendering convenience whose authoritative surface is the credited DID's own profile projection, and the `claim` token itself stays inside the document bytes.

The projection is governed by three normative rules on top of the registry's circuit breakers (which all apply — unlisted schemas, malformed entries, and unheld bytes project nothing):

- **Public-only, structurally.** Credit rows exist only while the chain's projected `publicRead` is `true` and the chain is not deleted. This is a strictly harder line than the display-name null-out: a non-public chain has **zero** credit rows — there is no redacted variant, and the family MUST NOT be usable to probe non-public content ([CREDITS.md](https://protocol.dfos.com/credits) — attribution must be no more public than the content it attributes).
- **Head-only, full-replace.** Every recompute derives the content's complete row set from the current head document and **replaces** the previous set. A revision that drops a credited entry drops its row; a head whose new document bytes are not yet held clears the set (rows reappear when the bytes land) — the family never serves a previous head's credits.
- **Assertion-tier, unverified.** Rows restate what the signed head document asserts. The relay never verifies a credit claim: `hasClaim` is byte-presence, not validity — the four verification states remain a client fold over the fetched document per [CREDITS.md](https://protocol.dfos.com/credits). Relays remain credit-claim-unaware as verifiers; this projection makes them aware of credits only as public-document structure.

### Determinism and Coverage

- **Deterministic enumeration.** By default identity, content, artifact, credential, and countersignature lists are ordered lexicographically ascending by their cursor key (`did`, `contentId`, or `cid`); identities, content, artifacts, and countersignatures additionally accept the route-specific time orderings below. Operations are the deliberate exception: they are a recency feed and default to `ingestedAt.desc`. Two relays holding the same operations serve identical author-time ordering and identical structural fields; relay-observed ingestion ordering is local by definition and need not converge across relays. Held-bytes-dependent fields (`docSchema`, projected values) additionally require the same held blobs to agree, per coverage below.
- **Keyset pagination is the normative shared envelope.** Every index route paginates identically — `after` (keyset cursor), `limit` (default 100, max 1000), `next` (the resume cursor, or `null` when caught up) — over the route's enumeration order. New index routes inherit this envelope; none may invent another. In the default lexical mode `after` is a **strictly-greater** cursor: a page returns the rows whose (post-filter) cursor key is lexicographically **greater than** `after`, ascending, capped at `limit`; `next` is the last returned row's key, or `null` when the page was not full (caught up). The cursor need not be a currently-present key — a value that falls between keys, or names a row that was mutated out of the active filter between pages, resumes at the next greater key rather than truncating to an empty page. This makes enumeration stable under concurrent row changes: keys are immutable natural identifiers, so a row's filtered membership or projected values may change between pages without dropping or duplicating other rows.
- **Time-ordered enumeration (`order=`).** `/identities` and `/content` accept `order=genesisAt.desc` (newest chains first) or `order=headAt.desc` (most recently active first). The sort key is the composite `(timestamp descending, cursor key ascending)` — the timestamps are the same author-claimed, head-selection-trusted `createdAt` values already surfaced as `genesisAt` / `headAt`, so ordered pages are exactly as deterministic and convergent across relays as the lexical default: an ordering of _claimed_ times, never receipt times, inheriting precisely the trust posture of the fields it sorts by. In ordered mode `after` and `next` are **opaque cursor tokens** — a client resumes by passing `next` back verbatim and MUST NOT parse or construct one; the token encoding is implementation-internal. Envelope semantics carry over (`limit` bounds, strictly-past-the-composite-key resumption), with one honest weakening of the lexical mode's stability guarantee: `genesisAt.desc` sorts by an immutable key and is fully stable under concurrent row changes, but `headAt` is a **mutable** sort key. It is monotonically non-decreasing (per-branch timestamp ordering plus max-over-tips head selection — an accepted operation can only raise it), so a chain updated mid-enumeration moves strictly toward the top of `headAt.desc` — into pages already served. An in-flight `headAt.desc` enumeration therefore never duplicates a row but MAY miss one that was updated while paginating; the row is not gone, it has moved to the front of a fresher enumeration. This is the correct contract for a recency feed — clients refresh from the top; completeness remains the job of the lexical enumeration (immutable keys, fully stable) or the log replay. Absent `order`, enumeration is the lexical default above — existing clients are untouched. Only the two enumerated values exist; an unrecognized value is a `400`.
- **Operation recency ordering.** `/operations` accepts `createdAt.desc` and `ingestedAt.desc` and defaults to `ingestedAt.desc`; `/artifacts` and `/countersignatures` accept the same values while retaining lexical CID order when `order` is absent. All use the same descending-timestamp/CID-ascending composite and opaque ordered cursor described above. `createdAt` is author-claimed; `ingestedAt` is when this relay accepted the operation, so it is relay-local browse chronology rather than protocol authority. Unrecognized orders and undecodable ordered cursors are `400`.
- **Boolean parameters fail closed.** A boolean filter is either absent (no filter), exactly `true`, or exactly `false`. A present empty or otherwise unparseable value is `400` with `{ "error": "invalid boolean" }`; it never silently widens to an unfiltered query.
- **Coverage is bounded by held bytes.** `docSchema` and projected fields are computable only for chains whose current head document bytes the relay holds (uploaded, or pulled via [content following](#content-following)). A chain whose bytes are absent reports `docSchema: null` — honest unknown, not a claim of schemalessness. A `docSchema` filter therefore matches only chains with held, decodable head bytes; callers MUST treat the result as a lower bound. Artifacts are the exception to the missing-bytes case: a verified artifact carries its document inline in the stored JWS, so its bytes and required `$schema` string are always held by construction; accepted artifact rows therefore have a non-null `docSchema` (the nullable wire shape preserves the index's honest-unknown convention defensively).
- **Timestamps are author-claimed.** `genesisAt` / `headAt` surface the `createdAt` fields signed inside the operations — the same values head selection uses — not relay receipt times.
- **Maintenance.** The index is fully re-derivable from the operation log plus held blobs. Reference implementations maintain it incrementally at ingestion and expose a rebuild path for pre-existing corpora; either way the serving contract is identical.
- **`publicRead` is a last-touch snapshot, and MAY lag time-based transitions.** A materialized `publicRead` reflects whether a standing public-read grant authorized anonymous read **at the moment the row was last recomputed** (its content's most recent op, or a rebuild). One input to that predicate — a grant credential's `exp` — is wall-clock-relative and crosses **without emitting any operation**, so incremental maintenance has no event to react to: a row can continue to advertise `publicRead: true` after the grant that made it public has expired, until the next op dirties that content or a rebuild reruns the projection. This is deliberately tolerated because the index is a discovery hint, never an authorization input (see [Hints, Not Authority](#hints-not-authority)) — the content plane re-derives `hasPublicStandingAuth` live on every read, where `exp` is always evaluated against the current clock. A relay MAY additionally re-sweep public rows near expiry to tighten the hint, but is not required to.

### Operations (`GET /index/v0/operations?kind=&chainId=&order=&after={cursor}&limit=N`)

Enumerates the operations this relay holds as metadata-only recency rows. This is a non-authoritative browse ordering: `createdAt` is the author-claimed timestamp signed into the operation (`iat`, normalized to ISO 8601, for credentials), while `ingestedAt` is the relay-observed acceptance timestamp. Neither establishes a consensus clock.

```json
{
  "operations": [
    {
      "cid": "bafyrei…",
      "kind": "content-op",
      "chainId": "a3n7r3nde8e4keeak92rr3aeztftvc2",
      "createdAt": "2026-04-02T00:00:00.000Z",
      "ingestedAt": "2026-04-02T00:00:01.123Z"
    }
  ],
  "next": null
}
```

Parameters: `kind` (optional exact match, one of `identity-op`, `content-op`, `artifact`, `countersign`, `revocation`, or `credential`; `400` otherwise), `chainId` (optional exact match against the operation-log routing identifier), `order` (`createdAt.desc` or `ingestedAt.desc`, default `ingestedAt.desc`), `after` (the opaque ordered cursor), and `limit` (default 100, max 1000). A signer filter is deliberately omitted: the reference stores do not retain operation signer DID as indexed metadata, and this browse route does not re-decode the corpus to manufacture one.

Rows are browsing metadata, never proof: they contain no JWS, payload, title, or name. `chainId` has the same structural visibility already present in `/index/v0/content` and the proof-plane global log, including for non-public or deleted chains; it does not expose document bytes or projected display names.

### Artifacts (`GET /index/v0/artifacts?cid=&signer={did}&docSchema=&order=&after={cid}&limit=N`)

Enumerates standalone signed artifacts, `cid` ascending by default; `order=createdAt.desc` / `order=ingestedAt.desc` select the shared recency ordering described above. This closes the only primitive that otherwise requires full-log replay for enumeration.

```json
{
  "artifacts": [
    {
      "cid": "bafyrei…",
      "signerDID": "did:dfos:hd34z9a4tf6h62864nh4f7at6hr36r4",
      "createdAt": "2026-04-02T00:00:00.000Z",
      "ingestedAt": "2026-04-02T00:00:01.123Z",
      "docSchema": "https://example.com/schema/v1"
    }
  ],
  "next": null
}
```

Parameters: `cid` (optional exact artifact-CID match, returning zero or one row; composes with the remaining filters), `signer` (optional exact DID from the artifact JWS `kid`; `400` when malformed), `docSchema` (optional exact opaque match against the inline document's `$schema`), `order` (optional `createdAt.desc` or `ingestedAt.desc`; lexical CID order when absent), `after` (a CID keyset cursor in lexical mode or an opaque ordered cursor in ordered mode), and `limit` (default 100, max 1000). Filters are ANDed. Rows contain no artifact payload or display-name projection; clients fetch the artifact from the proof plane and verify it before use.

### Identities (`GET /index/v0/identities?did=&hasPublicProfile=&nameContains=&order=&after={did}&limit=N`)

Enumerates identity chains, `did` ascending by default; `order=genesisAt.desc` / `order=headAt.desc` select time-ordered enumeration (recently arrived / recently active) per [Determinism and Coverage](#determinism-and-coverage).

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

| Field                  | Type           | Description                                                                                                                                                                                  |
| ---------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opCount`              | number         | Operations stored for this chain — identity chains are strictly linear, so this is the linear operation count (content-chain `opCount` in the content family below remains branch-inclusive) |
| `genesisAt` / `headAt` | string         | Author-claimed `createdAt` of the genesis and current head operations                                                                                                                        |
| `profile`              | object \| null | The [well-known projection](#well-known-projections), or `null` when the identity declares no profile-labeled content-chain anchor                                                           |
| `profile.anchor`       | string         | The anchored contentId — the client's verification pointer                                                                                                                                   |
| `profile.publicRead`   | boolean        | Whether a standing public-read grant currently authorizes anonymous read of the anchored chain, per this relay's fold — a hint, never an access decision                                     |
| `profile.docSchema`    | string \| null | `$schema` declared by the held head document; `null` when bytes are not held or not decodable                                                                                                |
| `profile.name`         | string \| null | Extracted per the projection table; `null` on any circuit breaker — including when `profile.publicRead` is `false` (a non-public profile never projects its name)                            |

Parameters: `did` (optional exact DID match, returning zero or one row; composes with the remaining filters), `hasPublicProfile` (optional boolean filter on the predicate "`profile` is non-null AND `profile.publicRead` is true" — `true` keeps only rows where it holds, `false` keeps only rows where it does not, absent applies no filter), `nameContains` (optional case-insensitive substring filter over projected `profile.name`; non-authoritative/amber; applied before keyset pagination), `order` (optional time ordering — `genesisAt.desc` or `headAt.desc`; `400` on any other value), `after` (a `did` keyset cursor in the lexical default — returns rows with `did` strictly greater — or an opaque token in ordered mode), `limit` (default 100, max 1000). Multiple profile-labeled anchors resolve deterministically to the one with the lexicographically smallest service `id`.

### Content Chains (`GET /index/v0/content?contentId=&creator={did}&signer={did}&docSchema=&documentCID=&publicRead=&isDeleted=&titleContains=&order=&after={contentId}&limit=N`)

Enumerates content chains, `contentId` ascending by default; `order=genesisAt.desc` / `order=headAt.desc` select time-ordered enumeration per [Determinism and Coverage](#determinism-and-coverage). All filters are ANDed exact matches.

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
      "docSchema": "https://schemas.dfos.com/profile/v1",
      "title": null
    }
  ],
  "next": null
}
```

`title` is the [display-name registry](#well-known-projections) projection for content rows (row 2, `post/v1 → title`): `null` for any chain whose held head document is not an enumerated schema, on any circuit breaker (including a non-public chain — `publicRead: false` — whose title is never projected), or when bytes are not held — an honest unknown, never a guess. Content-chain `opCount` is **branch-inclusive** — log length across all branches, not head-branch length.

Parameters: `contentId` (optional exact match, returning zero or one row; composes with the remaining filters), `creator` (exact DID — the chain's genesis signer; `400` when malformed), `signer` (exact DID — keeps chains in which the DID signed at least one **accepted** operation, branch-inclusive: "has signed in this chain," not "signs the current head lineage"; operations on branches later deleted or abandoned still count — the log records that the signature happened; `400` when malformed), `docSchema` (exact opaque string match against held head bytes — a lower bound, per coverage above), `documentCID` (exact match against the projected `currentDocumentCID` — the reverse lookup "who published this document"), `publicRead` (boolean), `isDeleted` (boolean exact match against terminal deletion state), `titleContains` (optional case-insensitive substring filter over projected `title`; non-authoritative/amber; applied before keyset pagination), `order` (optional time ordering — `genesisAt.desc` or `headAt.desc`; `400` on any other value), `after` (a `contentId` keyset cursor in the lexical default — returns rows with `contentId` strictly greater — or an opaque token in ordered mode), `limit` (default 100, max 1000). This is the reverse lookup "what content does DID X own" plus the composition surface for application-level queries — e.g. a client's notion of _public posts by X_ is `creator=X&docSchema=<its post schema>&publicRead=true`, and its notion of _recent public posts_ is `order=headAt.desc&docSchema=<its post schema>&publicRead=true`, composed client-side.

When `titleContains` is present, the query is implicitly restricted server-side to `publicRead=true` rows. A non-public chain's title is never projected, and `titleContains` MUST NOT be usable to probe non-public rows. Explicitly combining `titleContains` with `publicRead=false` is a `400` with `{ "error": "invalid filter combination" }`.

Post-class content chains are not tombstoned from this structural index when their subject is deleted. Concealment belongs to the credential/blob plane, so a deleted subject's chain metadata — identifiers, operation CIDs, and timestamps — remains enumerable. Consumers that do not want deleted rows use `isDeleted=false`; absent `isDeleted` preserves the complete metadata enumeration.

`signer` is an **actor-axis verification outcome**, deliberately raw: the creator matches their own chains (the creator signs genesis), and "contributed to but did not create" is client-composed as `signer=X` minus `creator=X`. It is proof-tier — the DID's key actually signed accepted operations, revealing nothing not already derivable from the public per-chain log — and it is never an authorship or credit claim: `credits` is assertion-tier and never enters this filter. Its sanctioned surface is the separately-declared [credits family](#credits-get-indexv0creditsdidcontentidroleaftercursorlimitn), public head documents only.

### Countersignatures by Witness (`GET /index/v0/countersignatures?witness={did}&relation=&order=&after={cid}&limit=N`)

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

`witness` is required (`400` when missing or malformed); `relation` is an optional exact match against the countersign's opaque open-namespace tag; `order` optionally selects `createdAt.desc` or `ingestedAt.desc`; `after` is a countersignature-`cid` keyset cursor in lexical mode or an opaque token in ordered mode; `limit` defaults to 100 and maxes at 1000. The row's `relation` is `null` when omitted by the signer. Each entry carries the full JWS — self-proving, same posture as the issuer revocations feed: the caller re-verifies the token rather than trusting the row.

### Credentials (`GET /index/v0/credentials?issuer={did}&resource=&action=&after={cid}&limit=N`)

Enumerates the relay's held public credentials, `cid` ascending.

```json
{
  "credentials": [
    {
      "cid": "bafyrei…",
      "issuerDID": "did:dfos:hd34z9a4tf6h62864nh4f7at6hr36r4",
      "aud": "*",
      "att": [{ "resource": "chain:a3n7r3nde8e4keeak92rr3aeztftvc2", "action": "read" }],
      "exp": 1775088000,
      "jwsToken": "eyJhbGciOiJFZERTQSIs…"
    }
  ],
  "next": null
}
```

Parameters: `issuer` (optional exact DID — `400` when malformed), `resource` (optional exact match against an `att[].resource`; when the requested resource starts with `chain:`, the `chain:*` wildcard bucket is always unioned in because a `chain:*` grant may authorize the named chain), `action` (optional exact match against an `att[].action`, with the same candidate-match posture as `resource`), `after` (a credential-`cid` keyset cursor — returns rows with `cid` strictly greater), `limit` (default 100, max 1000). Filters are ANDed. Rows project the verified public audience (`aud`, necessarily `"*"`) and unix expiry (`exp`); expired rows remain enumerable and clients may filter them locally.

Only public credentials (`aud: "*"`) are ever held by the relay. Targeted bearer credentials never enter relay storage, so they are neither enumerable nor leakable here.

This route is amber and relay-asserted: `resource=chain:Y` returns a superset of candidates (exact `chain:Y` plus any `chain:*`). Each entry carries the full JWS — self-proving, same posture as the issuer revocations feed. The caller folds each token against the proof plane (delegation roots at Y's creator, revocation, expiry) before treating it as authorization; the relay makes no authorization claim in this index row.

### Credits (`GET /index/v0/credits?did=&contentId=&role=&after={cursor}&limit=N`)

Enumerates the [credit projection](#credit-projection)'s rows: who _public_ head documents say made them. This is the sanctioned person-to-public-works lookup — `did=X` answers "which publicly readable documents credit X," the query [CREDITS.md](https://protocol.dfos.com/credits) refuses to serve for anything less than public content.

```json
{
  "credits": [
    {
      "contentId": "a3n7r3nde8e4keeak92rr3aeztftvc2",
      "did": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
      "role": "photography",
      "position": 1,
      "hasClaim": true
    }
  ],
  "next": null
}
```

Parameters: `did` (optional exact match against the credited entry's `did`), `contentId` (optional exact match, returning that chain's current public credit set in `position` order), `role` (optional exact opaque-string match; entries without a role match only its absence — there is no substring or vocabulary matching), `after` / `limit` per the shared envelope. Filters are ANDed. Enumeration order is `(contentId ascending, position ascending)`; because the natural key is composite, `after` and `next` are **opaque cursor tokens** in every mode (the ordered-mode rule of the shared envelope, applied always) — a client resumes by passing `next` back verbatim. Rows for one content may be replaced wholesale between pages (a head revision recomputes the set); as with `headAt.desc`, an in-flight enumeration never duplicates a row but MAY miss one that changed while paginating — completeness for a single chain is `contentId=` on a fresh page, or the document itself.

Every row is amber and assertion-tier: it restates the current public head document, carries no claim token, and makes no validity claim (`hasClaim` is byte-presence). A consumer that needs the proof tier fetches the chain, re-hashes the head document, and runs the CREDITS.md verification algorithm over the embedded entry — the row's only job is to say which documents are worth fetching. Join `contentId` against [`/index/v0/content`](#content-chains-get-indexv0contentcontentidcreatordidsignerdiddocschemadocumentcidpublicreadisdeletedtitlecontainsorderaftercontentidlimitn) for titles, schemas, and clocks, and `did` against [`/index/v0/identities`](#identities-get-indexv0identitiesdidhaspublicprofilenamecontainsorderafterdidlimitn) for profiles.

### Deferred from v0

- **`/search`** — anything beyond case-insensitive substring filters over the display-name registry's `name` and `title` projections. Tokenization, ranking, fuzzy matching, and their normalization semantics are deliberately kept off this clock; if they ship, they ship as their own explicitly-unstable family, never frozen into the index contract. `nameContains` and `titleContains` are the index's search ceiling and relocation candidates when `/search` exists.
- **Fork/tips visibility** — remains deferred at the proof-plane level (see [What's Deferred](#whats-deferred)).

---

## Key Resolution

The relay uses two key resolution strategies:

- **Historical resolver** (for chain re-verification): searches all keys that have ever appeared in an identity chain's log, including rotated-out keys. This is necessary because re-verifying a full content chain from genesis must resolve keys from operations signed before a key rotation.
- **Current-state resolver** (for live authentication): only resolves keys in the identity's current state. After a key rotation, the old key immediately stops working for identity proofs. This prevents a compromised rotated-out key from being used to authenticate new requests. A **deleted** identity has no live-authentication standing at all: a relay MUST reject an identity proof whose presenter's current state is deleted, however valid its signature — deletion is the terminal off-switch, and live authentication is exactly the question deletion answers. (Re-verification of committed history is untouched, per the historical resolver above.)

**Which primitive uses which resolver:**

- **Current-state resolver** — identity proofs ([API-AUTH](https://protocol.dfos.com/api-auth#the-identity-proof)'s own rule). A rotated-out key cannot mint one, preventing stale-key auth.
- **Historical resolver** — identity and content chain re-verification, artifacts, revocations, and countersignatures **once committed**. These are historical facts whose signing key may since have rotated out, so re-verifying them must resolve against every key that ever appeared in the chain's head lineage; re-verifying them under current state would break sync of honest operations after any rotation. Their invalidation mechanism is revocation or deletion, not key rotation.
- **Historical resolution governs re-verification and peer sync, not first admission.** This split is core protocol, normative in [PROTOCOL.md → Admission and Re-Verification](https://protocol.dfos.com/spec#admission-and-re-verification): first admission of a new artifact, countersignature, or content-chain operation is **current-state** (a freshly-signed operation from a rotated-out key is refused at the door, whatever its `createdAt` claims); once committed — accepted here, or ingested from a peer's committed log — an operation is a historical fact that re-verifies historically forever, the admission verdict never enters the replicated log, and peer-log ingestion inherits the **peer's** admission discipline (choosing peers is a trust decision). Credentials and credit claims stay on historical resolution per their own specs' MUST — revocation, not rotation, invalidates them.
- **Credentials are the exception to the auth grouping.** Although a credential proves authorization, it uses the **historical** resolver and survives key rotation — a credential signed before a rotation remains valid afterward. Revocation (not key rotation) is the invalidation mechanism for credentials. See [CREDENTIALS.md](https://protocol.dfos.com/credentials).

---

## Route and Auth Quick Reference

The full surface of a reference relay, frozen and optional families together. Construction, storage, and peer-client interfaces are package documentation ([`@metalabel/dfos-web-relay` README](https://github.com/metalabel/dfos/tree/main/packages/dfos-web-relay)).

| Method | Path                                        | Plane       | Auth                                           |
| ------ | ------------------------------------------- | ----------- | ---------------------------------------------- |
| `GET`  | `/.well-known/dfos-relay`                   | meta        | none                                           |
| `POST` | `/proof/v1/operations`                      | proof       | admission policy — anonymous or identity proof |
| `GET`  | `/proof/v1/operations/:cid`                 | proof       | none                                           |
| `GET`  | `/proof/v1/countersignatures/:cid`          | proof       | none                                           |
| `GET`  | `/proof/v1/identities/:did`                 | proof       | none                                           |
| `GET`  | `/proof/v1/identities/:did/log`             | proof       | none                                           |
| `GET`  | `/proof/v1/content/:contentId`              | proof       | none                                           |
| `GET`  | `/proof/v1/content/:contentId/log`          | proof       | none                                           |
| `GET`  | `/proof/v1/log`                             | proof       | none                                           |
| `GET`  | `/1.0/identifiers/:did`                     | meta        | none                                           |
| `GET`  | `/revocations/v1/credential/:credentialCID` | revocations | none                                           |
| `GET`  | `/revocations/v1/issuer/:did`               | revocations | none                                           |
| `GET`  | `/index/v0/operations`                      | index       | none                                           |
| `GET`  | `/index/v0/identities`                      | index       | none                                           |
| `GET`  | `/index/v0/content`                         | index       | none                                           |
| `GET`  | `/index/v0/artifacts`                       | index       | none                                           |
| `GET`  | `/index/v0/countersignatures`               | index       | none                                           |
| `GET`  | `/index/v0/credentials`                     | index       | none                                           |
| `GET`  | `/index/v0/credits`                         | index       | none                                           |
| `POST` | `/signing/v0/requests`                      | signing     | deposit credential (in body)                   |
| `GET`  | `/signing/v0/requests`                      | signing     | identity proof                                 |
| `POST` | `/signing/v0/requests/:cid/response`        | signing     | none — validity is the auth                    |
| `GET`  | `/signing/v0/requests/:cid/response`        | signing     | none — CID knowledge                           |
| `POST` | `/signing/v0/requests/:cid/decline`         | signing     | none — advisory                                |
| `PUT`  | `/content/:contentId/blob/:ref`             | content     | identity proof                                 |
| `GET`  | `/content/:contentId/blob[/:ref]`           | content     | standing auth, or identity proof + credential  |

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

The interface itself is package documentation ([README](https://github.com/metalabel/dfos/tree/main/packages/dfos-web-relay)); what is behavioral contract lives here. Each method corresponds to a peering behavior: per-chain log fetches support read-through, the operation-log fetch supports sync-in, and operation submission supports gossip-out. Every log fetch MUST surface a peer's 400 cursor rejection as a distinguishable **invalid-cursor** outcome, distinct from transport failure — the sync loop's self-heal depends on telling them apart, and a client that collapses the 400 into a generic failure leaves the puller retrying a dead cursor forever after a peer wipes or rebuilds its log. A content-chain fork whose head switches while a read-through walk is in flight invalidates the walk's cursor the same way, and the correct response is one restart of that walk from the beginning — not silently treating the chain as fully fetched.

**Sync discipline (normative for pullers).** A puller persists only peer-supplied `next` values — never a cursor fabricated from an entry CID (a peer whose cursor format is not a bare CID would 400 it). On `next: null` (caught up) it retains its last persisted cursor and cheaply re-fetches the final partial page next cycle; a peer whose whole log fits in one page is therefore re-read each cycle — a deliberate, bounded cost (one page, dedup-idempotent) accepted in exchange for never fabricating. On `'invalid-cursor'` it resets: at most **once per peer per sync cycle** (a second rejection in the same cycle aborts the cycle for that peer rather than looping), and the reset is persisted only after a from-scratch fetch succeeds — so one spurious 400 from an intermediary cannot destroy a real high-water mark.

---

## Convergence

The protocol guarantees: given the same set of operations, any relay computes the same deterministic head state. Peering (gossip, read-through, sync) replicates operations across relays. But operations may arrive before their causal dependencies — a content extension before its identity chain, a content fork before the branch it forks from. A relay MUST eventually process any structurally valid operation whose causal dependencies have been processed. This is the convergence contract.

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
   - **Permanent rejection** — structurally invalid, bad signature, deleted identity, a conflicting extension of a committed identity operation, etc. — will never succeed regardless of what state arrives

3. **Sequence loop**: after each ingestion batch, re-attempt all buffered operations in dependency order until no further progress is made (fixed-point). This ensures cross-batch dependencies resolve immediately — when batch B provides the identity that batch A's content operation was waiting for, the sequencer resolves it within B's response cycle.

### Dependency Failures

A rejection is a dependency failure if and only if it is caused by missing state that may arrive later via peering. The set is small and stable:

- Previous operation not yet in store (`previousOperationCID` unknown)
- Identity chain not yet available (key resolution fails)
- Content chain not yet created (genesis not arrived)
- Content-chain fork state cannot be computed (ancestor in branch path not yet available)

All other rejections are permanent. Permanent rejections MUST NOT be retried. In particular, an identity operation refused as a conflicting extension is a **permanent** rejection — the identity chain is linear, and no state that arrives later can make a second child of a committed parent valid.

### Serialization

All chain-state mutations (ingestion + sequencing) MUST be serialized. Concurrent ingestion of operations for the same chain produces a read-modify-write race: two goroutines read the chain log, both append their operation, and the second write clobbers the first. Raw operation storage (`putRawOp`) does not require serialization — it is idempotent and append-only.

### Convergence Bound

Given a fully connected peer mesh where every relay syncs from every other relay:

- After one sync cycle, every relay has every operation that any peer accepted (stored as raw)
- After one sequencer pass, every operation whose full dependency chain exists locally is sequenced
- Deterministic head selection ensures all relays agree on the canonical head

In practice, the dependency depth for chain operations is 1 (each op depends on its immediate predecessor). Convergence is typically achieved in a single sync + sequence cycle.

### Storage for Convergence

Reference stores extend their interface with a content-addressed raw-operation buffer (put, list-unsequenced, mark-sequenced, mark-rejected, count, reset) — see the [package README](https://github.com/metalabel/dfos/tree/main/packages/dfos-web-relay). The behavioral contract is store-then-verify above; the buffer is how it is implemented.

---

## What's Deferred

- **Peer discovery**: Static configuration only — no dynamic discovery
- **SSE/realtime push**: Not defined — reads poll `GET /proof/v1/log`
- **Fork visibility API**: No dedicated endpoint lists a content chain's tips/branches
- **Search**: fuzzy/tokenized name queries — deliberately excluded from the [index](#index-v0) contract; any such capability is its own family, never an index extension
- **Branch termination op**: No protocol-level operation explicitly kills content-chain fork branches
- **Rate limiting / anti-spam**: Operational concern, not protocol concern
- **Blob size limits**: No protocol enforcement — deployments add limits at the middleware layer
- **Artifact `$schema` registry**: Schema names are free-form strings — no formal registry or validation beyond structural checks
- **Content-plane index chains**: a chain enumerating an identity's documents is pure discovery — the [`index/v1`](https://protocol.dfos.com/content-model) content schema, an ordinary content chain gated by the same rules; no content-plane primitive
- **Credentials-by-resource query**: reverse discovery ("what can DID X read") serves no part of the read path
