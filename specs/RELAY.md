# DFOS Relay

A relay receives, verifies, stores, and serves the DFOS proof plane: identity
chains, content chains, artifacts, countersignatures, credentials, and
revocations. It optionally stores and serves the document bytes those chains
commit to. This document is the HTTP wire and the ingest rules for anyone
implementing or operating one.

Authorship is verifiable without trusting any server. Which view of an identity
you follow is a choice of relay.

[Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-web-relay) · [npm](https://www.npmjs.com/package/@metalabel/dfos-web-relay) · [Go relay](https://github.com/metalabel/dfos/tree/main/packages/dfos-web-relay-go) · [Protocol](https://protocol.dfos.com/spec)

---

## What a relay is

A relay verifies everything it accepts and serves everything it has verified. It
does not issue identity, grant permissions, or define content semantics.

**A relay serves one linear view per identity.** An identity chain is linear per
view ([PROTOCOL, Views](https://protocol.dfos.com/spec#views)). Two identity
operations that claim the same chain position are two views of that identity. A
relay admits the first successor it sees for a position and refuses later ones,
so the log it serves is one linear chain. Which relay you read is which view you
get. No rule in this corpus arbitrates between relays that admitted different
successors at one position.

**A relay carries authorship proofs; it is not an authority over them.** Every
read it serves is re-derivable by the reader from operations the reader verifies
itself. A relay's verdict on what it will hold is local. A signature is not.

Content chains need no choice of view: they are DAGs, and deterministic head
selection resolves the same operation set to the same head on every relay
([PROTOCOL, Chain validity](https://protocol.dfos.com/spec#chain-validity)).

### Two planes

**The proof plane is public and replicates.** Signed chain operations, artifacts,
countersignatures, credentials, and revocations are cryptographic proofs that
anyone can verify with a public key. Relays push them to peers and pull them from
peers; every route that reads them is unauthenticated, because the operations
carry their own authentication.

**The content plane holds document bytes and does not replicate.** The blobs a
content chain commits to via `documentCID` are never pushed on the operation log.
A blob enters a relay by upload to the relay that holds the chain. Its integrity
is its `documentCID`, so served bytes are checkable against the chain whatever
their source. Access is host-cooperative: the operator reads what it stores, and
anything that must stay confidential against the operator is withheld or
encrypted above the protocol.

### A relay is a library

`createRelay()` returns a portable Hono application: Node.js, Cloudflare Workers,
Deno, Bun, Docker, a Raspberry Pi. You supply storage and peer configuration. The
relay supplies verification, ingestion, and HTTP semantics. The Go relay in
[`packages/dfos-web-relay-go`](https://github.com/metalabel/dfos/tree/main/packages/dfos-web-relay-go)
is the full reference implementation and a byte twin of the TypeScript routes.

---

## The well-known document

`GET /.well-known/dfos-relay` is part of the contract. It is unauthenticated,
ungated, and rooted, per [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615); the
`dfos-relay` suffix is registered in the
[extension registry's external-registrations table](https://protocol.dfos.com/spec#external-registrations).
A client reads it before it calls anything else.

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
  "openapi": "/openapi.json",
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

| Field                      | Type           | Description                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| -------------------------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `did`                      | string         | The relay's DID, resolvable on this relay's proof plane                                                                                                                                                                                                                                                                                                                                                                                              |
| `protocol`                 | string         | Protocol identifier, always `"dfos-web-relay"`                                                                                                                                                                                                                                                                                                                                                                                                       |
| `version`                  | string         | The relay's own release version (semver). The proof-plane version lives in the `/proof/v1` path prefix, not here                                                                                                                                                                                                                                                                                                                                     |
| `capabilities`             | object         | Which route families this relay serves                                                                                                                                                                                                                                                                                                                                                                                                               |
| `capabilities.proof`       | boolean        | MUST be `true`. A relay without proof plane capability is not a relay                                                                                                                                                                                                                                                                                                                                                                                |
| `capabilities.write`       | boolean        | Whether the relay accepts writes via `POST /proof/v1/operations` and content-plane blob upload                                                                                                                                                                                                                                                                                                                                                       |
| `capabilities.content`     | boolean        | Whether the relay serves the content plane (blob upload and download)                                                                                                                                                                                                                                                                                                                                                                                |
| `capabilities.log`         | boolean        | Whether the global operation log is served (`GET /proof/v1/log`)                                                                                                                                                                                                                                                                                                                                                                                     |
| `capabilities.revocations` | boolean        | Whether the [revocation status](#revocation-status) reads are served (`GET /revocations/v1/*`). An absent flag reads as `true`                                                                                                                                                                                                                                                                                                                       |
| `capabilities.index`       | boolean        | Whether the [index](#index-capability-index) query family is served (`GET /index/v0/*`). An absent flag reads as `false`                                                                                                                                                                                                                                                                                                                             |
| `capabilities.signing`     | boolean        | Whether the [signing mailbox](#signing-mailbox-capability-signing) is served (`/signing/v0/*`). An absent flag reads as `false`                                                                                                                                                                                                                                                                                                                      |
| `ingestion`                | string         | [Admission-mode](#admission) hint: `"open"`, `"proof-required"`, or `"closed"`. Absent derives from `capabilities.write`: `true` reads as `"open"`, `false` as `"closed"`                                                                                                                                                                                                                                                                            |
| `profile`                  | string         | The relay's profile artifact as a compact JWS token, self-proving payload                                                                                                                                                                                                                                                                                                                                                                            |
| `openapi`                  | string         | OPTIONAL. URL of an OpenAPI document describing this relay's HTTP surface, absolute or root-relative against the relay's base URL. Serving the document is SHOULD, never MUST; a relay that serves one advertises it here, and a relay that serves no document omits the field. The document is discovery, never authority: the routes, capability gates, and auth rules in this specification govern regardless of what an advertised document says |
| `peers`                    | array          | OPTIONAL telemetry. Configured peer relays, surfaced for mesh discovery; reference relays emit `[]` when no peers are configured                                                                                                                                                                                                                                                                                                                     |
| `peers[].endpoint`         | string         | OPTIONAL telemetry. The peer relay's base URL                                                                                                                                                                                                                                                                                                                                                                                                        |
| `stats`                    | object         | Operational counters. `stats.pendingOps` is the count of operations pending sequencing (`-1` if unavailable)                                                                                                                                                                                                                                                                                                                                         |
| `stats.opCount`            | number         | OPTIONAL telemetry. Entries the relay **holds** in its global operation log. On a relay that prunes or [culls](#retention) this is below the log's tip position and is not a proxy for it. Counts are relay-local and not comparable across relays                                                                                                                                                                                                   |
| `stats.countsByKind`       | object         | OPTIONAL telemetry. Global-log counts by primitive kind, **operations, never chains**: the `identity` bucket counts identity operations, not identities. Reference relays emit `identity`, `content`, `artifact`, `credential`, `countersign`, `revocation`                                                                                                                                                                                          |
| `stats.oldestOpAt`         | string \| null | OPTIONAL telemetry. `createdAt` of the oldest-position global-log entry, or `null` when the log is empty                                                                                                                                                                                                                                                                                                                                             |
| `stats.headCid`            | string \| null | OPTIONAL telemetry. CID of the global-log tip, or `null` when the log is empty                                                                                                                                                                                                                                                                                                                                                                       |
| `stats.peerSync`           | object         | OPTIONAL telemetry. Per-peer sync state keyed by endpoint: `lastAttemptAt`, `lastSuccessAt`, `lastReceived`, `lastInserted`, `caughtUp`, `consecutiveFailures`, `lastReconcile*`, `pinMismatch`. Absent when no sync peer is configured                                                                                                                                                                                                              |

### Capabilities are how a relay honestly declines a family

A relay that does not serve a family says so in `capabilities` and answers
**501 Not Implemented** on that family's routes. 501 says the capability is
absent; 404 would say the resource is. The distinction is what lets a client tell
"this relay does not answer that question" from "there is no such thing".

- `capabilities.proof: false` is not a valid value. A compliant relay always
  serves the proof plane.
- `capabilities.log: false` makes `GET /proof/v1/log` a 501. Per-chain logs are
  served regardless.
- `capabilities.content: false` makes every content-plane route a 501, reads
  included.
- `capabilities.revocations: false` makes every `/revocations/v1/*` route a 501.
  Revocation **enforcement** runs regardless: only the reads are gated.
- `capabilities.index: false` or absent makes every `/index/v0/*` route a 501.
- `capabilities.signing: false` or absent makes every `/signing/v0/*` route a 501.
- `capabilities.write: false` makes `POST /proof/v1/operations` and
  `PUT /content/:contentId/blob/:ref` 501s. See [Write-disabled relays](#write-disabled-relays).

Credential and revocation ingestion have no flag of their own: they enter through
`POST /proof/v1/operations` like every other operation kind.

**Capability gates fire first**, before authentication, body parsing, or any
store lookup, uniformly across every gated family. Where two gates stack, blob
upload is gated by `content` and then by `write`, the plane-existence gate fires
first.

### Relay identity and profile

Every relay has a DID that resolves on its own proof plane. It is the relay's
peer identity when it gossips, and its self-proof anchor for anyone querying it.

The relay MUST publish a profile artifact signed by its own DID using the head
key state, under the `https://schemas.dfos.com/profile/v1` schema:

```json
{
  "$schema": "https://schemas.dfos.com/profile/v1",
  "name": "edge.relay.dfos.com",
  "description": "Cloudflare edge relay for the DFOS network",
  "links": [{ "uri": "https://dfos.com", "label": "operator", "description": "DFOS Inc" }]
}
```

All fields are optional except `name`, which SHOULD be present. The optional
`links` array carries up to 20 `{ uri, label?, description? }` entries. The
profile JWS token is inlined in the well-known response, so it is self-proving
and needs no second fetch.

---

## The read contract

Every route below is served when the relay holds the data and the family's
capability is on. Reads are unauthenticated: the proof plane is public and its
operations carry their own authentication.

| Method | Path                                        | Purpose                                         |
| ------ | ------------------------------------------- | ----------------------------------------------- |
| `POST` | `/proof/v1/operations`                      | Submit proof-plane operations                   |
| `GET`  | `/proof/v1/operations/:cid`                 | One stored operation by CID                     |
| `GET`  | `/proof/v1/countersignatures/:cid`          | Countersignatures on a target CID               |
| `GET`  | `/proof/v1/identities/:did`                 | Projected identity state                        |
| `GET`  | `/proof/v1/identities/:did/log`             | Identity chain operation log                    |
| `GET`  | `/proof/v1/content/:contentId`              | Projected content-chain state                   |
| `GET`  | `/proof/v1/content/:contentId/log`          | Content chain operation log                     |
| `GET`  | `/proof/v1/log`                             | Global ingestion-ordered operation log          |
| `GET`  | `/revocations/v1/credential/:credentialCID` | Revocation status of one credential             |
| `GET`  | `/revocations/v1/issuer/:did`               | Every revocation this relay holds for an issuer |

`POST /proof/v1/operations` is the one write route on this table; it is behind
`capabilities.write` and subject to the relay's [admission policy](#admission),
and it is specified in [The write contract](#the-write-contract). Everything else
above is a read.

The `/proof/v1` prefix encodes the plane and its version (`{plane}/{version}`),
so the plane mounts or proxies as a unit by prefix. `/revocations/v1` sits at the
relay root on its own prefix: revocations **enter** through
`POST /proof/v1/operations`, and this family exposes a read over the index a
relay already maintains for its own enforcement.

Four more families sit at the root, each on its own prefix:
`GET /.well-known/dfos-relay` ([above](#the-well-known-document)),
`GET /1.0/identifiers/:did` (the DIF Universal Resolver binding,
[DID-METHOD](https://protocol.dfos.com/did-method)), `GET /index/v0/*`
([Index](#index-capability-index)), and `/signing/v0/*`
([Signing mailbox](#signing-mailbox-capability-signing)). Content-plane blob
routes live at `/content/:contentId/blob*`, distinct from the proof node's
`/proof/v1/content/:contentId` paths, so a reverse proxy can fan the two planes
across origins by prefix.

### Error body

Every route answers failures with one body shape, `{ "error": "<prose>" }`, plus
the appropriate status code. The prose is diagnostic, never contractual: callers
branch on status codes and MUST NOT match message text. Two exceptions:
`POST /proof/v1/operations` MAY carry an additive `details` array of per-item
schema issues beside `error` on a `400` (diagnostic in the same way), and the
universal resolver answers in the DIF resolution envelope its own interface
requires.

A store failure is answered with the same body and a 5xx status. A relay MUST NOT
answer a store failure with an empty result: see
[A store error is never absence](#a-store-error-is-never-absence).

### Pagination envelope

Every list route paginates identically: `limit` (default 100, max 1000, values
above the max clamped, never rejected) plus `after` (cursor from a previous
page's `next`, passed back verbatim; omit to start) in, `next` out, the last
returned row's cursor, or `null` when the page was not full (caught up). An
unrecognized or undecodable cursor is a **400, never a silently empty page**.
Cursor conduct splits three ways, and each route names which it has:

| Conduct                    | Routes                                                                                             | An unrecognized `after`...                                                                                                                             |
| -------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Relay-local positional** | the ingestion-ordered logs (global and per-chain)                                                  | **400**: cursors are meaningful only against the relay that issued them, and the client restarts its walk from the beginning (ingestion is idempotent) |
| **Transparent keyset**     | countersignature reads, `/revocations/v1/issuer/:did`, the index families in their lexical default | resumes strictly past `after` whether or not it names a present row, so even a foreign cursor is safe and never errors                                 |
| **Opaque token**           | the index families in ordered mode, the mailbox poll                                               | resumes strictly past the encoded key when the token decodes; an **undecodable** token is 400                                                          |

A continuously syncing client persists only server-supplied `next` values, never
a fabricated one, and on `next: null` retains its last persisted cursor, cheaply
re-fetching the final partial page next cycle. On a 400 it resets and re-syncs
from the start. No route family invents another envelope.

### Operation read (`GET /proof/v1/operations/:cid`)

```json
{ "cid": "bafy…", "jwsToken": "eyJ…", "chainType": "identity", "chainId": "did:dfos:…" }
```

`chainType` is one of `identity`, `content`, `artifact`, `countersign`,
`revocation`, `credential`; `chainId` is the routing identifier (DID for
identity-keyed kinds, contentId for content operations, target CID for
countersignatures). 404 when the CID is not held.

### Identity state (`GET /proof/v1/identities/:did`)

```json
{
  "did": "did:dfos:…",
  "headCID": "bafy…",
  "state": {
    "did": "did:dfos:…",
    "isDeleted": false,
    "authKeys": [...],
    "assertKeys": [...],
    "controllerKeys": [...],
    "services": [...]
  }
}
```

Projected state: the computed result of replaying the chain to its head under the
core verification rules, including the identity's `services` discovery vocabulary
([PROTOCOL, Services](https://protocol.dfos.com/spec#services)). Key arrays carry
the **effective** state, so a key membership whose introduction carries no valid
possession envelope is absent from them
([PROTOCOL, Key possession](https://protocol.dfos.com/spec#key-possession)). Pure
chain state: no derived authorization material rides this route.

A deleted identity still resolves, carrying `isDeleted: true`. A sealed chain
stays addressable forever, because it is the verification substrate for
everything that identity ever signed.

### Content state (`GET /proof/v1/content/:contentId`)

```json
{
  "contentId": "…",
  "genesisCID": "bafy…",
  "headCID": "bafy…",
  "state": {
    "contentId": "…",
    "genesisCID": "bafy…",
    "headCID": "bafy…",
    "isDeleted": false,
    "currentDocumentCID": "bafy…",
    "length": 1,
    "creatorDID": "did:dfos:…"
  }
}
```

Pure chain state. Which credentials currently authorize a public read is a
content-plane question, answered live on the read path, and it does not ride this
route.

### Logs

**Global** (`GET /proof/v1/log?after={cursor}&limit=N`): every successfully
ingested operation in ingestion order, entries `{ cid, jwsToken, kind, chainId }`,
`kind` one of the six primitive kinds. JWS tokens are included in every entry
because proof-plane payloads are bounded, so a syncing peer replays the log
without separate fetches. Cursors are relay-local and implementation-shaped (the
reference relays use the entry CID; another relay MAY use an opaque composite
token), and an `after` the relay does not recognize is a 400.

> **`chainId` is not a per-chain partition key.** `credential` and `revocation`
> entries carry `chainId` = the issuer DID, the **same** value as that DID's
> `identity-op` and `artifact` entries, so folding the global log per-chain on
> `chainId` alone silently co-mingles kinds under one DID. An indexer
> reconstructing a specific chain MUST filter by `kind` first.

**Per-chain** (`GET /proof/v1/identities/:did/log`,
`GET /proof/v1/content/:contentId/log`): the chain's operations in chain order,
entries `{ cid, jwsToken }`, same envelope and same 400-on-unknown-cursor rule.
An identity chain is linear, so its per-chain cursor can only advance. A content
chain's log enumerates **every branch** the relay accepted, not the head lineage,
so a client folding it applies head selection itself.

### Countersignatures (`GET /proof/v1/countersignatures/:cid?after={cid}&limit=N`)

Returns `{ "countersignatures": [{ "cid", "jwsToken" }], "next" }`, sorted by each
countersignature's own CID ascending under the **transparent keyset** conduct: an
`after` that is not a present key resumes at the next greater key, so cursors
survive concurrent additions and cross-relay replay. Works for any CID-addressable
target. 404 only when the CID is neither a known operation nor has stored
countersignatures. Each countersignature's `targetCID` and `relation` live inside
its signed payload: the token is the truth, and the row fields are conveniences.

The row shape matches per-chain log entries, so a generic client handles both
identically.

### Revocation status

**Credential** (`GET /revocations/v1/credential/:credentialCID`):

```json
{ "credentialCID": "bafyrei…", "revoked": true, "revocation": "eyJ…" }
```

`200` revoked includes `revocation`, the full revocation JWS. `200` not revoked is
`{ "credentialCID": "…", "revoked": false }` with no `revocation` key. `400` when
the param is not a well-formed credential CID (`bafyrei` + 52 base32 chars). If
more than one issuer has revoked the same CID, the relay answers deterministically
with the lexicographically smallest `issuerDID`'s revocation.

**Issuer** (`GET /revocations/v1/issuer/:did?after={cid}&limit=N`):

```json
{
  "did": "did:dfos:…",
  "revocations": [{ "credentialCID": "bafyrei…", "revocation": "eyJ…" }],
  "next": null
}
```

Every revocation this relay has ingested for the issuer, sorted by
`credentialCID` ascending under the transparent-keyset conduct, so a revocation
whose signer-claimed `createdAt` is backdated can never be inserted behind a
client's cursor and silently skipped. `400` when the param is not a canonical
31-char `did:dfos` identifier. An issuer with none returns an empty array.

**The JWS is the proof; the boolean is a convenience.** A caller re-verifies the
returned revocation token itself: signature against the issuer's identity chain,
CID integrity, and the issuer-only rule. And **absence is NOT proof of
non-revocation**: `revoked: false` attests only that this relay has not ingested a
revocation for that CID. A caller that needs stronger assurance queries several
independent relays. A `501` from this family means the relay does not answer
revocation-status questions, and a client MUST NOT read it as a negative answer.

The two shapes carry a known privacy trade.
`GET /revocations/v1/credential/:credentialCID` is OCSP-shaped
([RFC 6960](https://www.rfc-editor.org/rfc/rfc6960)) and tells the relay exactly
which credential a verifier is checking.
`GET /revocations/v1/issuer/:did` is CRL-shaped
([RFC 5280 §5](https://www.rfc-editor.org/rfc/rfc5280#section-5)): fetch the
issuer's whole set and check locally, disclosing nothing per check at the cost of
the transfer. A verifier picks its half.

### Full route surface

Every route a reference relay serves, with its plane and its authentication.

| Method | Path                                        | Plane       | Auth                                          |
| ------ | ------------------------------------------- | ----------- | --------------------------------------------- |
| `GET`  | `/.well-known/dfos-relay`                   | meta        | none                                          |
| `POST` | `/proof/v1/operations`                      | proof       | admission policy: anonymous or identity proof |
| `GET`  | `/proof/v1/operations/:cid`                 | proof       | none                                          |
| `GET`  | `/proof/v1/countersignatures/:cid`          | proof       | none                                          |
| `GET`  | `/proof/v1/identities/:did`                 | proof       | none                                          |
| `GET`  | `/proof/v1/identities/:did/log`             | proof       | none                                          |
| `GET`  | `/proof/v1/content/:contentId`              | proof       | none                                          |
| `GET`  | `/proof/v1/content/:contentId/log`          | proof       | none                                          |
| `GET`  | `/proof/v1/log`                             | proof       | none                                          |
| `GET`  | `/1.0/identifiers/:did`                     | meta        | none                                          |
| `GET`  | `/revocations/v1/credential/:credentialCID` | revocations | none                                          |
| `GET`  | `/revocations/v1/issuer/:did`               | revocations | none                                          |
| `GET`  | `/index/v0/operations`                      | index       | none                                          |
| `GET`  | `/index/v0/identities`                      | index       | none                                          |
| `GET`  | `/index/v0/content`                         | index       | none                                          |
| `GET`  | `/index/v0/artifacts`                       | index       | none                                          |
| `GET`  | `/index/v0/countersignatures`               | index       | none                                          |
| `GET`  | `/index/v0/credentials`                     | index       | none                                          |
| `GET`  | `/index/v0/credits`                         | index       | none                                          |
| `POST` | `/signing/v0/requests`                      | signing     | deposit credential (in body)                  |
| `GET`  | `/signing/v0/requests`                      | signing     | identity proof                                |
| `POST` | `/signing/v0/requests/:cid/response`        | signing     | none, validity is the auth                    |
| `GET`  | `/signing/v0/requests/:cid/response`        | signing     | none, CID knowledge                           |
| `POST` | `/signing/v0/requests/:cid/decline`         | signing     | none, advisory                                |
| `PUT`  | `/content/:contentId/blob/:ref`             | content     | identity proof                                |
| `GET`  | `/content/:contentId/blob[/:ref]`           | content     | standing auth, or identity proof + credential |

A relay SHOULD serve an [OpenAPI](https://spec.openapis.org/oas/latest.html)
document describing this surface, advertised in the well-known's `openapi` field.

---

## The write contract

All proof-plane operations enter through one endpoint,
`POST /proof/v1/operations`, behind `capabilities.write`. Identity operations,
content operations, artifacts, countersignatures, credentials, and revocations
mix freely in one batch.

### Submission (`POST /proof/v1/operations`)

The request body is `{ "operations": [ "<JWS>", … ] }`, classified by each token's
JWS `typ` header (the
[extension registry](https://protocol.dfos.com/spec#extension-registry) names the
values). A batch carries at most **100 tokens**; a larger array is a **400**. The
reference implementations additionally guard the aggregate body at 16 MiB
(**413**; a client that sees 413 chunks and retries, while 400 remains the
malformed-content verdict). Gossiping peers chunk larger runs to stay within the
caps.

The response is `{ "results": [ { "cid", "status", "error"? } ] }` **in the same
order as the input array**: `results[i]` corresponds to `operations[i]`,
regardless of internal processing order, with exactly three statuses:

| Status      | Meaning                                                                                                                                                                                                                               |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `new`       | First time seen, verified, stored, state changed                                                                                                                                                                                      |
| `duplicate` | Already held: the exact same CID **and** JWS token, a true idempotent resubmission. Same CID with a different token is `rejected` (Ed25519 is deterministic, so a different token for the same payload means a different signing key) |
| `rejected`  | Verification failed (`error` says why, diagnostically)                                                                                                                                                                                |

Duplicate countersignatures (same witness DID, same target CID) MUST be
deduplicated: one countersign per witness per target, a relay MUST NOT store
multiple attestations from the same witness for the same target, and resubmission
SHOULD return `duplicate`.

### Admission

Who may ingest is a **policy axis**, not a fixed rule, and peers are not special:
gossip-in, client submission, and open deposit are one door with one grammar. A
submission arrives in one of two **admission modes**, **anonymous** (no proof) or
**identity-proven** (an
[identity proof](https://protocol.dfos.com/integrations#the-identity-proof)
signed by the submitting party's own DID, `jti` required), and the relay evaluates
a **relay-local admission policy** over what it now knows: a proven principal, or
anonymity. Policy MAY refuse either mode. Policy content is operator-defined and
outside this specification: one relay admits only DIDs its operator recognizes,
another is open-anonymous under quotas, another is allowlist-only. "My peers" is
one possible policy set, not a separate authentication scheme.

**The evaluation ladder is normative, cheapest first:**

1. **Structural caps**: batch size, body size, token shape. Failures are
   **400**/**413**.
2. **Proof verification**, when a proof is presented: one signature plus a
   current-state key resolution. An invalid proof is **401**; an unresolvable
   presenter is **503**.
3. **Admission policy** over (principal | anonymous). A refusal is **403** with
   the ordinary error body, distinguishable from malformed (400), from an invalid
   proof (401), from unverifiable (503), and from capability-off (501). Refusal is
   request-level: nothing in the batch is examined further, and no per-item results
   are produced. A policy that cannot be evaluated fails **closed** (503, the
   server's condition, not a judgment on the caller).
4. **Full verification**: the per-item work of the sections below, only for
   admitted submissions. The expensive step is never spent on a submission policy
   refuses.

The well-known's `ingestion` member advertises the mode so a client knows before
attempting: `"open"` (anonymous submissions admitted, subject to policy),
`"proof-required"` (anonymous refused at step 3), or `"closed"` (no external
ingestion, and `POST /proof/v1/operations` answers 501 as under
`capabilities.write: false`). Advertisement is a hint; the policy decision is the
authority.

**The `jti` replay cache is REQUIRED on every write-shaped proof.** An identity
proof presented to ingestion or to blob upload MUST carry the `jti` member,
recorded by the relay with an atomic insert-if-absent and expired with the
freshness window. Policy runs before full verification, so the relay grants
admission-layer effects (quota spend, reputation attribution) before it knows
whether the payload is a harmless duplicate. Read-shaped proofs rely on the
freshness window alone.

### Authentication

The relay owns **no authentication grammar**. Every authenticated request consumes
the request-bound possession-proof envelopes specified in
[INTEGRATIONS, API authentication](https://protocol.dfos.com/integrations#api-authentication),
and every route sits in exactly one of three tiers:

| Tier               | Wire                                                       | Routes                                                                                                                              |
| ------------------ | ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| **Public**         | nothing                                                    | every read above, index and revocation reads, publicly-granted blob reads, sign-response collect (CID knowledge) and decline        |
| **Identity proof** | `Authorization: DFOS <did:dfos:identity-proof JWS>`        | creator's own blob reads, blob upload, the mailbox poll, the authentication half of non-public blob reads, and optionally ingestion |
| **Credential**     | `X-Credential` presentation, or an ingested standing grant | non-creator blob reads (alongside the identity proof), mailbox deposit                                                              |

Verification is INTEGRATIONS', verbatim: the relay's **own configured authority**
is the `host` binding (a relay serving several hostnames selects the expected one
from its own configuration, never from a request header), presenter resolution is
current-state against the relay's local store, and the freshness window is the
relay's to own. A route that requires a credential rejects an identity proof at
the `typ` gate and the reverse. A relay MUST reject an identity proof whose
presenter's current state is deleted, however valid its signature.

### Classification

Each token is classified by its JWS `typ` header. Classification is unambiguous:
no DID comparison is needed.

| `typ` header           | Classification           |
| ---------------------- | ------------------------ |
| `did:dfos:identity-op` | Identity chain operation |
| `did:dfos:content-op`  | Content chain operation  |
| `did:dfos:artifact`    | Artifact                 |
| `did:dfos:countersign` | Countersignature         |
| `did:dfos:credential`  | DFOS credential          |
| `did:dfos:revocation`  | Credential revocation    |

### Dependency sort

Within a batch, operations are sorted by dependency priority before processing:

1. **Identity operations**, so their keys are available
2. **Artifacts**, which reference identity keys for signature verification
3. **Content operations**, which reference identity keys and may have chain
   dependencies
4. **Countersignatures**, which reference identity keys and an existing target

Within each priority level, genesis operations (no `previousOperationCID`) are
processed before extensions, so one batch bootstraps an entire
identity-and-content lifecycle without multiple round trips.

### Verification

Each operation is verified against the relay's stored state.

- **Identity operations**: extension operations verify against the relay's current
  trusted state with O(1) extension verification, the trusted head state plus the
  new operation. Genesis operations verify the single-operation chain.
- **Content operations**: extension operations verify against trusted state with
  `enforceAuthorization: true`. A non-creator signer MUST carry a DFOS credential
  with `action: "write"` attenuations in the operation's `authorization` field.
- **Revocations**: the signature verifies against the revoking DID's identity
  state, and the payload must reference a valid credential CID.
- **Artifacts**: the signature verifies against the signing DID's identity state,
  CID integrity is checked, the payload conforms to the declared `$schema`
  structure, and the CBOR-encoded payload MUST NOT exceed 16384 bytes.
- **Countersignatures**: two phases. Stateless, at the protocol level: signature,
  CID integrity, payload schema. Stateful, at the relay: the target CID MUST exist
  in the relay, the witness DID MUST differ from the target's author DID, and one
  countersign per witness per target.

Temporal checks resolve at the [basis time](https://protocol.dfos.com/spec#time-basis):
for these committed artifacts the basis is each operation's own `createdAt`, so
two relays reach the same verdict on the same operation whenever each one ingests
it. A relay MUST NOT add an ingest-time wall-clock `exp` check.

### Chain resolution

The relay routes each incoming operation to its chain. Resolution differs by kind:

- **Identity genesis**: no prior chain. The relay verifies the single-operation
  chain and creates a new stored identity chain keyed by the new DID.
- **Identity extension**: the `kid` in the JWS header is a DID URL
  (`did:dfos:<id>#<keyId>`). The relay extracts the DID prefix (before `#`) and
  looks up the existing chain. A `kid` without `#` on a non-genesis operation is
  rejected: it cannot be routed.
- **Content genesis**: no prior chain. The relay creates a new stored content
  chain keyed by the content ID derived from verification.
- **Content extension**: the `previousOperationCID` payload field looks up a
  stored operation, which carries the `chainId`; the relay then fetches the
  content chain by that `chainId`. If the previous operation does not exist or is
  not a content operation, the extension is rejected.
- **Countersignatures**: the `targetCID` payload field looks up the target
  operation, whose author DID enforces the witness-is-not-author rule.

### Identity linearity and admission

**Conflicting extension is a permanent rejection.** An incoming identity operation
whose `previousOperationCID` references an operation that already has a committed
child is refused with the named error
`identity chains are linear: conflicting extension refused`. It is not buffered,
not retried, and never admitted later: first-seen wins locally, whatever the
competing operation's `createdAt` claims. The rule holds on every path an identity
operation arrives by, including direct submission, gossip, sync, and read-through.
A peer-log identity operation that conflicts with a locally-committed extension is
refused identically: committed order in this relay's log is never re-arbitrated.

The refusal is this relay's admission verdict, not a claim that the refused
operation is invalid. Two operations at one chain position are two views of the
identity ([PROTOCOL, Views](https://protocol.dfos.com/spec#views)). What
first-seen admission buys is a log no later timestamp can reorder. An identity
write this relay refuses is admitted by a relay that holds no successor at that
position, so the writer either retries here or continues the chain there.

**Possession status never gates admission.** The relay admits and sequences every
structurally valid identity operation, meaning linearity, CIDs, timestamps, and
declared-state signer validity, whatever its key proofs say. This is the relay's
door of the three-door rule, normative in
[PROTOCOL, Key possession](https://protocol.dfos.com/spec#key-possession). An
update introducing a key without a valid proof ingests exactly like any other: the
membership it claims is **void** in every projection the relay serves, and the
operation itself is committed log. Rejecting it instead would make log membership
depend on semantic validation, and two relays disagreeing about one operation's
proofs on a linear chain is a forked log. The log answers what was written; the
projections answer what counts.

### Content-chain forks and head selection

Content-chain forks are accepted. If an incoming content operation's
`previousOperationCID` references any operation in the chain, not just the current
head, the relay verifies the extension against the chain state at that fork point
and accepts it. The chain log accumulates all branches.

After accepting a fork the relay recomputes the head: highest `createdAt` among
tips, lexicographic highest CID as tiebreaker
([PROTOCOL, Chain validity](https://protocol.dfos.com/spec#chain-validity)). This
is deterministic across relays given the same set of operations, regardless of
ingestion order.

To verify a fork extension the relay computes chain state at the parent CID.
Implementations choose the strategy: full replay, snapshot-backed, or otherwise.

**Content-chain deletes stay per-branch**: a content `delete` seals its own
branch, forks rooted at a pre-delete operation remain valid, and head selection
may make a non-deleted branch the head. Identity undeletion is not a fork
behavior: it is the explicit `restore` operation on the linear identity chain.

### The 24-hour future bound

Identity and content operations with a `createdAt` more than 24 hours in the
future are rejected. Head selection favors the highest timestamp, so a far-future
`createdAt` would permanently dominate content-chain head selection. The window
accommodates clock drift. Identity chains select no head, and the same bound
applies to their operations: one admission rule, no per-kind exception.

### Deletion and restore

Deletion means the identity stops being an active participant. Historical
operations remain verifiable, and no new acts flow from a deleted identity.

**The one exception, stated once for every gate below:** a **`restore`** identity
operation in exactly the successor-of-delete position (`previousOperationCID` =
the delete's CID, signed by a controller key of the deleted head state) is the
single operation a deleted identity's chain accepts. A valid restore returns the
identity to active: resolution reports `deactivated: false`, and every gate below
reopens for operations that follow it.

- **Identity operations after deletion**: rejected, except a valid `restore` as the
  immediate linear successor of the `delete`. Anything else appended after a
  delete, including a `restore` anywhere but that position or one signed by a key
  not in the deleted head state, is permanently rejected. The `delete`, and any
  `restore`, remain permanently in the linear log.
- **Content operations after deletion**: rejected. Both paths are checked, the
  signer's identity being deleted and the content chain's creator identity being
  deleted, and the chain is sealed regardless of who signs.
- **Artifacts from deleted identities**: rejected.
- **Credentials from deleted issuers**: rejected. Identity deletion suspends all
  authority, including outstanding credentials the deleted identity issued.
- **Countersignatures from deleted witnesses**: rejected. Countersignatures **on**
  operations by deleted authors are still accepted: deletion of the target's
  author does not prevent other identities from attesting.

**Restore resurrects, revocation terminates.** After a valid restore, credentials
issued before the delete are honored again, because they were never revoked and
their issuer was suspended. A credential the issuer actually revoked stays revoked
forever, restore or not.

Self-countersignatures, where the witness DID matches the target's author DID, are
rejected at the relay. A countersignature's semantic is that a distinct witness
attests. The protocol-level verifier is stateless and does not enforce this, so
the relay resolves the target's author and rejects self-attestation.

### Revocations and standing credentials

Revocations are ordinary proof-plane operations. When one is accepted:

1. The revoked credential's CID is recorded against its issuer, together with the
   revocation's own signed `createdAt`.
2. Standing authorization backed by that credential stops granting: the live
   per-request check denies it on the next read. A relay that keeps a candidate
   index MAY also evict the entry eagerly; the live check is what guarantees
   immediacy.
3. Future content-chain operations embedding the revoked credential as
   `authorization` are rejected.
4. Future content-plane requests presenting the revoked credential are rejected.

**Eviction is issuer-scoped.** A revocation retracts only its own issuer's
credential. A relay MUST key the eviction of a standing public credential on
`(issuer DID, credential CID)`, never on the CID alone, so a DID cannot revoke
credentials it did not issue
([CREDENTIALS, Revocation](https://protocol.dfos.com/credentials#revocation)).

**Ingest asks freshness; re-verification asks the basis.** Points 2 to 4 are
acceptance decisions, answered from what the relay currently knows: a relay MUST
refuse a **new** operation authorized by a credential it already holds a
revocation for, whatever that operation's `createdAt` claims, because backdating
would otherwise buy a revoked delegate an indefinite write window. Re-verifying an
operation the relay has **already committed**, when replaying a chain's history or
ingesting a peer's log, resolves at that operation's own `createdAt` per the
[time basis](https://protocol.dfos.com/spec#time-basis): a relay MUST NOT reject a
committed operation because a credential in its history was revoked later. The
acceptance verdict is local and never enters the replicated log; historical
validity is deterministic and identical on every relay.

### Buffering and sequencing

Operations may arrive before their causal dependencies. A relay MUST eventually
process any structurally valid operation whose causal dependencies have been
processed.

An operation's causal dependencies are the minimum state required for
verification:

| Operation type     | Dependencies                                            |
| ------------------ | ------------------------------------------------------- |
| Identity genesis   | None                                                    |
| Identity extension | Previous identity operation (by `previousOperationCID`) |
| Content genesis    | Creator's identity chain (for key resolution)           |
| Content extension  | Previous content operation + creator's identity chain   |
| Artifact           | Signer's identity chain                                 |
| Countersignature   | Signer's identity chain + target operation              |

A relay MUST NOT discard a structurally well-formed operation because its
dependencies are temporarily unavailable. The reference strategy is
store-then-verify:

1. **Store**: on receipt, store the raw JWS token in a content-addressed buffer
   keyed by operation CID. This is idempotent, and duplicate CIDs are ignored.
2. **Verify**: attempt full verification against current state. Three outcomes.
   **Sequenced**, verification succeeded and the operation is committed to chain
   state and the global log. **Dependency failure**, a causal dependency is
   missing and the operation stays in the buffer. **Permanent rejection**,
   structurally invalid, bad signature, deleted identity, or a conflicting
   extension of a committed identity operation, which will never succeed whatever
   state arrives.
3. **Sequence loop**: after each ingestion batch, re-attempt buffered operations
   in dependency order until no further progress is made. Cross-batch dependencies
   resolve within the providing batch's response cycle.

A rejection is a dependency failure if and only if it is caused by missing state
that may arrive later. The set is small and stable: the previous operation is not
in the store, the identity chain is not available for key resolution, the
content chain's genesis has not arrived, or fork state cannot be computed because
an ancestor in the branch path is absent. All other rejections are permanent and
MUST NOT be retried. In particular, an identity operation refused as a conflicting
extension is permanent.

The raw buffer and the sequencer are internal to the writing relay. They are not
wire surface, and nothing about them is visible to a client beyond
`stats.pendingOps`.

**All chain-state mutations MUST be serialized.** Concurrent ingestion of
operations for the same chain is a read-modify-write race: two workers read the
chain log, both append, and the second write clobbers the first. Raw operation
storage is idempotent and append-only and needs no serialization.

### A store error is never absence

A store read that fails MUST NOT be treated as a miss, and a store write that
fails MUST NOT leave a half-commit. Concretely:

- A failed read during verification is a **dependency failure**, retryable, never
  a permanent rejection: a transient failure MUST NOT delete a buffered operation.
- A failed read on an idempotency or existence check is an error answer, never
  "not held".
- A failed write inside a batch rolls the batch back rather than reporting an
  outcome it did not persist.
- A failed identity lookup on any authorization path refuses the request rather
  than falling through to a caller-supplied alternative.
- An unavailable check on the read path denies rather than grants.

The reason is one sentence: a relay that reads absence out of its own failures
converts an operational blip into a durable, signed-looking claim about the world.

### Write-disabled relays

`capabilities.write` says whether this relay accepts writes over HTTP. It says
nothing about where the relay's corpus comes from. A relay MAY be an **origin**,
the authoritative source of its own log, minting operations out of band from
whatever system of record it runs, and refusing external writes precisely because
nothing outside it is entitled to append. A relay MAY equally run as a **lite
pull-only proof node** that verifies, stores, and serves the proof plane and
accepts no writes, staying current by polling its peers' `/proof/v1/log` and
ingesting verified operations locally. `dfos serve --no-write` runs that mode.
Both advertise `write: false` with `ingestion: "closed"`, and the flag does not
distinguish them: `capabilities.write` is the **admission surface**, `ingestion`
is the **admission mode**, and where a relay's operations come from is a
deployment fact the wire does not carry.

`write: false` gates **every** write route on both planes.
`POST /proof/v1/operations` and `PUT /content/:contentId/blob/:ref` both answer
**501**. Because the POST route is both the client-write and the peer-gossip-ingest
path, and nothing in the request distinguishes them, refusing it disables gossip-in
along with client writes. Blob upload is the one route that accepts a
multi-megabyte body, so leaving it open on a node whose point is a minimal attack
surface would contradict the advertised capability.

"Writes" quantifies over the two replicated planes: proof-plane ingestion and
content-plane blob upload. The [signing mailbox](#signing-mailbox-capability-signing)
is on neither plane and is governed solely by `capabilities.signing`, so a
`write: false` relay MAY serve the mailbox. Its no-ingest invariant is exactly
"this relay never ingests proof-plane operations".

| Flags                          | Result                                                                                  |
| ------------------------------ | --------------------------------------------------------------------------------------- |
| `write: false`                 | No writes on either plane. Content-plane **reads** (blob download) still serve normally |
| `content: false`               | The content plane is absent entirely: all content routes 501, reads included            |
| `write: false, content: false` | A proof-plane-only, read-only node                                                      |

### Retention

The relay maintains a global append-only operation log: every successfully
ingested operation is appended in ingestion order, and identity and content chains
expose per-chain views in chain order.

**A relay's log is its own, and no relay's log is the corpus.** Append-only names
the relay's serving discipline, entries appended in ingestion order and never
reordered, not a promise that every relay holds everything forever. A relay is
sovereign over its own retention. Peers MUST NOT treat any relay's log as
complete, and cross-relay operation counts are not comparable.

- **Retraction MUST be expressed as revocation.** Deleting bytes from one relay's
  log does not propagate: a peer that already synced them keeps them, and nothing
  on the wire says they left. The act that travels is the signed one. Retraction
  on an identity chain is likewise a chain operation, an `update` removing the key,
  never a rewrite of history.
- **Relays SHOULD retain revocations indefinitely.** Revocations are the retraction
  record and they are tiny. A relay that prunes operations SHOULD prune around
  them.
- **Culling by visibility is sanctioned retention.** A relay MAY hold only the
  operations of chains that are publicly readable and cull the rest, pruning around
  revocations. This is retention, not admission: content visibility is not a
  property of a content operation, since a chain is created and then made publicly
  readable later by a separate `aud: "*"` credential, so no admission policy can
  express "I host only public content". Two consequences are visible on the wire
  and are the relay's to own. **Revocations outlive what they revoke**, so a
  captured grant reads revoked rather than unknown. **The log has holes**, so
  culled operations leave permanent gaps in the relay's sequence and `opCount` is
  not a log position.
- **A cursor past a relay's retention answers `400` or a from-scratch first page,
  never a silently empty page.** An empty page that reads as caught-up would
  convert one relay's retention into every downstream peer's silent gap.

### Artifacts and countersignatures on the wire

Artifacts and countersignatures are standalone signed primitives, immutable and
CID-addressable, specified in
[PROTOCOL, Artifacts](https://protocol.dfos.com/spec#artifacts) and
[PROTOCOL, Countersignatures](https://protocol.dfos.com/spec#countersignatures).
The relay's additions are the stateful checks named under
[Verification](#verification) and [Deletion and restore](#deletion-and-restore):
target existence, witness is not author, one countersign per witness per target,
and the deleted-signer gates.

---

## Profiles

The four families below sit beside the read and write contracts above. The
index, the signing mailbox, and the content plane are each behind their own
capability flag and answer 501 on every one of their routes when the flag is
off. Peering adds no route at all: it is a convention that runs over the
contracts above.

## Index (capability `index`)

A relay that verifies and folds chains already holds current-state projections.
The index exposes read-only, cursor-paginated queries over them at
`/index/v0/*`, so a light client browses and discovers without replaying the
global operation log.

### Hints, not authority

Index responses are discovery hints. Every row carries the identifiers needed to
re-derive its claims from the proof plane.

- **The index cannot lie by assertion.** Every claim in a row is verifiable
  against the proof plane, and a fabricated row fails the client's fold.
- **The index CAN lie by omission.** A relay can be behind, partitioned, or
  withholding rows, and a light client cannot detect a recall gap. Absence of a
  row is not proof of absence.
- **Index output MUST NOT be used as an authorization input.** `publicRead` is a
  discovery hint; content-plane access is re-derived live on every read.

### What the index may know

> **Every index field and filter MUST be computable from protocol-defined fields
> and verification outcomes alone. Document payloads are opaque**, except the
> well-known projections below.

> **The index knows who acted, when, and what things call themselves. Nothing
> else.**

Every index field and filter is an instance of one of three axes: **actor**
(creator, signer, witness, issuer, and the declared keys through which an actor
acts), **clock** (`genesisAt` / `headAt` / operation or artifact `createdAt` /
relay `ingestedAt`), or **name** (the display-name registry). A query that cannot
be phrased under these axes is a client-composed filter over them, or a
client-side fold over verified bytes.

The index serves **structural facts** the relay already computes to verify (chain
kind, genesis and head CIDs, op counts, creator DIDs, operation signer sets,
deletion state, countersign witnesses and targets, credential issuer and scope,
revocation status, standing public-read grants, identity service entries) and
**declared labels matched as opaque strings** (an artifact or document `$schema`,
a `ContentAnchor` `label`), matched byte-for-byte the way an HTTP server serves a
`Content-Type`.

The index MUST NOT interpret document payloads, join across application
semantics, rank, or reify application concepts. There is no "posts" route: an
application-level notion like _post_ is a client-composed filter expression over
structural parts (`docSchema=… & publicRead=true & creator=…`).

### Well-known projections

The **display-name registry** is the sole exception to payload opacity. Its rule:
one display-name field per enumerated `$schema`, so the index may know what a
thing calls itself, never what it says. Nothing else is extracted: no
descriptions, bodies, summaries, or payload timestamps. The one structured
exception is the [credit projection](#credit-projection).

| #   | Projection          | Definition                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| --- | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `profile/v1 → name` | For an identity whose terminal `services` contain a `ContentAnchor` whose `label`, lowercased, equals `"profile"` and whose `anchor` is a content-chain identifier: if the relay holds the bytes of that chain's current head document, and the decoded document declares `$schema: "https://schemas.dfos.com/profile/v1"`, and its `name` is a non-empty string, the index surfaces that `name` on the identity row's `profile` projection. |
| 2   | `post/v1 → title`   | For a content chain whose current head document bytes the relay holds: if the decoded document declares `$schema: "https://schemas.dfos.com/post/v1"` and its `title` is a non-empty string, the index surfaces that `title` on the content row.                                                                                                                                                                                             |

Every registry row carries the same circuit breakers, and every escape hatch
resolves to the honest unknown:

- A document under any `$schema` not in this table is never field-extracted.
- A listed schema whose document is malformed, or whose extracted field is
  missing, empty, or not a string, projects `null`. No partial parses, no
  coercion.
- Bytes the relay does not hold project `docSchema: null` and the field `null`.
- **A chain that is not publicly readable** (`publicRead` is `false`) never
  surfaces its extracted display-name field: the projected value is `null`. Only
  the extracted value is withheld; the structural `anchor` / `publicRead` /
  `docSchema` fields still project.

Extracted values are attribution-tier claims: the value is whatever the signed
head document says. Clients verify by fetching the chain and re-hashing the served
bytes to the committed `documentCID`. A relay MUST NOT ship extraction rules that
are not listed here.

### Credit projection

The second and only other payload extraction: the index may know who a public
document says made it. For a content chain whose current head document bytes the
relay holds, whose decoded document declares
`$schema: "https://schemas.dfos.com/post/v1"`, and whose `credits` is an array,
each entry with a string `did` projects one row onto the
[credits route](#credits-get-indexv0creditsdidcontentidroleaftercursorlimitn)
carrying `(contentId, did, role, position, hasClaim)`:
`role` is the entry's string `role` or `null`, `position` is the entry's array
index (`0` is the primary author), and `hasClaim` is whether the entry carries a
string `claim`. Nothing else in the entry is projected. `name` is a rendering
convenience whose authoritative surface is the credited DID's own profile
projection, and the `claim` token stays inside the document bytes.

Three normative rules ride on top of the registry's circuit breakers:

- **Public-only, structurally.** Credit rows exist only while the chain's
  projected `publicRead` is `true` and the chain is not deleted. A non-public
  chain has **zero** credit rows: there is no redacted variant, and the family
  MUST NOT be usable to probe non-public content, because attribution must be no
  more public than the content it attributes
  ([CONTENT-MODEL, Credits](https://protocol.dfos.com/content-model#credits)).
- **Head-only, full-replace.** Every recompute derives the content's complete row
  set from the current head document and replaces the previous set. A revision
  that drops a credited entry drops its row; a head whose new document bytes are
  absent clears the set, and rows reappear when the bytes land.
- **Assertion-tier, unverified.** Rows restate what the signed head document
  asserts. `hasClaim` is byte-presence, not validity: the verification states are
  a client fold over the fetched document.

### Determinism and coverage

- **Deterministic enumeration.** By default identity, content, artifact,
  credential, and countersignature lists are ordered lexicographically ascending
  by their cursor key (`did`, `contentId`, or `cid`), and all five additionally
  accept the route-specific time orderings below. Operations are the deliberate
  exception: they are a recency feed and default to `ingestedAt.desc`. Two relays
  holding the same operations serve identical author-time ordering and identical
  structural fields; relay-observed ingestion ordering is local by definition.
- **Keyset pagination is the shared envelope.** Every index route paginates with
  `after`, `limit` (default 100, max 1000), and `next`, over the route's
  enumeration order. In the default lexical mode `after` is a strictly-greater
  cursor: a page returns the rows whose post-filter cursor key is lexicographically
  greater than `after`, ascending, capped at `limit`, and `next` is the last
  returned row's key or `null` when the page was not full. The cursor need not be
  a currently-present key: a value that falls between keys, or one naming a row
  mutated out of the active filter between pages, resumes at the next greater key
  rather than truncating to an empty page. Keys are immutable natural identifiers,
  so a row's membership or projected values may change between pages without
  dropping or duplicating other rows.
- **Time-ordered enumeration (`order=`).** `/identities` and `/content` accept
  `order=genesisAt.desc` (newest chains first) or `order=headAt.desc` (most
  recently active first). The sort key is the composite
  `(timestamp descending, cursor key ascending)`, over the same author-claimed
  `createdAt` values surfaced as `genesisAt` / `headAt`, so ordered pages are as
  deterministic across relays as the lexical default. In ordered mode `after` and
  `next` are **opaque cursor tokens**: a client passes `next` back verbatim and
  MUST NOT parse or construct one. One honest weakening: `genesisAt.desc` sorts by
  an immutable key and is fully stable, while `headAt` is a **mutable** sort key.
  It is monotonically non-decreasing, so a chain updated mid-enumeration moves
  strictly toward the top of `headAt.desc`, into pages already served. An in-flight
  `headAt.desc` enumeration therefore never duplicates a row but MAY miss one that
  was updated while paginating; the row is not gone, it has moved to the front of a
  fresher enumeration. Completeness is the job of the lexical enumeration or the
  log replay. Only the two enumerated values exist, and an unrecognized value is a
  `400`.
- **Operation recency ordering.** `/operations` accepts `createdAt.desc` and
  `ingestedAt.desc` and defaults to `ingestedAt.desc`. `/artifacts`,
  `/credentials`, and `/countersignatures` accept the same values while retaining
  lexical CID order when `order` is absent. All use the same
  descending-timestamp/CID-ascending composite and the same opaque ordered cursor.
  `createdAt` is author-claimed; `ingestedAt` is when this relay accepted the
  operation, so it is relay-local browse chronology rather than protocol authority.
  Unrecognized orders and undecodable ordered cursors are `400`.
- **Boolean parameters fail closed.** A boolean filter is either absent (no
  filter), exactly `true`, or exactly `false`. A present empty or otherwise
  unparseable value is a **400**, never a silent widening to an unfiltered query.
- **Coverage is bounded by held bytes.** `docSchema` and projected fields are
  computable only for chains whose current head document bytes the relay holds. A
  chain whose bytes are absent reports `docSchema: null`, an honest unknown rather
  than a claim of schemalessness, and a `docSchema` filter matches only chains with
  held, decodable head bytes, so callers MUST treat the result as a lower bound.
  Artifacts are the exception: a verified artifact carries its document inline in
  the stored JWS, so accepted artifact rows have a non-null `docSchema`.
- **Timestamps are author-claimed.** `genesisAt` / `headAt` surface the `createdAt`
  fields signed inside the operations, not relay receipt times.
- **Maintenance.** The index is fully re-derivable from the operation log plus held
  blobs. Projection application is driven by a sequence cursor over the operation
  log and runs outside the ingestion lock, so index work never widens the
  transaction that admits an operation. Reference implementations also expose a
  rebuild path for pre-existing corpora. Either way the serving contract is
  identical.
- **`publicRead` is a last-touch snapshot and MAY lag time-based transitions.** A
  materialized `publicRead` reflects whether a standing public-read grant
  authorized anonymous read at the moment the row was last recomputed. One input to
  that predicate, a grant credential's `exp`, is wall-clock-relative and crosses
  without emitting any operation, so incremental maintenance has no event to react
  to: a row can continue to advertise `publicRead: true` after the grant that made
  it public has expired, until the next operation dirties that content or a rebuild
  reruns the projection. This is tolerated because the index is a discovery hint,
  never an authorization input: the content plane re-derives the predicate live on
  every read. A relay MAY additionally re-sweep public rows near expiry to tighten
  the hint.

### Operations (`GET /index/v0/operations?kind=&chainId=&signerKey=&order=&after={cursor}&limit=N`)

Enumerates the operations this relay holds as metadata-only recency rows.

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

Parameters: `kind` (optional exact match, one of `identity-op`, `content-op`,
`artifact`, `countersign`, `revocation`, or `credential`; `400` otherwise),
`chainId` (optional exact match against the operation-log routing identifier),
`signerKey` (optional exact multibase public-key match against the key the row's
verified signature resolved to at ingest, an opaque byte match with no format
validation and no `400`), `order` (`createdAt.desc` or `ingestedAt.desc`, default
`ingestedAt.desc`), `after` (the opaque ordered cursor), and `limit` (default 100,
max 1000). Filters are ANDed.

The signer filter is **key-addressed, not DID-addressed**. A `kid` is an
identity-local indirection, rebindable across key material by the chain that
defines it; the public key a signature verified against is the immutable fact of
the row, and ingestion already resolved it to verify the operation. A
DID-addressed signer filter is not defined on this route: which DID stands behind
a key is the identity index's question.

Rows are browsing metadata, never proof: they contain no JWS, payload, title, or
name.

### Artifacts (`GET /index/v0/artifacts?cid=&signer={did}&docSchema=&order=&after={cid}&limit=N`)

Enumerates standalone signed artifacts, `cid` ascending by default.

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

Parameters: `cid` (optional exact artifact-CID match, returning zero or one row,
composing with the remaining filters), `signer` (optional exact DID from the
artifact JWS `kid`; `400` when malformed), `docSchema` (optional exact opaque
match against the inline document's `$schema`), `order` (optional `createdAt.desc`
or `ingestedAt.desc`; lexical CID order when absent), `after` (a CID keyset cursor
in lexical mode or an opaque ordered cursor in ordered mode), and `limit` (default
100, max 1000). Filters are ANDed. Rows carry no artifact payload; clients fetch
the artifact from the proof plane and verify it before use.

### Identities (`GET /index/v0/identities?did=&key=&hasPublicProfile=&nameContains=&order=&after={did}&limit=N`)

Enumerates identity chains, `did` ascending by default.

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

| Field                  | Type           | Description                                                                                                                                                                                                                                                                                                                                                                          |
| ---------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `opCount`              | number         | Operations stored for this chain. Identity chains are linear per view, so this is the linear operation count                                                                                                                                                                                                                                                                         |
| `genesisAt` / `headAt` | string         | Author-claimed `createdAt` of the genesis and current head operations                                                                                                                                                                                                                                                                                                                |
| `profile`              | object \| null | The well-known projection, or `null` when the identity declares no profile-labeled content-chain anchor. Non-null means the chain **names** an anchor, never that this relay holds it                                                                                                                                                                                                |
| `profile.anchor`       | string         | The anchored contentId, the client's verification pointer. A chain fact, read from the identity's own signed services, present whenever the identity names an anchor, **including when this relay holds nothing under that contentId**                                                                                                                                               |
| `profile.publicRead`   | boolean        | Whether a standing public-read grant currently authorizes anonymous read of the anchored chain, per this relay's fold. A hint, never an access decision. `false` is the fold's answer for a chain this relay does not hold at all                                                                                                                                                    |
| `profile.docSchema`    | string \| null | `$schema` declared by the held head document. **MUST be `null` whenever the relay does not hold the anchored chain's current head bytes**, including when it holds no such chain. `null` has three causes: bytes not held, bytes that do not decode, and a decoded document declaring no string `$schema`. A non-null value is a claim that this relay holds and decoded those bytes |
| `profile.name`         | string \| null | Extracted per the projection table; `null` on any circuit breaker, including when the relay does not hold the anchored chain's head bytes and when `profile.publicRead` is `false`                                                                                                                                                                                                   |

**A named anchor and a held anchor are different facts.** `profile.anchor` comes
from the identity chain; everything beside it comes from what the relay holds
under that contentId. An identity that anchored a profile and later withdrew it,
or whose anchored chain this relay never held or culled, keeps a non-null
`profile` carrying its `anchor`, with `docSchema: null`, `name: null`, and
`publicRead: false`. That row is the honest rendering of "this identity names a
profile; ask elsewhere for it". Because `hasPublicProfile` folds no-anchor,
private-anchor, and not-held-anchor into a single `false`, a consumer that needs
to tell them apart reads the row's `profile` object, not the filter.

Parameters: `did` (optional exact DID match, returning zero or one row), `key`
(optional exact match against a public key the identity has ever proved, semantics
below), `hasPublicProfile` (optional boolean filter on the predicate "`profile` is
non-null AND `profile.publicRead` is true"), `nameContains` (optional
case-insensitive substring filter over projected `profile.name`, applied before
keyset pagination), `order` (optional `genesisAt.desc` or `headAt.desc`; `400` on
any other value), `after` (a `did` keyset cursor in the lexical default, or an
opaque token in ordered mode), `limit` (default 100, max 1000). Multiple
profile-labeled anchors resolve deterministically to the one with the
lexicographically smallest service `id`.

**Discovery and resolution are separate promises for deleted identities.** A relay
**MAY** omit deleted (`isDeleted: true`) identities from the **discovery** shapes
of this route (the unfiltered listing, the keyset and ordered walks,
`nameContains`, and `hasPublicProfile`). A relay **MUST** return a deleted
identity, carrying `isDeleted: true`, from either **resolution** shape, `did=` and
`key=`. The presence of either parameter makes the request a resolution whatever
else it carries, and a relay MUST NOT let a discovery-shaped filter reintroduce
the exclusion.

The line is whether the caller already holds the identifier. Answering a
resolution with an empty page would be a relay asserting non-existence, and
`key=`'s consumers, key-loss recovery and mint-time burn checking, hold no DID to
fall back to.

`key=` is the reverse lookup "which identities has this key ever been proved
into". The value is matched **byte-for-byte** against the multibase public-key
strings whose memberships entered the chain's **effective** key state
([PROTOCOL, Key possession](https://protocol.dfos.com/spec#key-possession)) under
any of the chain's accepted operations, every operation and not just the current
head: an identity matches when its genesis key is the key, or when any accepted
update ever introduced the key with a valid possession proof, whether or not a
later update rotated it out. The filter is has-ever-proved rather than
current-state, and proved rather than declared: a **void** membership never
indexes, so a hostile or defective listing neither surfaces the chain in the key's
recovery results nor burns the key against its true holder. One key may match many
identities, and a deleted identity always still matches. There is no key-class or
role column: which array carries the key, and whether it is current, is the
chain's answer. The value is matched as an opaque string, so a string no operation
ever proved matches nothing: no format validation, no `400`.

### Content chains (`GET /index/v0/content?contentId=&creator={did}&signer={did}&docSchema=&documentCID=&publicRead=&isDeleted=&titleContains=&order=&after={contentId}&limit=N`)

Enumerates content chains, `contentId` ascending by default. All filters are ANDed
exact matches.

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

`title` is the display-name registry projection for content rows (row 2,
`post/v1 → title`): `null` for any chain whose held head document is not an
enumerated schema, on any circuit breaker including a non-public chain, or when
bytes are not held. Content-chain `opCount` is **branch-inclusive**: log length
across all branches, not head-branch length.

Parameters: `contentId` (optional exact match, returning zero or one row),
`creator` (exact DID, the chain's genesis signer; `400` when malformed), `signer`
(exact DID, keeping chains in which the DID signed at least one **accepted**
operation, branch-inclusive, so operations on branches later deleted or abandoned
still count; `400` when malformed), `docSchema` (exact opaque string match against
held head bytes, a lower bound per coverage above), `documentCID` (exact match
against the projected `currentDocumentCID`, the reverse lookup "who published this
document"), `publicRead` (boolean), `isDeleted` (boolean exact match against
terminal deletion state), `titleContains` (optional case-insensitive substring
filter over projected `title`, applied before keyset pagination), `order` (optional
`genesisAt.desc` or `headAt.desc`; `400` on any other value), `after` (a
`contentId` keyset cursor in the lexical default, or an opaque token in ordered
mode), `limit` (default 100, max 1000). A client's notion of _public posts by X_
is `creator=X&docSchema=<its post schema>&publicRead=true`, composed client-side.

When `titleContains` is present, the query is implicitly restricted server-side to
`publicRead=true` rows: a non-public chain's title is never projected, and
`titleContains` MUST NOT be usable to probe non-public rows. Explicitly combining
`titleContains` with `publicRead=false` is a **400**.

A content chain is not tombstoned from this structural index when its subject is
deleted. Concealment belongs to the credential and blob plane, so a deleted
subject's chain metadata (identifiers, operation CIDs, timestamps) remains
enumerable. Consumers that do not want deleted rows use `isDeleted=false`.

`signer` is an actor-axis verification outcome and is deliberately raw: the
creator matches their own chains, and "contributed to but did not create" is
client-composed as `signer=X` minus `creator=X`. It is proof-tier, and it is never
an authorship or credit claim: `credits` is assertion-tier and never enters this
filter.

### Countersignatures by witness (`GET /index/v0/countersignatures?witness={did}&relation=&order=&after={cid}&limit=N`)

The reverse of the proof plane's by-target route: every countersignature this
relay has ingested **signed by** the given witness DID, ordered by
countersignature CID ascending.

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

`witness` is required (`400` when missing or malformed); `relation` is an optional
exact match against the countersign's opaque open-namespace tag; `order`
optionally selects `createdAt.desc` or `ingestedAt.desc`; `after` is a
countersignature-`cid` keyset cursor in lexical mode or an opaque token in ordered
mode; `limit` defaults to 100 and maxes at 1000. The row's `relation` is `null`
when omitted by the signer. Each entry carries the full JWS, so the caller
re-verifies the token rather than trusting the row.

### Credentials (`GET /index/v0/credentials?issuer={did}&resource=&action=&order=&after={cid}&limit=N`)

Enumerates the relay's held public credentials, `cid` ascending by default.

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

Parameters: `issuer` (optional exact DID; `400` when malformed), `resource`
(optional exact match against an `att[].resource`; when the requested resource
starts with `chain:`, the `chain:*` wildcard bucket is always unioned in, because
a `chain:*` grant may authorize the named chain), `action` (optional exact match
against an `att[].action`, with the same candidate-match posture as `resource`),
`order` (optional `createdAt.desc` or `ingestedAt.desc`; lexical CID order when
absent), `after` (a credential-`cid` keyset cursor in lexical mode or an opaque
ordered cursor in ordered mode), `limit` (default 100, max 1000). A credential's
`createdAt` is its JWT numeric `iat` normalized to ISO 8601; `ingestedAt` is when
this relay accepted it. Filters are ANDed. Expired rows remain enumerable and
clients filter them locally.

Only public credentials (`aud: "*"`) are ever held by the relay. Targeted bearer
credentials never enter relay storage, so they are neither enumerable nor leakable
here.

This route returns a superset of candidates: `resource=chain:Y` returns exact
`chain:Y` plus any `chain:*`. Each entry carries the full JWS. The caller folds
each token against the proof plane (delegation roots at Y's creator, revocation,
expiry) before treating it as authorization; the relay makes no authorization
claim in the row.

### Credits (`GET /index/v0/credits?did=&contentId=&role=&after={cursor}&limit=N`)

Enumerates the credit projection's rows: who _public_ head documents say made
them. `did=X` answers "which publicly readable documents credit X", the query
[CONTENT-MODEL](https://protocol.dfos.com/content-model#credits) refuses to serve
for anything less than public content.

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

Parameters: `did` (optional exact match against the credited entry's `did`),
`contentId` (optional exact match, returning that chain's current public credit
set in `position` order), `role` (optional exact opaque-string match, where
entries without a role match only its absence), `after` and `limit` per the shared
envelope. Filters are ANDed. Enumeration order is
`(contentId ascending, position ascending)`, and because the natural key is
composite, `after` and `next` are **opaque cursor tokens** in every mode. Rows for
one content may be replaced wholesale between pages, so an in-flight enumeration
never duplicates a row but MAY miss one that changed while paginating.
Completeness for a single chain is `contentId=` on a fresh page, or the document
itself.

Every row is assertion-tier: it restates the current public head document, carries
no claim token, and makes no validity claim. A consumer that needs the proof tier
fetches the chain, re-hashes the head document, and runs the
[content model](https://protocol.dfos.com/content-model#verification-algorithm)
verification algorithm over the embedded entry.

---

## Signing mailbox (capability `signing`)

A **sign request** is a signed envelope that says: I, this requester, ask this
subject to sign exactly these bytes, as this kind of artifact, before this
deadline. The mailbox is a relay-hosted, poll-based courier that carries the
envelope to the subject and the resulting signature back, one mailbox per subject
DID. Relays serve it when `capabilities.signing` is `true`. Signature production
is not a relay concern: the signer is whoever holds the subject's key, and the
signer path in service is the hosted authorize flow of
[INTEGRATIONS, Profile A](https://protocol.dfos.com/integrations#profile-a-web-redirect).

A relay MAY serve `signing: true` alongside `write: false`: courier state is on
neither replicated plane, so the mailbox does not make a read-only relay an
ingest path.

### Courier, not ledger

- Mailbox state is **not proof plane**. It is never gossiped, never indexed, never
  referenced by any chain, and confers no meaning on its contents. A relay holds
  it the way a post office holds a letter.
- **Retention MUST NOT exceed the envelope's `expiresAt`.** Two obligations, not
  one: an expired request MUST NOT be served on any route, and its bytes MUST NOT
  be retained at rest past expiry. A relay MUST delete expired courier state, not
  merely filter it from reads. A relay MAY delete opportunistically or on a sweep;
  the reference relays prune expired rows as they touch them and sweep once at
  construction. A relay MAY drop courier state earlier under its own policy:
  durability is not promised, and a composer that needs delivery guarantees
  re-deposits.
- A relay stores **only** the request token, the response artifact, the decline
  flag, and its own bookkeeping timestamps. The deposit credential and any identity
  bundle are verified and **discarded**.
- **No cross-subject enumeration.** No route lists mailboxes, counts them, or
  reveals whether a subject's mailbox exists to anyone who cannot read it. Pending
  requests reveal who is asking whom to sign what.
- **The courier sees payloads in the clear.** A relay operator can read every
  pending request it carries. Deployments for which that matters run their own
  relay.

The mailbox requires the relay to resolve the **subject's** identity chain
locally: a mailbox lives where its subject's identity lives. A deposit for a
subject the relay cannot resolve is refused (404), and so is a deposit for a
subject whose local state is deleted: a tombstoned identity cannot be asked to
sign, and its mailbox does not exist. A composer picks the subject's relay from
the subject's resolved `services` entries of `type: "DfosRelay"`
([PROTOCOL, Services](https://protocol.dfos.com/spec#services)). When the subject
lists more than one relay, a composer SHOULD deposit at every listed relay that
advertises `signing`, and a signer SHOULD poll every relay its own state lists:
one-sided selection is how a correct composer and a correct signer miss each
other. Ed25519 is deterministic, so a request signed twice yields byte-identical
responses and the first-write-wins gate absorbs the duplicate.

### The sign-request envelope

A sign request is a JWS in the same envelope family as credentials, credit claims,
and revocations, with its own `typ`.

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:sign-request",
  "kid": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_r9ev34fvc23z999veaaft83nn29zvhe",
  "cid": "bafyrei..."
}
```

```json
{
  "version": 1,
  "type": "sign-request",
  "did": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
  "subject": "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae",
  "payloadTyp": "did:dfos:credit-claim",
  "payload": "eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlZGl0LWNsYWltIiw...",
  "createdAt": "2026-08-10T00:00:00.000Z",
  "expiresAt": "2026-08-13T00:00:00.000Z"
}
```

| Field        | Type             | Required | Description                                                                                                           |
| ------------ | ---------------- | -------- | --------------------------------------------------------------------------------------------------------------------- |
| `version`    | `1`              | yes      | Schema version (literal `1`)                                                                                          |
| `type`       | `"sign-request"` | yes      | Literal discriminator                                                                                                 |
| `did`        | string           | yes      | The requester DID, which MUST equal the `kid`'s DID                                                                   |
| `subject`    | string           | yes      | The target signer DID, the only identity being asked                                                                  |
| `payloadTyp` | string           | yes      | The JWS `typ` the produced artifact MUST carry (for example `did:dfos:credit-claim`)                                  |
| `payload`    | string           | yes      | **Unpadded base64url of the exact bytes to be signed**                                                                |
| `createdAt`  | string           | yes      | The [timestamp grammar](https://protocol.dfos.com/spec#timestamp-grammar) (millisecond precision, UTC)                |
| `expiresAt`  | string           | yes      | The [timestamp grammar](https://protocol.dfos.com/spec#timestamp-grammar) (millisecond precision, UTC), hard deadline |

The `kid` MUST be a DID URL containing `#`, and its DID portion MUST equal the
payload's `did`: the requester signs its own ask. The requester's signing key
resolves against the **current** state of its identity chain, so rotated-out keys
and deleted requesters are rejected. A sign request is an ephemeral ask with a
hard expiry and no revocation primitive, and rotation is how a requester whose key
is compromised stops it minting asks. Any current key role may sign.

**`payload` carries bytes, not JSON.** The field is the unpadded base64url
encoding (RFC 4648 §5, no `=` padding) of the exact octets the composer wants
signed, the octets that become the produced JWS's payload segment byte for byte.
It is never a re-serialized parse. Padded input, or any encoding of the same bytes
other than the canonical unpadded form, is invalid, and the decoded bytes MUST be
non-empty.

**One subject.** One requester asks one subject to sign one payload. Fan-out is N
requests composed by the requester, not a multi-subject envelope.

**`payloadTyp` names the artifact, and the artifact's own specification governs
it.** The envelope does not say which of the subject's keys should sign, what the
payload schema is, or what the artifact means. There is no `keyRole` field.

**Timestamps are whole-second.** Signers of the envelope MUST normalize
`createdAt` and `expiresAt` to whole seconds (`.000Z` millisecond component), by
flooring and never rounding, so re-deriving a request from the same inputs lands
on the same CID in every implementation.

Unknown top-level fields on the envelope are preserved and ignored: the CID
commits to the exact bytes, so a verifier that stripped unknown keys would fail
its own CID check. The target payload inside `payload` is held to the opposite,
stricter standard at signing time.

**Expiry.** `expiresAt` MUST be strictly after `createdAt`, and
`expiresAt − createdAt` MUST NOT exceed **7 days** (604800 seconds). The bound is
validity-determining and identical across implementations: a verifier MUST reject
an envelope whose window exceeds it, however far in the future or past the window
sits. A verifier evaluates expiry against the current time, so a request is live
only while `now < expiresAt`. The ceiling is a phishing control: a long-lived
pending request waits in a mailbox for a moment of inattention. There is no
cancellation primitive; a composer that wants a request gone stops honoring its
CID, and expiry collects it.

**CID derivation** is identical to every other protocol object:

```
dagCborCanonicalEncode(payload) -> SHA-256 -> CIDv1 (dag-cbor + SHA-256)
```

The derived CID is embedded in the protected header as `cid`, and verification
re-derives it from the parsed payload and compares. The request CID is also the
request's correlation handle everywhere: the mailbox slot key and the requester's
poll handle.

**Size bounds.** Both are validity-determining and MUST be identical across
implementations.

| Bound                  | Value          | Applies to                      |
| ---------------------- | -------------- | ------------------------------- |
| sign-request JWS token | **8192 bytes** | the serialized envelope token   |
| decoded target payload | **4096 bytes** | the octets `payload` decodes to |

### Envelope verification

Given the token, a way to resolve identities, and the current time:

1. **Size.** If the token exceeds **8192 bytes**, reject. Check this before any
   decode.
2. **Decode** the JWS and apply the
   [signature verification profile](https://protocol.dfos.com/spec#signature-verification-profile)
   header gates: `typ` MUST be exactly `did:dfos:sign-request`, `alg` exactly
   `EdDSA`, a `crit` member rejects, an embedded key member (`jwk`, `x5c`, …)
   rejects. A header whose `typ` or `kid` is missing or not a string rejects.
3. **Payload schema.** `version` MUST be `1`, `type` MUST be `"sign-request"`,
   `did` and `subject` MUST be non-empty and carry the `did:` prefix, `payloadTyp`
   MUST be a non-empty string, `payload` MUST be a non-empty string, `createdAt`
   and `expiresAt` MUST parse per the
   [timestamp grammar](https://protocol.dfos.com/spec#timestamp-grammar). The
   `did:` checks are prefix checks, not full `did:dfos` validation.
4. **Target bytes.** `payload` MUST decode as unpadded base64url; the decoded bytes
   MUST be non-empty and MUST NOT exceed **4096 bytes**.
5. **`kid` ↔ `did`.** The `kid`'s DID portion MUST equal `payload.did`.
6. **Resolve the requester** named by `did` to its **current** identity state.
   Unresolvable is **unverifiable**. Deleted rejects. Resolvable with no key
   matching the `kid` fragment in current state rejects.
7. **Signature.** Verify the JWS under that key.
8. **CID integrity.** Re-derive the payload CID and compare against the header
   `cid`.
9. **Temporal.** `expiresAt` MUST be strictly after `createdAt`, the window MUST
   NOT exceed 7 days, and `now` MUST be strictly before `expiresAt`.

The two failure verdicts MUST be machine-distinguishable: **invalid** (checked and
failed) versus **unverifiable** (could not check, an unresolvable requester or a
resolver transport failure). The reference implementations expose the verdict
structurally, never as prose to string-match.

### Signer obligations

The central risk of any remote-signing protocol is display and sign divergence:
the human approves what the screen says and the key signs what the bytes say.
Given a verified envelope, a signer MUST, in order:

1. **Verify the subject is itself.** `subject` MUST equal the signer's own DID. A
   request addressed to anyone else MUST NOT be signed. `subject` sits inside the
   requester-signed bytes, so a request minted for one DID cannot be re-aimed at
   another.
2. **Refuse unknown types.** If the signer does not implement `payloadTyp`, its
   schema, its canonical serialization, and its signer-side rules, it MUST NOT
   sign. There is no generic path.
3. **Decode and parse.** Base64url-decode `payload` and parse the octets as UTF-8
   JSON. Any parse failure refuses.
4. **Validate against the `payloadTyp` schema, strictly.** The parse MUST satisfy
   the target specification's payload schema **and MUST contain no unknown
   fields**. Ignore-unknown is a verifier's forward-compatibility posture; a signer
   is taking responsibility for bytes and cannot render a field it does not
   understand. The target typ's signer-side obligations apply in full.
5. **Re-canonicalize and byte-compare.** Re-serialize the validated parse using the
   target typ's canonical serialization and compare the result to the decoded
   input, byte for byte. **Any mismatch refuses.** After it passes, the input bytes
   are provably the unique canonical encoding of the parse: no duplicate key the
   parser collapsed, no non-shortest number form, no whitespace or escape trick, no
   key-order game.
6. **Render from the parse.** Whatever the signer displays for approval MUST be
   derived from the validated parse, never from requester-supplied display text
   (the envelope carries none) and never from a second decode.
7. **Sign the original bytes.** The produced JWS's payload segment MUST be the
   decoded input octets exactly, not a re-serialization, however canonical. The
   signer constructs its own protected header: `alg: "EdDSA"`, `typ` equal to the
   request's `payloadTyp`, its own `kid`, and whatever header fields the target
   specification requires.

Steps 5 and 7 together are the contract: the byte-compare proves that rendering
from the parse is rendering the bytes, and signing the original bytes proves the
signature covers what was rendered. An implementation that skips the byte-compare
and signs the re-serialization has the same bytes in the honest case and different
bytes exactly in the adversarial one. The reference implementations ship
adversarial vectors for this check (duplicate keys, non-shortest numbers, permuted
key order, whitespace injection, unicode escapes of ASCII, unknown fields,
sub-second timestamps), and an independent implementation copies them wholesale.

**Canonical serialization** is defined per `payloadTyp`, and for every DFOS
envelope family it is one rule: the payload object serialized as minimal UTF-8
JSON (no insignificant whitespace), members in the exact order of the target
specification's payload table, absent optional members omitted, timestamps in
`.000Z` whole-second form. A composer that builds payloads with the target's
reference implementation produces canonical bytes by construction; the signer-side
check exists for composers that do not.

A stale request is refused and re-composed, never patched. Stateless envelopes (a
credit claim, a countersign payload, a sign-in challenge) carry no reference to a
chain head and cannot go stale. Chain operations embed a `previousOperationCID`,
so if the chain advances while the request sits in a mailbox the produced
operation is invalid at ingest and harmless everywhere; the remedy is composer-side
re-composition. Nothing in the courier retries, rebases, or mutates bytes.

### The response

**There is no response envelope.** The response to a sign request is the produced
JWS: a complete, self-authenticating artifact of the requested `payloadTyp`,
verifiable by anyone under its own rules with no reference to the request that
solicited it.

Correlation is by request CID, and the binding is byte-equality: the response's
payload segment decodes to exactly the requested bytes, checkable by anyone
holding both with no courier trust involved.

**Declines are courier-level and advisory.** A subject that wants to say no tells
the courier, unsigned. A composer MAY surface a decline as user-facing text and
MUST NOT treat it as authoritative: the courier is untrusted and could fabricate
or suppress declines. **Expiry is the only real terminator.** A composer MUST NOT
irreversibly cancel real-world state on the strength of a decline, because a
response may still arrive from another of the subject's devices until
`expiresAt`.

Approving twice is harmless: Ed25519 is deterministic, so the same key over the
same bytes yields a byte-identical artifact. Two different enrolled keys produce
two different valid artifacts, which is why the response slot is first-write-wins.

### Routes

All routes live under `/signing/v0` at the relay root. Errors use the relay's
uniform error body; callers branch on status codes, never on message text.

#### `POST /signing/v0/requests` (deposit, credentialed)

```json
{
  "request": "<sign-request JWS>",
  "credential": "<DFOS credential JWS>",
  "chain": ["<identity operation JWS>", "..."]
}
```

| Field        | Required | Description                                                                 |
| ------------ | -------- | --------------------------------------------------------------------------- |
| `request`    | yes      | The sign-request envelope                                                   |
| `credential` | yes      | The deposit credential, see [Deposit authorization](#deposit-authorization) |
| `chain`      | no       | Identity-chain operations for identities the relay cannot resolve locally   |

The relay verifies the envelope (the full algorithm above, wall-clock `now`),
verifies the deposit credential, and stores the request keyed by its CID.
Responses: **201** with `{ "cid": "...", "expiresAt": "..." }`; **200** with the
same body for an idempotent re-deposit of the identical token; **409** when the
CID already holds a different request token; **400** for an invalid or expired
envelope; **404** when the subject is not resolvable on this relay; **403** when
the credential fails the deposit rule; **413** over the caps; **429** when the
subject's pending set is at the relay's cap (relay policy, reference cap 1024).
The aggregate deposit body MUST NOT exceed **524288 bytes** (512 KiB).

**The deposit is self-contained.** Verifying it requires resolving the requester's
identity chain and every issuer in the credential chain, identities the subject's
relay may not host. The relay resolves locally first, and `chain` fills the gaps
for foreign identities. Bundled operations are verified exactly as chain
verification always verifies them, then used ephemerally for key resolution and
**discarded**: never ingested, stored, gossiped, or folded. A deposit MUST NOT
become a cross-relay resolution dependency: if the bundle plus local state does not
suffice, the deposit is refused, not deferred. Local state is always the chain's
true head and always wins, and a lookup that fails refuses the deposit rather than
falling through to the bundle.

For an identity resolved **from the bundle**, three checks degrade to "as attested
by the depositor", because a prefix of an append-only chain is itself a valid
chain: current-state key resolution (a bundle truncated before a rotation presents
a rotated-out key as current), deletion of a credential issuer, and revocation of a
mid-chain delegation. None of these reaches what the subject signs: the signer runs
the full verification algorithm on every polled request against its own resolution
path. What a truncated bundle buys is mailbox-slot spam, bounded by the deposit
credential's own root and expiry. A deployment that will not accept that bound
requires the requester and every credential issuer to be locally resolvable and
rejects bundle-only deposits; the reference relays accept the bundle.

#### `GET /signing/v0/requests` (poll, subject only)

Authenticated with an **identity proof**: a request-bound possession proof
self-signed by a current key on the subject's identity chain, host-bound to this
relay. Reading your own mailbox is a "prove you are currently this DID" question,
and no credential exists for it. Revoking a device's mailbox access is key
rotation.

The subject is the proof's `kid` DID. The response lists **pending** requests,
deposited, unexpired, and unresponded, oldest first:

```json
{
  "requests": [
    {
      "cid": "bafyrei...",
      "request": "<sign-request JWS>",
      "depositedAt": "...",
      "declined": false
    }
  ],
  "next": "..."
}
```

Pagination is the shared envelope: `after`, `limit` (default 100, max 1000, values
above the max clamped), and `next`. The pending set is ordered by deposit time
ascending, tiebroken by request CID, and because that is a composite key `after`
and `next` are **opaque cursor tokens**. Resumption is strictly past the composite
key, so a decodable cursor whose request has since expired or been responded
resumes at the next key. An undecodable token, or one minted for a different
subject's mailbox, is a **400**: the cursor is bound to the mailbox it came from,
and reusing it across subjects would silently skip the new subject's older pending
requests. Reference relays cap a mailbox's pending set (relay policy, reference cap
1024), and the deposit that would exceed it is refused with **429**. Polling is the
transport in full: there is no server push, no SSE, and no delivery callback. A
push notification may prompt a poll, but delivery is always the poll.

A signer MUST run the full verification algorithm and every signer obligation on
each polled envelope. The mailbox's own checks are anti-abuse, not delegated trust:
a signer treats a polled request exactly as one that arrived by QR code from a
stranger.

#### `POST /signing/v0/requests/{cid}/response` (respond)

```json
{ "response": "<produced artifact JWS>" }
```

**Unauthenticated, deliberately.** A valid response is unforgeable, since only a
holder of the subject's key can produce it, so proving who couriers it adds
nothing.

The aggregate request body MUST NOT exceed **8704 bytes**, the 8192-byte token cap
plus JSON-wrapper headroom, checked before any decode (**413** over it). The relay
accepts the response if and only if all of the following hold; otherwise **400**,
or **404** for an unknown or expired `cid`:

1. A pending request with this CID exists and is unexpired.
2. The token does not exceed **8192 bytes** (checked before any decode).
3. The JWS decodes, passes the profile header gates, and its `typ` equals the
   request's `payloadTyp` exactly.
4. The `kid`'s DID portion equals the request's `subject`.
5. The `kid` names a key that has appeared in the subject's identity chain. The
   courier gate resolves against every key the chain has held, because the artifact
   will be judged by its own rules downstream and the gate must not be stricter
   than the artifact's own verifier.
6. The payload segment decodes to **exactly the request's target bytes**. Its
   base64url spelling MUST be canonical (unpadded, no non-zero trailing bits): the
   stored artifact is served back verbatim and must round-trip identically across
   implementations.
7. The signature verifies under the resolved key.

The slot is **first-write-wins**: at most one response per request, the first valid
one stored. A re-put of the byte-identical token is idempotent (**200**); a
different valid artifact, possible when the subject holds multiple enrolled keys,
is refused (**409**), and the composer reads the one that won. **201** on first
acceptance. Responding to a declined request is legal, and the response simply
wins.

#### `GET /signing/v0/requests/{cid}/response` (requester poll)

**Unauthenticated.** Knowledge of the request CID is the capability: it is held by
the composer that deposited the request and the subject that polled it, and it is
not enumerable. The CID is a hash of the requester-signed payload and those inputs
are not secret, so this route protects against enumeration, not against a guesser
who already knows what was asked; and what it guards is a self-authenticating
artifact, not a secret.

```json
{ "status": "pending" }
{ "status": "declined" }
{ "status": "responded", "response": "<artifact JWS>" }
```

**404** for an unknown or expired CID: after expiry a request and its response
cease to be served at all, and a composer that wants the artifact keeps it.

A composer MUST verify a fetched response itself, under the artifact's own rules.
The courier's checks are not a verification the composer inherits.

#### `POST /signing/v0/requests/{cid}/decline` (advisory)

Unauthenticated, no body. A non-empty body under the cap is a **400**, and a body
over **512 bytes** is a **413**. Sets the advisory decline flag on a pending
request: **204**, idempotent on repeat; **409** if a response already exists;
**404** unknown or expired. Unauthenticated is coherent because the flag carries no
authority, and requiring subject auth would lend it a credibility this document
denies it. No reason text is carried.

### Deposit authorization

Depositing into a mailbox requires a
[DFOS credential](https://protocol.dfos.com/credentials): standard verification,
plus one rule that makes the mailbox the subject's own.

The resource form is `mailbox:<id>`, where `<id>` is the subject DID's 31-character
identifier with the `did:dfos:` prefix stripped, exactly as `chain:<contentId>`
does not repeat its scheme. The action is **`deposit`**.

A relay MUST verify, at deposit time:

1. **The credential chain verifies** in full: signatures, schema, CID integrity,
   linear delegation, depth, monotonic attenuation, and audience linkage at every
   hop, with expiry evaluated against the wall clock (a deposit is a live decision)
   and revocation checked at every level against the relay's current knowledge.
2. **The chain roots at the subject.** The root credential's `iss` MUST equal the
   request's `subject` DID. Only the subject is original authority over its own
   mailbox. This rule is what makes a mailbox belong to its subject on an untrusted
   relay.
3. **The leaf reaches the requester.** The leaf credential's `aud` MUST equal the
   request's `did`, or be `"*"`. A public deposit credential is the subject opting
   into an open mailbox, carrying the same bearer-grant caution as every public
   credential: anyone may deposit, and the caps and rate limits are what stand
   between an open mailbox and a flooded one. The default posture is a named
   audience.
4. **Attenuation covers the deposit.** Some `att` entry on the leaf MUST cover
   resource `mailbox:<subject id>` with action `deposit`, under the credential
   specification's action-canonicalization rules. The resource match is **exact
   only**: no wildcard form is defined for `mailbox`, and a relay MUST NOT honor
   `mailbox:*` as covering a deposit.

There is no `collect` action. Credentials delegate authority to others, and being
yourself is not a delegation: key possession is necessary and sufficient to read
your own mailbox. A credential attenuated to `collect` on a mailbox grants nothing.

The deposit credential falls out of consent moments that already exist: a sign-in
authorization returns one alongside its proof, and a subject-rooted grant to a
platform sub-delegates onward through linear chains without re-touching the
subject's key. Each of those presupposes a standing relationship, and that is the
bound: a stranger with no prior grant cannot deposit at all, by any route. How a
stranger obtains a subject's public deposit credential is unspecified here, but
the convention is that a subject MAY publish its `aud: "*"` deposit credential as
a public credential on its own chain, where any composer discovers it through
[`GET /index/v0/credentials?issuer=<subject id>`](#credentials-get-indexv0credentialsissuerdidresourceactionorderaftercidlimitn).
The deposit gate treats a discovered grant exactly as a directly-delivered one.

**Caps are load-bearing on a public relay.** The 8 KiB envelope cap, the 4 KiB
payload cap, the 512 KiB deposit body cap, and the deposit credential gate are the
difference between a public courier and unauthenticated durable storage of
arbitrary bytes. Relays SHOULD add per-requester rate limits on deposit.

---

## Peering (convention)

Peering replicates proof-plane data across relays. It is a convention, not a wire
contract: it adds no route a relay must serve, and it runs entirely over the read
and write contracts above.

| Behavior         | Trigger          | Mechanism                                             |
| ---------------- | ---------------- | ----------------------------------------------------- |
| **Gossip-out**   | New op ingested  | Push to peers with `gossip: true`                     |
| **Read-through** | Local 404 on GET | Fetch from peers with `readThrough: true`             |
| **Sync-in**      | Scheduled poll   | Pull from peers with `sync: true` via `/proof/v1/log` |

Gossip fires on `new` status only: `duplicate` results are not re-gossiped, which
prevents gossip storms. Read-through applies to identity chains and content chains
only; operations and countersignatures are not read-through targets. When
triggered, the relay fetches the full chain log from a peer and ingests it locally
under full verification. Sync-in uses cursor-based pagination against the peer's
global log.

```typescript
interface PeerConfig {
  url: string;
  gossip?: boolean; // default: true
  readThrough?: boolean; // default: true
  sync?: boolean; // default: true
}
```

There are no relay roles or types. Topology is emergent from configuration: a
relay with `gossip: true, readThrough: false, sync: false` is a write-only edge
node, and one with `gossip: false, readThrough: true, sync: false` is a read-only
cache.

**Admission is the peering rule.** Everything a peer sends enters through the same
door as a client submission, with the same
[admission ladder](#admission) and the same
[linearity rule](#identity-linearity-and-admission): a peer-log identity operation
that conflicts with a locally-committed extension is refused like any other, and
committed order in this relay's log is never re-arbitrated. Peer-log ingestion
inherits the peer's admission discipline, so choosing peers is a trust decision.
Choosing which peers to sync from is also choosing which view of a divergent
identity this relay ends up serving.

**Sync discipline for pullers.** A puller persists only peer-supplied `next`
values, never a cursor fabricated from an entry CID. On `next: null` it retains its
last persisted cursor and cheaply re-fetches the final partial page next cycle, so
a peer whose whole log fits in one page is re-read each cycle: a bounded,
dedup-idempotent cost accepted in exchange for never fabricating. Every log fetch
MUST surface a peer's 400 cursor rejection as a distinguishable **invalid-cursor**
outcome, distinct from transport failure, because a client that collapses the 400
into a generic failure leaves the puller retrying a dead cursor forever after a
peer wipes or rebuilds its log. On `invalid-cursor` the puller resets at most once
per peer per sync cycle, and the reset is persisted only after a from-scratch
fetch succeeds, so one spurious 400 from an intermediary cannot destroy a real
high-water mark. A content-chain head switch mid-walk invalidates a read-through
cursor the same way, and the correct response is one restart of that walk from the
beginning.

Peer log pages are decoded under a byte bound. A peer's response is untrusted
input.

**Peers converge by exchanging operations, and nothing bounds when.** Given the
same set of operations, every relay computes the same content-chain head. Which
operations a relay has is a function of its peers, its retention, and its
admission verdicts, and no relay's log is the corpus.

---

## Content plane (capability `content`)

The content plane is the relay's read and write face for document bytes, the
preimages of the `documentCID`s content chains commit to. It does two things: it
**stores bytes** addressed by a committed `documentCID`, and it **serves bytes** to
readers it can verify are authorized, where authorized is a judgment re-derived
live from the proof plane on every request and never trusted from a stored flag.
Everything that gives a document meaning, which chain it belongs to, who committed
it, who may read it, lives in the proof plane.

The content plane has no chains of its own, no signatures of its own, no operation
log, and no replication: blobs are never pushed on the operation log, and a blob
enters a relay by upload to the relay that holds the chain. Capability flows up
from the proof plane; the proof plane never reaches down.

A reverse proxy can split the planes across origins: the proof node owns
`GET /proof/v1/content/:contentId` and its `/log`, and the content plane owns the
`/content/:contentId/blob*` sub-paths.

### Terminal and referential documents

A document is either **terminal**, where the `{ $schema, … }` blob is the content,
or **referential**, where the document describes how to fetch external bytes: an
`ipfs://` CID, or an opaque `attachment://<id>` resolved by an out-of-protocol
signed-CDN API, optionally carrying a hash of the target bytes so a consumer can
re-bind delivery to the committed reference. The relay serves the document blob
either way and **never resolves a referential pointer**: dereferencing is delivery,
and delivery lives outside the protocol. There is no media server here: no range
requests, no partial content, no streaming, no minting of CDN URLs. Media is a
content-schema convention
([CONTENT-MODEL, Media object](https://protocol.dfos.com/content-model#media-object)),
never a relay primitive.

### Discovery

A reader finds a content-plane host through the identity's `services` vocabulary
([PROTOCOL, Services](https://protocol.dfos.com/spec#services)). Two
open-namespace service types serve it, both indexed in the
[extension registry](https://protocol.dfos.com/spec#extension-registry):

| Service `type`        | Fields           | Meaning                                                                                        |
| --------------------- | ---------------- | ---------------------------------------------------------------------------------------------- |
| `DfosDocumentGateway` | `endpoint` (URL) | Base URL of a content-plane host serving this identity's content                               |
| `DfosProfile`         | `anchor`         | The identity's profile document: a 31-char contentId (living chain) or a `baf…` CID (artifact) |

A resolver replays the identity chain to current state, reads the
`DfosDocumentGateway` endpoint, and requests the document. `DfosProfile` dispatches
by shape exactly as `ContentAnchor` does: a contentId resolves to a content chain,
a CIDv1 resolves to an artifact. Discovery and authorization stay orthogonal.

### Authorization is one routine

The content plane holds **no authoritative authorization state**: every decision is
re-derived live from the proof plane, so nothing it stores can be served stale. A
relay MAY keep a materialized index of ingested public grants as a performance
optimization, an O(1) candidate lookup whose every candidate is re-verified live
before it can authorize anything. The index is a cache over the operation log,
fully re-derivable from it, never a source of truth.

Both the public path and the delegated path reduce to the same verification, and
the only difference is where the credential came from:

```
verify(credential, resource, action):
  resolve issuer keys from the proof plane      # required for any signature check
  check the credential signature
  check the delegation chain roots at the content creator
  check not expired
  check not revoked — for EVERY link in the prf delegation chain
  → authorized iff all checks pass
```

- **Public path.** The reader presents no credential. The relay derives the public
  credentials (`aud: "*"`) covering the chain from the proof plane it already
  reads, and runs each through the verifier. A surviving public grant authorizes
  the read. The relay works from the credentials themselves, never a pre-chewed
  `publiclyReadable: true`.
- **Delegated path.** The reader presents a DFOS credential in the `X-Credential`
  header. The same verifier runs over it, including the same per-link revocation
  check.

A public grant may name `chain:<contentId>` (this chain) or `chain:*` (all of the
issuer's chains); either way it MUST root at the content creator to authorize.
Public credentials SHOULD be read-scoped: a public `write` grant is a
world-writable bearer token
([CREDENTIALS](https://protocol.dfos.com/credentials#aud--plus-write-is-a-bearer-grant)).

A check the relay cannot complete denies. An unreachable revocation source or a
failed store read is not an absence of revocation.

### Standing authorization

Instead of presenting a read credential on every request, a credential with
`aud: "*"` can be ingested by the relay as a **standing authorization**: once
ingested, matching content-plane requests are authorized without an `X-Credential`
header. Ingestion is ordinary, through `POST /proof/v1/operations`, and the
credential is stored in the operation log like any other operation, addressable by
CID and carried in the global log as `kind: "credential"`.

**Authority is re-derived live, not read from a stored flag.** On every access the
relay re-verifies the standing credential against current proof-plane state:
signature, issuer-key resolution, expiry, revocation at every link, and a
delegation chain rooted at the content creator, through the same verifier the
per-request path uses. The two paths differ only in where the credential came from
and an audience check that public credentials skip.

A standing authorization stops granting access the moment any live check fails: the
credential expires, the credential or any parent in its delegation chain is
revoked, or the issuer's identity (or any delegating identity) is deleted. These
are evaluated live per request, so the effect is immediate and no cache
invalidation is required for correctness.

### Access

Non-public content-plane requests carry an **identity proof** in the
`Authorization: DFOS` header, verified against the presenter's current identity
state with the relay's own configured authority as the `host` binding. There is no
lifetime knob: a proof lives inside the verifier-owned freshness window, seconds
rather than hours, and binds one exact request.

The content creator, the DID that signed the genesis content operation, can always
read their own blobs with just an identity proof.

### Blob upload (`PUT /content/:contentId/blob/:ref`)

The upload path mirrors the download path: the operation CID identifies which
operation's document is being uploaded.

- A valid identity proof (`Authorization: DFOS`).
- The operation CID MUST reference an operation in this content chain that has a
  `documentCID`.
- The authenticated DID MUST be either the chain creator or the signer of the
  referenced operation, which is what enables delegated uploads.
- The uploaded bytes MUST hash to the operation's `documentCID` (dag-cbor plus
  sha-256 verification).

Blobs are stored by `(creatorDID, documentCID)`, always keyed to the chain creator
regardless of who uploads. If several content chains by the same creator reference
the same document, the blob is shared.

### Blob download (`GET /content/:contentId/blob[/:ref]`)

- If a standing authorization exists for the content (a public credential with
  `aud: "*"` covering the resource), access is granted anonymously: no proof, no
  per-request credential.
- Otherwise a valid identity proof (`Authorization: DFOS`) is required, plus: if
  the caller is the chain creator, no further credential; if the caller is not the
  creator, a DFOS credential with `action: "read"` in the `X-Credential` header,
  with a delegation chain rooting at the creator.

The optional `:ref` parameter selects which operation's document to return: `head`
(default) is the current document at chain head, and an operation CID is the
document that operation committed.

There is deliberately no relay-side document list route. Fetch
`GET /content/:contentId/blob` for the document at head,
`GET /content/:contentId/blob/:ref` for the document any specific operation
committed, and `GET /proof/v1/content/:contentId/log` to enumerate the chain's
operations, each carrying its `documentCID`. That composition is strictly more
verifiable: every blob is checked against its committed `documentCID`, and the
operation log is the proof-plane enumeration.

### What a 200 from the content plane means

A `200` is an endorsement: a cooperating host verified against the live proof plane
that a grant authorizes this read. Every input to that decision is public and
re-derivable, so a caller MAY re-run the verifier itself and reach the same yes
independently.

| Property                | Guarantee                                                                                                                                                                                                               |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Can't forge**         | A reader checks served bytes against the known `documentCID` by re-canonicalizing (decode-JSON, dag-cbor, sha-256), not by hashing the served bytes directly. Integrity is cryptographic even against a malicious host. |
| **Can withhold / leak** | The host holds plaintext. Content-plane access control is host-cooperative: it protects an honest host from mis-serving. It is not a cryptographic vault.                                                               |

What is not re-verifiable is the host's serve discipline, whether an honest host
actually withholds bytes from an unauthorized reader. That is unprovable for any
content host. Anything that must stay confidential against a hostile host is
withheld or encrypted above the protocol.

**Blobs are unsigned, and that is correct.** A blob's integrity is its CID, and the
CID is already signed in the proof plane. Note the byte encoding: stored and served
blob bytes are the bytes **as received**, canonically a JSON document, and NOT a
re-canonicalized form. A naive `sha256(servedBytes)` will NOT equal `documentCID`;
a verifier re-canonicalizes through the same decode and dag-cbor path the upload
check uses.

---

## Conformance

**`packages/relay-conformance` is the definition.** It is a Go integration suite
that runs against any live relay over HTTP: set `RELAY_URL` and run it. A passing
run is the conformance claim, and there is no central authority that grants one.

```bash
RELAY_URL=http://localhost:4444 go test -v -count=1 ./...
```

Authenticated requests sign an identity proof bound to the relay's own configured
authority, so the target is booted with one (`authority` /
`RelayOptions.Authority` / `dfos serve --authority`) or every authenticated route
answers 503. The suite binds proofs to the authority of the URL it dials; set
`RELAY_AUTHORITY` when the relay is configured for a different host than the one
you reach it at.

Capability-gated variants self-skip unless the relay advertises the matching flag,
and the gated families have posture-specific scripts that boot a relay in that
posture and assert it: `scripts/run-write-disabled.sh` and
`scripts/run-index-disabled.sh` assert **501** on every route of a family whose
flag is off, with adjacent surfaces unaffected; `scripts/run-signing.sh` runs the
signing mailbox against both reference relays; `scripts/run-proof-required.sh`
asserts the admission ladder's gated posture, an anonymous submission refused
**403** at request level and the same batch admitted with an identity proof.
`scripts/run-conformance.sh` starts a TypeScript relay on a random port and runs
the full suite. `scripts/run-parity.sh` compares
the two reference relays over the same fixture: given the same accepted operations
and held blobs, they serve byte-identical canonicalized-JSON rows, ordering,
filters, and cursor pages.

A read-only node cannot be seeded by the suite, since its POSTs answer 501, so the
write-disabled variant verifies it by recomputing from the log: it pulls a served
chain's log and independently re-derives the head and state, then asserts the
served state matches. The served state is reproducible from the served operations
alone.

Declare your capability flags honestly in `/.well-known/dfos-relay`. A
proof-plane-only relay is a conformant relay. State which corpora you ran: the
protocol-level verifier and signer rules are proven separately by
[`packages/protocol-verify`](https://github.com/metalabel/dfos/tree/main/packages/protocol-verify)
and `packages/protocol-verify/vectors.json`.

---

## Not defined here

Present absences, stated so a reader does not infer them:

- **Peer discovery.** Static configuration only.
- **Server push.** No SSE or realtime push; reads poll `GET /proof/v1/log`.
- **Fork visibility.** No endpoint lists a content chain's tips or branches.
- **Search.** No tokenization, ranking, or fuzzy matching. `nameContains` and
  `titleContains` are the index's ceiling, and anything beyond them is its own
  family, never an index extension.
- **Branch termination.** No operation kills a content-chain fork branch.
- **Rate limiting and anti-spam.** An operational concern, set per deployment.
- **Blob size limits.** No protocol enforcement; deployments add limits at the
  middleware layer.
- **Artifact `$schema` registry.** Schema names are free-form strings, with no
  validation beyond structural checks.
- **Credentials-by-resource query.** Reverse discovery ("what can DID X read")
  serves no part of the read path.
- **Content-plane replication.** A relay serves the bytes it stores. What a fork of
  an identity carries to another relay is the proof of history, not the bytes.

---

## Source

The reference TypeScript relay is
[`packages/dfos-web-relay/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-web-relay),
published as
[`@metalabel/dfos-web-relay`](https://www.npmjs.com/package/@metalabel/dfos-web-relay).
Its Go twin, the full reference relay, is
[`packages/dfos-web-relay-go/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-web-relay-go).
The conformance suite is
[`packages/relay-conformance/`](https://github.com/metalabel/dfos/tree/main/packages/relay-conformance).
Construction, storage, and peer-client interfaces are package documentation.

### Related specifications

- [Protocol](https://protocol.dfos.com/spec): encoding, chains, views, time basis, key possession, and the signature verification profile
- [Credentials](https://protocol.dfos.com/credentials): authorization credentials and revocation
- [Content Model](https://protocol.dfos.com/content-model): document schemas and the credit vocabulary
- [Integrations](https://protocol.dfos.com/integrations): sign-in, API authentication, and origin binding
- [DID Method: `did:dfos`](https://protocol.dfos.com/did-method): the W3C DID method registration
