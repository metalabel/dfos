# DFOS Relay Contract

The **frozen wire surface** of a DFOS relay — the minimal set of routes, request shapes, and response shapes a client may hardcode against any conformant relay. This is the interoperability half of federation-without-coordination: verification itself is transport-agnostic (a chain verifies from its bytes, however obtained — see [DID-METHOD.md](https://protocol.dfos.com/did-method)), and this contract is what makes the bytes reachable the same way everywhere.

> **Status — frozen with Protocol v1.** The routes and shapes below are **frozen** as part of the v1 surface: a conformant relay MUST serve them at exactly these paths with exactly these shapes, and changes follow the [core protocol status](https://protocol.dfos.com/spec) — clarifications corrected in place, additive capability beside the frozen surface, a genuine break becomes v1.1 or v2, never a silent edit. Everything else a relay does — ingestion pipeline, peering, convergence, the content plane, and every optional route family — is reference behavior on its own clock, specified in [WEB-RELAY.md](https://protocol.dfos.com/web-relay). Discuss in the [DFOS](https://nce.dfos.com) space.

---

## The Frozen Surface

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

The `/proof/v1` prefix encodes the plane and its version (`{plane}/{version}`), so the frozen clock is legible in the URL and the plane mounts or proxies as a unit by prefix. `/revocations/v1` is a frozen `v1` contract at the relay root on its own v1 clock — revocations still _enter_ through `POST /proof/v1/operations`; this family only exposes a read over the index a relay already maintains for its own enforcement. All routes above are unauthenticated: proof-plane operations carry their own authentication (Ed25519 signatures), and the reads serve public data.

## Error Body

Every route answers failures with one body shape — `{ "error": "<prose>" }` — plus the appropriate status code. The prose is diagnostic, never contractual: callers branch on status codes and MUST NOT match message text. Two deliberate exceptions: `POST /proof/v1/operations` MAY carry an additive `details` array of per-item schema issues beside `error` on a `400` (same discipline — diagnostic only), and the universal resolver (`GET /1.0/identifiers/:did`, on the DIF driver interface's own clock and not part of this contract) answers in the DIF resolution envelope its own contract requires.

## Pagination Envelope

Every list route paginates identically: `limit` (default 100, max 1000, values above the max clamped, never rejected) + `after` (cursor from a previous page's `next`, passed back verbatim; omit to start) in, `next` out — the last returned row's cursor, or `null` when the page was not full (caught up). An unrecognized or undecodable cursor is a **400, never a silently empty page**. Cursor conduct splits three ways, and each route names which it has:

| Conduct                    | Routes                                                              | An unrecognized `after`…                                                                                                                            |
| -------------------------- | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Relay-local positional** | the ingestion-ordered logs (global and per-chain)                   | **400** — cursors are meaningful only against the relay that issued them; the client restarts its walk from the beginning (ingestion is idempotent) |
| **Transparent keyset**     | countersignature reads, `/revocations/v1/issuer/:did`               | resumes strictly past `after` whether or not it names a present row — even a foreign cursor is safe and never errors                                |
| **Opaque token**           | none in this contract (unfrozen families use it — see WEB-RELAY.md) | resumes strictly past the encoded key when the token decodes; an **undecodable** token is 400                                                       |

A continuously syncing client persists only server-supplied `next` values — never a fabricated one — and on `next: null` retains its last persisted cursor, cheaply re-fetching the final partial page next cycle; on a 400 it resets and re-syncs from the start. For a per-chain content log the 400 is also how a fork/head-switch mid-walk surfaces: the client is told its cursor is off the served branch and restarts, instead of being silently told it is caught up on a branch that is no longer the head. (An identity chain is linear, so its per-chain cursor can only advance.)

## Submission (`POST /proof/v1/operations`)

The request body is `{ "operations": [ "<JWS>", … ] }` — identity operations, content operations, artifacts, countersignatures, credentials, and revocations mixed freely, classified by each token's JWS `typ` header (the [extension registry](https://protocol.dfos.com/extensions) names the values). A batch carries at most **100 tokens** — a larger array is a **400** — and the reference implementations additionally guard the aggregate body at 16 MiB (**413**; a client that sees 413 chunks and retries — 400 remains the malformed-content verdict).

The response is `{ "results": [ { "cid", "status", "error"? } ] }` **in the same order as the input array** — `results[i]` corresponds to `operations[i]`, regardless of internal processing order — with exactly three statuses:

| Status      | Meaning                                                                                                                                                                                                                                |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `new`       | First time seen, verified, stored, state changed                                                                                                                                                                                       |
| `duplicate` | Already held: the exact same CID **and** JWS token — a true idempotent resubmission. Same CID with a different token is `rejected` (Ed25519 is deterministic, so a different token for the same payload means a different signing key) |
| `rejected`  | Verification failed (`error` says why, diagnostically)                                                                                                                                                                                 |

How a relay verifies, buffers, and sequences what it accepts is behavior, not wire — [WEB-RELAY.md → Operation Ingestion](https://protocol.dfos.com/web-relay#operation-ingestion) and [Convergence](https://protocol.dfos.com/web-relay#convergence).

## Operation Read (`GET /proof/v1/operations/:cid`)

```json
{ "cid": "bafy…", "jwsToken": "eyJ…", "chainType": "identity", "chainId": "did:dfos:…" }
```

`chainType` is one of `identity`, `content`, `artifact`, `countersign`, `revocation`, `credential`; `chainId` is the routing identifier (DID for identity-keyed kinds, contentId for content operations, target CID for countersignatures). 404 when the CID is not held.

## Identity State (`GET /proof/v1/identities/:did`)

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

Projected state — the computed result of replaying the chain to its head under the core verification rules, including the identity's `services` discovery vocabulary ([PROTOCOL.md → Services](https://protocol.dfos.com/spec#services)). Pure chain state, no derived authorization material.

## Content State (`GET /proof/v1/content/:contentId`)

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

Frozen **as-is**, and deliberately pure chain state: no derived authorization material rides this route. Public-read discovery (which `aud: "*"` credentials currently authorize a read) is a content-plane ergonomic on its own unfrozen clock — keeping it off the frozen route is what lets that ergonomic evolve without touching the locked contract.

## Logs

**Global** (`GET /proof/v1/log?after={cursor}&limit=N`) — every successfully ingested operation in ingestion order, entries `{ cid, jwsToken, kind, chainId }`, `kind` one of the six primitive kinds. JWS tokens are included in every entry because proof-plane payloads are bounded, keeping the log self-contained — a syncing peer replays it without separate fetches. Cursors are **relay-local and implementation-shaped** (the reference relays use the entry CID; other conformant relays MAY use opaque composite tokens): an `after` the relay does not recognize is a 400, per the envelope above.

> **`chainId` is not a per-chain partition key.** `credential` and `revocation` entries carry `chainId` = the issuer DID — the **same** value as that DID's `identity-op` and `artifact` entries — so folding the global log per-chain on `chainId` alone silently co-mingles kinds under one DID. An indexer reconstructing a specific chain MUST filter by `kind` first.

**Per-chain** (`GET /proof/v1/identities/:did/log`, `GET /proof/v1/content/:contentId/log`) — the chain's operations in chain order, entries `{ cid, jwsToken }`, same envelope and 400-on-unknown-cursor rule.

## Countersignatures (`GET /proof/v1/countersignatures/:cid?after={cid}&limit=N`)

Returns `{ "countersignatures": [{ "cid", "jwsToken" }], "next" }`, sorted by each countersignature's own CID ascending under the **transparent keyset** conduct — an `after` that is not a present key resumes at the next greater key, so cursors survive concurrent additions and cross-relay replay. Works for any CID-addressable target; 404 only when the CID is neither a known operation nor has stored countersignatures. Each countersignature's `targetCID` and `relation` live inside its signed payload — the token is the truth; the row fields are conveniences.

## Revocation Status

**Credential** (`GET /revocations/v1/credential/:credentialCID`):

```json
{ "credentialCID": "bafyrei…", "revoked": true, "revocation": "eyJ…" }
```

`200` revoked includes `revocation`, the full revocation JWS; `200` not revoked is `{ "credentialCID": "…", "revoked": false }` with no `revocation` key; `400` when the param is not a well-formed credential CID (`bafyrei` + 52 base32 chars). If more than one issuer has revoked the same CID, the relay answers deterministically with the lexicographically smallest `issuerDID`'s revocation.

**Issuer** (`GET /revocations/v1/issuer/:did?after={cid}&limit=N`):

```json
{
  "did": "did:dfos:…",
  "revocations": [{ "credentialCID": "bafyrei…", "revocation": "eyJ…" }],
  "next": null
}
```

Every revocation this relay has ingested for the issuer, sorted by `credentialCID` ascending under the transparent-keyset conduct — decisively, a revocation whose signer-claimed `createdAt` is backdated can never be inserted _behind_ a client's cursor and silently skipped, which a time-ordered enumeration could not promise. `400` when the param is not a canonical 31-char `did:dfos` identifier. An issuer with none returns an empty array.

**The JWS is the proof; the boolean is a convenience.** A zero-trust caller re-verifies the returned revocation token itself — signature against the issuer's identity chain, CID integrity, and the issuer-only rule. And **absence is NOT proof of non-revocation**: `revoked: false` attests only that _this relay_ has not ingested a revocation for that CID — a relay can be behind, partitioned, or adversarially withholding. A caller that needs stronger assurance queries a quorum of independent relays; gossip makes withholding progressively harder. This is the same trust posture as every other read in the protocol.

## What Is Deliberately Not Here

- **Discovery** (`GET /.well-known/dfos-relay`) — capabilities, relay identity, telemetry: on its own clock, in [WEB-RELAY.md](https://protocol.dfos.com/web-relay#well-known-endpoint-get-well-knowndfos-relay). A relay MAY gate optional surfaces by capability flags; this contract's routes are never gated (`capabilities.proof` is always true; `capabilities.write: false` turns `POST /proof/v1/operations` into a 501 on a pull-only node, and `capabilities.log`/`revocations` gate the global log and revocation reads the same way — the flags are discovery, the 501 semantics are WEB-RELAY's).
- **The universal resolver** (`GET /1.0/identifiers/:did`) — the DIF driver binding on its own `1.0` clock ([DID-METHOD.md](https://protocol.dfos.com/did-method)).
- **The content plane** (`/content/:contentId/blob*`), **index** (`/index/v0/*`), and **signing mailbox** (`/signing/v0/*`) — optional families on their own unfrozen clocks, in [WEB-RELAY.md](https://protocol.dfos.com/web-relay) and [SIGNING.md](https://protocol.dfos.com/signing).
- **Behavior** — ingestion pipeline, dependency buffering, convergence, peering, key resolution mechanics: [WEB-RELAY.md](https://protocol.dfos.com/web-relay), whose normative anchors for verification semantics are the core specs ([PROTOCOL.md → Chain Validity](https://protocol.dfos.com/spec#chain-validity), [Admission and Re-Verification](https://protocol.dfos.com/spec#admission-and-re-verification), [CREDENTIALS.md](https://protocol.dfos.com/credentials)).
