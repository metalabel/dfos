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

| Method | Path                                          | Description                                                 |
| ------ | --------------------------------------------- | ----------------------------------------------------------- |
| `GET`  | `/.well-known/dfos-relay`                     | Relay metadata (DID, protocol version)                      |
| `POST` | `/proof/v1/operations`                        | Submit signed operations (identity, content, countersig)    |
| `GET`  | `/proof/v1/identities/:did`                   | Get identity chain state and operation log                  |
| `GET`  | `/proof/v1/content/:contentId`                | Get content chain state and operation log                   |
| `GET`  | `/proof/v1/operations/:cid`                   | Get a single operation by CID                               |
| `GET`  | `/proof/v1/countersignatures/:cid`            | Get countersignatures for an operation                      |
| `GET`  | `/proof/v1/operations/:cid/countersignatures` | Same as above (alias)                                       |
| `GET`  | `/1.0/identifiers/:did`                       | Resolve a `did:dfos` to a W3C DID Document (DIF-compat)     |
| `GET`  | `/revocations/v1/credential/:credentialCID`   | Revocation status for a credential (self-proving JWS)       |
| `GET`  | `/revocations/v1/issuer/:did`                 | All revocations ingested for an issuer                      |
| `PUT`  | `/content/:contentId/blob/:operationCID`      | Upload blob (auth required)                                 |
| `GET`  | `/content/:contentId/blob`                    | Download blob at head (standing auth, or auth + credential) |
| `GET`  | `/content/:contentId/blob/:ref`               | Download blob at specific operation ref                     |

## DID Resolution

`GET /1.0/identifiers/:did` resolves a `did:dfos` identifier into a
[W3C DID Document](https://www.w3.org/TR/did-core/), following the
[DIF Universal Resolver](https://dev.uniresolver.io/) HTTP binding. The response
is a resolution result — `{ didDocument, didResolutionMetadata,
didDocumentMetadata }` — with `contentType: application/did+ld+json`.

Resolution is **read-only and self-certifying**: the relay serves the DID
Document projection of the identity chain's verified terminal state
(verification methods from the current key sets, `service` from the chain's
services). A deactivated identity resolves with `deactivated: true` in the
document metadata and an empty verification-method set. A malformed `did:dfos`
returns `400 invalidDid`; an unknown identity returns `404 notFound`. Public and
unauthenticated, like the proof plane. This route is **additive** — it rides the
frozen v1 surface without touching the wire or the proof plane. See
[DID-METHOD.md](../../specs/DID-METHOD.md) §4 for the normative mapping.

## Revocation Status

`GET /revocations/v1/credential/:credentialCID` answers whether the relay has
ingested a revocation for a credential —
`{ credentialCID, revoked, revocation? }` — and
`GET /revocations/v1/issuer/:did` lists every revocation ingested for an issuer,
sorted by `credentialCID`. Like the universal resolver, the family rides its own
`0.x` clock at the relay root; revocations still _enter_ through
`POST /proof/v1/operations` as ordinary proof-plane operations.

Every positive answer carries the **full revocation JWS**, so a zero-trust
caller re-verifies the proof (signature, CID integrity, kid-DID == payload
`did`, issuer-only rule) instead of trusting the relay's boolean.
`revoked: false` is an honest known-nothing answer — the relay attests only to
what it has ingested; absence is NOT proof of non-revocation (query a quorum of
relays for stronger assurance). A malformed CID or DID returns `400`. Support is
advertised via `capabilities.revocations` in the well-known (always `true` for
this relay); a relay without the index returns `501` on these routes. See
[WEB-RELAY.md](../../specs/WEB-RELAY.md) → Revocation Status for the full
semantics.

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
