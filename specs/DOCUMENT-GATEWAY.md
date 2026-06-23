# DFOS Document Gateway

A stateless, content-addressed blob store whose authorization is a re-verifiable endorsement derived live from the proof plane. The gateway serves the **content plane** — the raw documents that content chains commit to via `documentCID` — and holds no _authoritative_ authorization state of its own (it re-derives every decision live).

This spec is under active review. Discuss it in the [clear.txt](https://clear.dfos.com) space on DFOS.

[Protocol](https://protocol.dfos.com) · [Web Relay](https://protocol.dfos.com/web-relay) · [Credentials](https://protocol.dfos.com/credentials)

> **Gateway version 0.1.** This document specifies the document gateway as an
> optional service on its own `0.x` clock, independent of the Protocol v1 freeze.
> It matches the behavior the reference relay (`@metalabel/dfos-web-relay`,
> `dfos-web-relay-go`) ships today: both the public-grant and delegated read paths
> re-derive authorization live from the proof plane on every request — the gateway
> derives the public grants covering a chain directly from the proof-plane
> operation log it already reads (see [Public-grant derivation](#public-grant-derivation)).
> A relay MAY keep a materialized public-credential index as a **non-authoritative
> performance cache** — it is never authority (see [Statelessness](#statelessness)).
> One ergonomic is **not yet built**: inlining the authorizing credentials in the
> blob response so an unauthenticated caller can re-verify the gateway's decision
> (see [Public-read discovery](#public-read-discovery-0x)) — a `0.x` design slated
> for after the v1 freeze. Published here for review and to inform implementors.

---

## What it is

The document gateway is the read/write face of the **content plane**. Content chains live in the proof plane as signed commitments — each operation carries a `documentCID`, the hash of a document the chain commits to. The gateway stores and serves those documents (the **preimages** of the committed CIDs).

It is deliberately **dumber** than a proof node. It has no chains, no signatures of its own, no gossip, no consensus, no operation log. It does exactly two things:

- **Stores bytes** addressed by the `documentCID` a content chain already committed to.
- **Serves bytes** to readers it can verify are authorized — where "authorized" is a judgment re-derived live from the proof plane on every request, never trusted from a stored flag.

Everything that gives a document _meaning_ — which chain it belongs to, who committed it, who may read it — lives in the proof plane. The gateway holds only the bytes. This split is the heart of the design:

| Plane                       | Holds                                                    | Guarantees                                                                         |
| --------------------------- | -------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **Proof plane**             | Signed commitments (ops, CIDs, credentials, revocations) | Integrity + authenticity + authorization, cryptographically, against any adversary |
| **Content plane (gateway)** | Document preimages, verified by content-addressing       | Integrity (bytes → CID) cryptographically; access control _honest-host_            |

A relay's content plane **is** a document gateway. The two terms name the same surface from two angles: "content plane" is the relay-internal plane (paired with the proof plane); "document gateway" is the standalone service contract on a `0.x` clock. A reverse proxy can split them across origins — the proof node owns `GET /proof/v1/content/:contentId` and `/log`; the gateway owns the `/content/:contentId/blob*` and `/documents` sub-paths.

### Terminal and referential documents

A document the gateway serves is either **terminal** — the `{ $schema, … }` blob _is_ the content — or **referential** — a `{ $schema, … }` document that describes _how to fetch_ external bytes: an `ipfs://` CID, or an opaque `attachment://<id>` resolved by an out-of-protocol signed-CDN API, optionally carrying a hash of the target bytes so a consumer can re-bind delivery to the committed reference. **The gateway serves the document blob either way and never resolves a referential pointer.** Dereferencing — actually fetching the external bytes — is _delivery_, and delivery lives outside the protocol and outside the gateway.

### What it is not

The document gateway is **not** a media server. It does not resolve or dereference referential documents, does not deliver external media bytes, does not mint or sign CDN URLs, and has no range requests, partial content, or streaming surface. There is no "media gateway" and no protocol-level media: large or binary media is a **referential document** (a content-schema convention) whose bytes are fetched out-of-protocol. The gateway is an authorization-gated, content-agnostic store of opaque document blobs — nothing more.

---

## Statelessness

The gateway holds **no _authoritative_ authorization state and no proof-plane replica**. "Stateless" here means _stateless over the proof plane_: every authorization decision is re-derived live from the proof plane, and nothing the gateway stores is ever trusted as authority — so nothing it stores can be served stale.

A relay MAY keep a materialized index of ingested public grants (a resource → candidate-credential map) as a **performance optimization** — it makes "which grants might cover this chain?" an O(1) lookup instead of an op-log scan. That index is **not authority**: every candidate it yields is re-verified live (signature, issuer-key resolution, expiry, revocation, delegation rooted at the creator) before it can authorize anything. A stale or revoked entry in the index cannot grant access, because the live re-verify rejects it. The index is a cache over the proof-plane op log, fully re-derivable from it — never a source of truth. (This is the same "re-verified, non-authoritative cache" the split-deployment TTL cache is; see [Deployment locality](#deployment-locality).)

This is not the same as offline. Verifying any signature requires the issuer's keys, which live in a **mutable, revocable** identity chain. "Is this grant valid right now?" is a question about _current_ proof-plane state — a key may have rotated, a credential may have been revoked, an identity may have been deleted. There is no correct offline answer. A live read is the honest price of verifying against live, revocable truth.

What the gateway gains by holding no authority: it can never serve a stale authorization. It is coupled to _truth_ and holds no authoritative replica to drift. See [Coupling](#coupling-why-tight-is-correct), which separates the three couplings that "stateful/stateless" usually smears together.

---

## Discovery

A reader finds a gateway through the identity's `services` vocabulary (see [PROTOCOL.md → Services](https://protocol.dfos.com/spec#services), [DID-METHOD.md → Services](https://protocol.dfos.com/did-method#45-services)). The `services` namespace is open: recognized types (`DfosRelay`, `ContentAnchor`) are structurally validated; any other type is preserved verbatim and ignored. The gateway adds two **open-namespace** types — additive, requiring no protocol or relay change:

| Service `type`        | Fields           | Meaning                                                                                         |
| --------------------- | ---------------- | ----------------------------------------------------------------------------------------------- |
| `DfosDocumentGateway` | `endpoint` (URL) | Base URL of a document gateway serving this identity's content                                  |
| `DfosProfile`         | `anchor`         | The identity's profile document — a 31-char contentId (living chain) or a `baf…` CID (artifact) |

A resolver replays the identity chain to current state, reads the `DfosDocumentGateway` endpoint, and requests the document. `DfosProfile` dispatches by shape exactly as `ContentAnchor` does: a contentId resolves to a content chain (a living, updatable profile), a CIDv1 resolves to an artifact (an immutable snapshot). Both are just content the gateway serves under the same authorization rules — discovery and authorization stay orthogonal.

Because these are open-namespace service types, a relay that does not recognize them preserves and ignores them; a gateway-aware client reads them. No coordinated upgrade is required.

---

## The unified verifier

Authorization is **one routine**. Both the public path and the delegated path reduce to the same verification — the only difference is _where the credential came from_.

```
verify(credential, resource, action):
  resolve issuer keys from the proof plane      # required for any signature check
  check the credential signature
  check the delegation chain roots at the content creator
  check not expired
  check not revoked — for EVERY link in the prf delegation chain
  → authorized iff all checks pass
```

There is no second code path, no "is it public?" branch that trusts a stored flag, no stored table treated as authority before the verifier runs. A grant is authorized **iff** a credential covering the resource survives this routine against live proof-plane state.

### Two paths, one verifier

- **Public path.** The reader presents no credential. The gateway derives the relevant public credentials (`aud: "*"`) covering the chain from the proof-plane operation log it already reads (see [Public-grant derivation](#public-grant-derivation)) and runs each through the unified verifier. A surviving public grant authorizes the read. The candidates may come from a materialized public-credential index, but that index is a **non-authoritative cache** — authority is the live re-verify, never the stored lookup.
- **Delegated path.** The reader presents a DFOS credential in the `X-Credential` header. The gateway runs the same verifier over it. Unchanged in shape — it simply gains the same revocation check the public path runs.

Both paths check revocation at **every link** of the delegation chain. There is no asymmetry: a revoked public grant and a revoked presented credential are denied identically. See [Revocation](#revocation).

### Public-grant derivation

Public credentials (`aud: "*"`) are ordinary proof-plane operations — they enter through `POST /proof/v1/operations` and live in the operation log like any other signed op (kind `credential`). The gateway therefore needs no separate grant table _as authority_: it derives the public grants covering a chain from the proof plane it already reads for the chain head. (A relay MAY keep a materialized index of these credentials as a non-authoritative candidate cache; see [Statelessness](#statelessness).)

Because the grants live in the proof-plane log the gateway already reads, the gateway holds the **credentials themselves**, never a pre-chewed `publiclyReadable: true`. It re-verifies each through the unified verifier and makes the _decision_ itself — there is no authorization judgment handed down from elsewhere that the gateway must blindly trust. A malformed or revoked credential is caught by the verifier. This keeps the verifier honest and composable. When the gateway _serves_ a public read, it can hand the same authorizing credentials back to the caller so the caller re-verifies the decision independently (see [Public-read discovery](#public-read-discovery-0x)) — a `0.x` ergonomic, not yet built.

A public grant may name `chain:<contentId>` (this chain) or `chain:*` (all of the issuer's chains). Either way it MUST root at the content creator to authorize. Public credentials SHOULD be read-scoped — a public `write` grant is a world-writable bearer token (see [CREDENTIALS.md → `aud: "*"` + write](https://protocol.dfos.com/credentials#security-aud--write--a-world-writable-bearer-grant)).

---

## Routes

The gateway's route **surface** is unchanged from what the relay serves today; only the authorization _logic_ behind it changes. The 0.1 gateway adds **zero new gateway routes**.

| Method | Path                                     | Purpose                                                     |
| ------ | ---------------------------------------- | ----------------------------------------------------------- |
| `PUT`  | `/content/:contentId/blob/:operationCID` | Upload the document committed by a given operation          |
| `GET`  | `/content/:contentId/blob[/:ref]`        | Download a document (`:ref` = `head` default, or an op CID) |
| `GET`  | `/content/:contentId/documents`          | Download all documents committed to a chain, genesis→head   |

These remain at the root (not under `/proof/v1`) because they belong to the gateway's `0.x` clock, not the frozen proof plane. Content-plane support is optional per relay: when `capabilities.content: false`, all three return **501 Not Implemented**.

### Download authorization

`GET /content/:contentId/blob[/:ref]` and `GET /content/:contentId/documents` require, in order:

1. A valid **auth token** (`Bearer`) proving caller identity — except where a public grant authorizes the resource, in which case no auth token is required.
2. Then exactly one of:
   - the caller is the **chain creator** (creator always reads their own blobs);
   - a **public grant** survives the unified verifier for `(resource, read)`;
   - the caller presents a **DFOS credential** (`X-Credential`) that survives the unified verifier for `(resource, read)`.

### Upload authorization

`PUT /content/:contentId/blob/:operationCID` requires a valid auth token and:

- the referenced operation exists in this content chain and carries a `documentCID`;
- the authenticated DID is the chain creator **or** the signer of the referenced operation (delegated uploads);
- the uploaded bytes hash to that operation's `documentCID` (dag-cbor + sha-256).

Blobs are stored by `(creatorDID, documentCID)` — keyed to the chain creator regardless of who uploads, so identical documents across a creator's chains deduplicate.

---

## Ingestion: none

The proof plane has an ingestion pipeline (`POST /proof/v1/operations` → verify signatures, store, gossip). The gateway has **no signed-object ingestion**. It never verifies a chain, never checks a countersignature, never participates in consensus. It has two doors, and both reduce to content-addressing plus a proof-plane read:

- **Upload** checks (a) the bytes hash to a `documentCID` already committed by the named operation — pure content-addressing, self-verifying — and (b) the proof plane confirms the op exists, commits that `documentCID`, and the uploader is creator or signer.
- **Download** runs the unified verifier and serves the bytes.

**Blobs are unsigned, and that is correct.** A blob's integrity _is_ its CID, and the CID is already signed in the proof plane. Re-signing the bytes at the gateway would be redundant: a blob that does not hash to its committed `documentCID` is rejected by content-addressing alone, against any adversary including a malicious gateway. The proof plane provides **legitimacy** (a real, committed document of a real chain) and **authorization**; content-addressing provides **integrity**. The gateway needs both — a blob alone is just bytes; all of its meaning lives in the proof plane.

---

## Revocation

Revocation is checked **symmetrically** and **per-link**. There is no path on which a revoked credential is honored:

- On the **public path**, each derived public grant is checked for revocation before it can authorize.
- On the **delegated path**, the presented credential and **every parent** in its `prf` delegation chain are checked.

Revocations are themselves proof-plane operations (kind `revocation`), so revocation status is resolved live from the proof plane the gateway already reads — consistent with statelessness, no separate revocation cache that could serve a stale "still valid." A depth-`N` delegation chain costs up to `N` revocation lookups; public grants are usually depth-1.

This matches the protocol's revocation rule: a credential is denied if it, or any link in its delegation chain, is revoked — checking only parents is insufficient (see [CREDENTIALS.md → Revocation](https://protocol.dfos.com/credentials#revocation)). Revocation controls **future** access; it does not rewrite the append-only proof-plane history.

Revocation is immediate against live proof-plane state. In a [split deployment](#deployment-locality) with a TTL cache, "immediate" is bounded by the cache TTL — a stated, finite staleness window, never authoritative state.

---

## Trust model

A `200` from the gateway is an **endorsement**: "I, a cooperating host, verified against the live proof plane that a grant authorizes this read." It is not a bare assertion the caller must take on faith — every input to the decision is **public and re-derivable**, so a zero-trust caller can re-run the unified verifier itself:

- The chain head and `documentCID` come from the proof plane.
- The public grants (or the presented credential) are signed, CID-addressable proof-plane objects.
- Revocation status is a proof-plane query.

So the gateway's policy is **"a presented credential is valid implicitly — the gateway is endorsing it — but the caller MAY re-verify."** Presence of a surviving credential _is_ public-read authorization; re-verifying it is cheap and fully client-side.

What is **not** re-verifiable is the host's **serve discipline** — whether an honest host actually withholds bytes from an unauthorized reader. That is unprovable for _any_ content host, and it is the one place the model is host-cooperative rather than cryptographic.

---

## Security model

| Property                | Guarantee                                                                                                                                                           |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Can't forge**         | A reader checks served bytes against the known `documentCID`; wrong bytes fail content-addressing. Integrity is cryptographic **even against a malicious gateway**. |
| **Can withhold / leak** | The gateway holds plaintext. Content-plane access control is **host-cooperative** — it protects an _honest_ host from mis-serving. It is not a cryptographic vault. |

The cryptographic guarantees — integrity, authenticity, authorization — live in the **proof plane**. The content plane is honest-host access control: the "undisclosed-by-default among cooperating relays" layer of the dark forest, not end-to-end encryption. Anything that must stay confidential against a _hostile_ host is withheld or encrypted **above** the protocol. This is the explicit, accepted trust boundary; see [THREAT-MODEL.md](https://protocol.dfos.com/threat-model) for the consolidated proof-plane / content-plane split.

---

## Coupling: why tight is correct

It is tempting to call the gateway "tightly coupled" to the proof plane and treat that as a smell. Three distinct couplings hide under that word; separating them shows the design kept the good one and killed the bad one:

1. **State coupling (replication)** — does it hold an _authoritative_ copy of proof-plane state? A standing-authorization table _trusted as authority_ does (→ invalidation, drift). The stateless gateway holds none: any materialized index it keeps is a re-verified, non-authoritative cache, not authority. ← _the coupling we killed._
2. **Read coupling (runtime dependency)** — does it talk to the proof plane per request? **Yes, unavoidably.** You cannot verify a signature without the issuer's mutable, revocable key. This is intrinsic and correct, not a defect.
3. **Trust coupling** — does it believe the node's judgment or re-derive? **Minimal** — the node hands self-verifying data (signed ops, CIDs, credentials); the gateway decides; a lying node is caught by the verifier.

You **cannot** decouple a verifier from the source of the keys it verifies against. Decoupling would mean either caching authority (→ state coupling, the bug we removed) or ignoring mutability (→ honoring rotated-out keys and revoked grants, a security hole). Tight _read_-coupling to live truth, with **zero** _authoritative_ state replicated, is exactly the shape that is always correct.

### Deployment locality

Performance is a _deployment_ question, not an architectural one. Logical coupling does not imply network latency:

- **Co-located** (gateway beside a proof node or read-replica) — reads are local, microseconds. This is the default.
- **Split** (gateway and proof plane on different origins) — network reads, optionally fronted by a **TTL cache**. The cache is a _performance optimization_ with bounded, stated staleness and is always re-verifiable; it is **never** authoritative state. Logical coupling, physical locality.

---

## Versioning and governance

The document gateway sits below two version clocks and references neither's internals:

- **Protocol v1 (frozen)** — chain mechanics, DAG-CBOR encoding, identifier derivation, validity bounds. The gateway depends **only** on these frozen primitives (CIDs, credentials, signatures). The protocol never references the gateway.
- **Content-schema conventions** — the gateway is content-agnostic; it serves bytes addressed by `documentCID` and does not interpret document schemas.

The gateway's own `0.x` clock advances independently. New gateway capability arrives **additively** atop frozen v1 — a new service type, a richer (backward-compatible) blob-response envelope — never as a protocol break. The governance invariant: **capability flows up from frozen primitives; the protocol never reaches down to a gateway.**

---

## Public-read discovery (0.x)

> **Status: design, not yet built.** A `0.x` gateway ergonomic slated for after the
> v1 freeze. The frozen proof plane is **not** involved — `GET /proof/v1/content/:contentId`
> returns pure replayed chain state and carries no derived authorization data. This
> ergonomic lives entirely at the gateway tier and ships on the gateway's own clock.

When a reader fetches a blob over the **public path** — an unauthenticated `GET /content/:contentId/blob[/:ref]` that a public standing grant authorizes — the gateway already had to derive and re-verify the authorizing `aud: "*"` credential(s) to make its serve/deny decision. The ergonomic: hand those same credentials **back to the caller alongside the bytes**, so the caller can independently re-run the [unified verifier](#the-unified-verifier) and confirm the gateway's authorization decision rather than take the `200` on faith.

The authorizing credentials are returned **in a response envelope, not a header**. A delegated grant carries its full `prf` chain and can run to a few hundred bytes per link; bounded at **≤256 KiB** total (the protocol's credential-size ceiling), that is comfortably an envelope payload but well past what belongs in an HTTP header. The envelope wraps the blob bytes (or references them) and carries the compact credential JWS tokens that authorized the read — each `aud: "*"`, covering `chain:<contentId>` or `chain:*`, rooted at the content creator. Revocation-currency is an **optional extra proof-plane check** the caller MAY run (each credential and every `prf` link against live revocation state); the gateway already ran it before serving, so it is a backstop, not a requirement.

This keeps the gateway honest the same way the proof plane does elsewhere: the node provides the re-verifiable _credentials themselves_, never a pre-chewed `publiclyReadable: true` boolean. A zero-trust caller — or a gateway split across origins from its proof plane — re-verifies and arrives at the same answer. The gateway's filtering is the convenience; the caller's re-verify is the backstop. It adds **zero proof-plane routes** and **zero new gateway routes** — it enriches the existing blob response, and only on the public path. The grants are public credentials; surfacing them discloses nothing private.

The exact envelope shape (inline bytes vs. a sidecar metadata response, field names, content negotiation) is left for the implementation that builds it; this section fixes the **intent** — re-verifiable public-read authorization handed back with the bytes — not the wire format.

---

## What's deferred

- **`DfosManifest`** — a content chain enumerating an identity's documents. Pure discovery, orthogonal to authorization; a gated manifest is just another content chain under the same rules. Out of 0.1 scope.
- **Credentials-by-resource query** — reverse discovery ("what can DID X read"). It serves no part of the read path; YAGNI for 0.1.
- **Blob-response credential envelope** — inlining the authorizing public-read credentials with the served bytes so the caller re-verifies the gateway's decision (see [Public-read discovery](#public-read-discovery-0x)). Designed, not yet built; a `0.x` gateway addition with no proof-plane change.
- **Media** — explicitly **out of gateway and protocol scope**. Media is a [referential document](#terminal-and-referential-documents): a content-schema convention describing how to fetch external bytes (`ipfs://`, a proprietary signed-CDN API), delivered out-of-protocol. If it ever earns a spec, that spec is a SIWD-class content convention — never a gateway `0.x` version or a protocol primitive.
