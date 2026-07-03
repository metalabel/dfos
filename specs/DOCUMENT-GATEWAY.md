# DFOS Document Gateway

A stateless, content-addressed blob store whose authorization is a re-verifiable endorsement derived live from the proof plane. The gateway serves the **content plane** — the raw documents that content chains commit to via `documentCID` — and holds no _authoritative_ authorization state of its own (it re-derives every decision live).

This spec is under active review. Discuss it in the [DFOS](https://nce.dfos.com) space.

[Protocol](https://protocol.dfos.com) · [Web Relay](https://protocol.dfos.com/web-relay) · [Credentials](https://protocol.dfos.com/credentials)

> **Gateway version 0.1.** This document specifies the document gateway as an
> optional service on its own `0.x` clock, independent of the Protocol v1 freeze.
> It matches the behavior the reference relay (`@metalabel/dfos-web-relay`,
> `dfos-web-relay-go`) ships today: both the public-grant and delegated read paths
> re-derive authorization live from the proof plane on every request. How the
> gateway hands a public-read caller the grants it re-verified — a 0.x ergonomic
> that does **not** touch the frozen proof plane — is sketched under
> [Public-read discovery](#public-read-discovery-0x). A relay MAY keep a
> materialized public-credential index as a **non-authoritative performance
> cache** — it is never authority (see [Statelessness](#statelessness)). Published
> here for review and to inform implementors.

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

- **Public path.** The reader presents no credential. The gateway derives the relevant public credentials (`aud: "*"`) covering the chain from the proof plane (see [Public-grant derivation](#public-grant-derivation)) and runs each through the unified verifier. A surviving public grant authorizes the read. The candidates may come from a materialized public-credential index, but that index is a **non-authoritative cache** — authority is the live re-verify, never the stored lookup.
- **Delegated path.** The reader presents a DFOS credential in the `X-Credential` header. The gateway runs the same verifier over it. Unchanged in shape — it simply gains the same revocation check the public path runs.

Both paths check revocation at **every link** of the delegation chain. There is no asymmetry: a revoked public grant and a revoked presented credential are denied identically. See [Revocation](#revocation).

### Public-grant derivation

Public credentials (`aud: "*"`) are ordinary proof-plane operations — they enter through `POST /proof/v1/operations` and live in the operation log like any other signed op (kind `credential`). The gateway therefore needs no separate grant table _as authority_: it derives the public grants covering a chain from the proof plane it already reads for the chain head. (A relay MAY keep a materialized index of these credentials as a non-authoritative candidate cache; see [Statelessness](#statelessness).)

The gateway derives these grants from the proof-plane operation log it already reads (see [Public-read discovery](#public-read-discovery-0x) for how it then hands them to a public-read caller). Crucially, the gateway works from the **credentials themselves**, not a pre-chewed `publiclyReadable: true`. The proof plane provides _data_; the gateway makes the _decision_ by re-verifying through the unified verifier. The proof plane never makes an authorization judgment the gateway blindly trusts — a malformed or revoked credential is rejected by the verifier. This keeps the verifier honest and composable.

A public grant may name `chain:<contentId>` (this chain) or `chain:*` (all of the issuer's chains). Either way it MUST root at the content creator to authorize. Public credentials SHOULD be read-scoped — a public `write` grant is a world-writable bearer token (see [CREDENTIALS.md → `aud: "*"` + write](https://protocol.dfos.com/credentials#security-aud-quotquot--write--a-world-writable-bearer-grant)).

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

> **Byte encoding of blobs.** Stored and served blob bytes are the bytes **as received** (the raw upload body — canonically a JSON document), NOT a re-canonicalized form. The `documentCID` check is therefore **decode-JSON → dag-cbor canonical encode → sha-256 → compare CID** (matching the reference relay's upload check), not a direct hash of the served bytes. A naive `sha256(servedBytes)` will NOT equal `documentCID`; a verifier must re-canonicalize through the same decode → dag-cbor path.

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

| Property                | Guarantee                                                                                                                                                                                                                                                             |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Can't forge**         | A reader checks served bytes against the known `documentCID` by re-canonicalizing (decode-JSON → dag-cbor → sha-256), not by hashing the served bytes directly; wrong bytes fail content-addressing. Integrity is cryptographic **even against a malicious gateway**. |
| **Can withhold / leak** | The gateway holds plaintext. Content-plane access control is **host-cooperative** — it protects an _honest_ host from mis-serving. It is not a cryptographic vault.                                                                                                   |

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

The gateway's own `0.x` clock advances independently. New gateway capability arrives **additively** atop frozen v1 — a new service type, a richer blob-response envelope on a gateway-owned route — never as a protocol break, and never by adding fields to a frozen proof-plane route. The governance invariant: **capability flows up from frozen primitives; the protocol never reaches down to a gateway.**

---

## Public-read discovery (0.x)

> **Status: design, not yet built.** This sketches a `0.x` gateway ergonomic. It is **not** part of the reference relay today and is deliberately under-specified at the wire level — the framing below fixes the _shape_ of the answer; an implementor picks the exact bytes.

A zero-trust public-read caller wants two things at once: the document bytes, _and_ the `aud: "*"` credentials that authorized the read, so it can re-verify the grant itself instead of trusting "the gateway let me in." The challenge is handing back both without:

1. **Touching the frozen proof plane.** The grants do **not** ride `GET /proof/v1/content/:contentId` — that route is frozen with protocol v1 and carries pure chain state, nothing derived. Public-read discovery is a gateway concern on the gateway's own `0.x` clock, so it lives entirely on a **gateway-owned route** (the public blob path), never as a new field on a locked proof route.
2. **Overloading HTTP headers.** A delegation chain of credential JWS tokens can run to many kilobytes — well past what belongs in a response header. So the grants come back in a **response envelope** (a body the caller parses), not a header.

The ergonomic, then: on the public blob path the gateway already serves, when a public grant authorized the read, the gateway hands back — alongside (or wrapping) the blob — the **authorizing credentials themselves**: the `aud: "*"` JWS tokens (`chain:<contentId>` or `chain:*`) it re-verified to allow the read. The caller re-runs the same unified verifier over them and arrives at the same yes independently. The gateway's filtering is a convenience; the caller's re-verify is the backstop, exactly as on the server side.

Constraints that fix the shape (not the bytes):

- **Response envelope, not header.** The delegated grant set is bounded at **≤ 256 KiB** of credential material; anything that large signals a pathological delegation graph and the gateway MAY refuse to inline it (the caller can still fall back to fetching credentials by CID off the proof plane).
- **Re-verified, not raw.** Only grants that survive the live verifier (signature, issuer-key resolution, expiry, revocation, delegation rooted at the creator) are inlined — same filter the read decision used.
- **Revocation currency is the caller's option.** The inlined grants were revocation-checked at serve time; a caller that wants stronger currency MAY re-check revocation live against the proof plane it can read directly. The envelope is a head-start, never a substitute for the caller's own proof-plane reads.
- **Wire shape left to the implementor.** Whether the envelope is a JSON wrapper around a base64 blob, a multipart response, or a sidecar `Link`-discoverable resource is a `0.x` implementation choice. This section fixes only that the grants come back **in a body, on a gateway route, re-verified** — not the field names.

This adds **zero proof-plane surface**: it is purely a gateway-side enrichment of a response the gateway already owns. The grants are public credentials; surfacing them discloses nothing private.

---

## Follower materialization (0.x)

A gateway holds the bytes for the chains it authored or was uploaded to. A gateway MAY also acquire bytes by **following**: pulling the documents of chains it is authorized to read from peer gateways, so it can serve that content independently of the origin. This is the content-plane counterpart to proof-plane sync — same "authored at origin, verified at the edge" geometry, opposite transport (pull, not gossip), one shared gate.

It is an optional `0.x` behavior that adds **no new route** and is invisible to a gateway that does not opt in. The normative shape:

- **Pull over the existing public blob route.** A follower fetches `GET /content/:contentId/blob/:operationCID` (or `/blob` for the head) from a source gateway. No new endpoint, no new wire field.
- **Content-addressed, source-agnostic.** Each pulled blob is verified against the `documentCID` the chain committed — the same content-addressing check `PUT` enforces. Integrity is the CID, which is already signed in the proof plane, so a follower may pull from any source and reject anything that does not hash to its committed CID. This is what makes following trustless.
- **Gated by the same predicate that serves.** A follower materializes a chain's bytes only while a surviving public-read grant authorizes anonymous read of it — the gateway's own download-authorization decision (see [Download authorization](#download-authorization)). A private, revoked, or deleted chain is never followed.
- **`200 + document: null` is CONFORMANT.** Authorization (the grant) arrives on the proof plane instantly; the bytes arrive asynchronously. A follower that is authorized for a chain but has not yet materialized a document returns `200` with `document: null` on `/documents`, and `404 blob not found` on `/blob`. This is the honest **authorized-but-not-yet-materialized** state, NOT a conformance failure. A conforming follower converges to serving the bytes (it is _eventually_ consistent); a conformance test asserts eventual materialization (poll until served), never instantaneous.
- **Revoke is correctness-free; GC is reclamation.** The per-request download-authorization decision is re-derived live, so revoking a grant makes any cached bytes immediately unreachable — the gate, not deletion, is what enforces revocation. Deleting the now-orphaned bytes is a separate convergent garbage-collection pass keyed on the same gate; it reclaims storage and is never load-bearing for correctness.

Whether a gateway follows, which sources it pulls from, and how aggressively are deployment choices, not protocol. The reference Go relay exposes following as `CONTENT_FOLLOW=eager` (default `none`); see [WEB-RELAY.md → Content Following](https://protocol.dfos.com/web-relay#content-following).

---

## What's deferred

- **Index chains** — a content chain enumerating an identity's documents (a catalog, an author's works) is pure discovery, orthogonal to authorization. This is served by the [`index/v1`](https://protocol.dfos.com/content-model#index-httpsschemasdfoscomindexv1) content schema, which needs no special gateway support: an index is just another content chain, gated by the same rules, and a consumer folds it via the canonical fold. No gateway `0.x` primitive.
- **Credentials-by-resource query** — reverse discovery ("what can DID X read"). It serves no part of the read path; YAGNI for 0.1.
- **Blob-response credential envelope** — inlining the re-verified `aud: "*"` grants alongside the public blob so a zero-trust caller re-verifies the grant itself (see [Public-read discovery](#public-read-discovery-0x)). Designed, not yet built; the exact wire shape is deferred to the implementor.
- **Media** — explicitly **out of gateway and protocol scope**. Media is a [referential document](#terminal-and-referential-documents): a content-schema convention describing how to fetch external bytes (`ipfs://`, an opaque `attachment://<id>` resolved by an out-of-protocol signed-CDN API), delivered out-of-protocol. That convention is now specced as the [Media object](https://protocol.dfos.com/content-model#media-object) in the content model — a content-schema convention, never a gateway `0.x` version or a protocol primitive. Nothing changes for the gateway: it serves the document that carries the media object and never dereferences the pointer.
