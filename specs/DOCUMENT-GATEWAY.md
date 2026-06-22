# DFOS Document Gateway

A stateless, content-addressed blob store whose authorization is a re-verifiable endorsement derived live from the proof plane. The gateway serves the **content plane** — the raw documents that content chains commit to via `documentCID` — and holds no authorization state of its own.

This spec is under active review. Discuss it in the [clear.txt](https://clear.dfos.com) space on DFOS.

[Protocol](https://protocol.dfos.com) · [Web Relay](https://protocol.dfos.com/web-relay) · [Credentials](https://protocol.dfos.com/credentials)

> **Gateway version 0.1 — converging.** This document specifies the document
> gateway as an optional service on its own `0.x` clock, independent of the
> Protocol v1 freeze. The reference relay (`@metalabel/dfos-web-relay`,
> `dfos-web-relay-go`) already implements most of this contract: the delegated
> read path is the stateless verifier described here. The remaining delta is the
> **public-grant path**, which is converging from a stored standing-authorization
> table to the stateless proof-plane derivation specified below. Where current
> relay behavior differs, [Web Relay → Standing Authorization](https://protocol.dfos.com/web-relay#standing-authorization)
> describes what ships today; this spec describes the 0.1 target the
> implementation is converging to. Published here for review and to inform
> implementors.

---

## What it is

The document gateway is the read/write face of the **content plane**. Content chains live in the proof plane as signed commitments — each operation carries a `documentCID`, the hash of a document the chain commits to. The gateway stores and serves those documents (the **preimages** of the committed CIDs).

It is deliberately **dumber** than a proof node. It has no chains, no signatures of its own, no gossip, no consensus, no operation log. It does exactly two things:

- **Stores bytes** addressed by the `documentCID` a content chain already committed to.
- **Serves bytes** to readers it can verify are authorized — where "authorized" is a judgment re-derived live from the proof plane on every request, never a stored grant.

Everything that gives a document _meaning_ — which chain it belongs to, who committed it, who may read it — lives in the proof plane. The gateway holds only the bytes. This split is the heart of the design:

| Plane                       | Holds                                                    | Guarantees                                                                         |
| --------------------------- | -------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **Proof plane**             | Signed commitments (ops, CIDs, credentials, revocations) | Integrity + authenticity + authorization, cryptographically, against any adversary |
| **Content plane (gateway)** | Document preimages, verified by content-addressing       | Integrity (bytes → CID) cryptographically; access control _honest-host_            |

A relay's content plane **is** a document gateway. The two terms name the same surface from two angles: "content plane" is the relay-internal plane (paired with the proof plane); "document gateway" is the standalone service contract on a `0.x` clock. A reverse proxy can split them across origins — the proof node owns `GET /proof/v1/content/:contentId` and `/log`; the gateway owns the `/content/:contentId/blob*` and `/documents` sub-paths.

---

## Statelessness

The gateway holds **no authorization state and no proof-plane replica**. "Stateless" here means _stateless over the proof plane_: the gateway reads the proof plane live on every authorization decision, and stores nothing it could serve stale.

This is not the same as offline. Verifying any signature requires the issuer's keys, which live in a **mutable, revocable** identity chain. "Is this grant valid right now?" is a question about _current_ proof-plane state — a key may have rotated, a credential may have been revoked, an identity may have been deleted. There is no correct offline answer. A live read is the honest price of verifying against live, revocable truth.

What the gateway gains by holding no copy: it can never serve a stale authorization. It is coupled to _truth_ and holds no replica to drift. See [Coupling](#coupling-why-tight-is-correct), which separates the three couplings that "stateful/stateless" usually smears together.

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

There is no second code path, no "is it public?" branch that trusts a stored flag, no standing-authorization table consulted before the verifier runs. A grant is authorized **iff** a credential covering the resource survives this routine against live proof-plane state.

### Two paths, one verifier

- **Public path.** The reader presents no credential. The gateway derives the relevant public credentials (`aud: "*"`) covering the chain from the proof plane (see [Public-grant derivation](#public-grant-derivation)) and runs each through the unified verifier. A surviving public grant authorizes the read. This **replaces** a stored standing-authorization lookup with live derivation.
- **Delegated path.** The reader presents a DFOS credential in the `X-Credential` header. The gateway runs the same verifier over it. Unchanged in shape — it simply gains the same revocation check the public path runs.

Both paths check revocation at **every link** of the delegation chain. There is no asymmetry: a revoked public grant and a revoked presented credential are denied identically. See [Revocation](#revocation).

### Public-grant derivation

Public credentials (`aud: "*"`) are ordinary proof-plane operations — they enter through `POST /proof/v1/operations` and live in the operation log like any other signed op (kind `credential`). The gateway therefore does **not** maintain a separate grant table. It derives the public grants covering a chain by querying the proof plane it already reads for the chain head.

The proof plane surfaces these grants through an enriched content-state response (see [Enriched resolve](#enriched-resolve-proof-plane-support)). Crucially, the proof node hands the gateway the **credentials themselves**, not a pre-chewed `publiclyReadable: true`. The node provides _data_; the gateway makes the _decision_ by re-verifying through the unified verifier. The node never makes an authorization judgment the gateway blindly trusts — a lying node hands a malformed or revoked credential and the verifier rejects it. This keeps the verifier honest and composable.

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

1. **State coupling (replication)** — does it hold a coherent _copy_ of proof-plane state? A stored standing-authorization table does (→ invalidation, drift). The stateless gateway does **not**. ← _the coupling we killed._
2. **Read coupling (runtime dependency)** — does it talk to the proof plane per request? **Yes, unavoidably.** You cannot verify a signature without the issuer's mutable, revocable key. This is intrinsic and correct, not a defect.
3. **Trust coupling** — does it believe the node's judgment or re-derive? **Minimal** — the node hands self-verifying data (signed ops, CIDs, credentials); the gateway decides; a lying node is caught by the verifier.

You **cannot** decouple a verifier from the source of the keys it verifies against. Decoupling would mean either caching authority (→ state coupling, the bug we removed) or ignoring mutability (→ honoring rotated-out keys and revoked grants, a security hole). Tight _read_-coupling to live truth, with **zero** state replicated, is exactly the shape that is always correct.

### Deployment locality

Performance is a _deployment_ question, not an architectural one. Logical coupling does not imply network latency:

- **Co-located** (gateway beside a proof node or read-replica) — reads are local, microseconds. This is the default.
- **Split** (gateway and proof plane on different origins) — network reads, optionally fronted by a **TTL cache**. The cache is a _performance optimization_ with bounded, stated staleness and is always re-verifiable; it is **never** authoritative state. Logical coupling, physical locality.

---

## Versioning and governance

The document gateway sits below two version clocks and references neither's internals:

- **Protocol v1 (frozen)** — chain mechanics, DAG-CBOR encoding, identifier derivation, validity bounds. The gateway depends **only** on these frozen primitives (CIDs, credentials, signatures). The protocol never references the gateway.
- **Content-schema conventions** — the gateway is content-agnostic; it serves bytes addressed by `documentCID` and does not interpret document schemas.

The gateway's own `0.x` clock advances independently. New gateway capability arrives **additively** atop frozen v1 — a new service type, an enriched (backward-compatible) response field, a future media gateway — never as a protocol break. The governance invariant: **capability flows up from frozen primitives; the protocol never reaches down to a gateway.**

---

## Enriched resolve (proof-plane support)

The gateway needs the proof plane to surface, alongside a chain's head state, the **public grant credentials** covering that chain — so the gateway can re-verify them rather than consult a stored table.

`GET /proof/v1/content/:contentId` (already called for the head `documentCID`) is **enriched** with a `publicGrants` field: an array of compact credential JWS tokens (`aud: "*"`) whose attenuations cover this chain (`chain:<contentId>` or `chain:*`). The field sits as a top-level sibling to `state`, not inside it — `state` remains the pure replayed chain projection; `publicGrants` is derived authorization data.

```json
{
  "contentId": "abc123...",
  "genesisCID": "bafy...",
  "headCID": "bafy...",
  "state": { "...": "pure replayed chain state" },
  "publicGrants": ["eyJhbGciOiJFZERTQSIs...", "..."]
}
```

This is **additive and backward-compatible** (MUST-ignore-unknown): a consumer that does not know `publicGrants` ignores it. It adds **+0 routes** — it enriches an existing one. The grants are public credentials; surfacing them discloses nothing private.

**Coupling wrinkle to watch.** Enriching the content-_state_ response folds authorization metadata into a chain-state response. This is fine for 0.1 (public grants are public; it saves a round-trip). If the conflation ever bites, the clean split is a sibling `GET /proof/v1/content/:contentId/grants` (mirroring `/log`) — at the cost of +1 route and +1 round-trip. Deferred until it earns its place.

---

## What's deferred

- **`DfosManifest`** — a content chain enumerating an identity's documents. Pure discovery, orthogonal to authorization; a gated manifest is just another content chain under the same rules. Out of 0.1 scope.
- **Credentials-by-resource query** — reverse discovery ("what can DID X read"). It serves no part of the read path; YAGNI for 0.1.
- **Sibling `/grants` route** — the cleaner separation of authorization metadata from chain state, deferred until the enriched-resolve conflation actually bites.
- **Media gateway** — the same spine with a binary skin (range requests, variants/thumbnails). A future `0.x` sibling on its own clock; it will pressure-test this design.
