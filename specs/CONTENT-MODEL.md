# DFOS Content Model

Standard content schemas for documents committed to DFOS content chains. JSON Schema (draft 2020-12) definitions for content objects committed by CID.

> **Status — encoding rule frozen; vocabulary on its own clock.** The one normative constraint here — the integer-only number-encoding rule below — is part of the frozen [Protocol v1](https://protocol.dfos.com/spec) wire and will not change. The schema _vocabulary_ these documents define is additive and evolves on its own `0.x` content-schema line, independent of the v1 freeze.

The protocol commits to content by hash — it never inspects what's inside, beyond one canonicalization constraint. Any JSON object with a `$schema` field can be committed, with a single rule on numbers: every number MUST be an integer in JSON's safe range (`[-(2^53 - 1), 2^53 - 1]`) — no fractions, `NaN`, or `±Infinity`. Encode fractional or larger-magnitude values as strings. This keeps the content CID byte-identical across implementations (see Number Encoding in the [protocol spec](https://protocol.dfos.com/spec)). These schemas define the vocabulary DFOS uses internally and serve as the starting vocabulary for applications built on the protocol.

[Protocol Specification](https://protocol.dfos.com/spec) · [schemas.dfos.com](https://schemas.dfos.com) · [Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/schemas)

---

## Schema Convention

Content objects are committed directly to a content chain by CID. The CID is derived from the canonical dag-cbor encoding of the content object itself:

```
documentCID = CID(dagCborCanonicalEncode(contentObject))
```

The protocol requires one thing of the content object: it must include a `$schema` property identifying its content type.

```json
{
  "$schema": "https://schemas.dfos.com/post/v1",
  "format": "short-post",
  "body": "Hello world."
}
```

Because `$schema` is part of the content object, it is behind the `documentCID` — cryptographically committed in the content chain. Any verifier can resolve the document, read `$schema`, and validate against the schema. Documents are self-describing.

---

## Schema Evolution

Schemas are versioned via the URI path (`/post/v1`, `/post/v2`). Evolution rules:

- **Strictly additive within a version** — new optional fields can be added to an existing version at any time without breaking existing documents
- **Breaking changes require a new version** — removing fields, changing types, or adding new required fields means a new version URI
- **Implementations declare which versions they understand** — a registry or application can accept `post/v1` and `post/v2` simultaneously, or only `post/v1`

Immutability here is twofold, and the two senses are deliberately distinct:

1. **Document immutability** — every committed document is CID-addressed and byte-immutable. A specific document, once published, can never change; an edit is a new document with a new CID appended to the content chain.
2. **Schema-version immutability** — a published schema version (e.g. `post/v1`) evolves only additively. Adding optional fields to `post/v1` never invalidates documents already committed against it. Removing or retyping a field is a new version (`post/v2`), never an in-place change.

A document's own field _values_ (e.g. `format`) are fixed at the operation that set them — see the `format` field below.

---

## Standard Schemas

Schema files live in [`schemas/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/schemas) in the protocol package. Each is a standalone JSON Schema (draft 2020-12) definition, served at `https://schemas.dfos.com`.

### Post (`https://schemas.dfos.com/post/v1`)

The primary content type. Covers short posts, long-form posts, comments, and replies via the `format` discriminator.

| Field          | Type     | Required | Description                                                                                                       |
| -------------- | -------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| `$schema`      | string   | yes      | `"https://schemas.dfos.com/post/v1"`                                                                              |
| `format`       | enum     | yes      | `"short-post"`, `"long-post"`, `"comment"`, `"reply"` — fixed at chain genesis and not changed by later revisions |
| `title`        | string   | no       | Post title (typically for long-post format)                                                                       |
| `body`         | string   | no       | Post body content                                                                                                 |
| `cover`        | media    | no       | Cover image                                                                                                       |
| `attachments`  | media[]  | no       | Attached media objects                                                                                            |
| `topics`       | string[] | no       | Topic names (stored as names for portability)                                                                     |
| `createdByDID` | string   | no       | DID of the content author — distinct from the chain operation signer                                              |

`createdByDID` is a content-layer authorship convention, distinct from the operation signer. The `kid` DID in the JWS header identifies who cryptographically signed the operation — this is the protocol-level signer with key authority. `createdByDID` records who authored the content at the application layer. These often differ: an agent, bot, or delegate may sign the operation on behalf of a human author. The protocol verifies the signer; applications display `createdByDID`.

### Profile (`https://schemas.dfos.com/profile/v1`)

The displayable identity for any agent, person, group, or space.

| Field         | Type   | Required | Description                                                     |
| ------------- | ------ | -------- | --------------------------------------------------------------- |
| `$schema`     | string | yes      | `"https://schemas.dfos.com/profile/v1"`                         |
| `name`        | string | no       | Display name                                                    |
| `description` | string | no       | Short bio or description                                        |
| `avatar`      | media  | no       | Avatar image as a [Media object](#media-object)                 |
| `links`       | link[] | no       | External links — up to 20 `{ uri, label?, description? }` items |

`avatar` is an **additive** `profile/v1` field (per the schema-evolution rules above — no `profile/v2`): existing avatar-less profile documents remain valid, and implementations that predate the field ignore it. It is the first consumer of the [Media object](#media-object) shape:

```json
{
  "$schema": "https://schemas.dfos.com/profile/v1",
  "name": "Alice",
  "avatar": {
    "uri": "attachment://media_abc123",
    "cid": "bafkreibovzpnn2y6dquvxhidhx64hg7smduemox7drjs4vprjhlbmivfli"
  }
}
```

### Index (`https://schemas.dfos.com/index/v1`)

An **index chain** is a curated map of content refs — a space's catalog, an author's works, a reading list, a set of pinned items. It is an LWW-Map folded via the [canonical fold](#canonical-fold): each operation commits an `index/v1` document carrying deltas, and the resolved index is the fold over every operation in the log.

An index document carries an **array of deltas** — matching the delta-per-event shape of the [reference content stream](#reference-content-stream-schema). A single append can set or remove several entries at once, and the index accumulates through many small delta documents instead of re-committing a whole catalog each time. (Note the deltas live in the document blob, which the operation-size cap does not measure — content operations commit only the `documentCID`. The protocol does not bound document blob size; any blob limit is gateway or application policy.)

| Field     | Type    | Required | Description                                  |
| --------- | ------- | -------- | -------------------------------------------- |
| `$schema` | string  | yes      | `"https://schemas.dfos.com/index/v1"`        |
| `deltas`  | delta[] | yes      | Ordered deltas contributed by this operation |

Each delta is one of two shapes:

| Delta                              | Effect                                                                                                                      |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `{ "op": "set", "key", "value"? }` | Add or replace entry `key`. `value` is optional metadata (see below); omit it (or use `{}`) for a pure set-membership entry |
| `{ "op": "remove", "key" }`        | Drop entry `key`                                                                                                            |

- **`key`** is a **content ref** — a 31-char content chain id or a CID — consistent with how refs are named elsewhere in the content model.
- **`value`** is an optional entry-metadata object `{ label?, order?, … }`. `label` is a display string; `order` is an integer ordering hint (integers only, per the number-encoding rule above). A pure set-membership index uses the degenerate `value: {}`. Unknown metadata fields are preserved (additive forward compat).

```json
{
  "$schema": "https://schemas.dfos.com/index/v1",
  "deltas": [
    {
      "op": "set",
      "key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "value": { "label": "First Release", "order": 1 }
    },
    { "op": "remove", "key": "ccccccccccccccccccccccccccccccc" }
  ]
}
```

**Fold semantics.** The resolved index is the [canonical fold](#canonical-fold) as an LWW-Map:

1. **Linearize** every operation in the log (all branches) into the canonical total order.
2. **Flatten** each `index/v1` document's `deltas` array in array order, producing one ordered delta stream.
3. **Fold** the stream: `set` writes `key → value`, `remove` deletes `key`. The **last delta touching a key wins** at its linearized position — so a `remove` supersedes an earlier `set`, and a later `set` re-adds a removed key.

**Unknown delta shapes are skipped deterministically** — a delta whose `op` is neither `set` nor `remove`, whose `key` is not a string, or whose `set` `value` is present but not an object is ignored, not an error. This lets the vocabulary grow (new delta ops) without forking existing readers, and every reader skips the same deltas. The published JSON Schema mirrors this: schema validity covers the known vocabulary constraints only (a delta needs an object shape and a string `op`; a `set` or `remove` must carry a string `key`), and validators MUST NOT reject documents carrying additional delta shapes.

Because the fold is branch-inclusive and last-applied-wins, an index **converges**: any ingest order of the same operation set folds to the same map, and two clients that concurrently append entries both keep their writes. If the chain's selected head is delete-terminal, the index is deleted and the fold is moot (see [Delete-terminality](#delete-terminality)).

The `index/v1` fold is implemented as `foldIndexV1(ops)` in [`@metalabel/dfos-protocol/fold`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/src/fold). See [`schemas/index.v1.json`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/schemas/index.v1.json) and the worked chain in [`examples/index/`](https://github.com/metalabel/dfos/tree/main/examples/index).

### Media Object

The standard representation of a reference to external media bytes. Defined once here; schemas that carry media reference this shape (the first consumer is the `profile/v1` `avatar` field above).

```json
{
  "uri": "attachment://media_abc123",
  "cid": "bafkreibovzpnn2y6dquvxhidhx64hg7smduemox7drjs4vprjhlbmivfli",
  "href": "https://cdn.example.com/media/abc123.jpg"
}
```

| Field  | Type   | Required | Description                                                                                      |
| ------ | ------ | -------- | ------------------------------------------------------------------------------------------------ |
| `uri`  | string | yes      | Canonical reference to the media — an `attachment://<id>` ref or any other URI. Always present   |
| `cid`  | string | no       | Content commitment — CIDv1, raw codec (`0x55`), sha2-256, base32 lowercase, over the media bytes |
| `href` | string | no       | Resolution hint — a plain URL where the bytes may currently be fetched. Non-normative            |

- **`uri`** (REQUIRED) is the stable, canonical name of the media. It MAY be an `attachment://<id>` ref (below) or any other URI scheme (`ipfs://`, `https://`, …). The `uri` identifies; it does not promise integrity.
- **`cid`** (OPTIONAL) is a verifiable commitment to the bytes: a CIDv1 with the **raw codec (`0x55`)** and **sha2-256**, encoded base32 lowercase (a 59-char `bafkrei…` string), computed over the media bytes **exactly as stored and served**. Media bytes are opaque binary, so a consumer verifies by hashing the fetched bytes directly — unlike document blobs, no re-canonicalization is involved. `cid` is optional because a cid may not have been computed (yet, or ever) for some media; when present, a consumer SHOULD verify the bytes it ultimately receives against it.
- **`href`** (OPTIONAL) is an implementation-dependent fallback: a plain URL where the bytes may currently be fetched. It is non-normative, carries no integrity promise, and MAY rot. Consumers prefer resolving `uri` and verifying with `cid`; `href` is a hint, never the reference.

#### The `attachment://` ref

`attachment://<id>` is an **opaque, host-scoped media reference**: `<id>` is an identifier meaningful to the host that committed the document, and nothing about the bytes can be derived from the ref itself. Resolution — turning the ref into fetchable bytes — is host- or gateway-dependent (for example, a [document-gateway](https://protocol.dfos.com/document-gateway) deployment may resolve it via an out-of-protocol signed-CDN API). The ref carries **no integrity**; integrity is exactly what `cid` is for.

A media object is the canonical **referential** case: a document is either _terminal_ (the `{ $schema, … }` blob _is_ the content) or _referential_ (it describes how to fetch external bytes). A media object is a pointer, and resolving it (delivery of the actual media bytes) is **outside the protocol**. The document gateway serves the document that _contains_ the media object as opaque bytes; it never dereferences the pointer. There is no "media gateway": media lives at the application/delivery layer, bound to the proof plane only by the signed reference — with `cid` as the optional content hash that lets a consumer verify the bytes it ultimately receives.

> **Legacy shape (`post/v1`).** The `cover` and `attachments` fields of `post/v1` predate this definition and use an earlier `{ id, uri? }` media shape (`id` required, `uri` optional). Per the schema-evolution rules, that shape is unchanged within `post/v1`; a future post version adopts the Media object defined here.

---

## Chain Interpretation

A content chain is a signed append-only log. The protocol enforces ordering, authorship, and integrity. It does not prescribe what the chain _means_. How an application interprets a content chain depends on the content types committed to it.

### Living Document

The chain represents a single evolving thing — a profile, a post, a policy document. Each operation is a **revision**. The resolved state is the latest `documentCID`. History is audit trail. The content _is_ the current version.

This is the default interpretation for the standard schemas. Edit lineage is tracked via `baseDocumentCID` on the content operation payload — each new operation can reference the document CID it replaced.

### Stream

The chain represents a sequence — a feed, a journal, a log. Each operation is a discrete emission, not a revision. There is no single "current state" — the chain _is_ the content. Previous documents aren't superseded, they're siblings in a series.

A stream chain accumulates documents over time. The resolved content is the full ordered list of documents, not just the head. Applications read streams by walking the chain log and collecting each operation's `documentCID`.

### Event Fold

The chain represents a sequence of events that fold into a computed state. Each operation contributes a delta or event. The resolved state is the result of replaying all events in order — similar to event sourcing. The `$schema` of the documents defines the event types and fold semantics.

Unlike a living document (where the head document is the state) or a stream (where all documents are siblings), an event fold requires interpretation logic specific to the schema. The chain log is the source of truth; the projected state is derived.

### Projection Rules per Schema

Each schema implies a default projection — how applications derive resolved state from the chain:

| Schema       | Projection                                                                                                         |
| ------------ | ------------------------------------------------------------------------------------------------------------------ |
| `post/v1`    | Living document — head `documentCID` is the current post. History is edit trail                                    |
| `profile/v1` | Living document — head `documentCID` is the current profile                                                        |
| `index/v1`   | Canonical fold — LWW-Map folded over all operations (every branch). See [Index](#index-httpsschemasdfoscomindexv1) |

Stream and event fold schemas define their own projection rules in their schema documentation. The protocol does not enforce projections — these are reading conventions that applications agree on.

### Intra-Chain References (`targetOperationCID`)

Content documents may reference specific operations within their own chain or other chains via `targetOperationCID`. This is a content-layer convention — the protocol does not validate or enforce it.

Use cases for `targetOperationCID`:

- **Comments and replies**: A reply document references the operation CID of the post being replied to
- **Reactions**: A reaction document references the operation it reacts to
- **Annotations**: A document annotates a specific version (operation) of another chain's content

`targetOperationCID` is a content field (inside the document committed by CID), not an operation field. The protocol commits to it via `documentCID` but does not interpret it. Applications resolve the reference by looking up the target operation on the relay.

---

## Canonical Fold

The [Event Fold](#event-fold) interpretation says a chain's resolved state is the result of replaying its operations "in order." The **canonical fold** makes that order precise: a single deterministic total order over **all** operations in a chain's log — every branch, not just the selected-head branch — so that any implementation holding the same set of operations computes the same folded state.

### Linearization

The canonical order is the [web relay's deterministic head-selection comparator](https://protocol.dfos.com/web-relay#fork-acceptance) generalized from "pick one tip" to "order the whole log."

Head selection prefers, among the chain's tips (operations with no child), the operation with the **highest `createdAt`**, breaking ties by the **highest operation CID** — both compared **byte-wise** over the multibase CID string and the ASCII ISO-8601 timestamp (a code-point comparison, never locale collation, so every implementation agrees; see [Threat Model → Fork head selection](https://protocol.dfos.com/threat-model)).

The canonical linearization lays that same preference out in full, **ascending**, so the operation head selection would prefer sorts **last**:

1. **`createdAt` ascending** (byte-wise string comparison).
2. **Operation CID ascending** as tiebreak (byte-wise multibase string).

Because the two orderings are exact reverses of one another, they can never disagree: the **last** operation of a full-log linearization is exactly the operation head selection picks. This holds structurally — any operation with a child has a strictly-greater-`createdAt` child (each write's `createdAt` must exceed its predecessor's), so the operation with the globally-maximal `createdAt` is always a tip. Sorting the head-preferred operation last is what makes the fold **last-applied-wins**: the newest write settles a contended key.

Both the relay's head selection and the fold's linearization call the **same exported comparison function** ([`compareHeadPreference`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/fold/linearize.ts)), so the two cannot drift.

### Branch-inclusive is deliberate

Folding **every branch**, rather than only the selected-head branch, is a deliberate divergence from the head-selection register semantics used by living-document schemas:

- **Head selection answers "which single document is current."** A `profile/v1` or `post/v1` chain is a register — one head document is the state, and a losing fork is simply not the head. A concurrently-appended fork is _dropped_ from the resolved value.
- **The canonical fold answers "what is the merged state of a CRDT chain."** An index (or any LWW-Map / event-fold schema) is not a register; its state is the accumulation of every operation. Here concurrent forks must **converge**, not compete — dropping a branch would silently lose the writes on it.

So the two readings coexist on the same wire format: a register chain reads its head via head selection; a fold chain folds its whole log. This is what retro-solves the concurrent-append fork-drop hazard for accumulating schemas — two clients that append at the same chain position both keep their writes, and every reader converges on the same merged state regardless of ingest order.

### Delete-terminality

The fold assumes a **live** chain. If the **selected head branch is delete-terminal** — the highest-ranked tip is a `delete` — the chain is deleted, resolution reports it as such, and **the fold is moot**: a consumer checks `isDeleted` (from chain verification) first and does not fold a deleted chain. (A `delete` on a _non-head_ branch is just another superseded operation and does not delete the chain — see [Undeletion](https://protocol.dfos.com/web-relay).)

### Library

The fold is a set of **pure functions** over already-verified operations, published at [`@metalabel/dfos-protocol/fold`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/src/fold) (no cryptographic or network dependencies):

- `linearize(ops)` — the deterministic total order above.
- `foldLwwMap(deltas)` — the generic LWW-Map fold over an ordered delta stream.
- `foldIndexV1(ops)` — the [`index/v1`](#index-httpsschemasdfoscomindexv1) fold built on the two.

---

## Reference Content Stream Schema

The content stream is the canonical example of the stream interpretation pattern. A stream chain accumulates discrete entries — each operation appends a new document to the sequence rather than replacing the previous one. This is a **reference/example schema** — it illustrates the stream pattern and is not one of the hosted standard schemas. Its `$id` carries the `reference-content-stream/v1` URI to mark it as such; see [`schemas/reference-content-stream.v1.json`](https://github.com/metalabel/dfos/blob/main/schemas/reference-content-stream.v1.json) and the worked chain in [`examples/reference-content-stream/`](https://github.com/metalabel/dfos/tree/main/examples/reference-content-stream).

### Reference Content Stream (`https://schemas.dfos.com/reference-content-stream/v1`)

A stream entry document. Each document in a content stream chain is a standalone entry in the sequence.

| Field                | Type    | Required | Description                                                         |
| -------------------- | ------- | -------- | ------------------------------------------------------------------- |
| `$schema`            | string  | yes      | `"https://schemas.dfos.com/reference-content-stream/v1"`            |
| `body`               | string  | no       | Entry body content                                                  |
| `attachments`        | media[] | no       | Attached media objects                                              |
| `targetOperationCID` | string  | no       | CID of an operation this entry references (reply, annotation, etc.) |
| `createdByDID`       | string  | no       | DID of the content author (distinct from the operation signer)      |

```json
{
  "$schema": "https://schemas.dfos.com/reference-content-stream/v1",
  "body": "This is a stream entry.",
  "createdByDID": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr"
}
```

Content stream chains use the **stream** interpretation — the resolved content is the full ordered list of documents, not just the head. Applications read content streams by walking the chain log and collecting each operation's `documentCID`.

---

## Custom Schemas

Any implementation can define custom document schemas following the same pattern — a JSON Schema with a `$schema` const field pointing to a unique URI. The protocol will commit to the document via CID regardless of what's inside. The standard schemas are conventions, not constraints.

Custom schema URIs should use a namespace you control (e.g., `https://schemas.example.com/my-type/v1`) to avoid collisions with the standard library.
