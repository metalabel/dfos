# DFOS Content Model

Standard content schemas for documents committed to DFOS content chains. JSON Schema (draft 2020-12) definitions for content objects committed by CID.

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

| Field          | Type   | Required | Description                             |
| -------------- | ------ | -------- | --------------------------------------- |
| `$schema`      | string | yes      | `"https://schemas.dfos.com/profile/v1"` |
| `name`         | string | no       | Display name                            |
| `description`  | string | no       | Short bio or description                |
| `avatar`       | media  | no       | Avatar image                            |
| `banner`       | media  | no       | Banner image                            |
| `background`   | media  | no       | Background image                        |
| `createdByDID` | string | no       | DID of the identity subject             |

### Media Object

Several schemas reference media objects. The standard representation:

```json
{
  "id": "media_abc123",
  "uri": "https://cdn.example.com/media/abc123.jpg"
}
```

`id` is required (opaque identifier). `uri` is optional.

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

| Schema       | Projection                                                                      |
| ------------ | ------------------------------------------------------------------------------- |
| `post/v1`    | Living document — head `documentCID` is the current post. History is edit trail |
| `profile/v1` | Living document — head `documentCID` is the current profile                     |

Stream and event fold schemas define their own projection rules in their schema documentation. The protocol does not enforce projections — these are reading conventions that applications agree on.

### Intra-Chain References (`targetOperationCID`)

Content documents may reference specific operations within their own chain or other chains via `targetOperationCID`. This is a content-layer convention — the protocol does not validate or enforce it.

Use cases for `targetOperationCID`:

- **Comments and replies**: A reply document references the operation CID of the post being replied to
- **Reactions**: A reaction document references the operation it reacts to
- **Annotations**: A document annotates a specific version (operation) of another chain's content

`targetOperationCID` is a content field (inside the document committed by CID), not an operation field. The protocol commits to it via `documentCID` but does not interpret it. Applications resolve the reference by looking up the target operation on the relay.

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
