# DFOS Content Model

Standard content schemas for documents committed to DFOS content chains. JSON Schema (draft 2020-12) definitions for what goes inside the document envelope's `content` field.

These schemas are conventions, not protocol requirements. The DFOS Protocol commits to documents by CID without inspecting their contents — any valid JSON object with a `$schema` field can be committed. The content model defines the vocabulary that DFOS uses internally, provided as a starting point for applications built on the protocol.

[Protocol Specification](https://protocol.dfos.com/spec) · [schemas.dfos.com](https://schemas.dfos.com) · [Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/schemas)

---

## Schema Convention

Every document committed to a content chain is wrapped in a [document envelope](https://protocol.dfos.com/spec#document-envelope). The envelope's `content` field holds the application-defined payload. The protocol requires one thing of this payload: it must include a `$schema` property identifying its content type.

```json
{
  "$schema": "https://schemas.dfos.com/post/v1",
  "format": "short-post",
  "body": "Hello world."
}
```

Because `$schema` is part of the document, it is behind the `documentCID` — cryptographically committed in the content chain. Any verifier can resolve the document, read `$schema`, and validate against the schema. Documents are self-describing.

---

## Schema Evolution

Schemas are versioned via the URI path (`/post/v1`, `/post/v2`). Evolution rules:

- **Strictly additive within a version** — new optional fields can be added to an existing version at any time without breaking existing documents
- **Breaking changes require a new version** — removing fields, changing types, or adding new required fields means a new version URI
- **Implementations declare which versions they understand** — a registry or application can accept `post/v1` and `post/v2` simultaneously, or only `post/v1`

---

## Standard Schemas

Schema files live in [`schemas/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/schemas) in the protocol package. Each is a standalone JSON Schema (draft 2020-12) definition, served at `https://schemas.dfos.com`.

### Post (`https://schemas.dfos.com/post/v1`)

The primary content type. Covers short posts, long-form posts, comments, and replies via the `format` discriminator.

| Field         | Type     | Required | Description                                                                        |
| ------------- | -------- | -------- | ---------------------------------------------------------------------------------- |
| `$schema`     | string   | yes      | `"https://schemas.dfos.com/post/v1"`                                               |
| `format`      | enum     | yes      | `"short-post"`, `"long-post"`, `"comment"`, `"reply"` — immutable, set at creation |
| `title`       | string   | no       | Post title (typically for long-post format)                                        |
| `body`        | string   | no       | Post body content                                                                  |
| `cover`       | media    | no       | Cover image                                                                        |
| `attachments` | media[]  | no       | Attached media objects                                                             |
| `topics`      | string[] | no       | Topic names (stored as names for portability)                                      |

### Profile (`https://schemas.dfos.com/profile/v1`)

The displayable identity for any agent, person, group, or space.

| Field         | Type   | Required | Description                             |
| ------------- | ------ | -------- | --------------------------------------- |
| `$schema`     | string | yes      | `"https://schemas.dfos.com/profile/v1"` |
| `name`        | string | no       | Display name                            |
| `description` | string | no       | Short bio or description                |
| `avatar`      | media  | no       | Avatar image                            |
| `banner`      | media  | no       | Banner image                            |
| `background`  | media  | no       | Background image                        |

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

The chain represents a single evolving thing — a profile, a post, a policy document. Each operation is a **revision**. The resolved state is the latest `documentCID`. History is audit trail. The entity _is_ the current version.

This is the default interpretation for the standard schemas. The document envelope's `baseDocumentCID` field supports edit lineage — each new document version can point back to the one it replaced.

### Stream

The chain represents a sequence — a feed, a journal, a log. Each operation is a discrete emission, not a revision. There is no single "current state" — the chain _is_ the content. Previous documents aren't superseded, they're siblings in a series.

### Other Patterns

The protocol cannot distinguish these patterns — the operation schema is identical in both cases. The difference is a reading convention, signaled by the `$schema` of the documents. Future content types could define event-sourcing patterns, append-only collections, or interpretations not yet imagined.

---

## Custom Schemas

Any implementation can define custom document schemas following the same pattern — a JSON Schema with a `$schema` const field pointing to a unique URI. The protocol will commit to the document via CID regardless of what's inside. The standard schemas are conventions, not constraints.

Custom schema URIs should use a namespace you control (e.g., `https://schemas.example.com/my-type/v1`) to avoid collisions with the standard library.
