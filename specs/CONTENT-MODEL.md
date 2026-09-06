# DFOS Content Model

Standard content schemas for documents committed to DFOS content chains. JSON Schema (draft 2020-12) definitions for content objects committed by CID. These schemas are the vocabulary DFOS uses internally and the starting vocabulary for applications built on the protocol.

[Protocol Specification](https://protocol.dfos.com/spec) · [schemas.dfos.com](https://schemas.dfos.com) · [Source](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/schemas)

---

## Encoding

A content object is committed to a content chain by CID, derived from the canonical dag-cbor encoding of the object itself:

```
documentCID = CID(dagCborCanonicalEncode(contentObject))
```

The protocol commits to content by hash and never inspects what is inside, with one constraint on the encoding: every number in a content object MUST be an integer in JSON's safe range (`[-(2^53 - 1), 2^53 - 1]`), with no fractions, no `NaN`, and no `±Infinity`. Encode fractional or larger-magnitude values as strings. This keeps the content CID byte-identical across implementations (see Number Encoding in the [protocol spec](https://protocol.dfos.com/spec)).

Every document in this vocabulary carries a `$schema` property naming its content type.

```json
{
  "$schema": "https://schemas.dfos.com/post/v1",
  "format": "short-post",
  "body": "Hello world."
}
```

Because `$schema` is part of the content object, it is behind the `documentCID` and is cryptographically committed in the content chain. A verifier resolves the document, reads `$schema`, and validates against that schema. Documents are self-describing. `$schema` is a convention of this vocabulary rather than a protocol rule: an operation committing a document without one is a valid operation, and this vocabulary does not describe that document.

---

## Schema Versions

Schemas are versioned in the URI path (`/post/v1`, `/post/v2`).

- **Additive within a version.** New optional fields are added to a published version at any time, and documents already committed against that version stay valid.
- **Breaking changes take a new version.** Removing a field, changing a type, or adding a required field is a new version URI, never an in-place edit.
- **Implementations declare which versions they understand.** An application accepts `post/v1` and `post/v2` at once, or only `post/v1`.

Two immutabilities, deliberately distinct. A committed **document** is CID-addressed and byte-immutable: a specific document never changes, and an edit is a new document with a new CID appended to the content chain. A published **schema version** evolves only additively: adding optional fields to `post/v1` never invalidates documents already committed against it.

A document's own field values are fixed at the operation that set them.

---

## Documents

Schema files live in [`schemas/`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/schemas) in the protocol package. Each is a standalone JSON Schema (draft 2020-12) definition, served at `https://schemas.dfos.com`.

### Post (`https://schemas.dfos.com/post/v1`)

The primary content type. Covers short posts and long-form posts via the `format` discriminator. Comments and replies are not `post/v1` surface: threaded content needs signed target linkage (see [Intra-chain references](#intra-chain-references-targetoperationcid)) and takes its own schema rather than additional `format` values.

| Field         | Type     | Required | Description                                                                                                                                                          |
| ------------- | -------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `$schema`     | string   | yes      | `"https://schemas.dfos.com/post/v1"`                                                                                                                                 |
| `format`      | enum     | yes      | `"short-post"` or `"long-post"`. Set at creation and not changed by later revisions                                                                                  |
| `publishedAt` | string   | no       | Asserted original publication time, an [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) `date-time` string per the published schema's `format`. See **Two clocks** |
| `title`       | string   | no       | Post title, typically for long-post format                                                                                                                           |
| `body`        | string   | no       | Post body content, markdown (CommonMark) text                                                                                                                        |
| `cover`       | media    | no       | Cover image as a [media object](#media-object)                                                                                                                       |
| `attachments` | media[]  | no       | Attached media as [media objects](#media-object)                                                                                                                     |
| `credits`     | credit[] | no       | Ordered authorship credits. See [Credits](#credits)                                                                                                                  |

`post/v1` is a closed shape (`additionalProperties: false`).

**Two clocks.** A post and its operations carry two distinct times. The operation's `createdAt` records when the operation was signed and is protocol state. `publishedAt` records when the content was originally published, as asserted inside the signed document: a chain anchored long after the fact carries the original publication time here while its genesis operation records the later anchoring time. `publishedAt` is assertion-tier, like `credits`: the protocol verifies the signer, never the claim. A later revision MAY change it, and the operation log preserves every previously committed value, so re-dating is auditable. Operation `createdAt` is never backdated to encode publication time.

**No topics.** `post/v1` defines no topic or category field. Topic labels are mutable organizational taxonomy, and a signed CID-committed document that embedded them would turn every taxonomy rename into a corpus-wide revision wave. Organization lives in [index](#index-httpsschemasdfoscomindexv1) entries and host-side projections, which are mutable and cheap to rebuild.

**Body to attachment binding.** A post body MAY embed `attachment://<id>` refs inline, for example an image reference inside markdown. Each inline ref SHOULD have a corresponding entry in `attachments` whose `uri` is that same ref. The body names media; `attachments` carries the verifiable reference.

The example post documents in the [protocol spec](https://protocol.dfos.com/spec)'s test-vector section, and the matching `examples/` chain fixtures, carry an older draft credit shape and do not validate against `post/v1`. Those bytes are the input to published hashes, and a document CID from them appears verbatim in the spec's reference-artifact tables, so they are read as fixtures for the signing and verification rules they demonstrate, never as content-model examples. A drift guard in the protocol test suite pins the fixtures and the spec vectors to each other.

### Profile (`https://schemas.dfos.com/profile/v1`)

The displayable identity for any agent, person, group, or space.

| Field         | Type   | Required | Description                                                    |
| ------------- | ------ | -------- | -------------------------------------------------------------- |
| `$schema`     | string | yes      | `"https://schemas.dfos.com/profile/v1"`                        |
| `name`        | string | no       | Display name                                                   |
| `description` | string | no       | Short bio or description                                       |
| `avatar`      | media  | no       | Avatar image as a [media object](#media-object)                |
| `links`       | link[] | no       | External links, up to 20 `{ uri, label?, description? }` items |

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

The credited party's profile is authoritative for its current display name.

### Index (`https://schemas.dfos.com/index/v1`)

An **index chain** is a curated map of content refs: a space's catalog, an author's works, a reading list, a set of pinned items. It is an LWW-Map folded via the [canonical fold](#the-canonical-fold). Each operation commits an `index/v1` document carrying deltas, and the resolved index is the fold over the operations in the log.

An index document carries an **array of deltas**. A single append sets or removes several entries at once, and the index accumulates through many small delta documents instead of re-committing a whole catalog each time. The deltas live in the document blob, which the operation-size cap does not measure: content operations commit only the `documentCID`. The protocol does not bound document blob size; any blob limit is gateway or application policy.

| Field     | Type    | Required | Description                                  |
| --------- | ------- | -------- | -------------------------------------------- |
| `$schema` | string  | yes      | `"https://schemas.dfos.com/index/v1"`        |
| `deltas`  | delta[] | yes      | Ordered deltas contributed by this operation |

Each delta is one of two shapes:

| Delta                              | Effect                                                                                                          |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `{ "op": "set", "key", "value"? }` | Add or replace entry `key`. `value` is optional metadata; omit it (or use `{}`) for a pure set-membership entry |
| `{ "op": "remove", "key" }`        | Drop entry `key`                                                                                                |

- **`key`** is a **content ref**, a 31-char content chain id or a CID, consistent with how refs are named elsewhere in this model.
- **`value`** is an optional entry-metadata object `{ label?, order?, … }`. `label` is a display string; `order` is an integer ordering hint (integers only, per the encoding rule above). A pure set-membership index uses the degenerate `value: {}`. Unknown metadata fields are preserved.

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

**Fold semantics.** The resolved index is the [canonical fold](#the-canonical-fold) as an LWW-Map:

1. **Linearize** the operations in the log, all branches, into the fold order.
2. **Flatten** each `index/v1` document's `deltas` array in array order, producing one ordered delta stream.
3. **Fold** the stream: `set` writes `key → value`, `remove` deletes `key`. The **last delta touching a key wins** at its linearized position, so a `remove` supersedes an earlier `set`, and a later `set` re-adds a removed key.

**Unknown delta shapes are skipped deterministically.** A delta whose `op` is neither `set` nor `remove`, whose `key` is not a string, or whose `set` `value` is present but not an object is ignored, not an error. Every reader skips the same deltas, so the vocabulary grows without forking existing readers. The published JSON Schema mirrors this: schema validity covers the known vocabulary constraints only (a delta needs an object shape and a string `op`; a `set` or `remove` carries a string `key`), and validators MUST NOT reject documents carrying additional delta shapes.

Because the fold is branch-inclusive and last-applied-wins, an index **converges**: any ingest order of the same operation set folds to the same map, and two clients that concurrently append entries both keep their writes. If the chain's selected head is delete-terminal, the index is deleted and the fold is moot (see [Delete-terminality](#delete-terminality)).

The `index/v1` fold is `foldIndexV1(ops)` in [`@metalabel/dfos-protocol/fold`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/src/fold). See [`schemas/index.v1.json`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/schemas/index.v1.json) and the worked chain in [`examples/index/`](https://github.com/metalabel/dfos/tree/main/examples/index).

### Media object

The standard representation of a reference to external media bytes. Defined once here; schemas that carry media reference this shape (the `profile/v1` `avatar` field, and the `post/v1` `cover` and `attachments` fields).

```json
{
  "uri": "attachment://media_abc123",
  "cid": "bafkreibovzpnn2y6dquvxhidhx64hg7smduemox7drjs4vprjhlbmivfli",
  "href": "https://cdn.example.com/media/abc123.jpg"
}
```

| Field  | Type   | Required | Description                                                                                     |
| ------ | ------ | -------- | ----------------------------------------------------------------------------------------------- |
| `uri`  | string | yes      | Canonical reference to the media: an `attachment://<id>` ref or any other URI. Always present   |
| `cid`  | string | no       | Content commitment: CIDv1, raw codec (`0x55`), sha2-256, base32 lowercase, over the media bytes |
| `href` | string | no       | Resolution hint: a plain URL where the bytes may currently be fetched. Non-normative            |

- **`uri`** (REQUIRED) is the stable, canonical name of the media. It is an `attachment://<id>` ref or any other URI scheme (`ipfs://`, `https://`, …). The `uri` identifies; it does not promise integrity.
- **`cid`** (OPTIONAL) is a verifiable commitment to the bytes: a CIDv1 with the **raw codec (`0x55`)** and **sha2-256**, encoded base32 lowercase (a 59-char `bafkrei…` string), computed over the media bytes **exactly as stored and served**. Media bytes are opaque binary, so a consumer verifies by hashing the fetched bytes directly; unlike document blobs, no re-canonicalization is involved. `cid` is optional because some media has no cid computed for it. When `cid` is present, a consumer SHOULD verify the bytes it receives against it.
- **`href`** (OPTIONAL) is an implementation-dependent fallback: a plain URL where the bytes may currently be fetched. It is non-normative, carries no integrity promise, and MAY rot. Consumers resolve `uri` and verify with `cid`; `href` is a hint, never the reference.

**The `attachment://` ref is opaque and host-scoped.** `<id>` is an identifier meaningful to the host that committed the document, and nothing about the bytes is derivable from the ref itself. Resolution, turning the ref into fetchable bytes, is host- or gateway-dependent: a [document-gateway](https://protocol.dfos.com/web-relay#content-plane--document-gateway) deployment resolves it out of protocol, for example via a signed-CDN API. **The ref carries no integrity. `cid` is the only integrity commitment a media object makes**, and a media object with no `cid` gives a consumer nothing to check the bytes against.

A media object is the referential case: a document is either _terminal_, where the `{ $schema, … }` blob is the content, or _referential_, where it describes how to fetch external bytes. Resolving a media object, the delivery of the actual media bytes, is outside the protocol. The document gateway serves the document that _contains_ the media object as opaque bytes and never dereferences the pointer. There is no media gateway: media lives at the application and delivery layer, bound to the proof plane only by the signed reference, with `cid` as the optional content hash that lets a consumer verify the bytes it receives.

### Reference content stream (`https://schemas.dfos.com/reference-content-stream/v1`)

The canonical example of the [stream](#stream) interpretation. Each operation appends a new entry to the sequence rather than replacing the previous one. This is a reference schema, not one of the hosted standard schemas, and its `$id` carries the `reference-content-stream/v1` URI to mark it as such.

| Field                | Type   | Required    | Description                                                                    |
| -------------------- | ------ | ----------- | ------------------------------------------------------------------------------ |
| `$schema`            | string | yes         | `"https://schemas.dfos.com/reference-content-stream/v1"`                       |
| `action`             | enum   | yes         | `"create-item"`, `"update-item"`, `"delete-item"`, `"react"`, `"unreact"`      |
| `createdByDID`       | string | yes         | DID of the content author, distinct from the operation signer                  |
| `title`              | string | conditional | REQUIRED for `create-item`. Optional on `update-item` and `delete-item`        |
| `body`               | string | no          | Entry body content, carried on `create-item`, `update-item`, and `delete-item` |
| `targetOperationCID` | string | conditional | REQUIRED for `update-item`, `delete-item`, `react`, and `unreact`              |
| `reaction`           | string | conditional | REQUIRED for `react` and `unreact`                                             |

```json
{
  "$schema": "https://schemas.dfos.com/reference-content-stream/v1",
  "action": "create-item",
  "createdByDID": "did:dfos:alice",
  "title": "Hello world",
  "body": "My first post."
}
```

See [`schemas/reference-content-stream.v1.json`](https://github.com/metalabel/dfos/blob/main/schemas/reference-content-stream.v1.json) and the worked chain in [`examples/reference-content-stream/`](https://github.com/metalabel/dfos/tree/main/examples/reference-content-stream).

---

## Credits

Who **signed** a thing and who **made** it are different claims. The protocol verifies signers: the `kid` DID in every operation's JWS header is cryptographic fact. Authorship is a document-layer statement, and this vocabulary expresses it in two tiers.

A `credits[]` entry is the assertion tier: the identity that signed the revision asserts these credits, and nothing more is claimed. Consumers SHOULD display it as an assertion of the signer, not a verified fact. This is often exactly right, because a custodial host or space signs content on behalf of the people it credits. An entry that stops there is **unclaimed**, the ordinary case.

A credited DID upgrades its credit to the proof tier by signing the credit itself: a **credit claim**, a small standalone JWS asserting `(contentId, did, role)`, carried in the entry's `claim` field. Both the entry shape and the claim payload are published as [`credit-claim/v1`](https://schemas.dfos.com/credit-claim/v1).

**Claims travel inside document bytes.** A claim is not an operation and is not gossiped. Relays are not credit-claim aware: a relay sees document blobs, stores and serves them as opaque bytes, and applies exactly the access control it already applies to those bytes. A credit on gated content is therefore exactly as visible as that content, and attribution never becomes more public than the work it attributes. The verifier is always the consumer that reads the document.

### The `credits[]` entry

```json
"credits": [
  {
    "did": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
    "role": "photography",
    "name": "Alice",
    "claim": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNyZWRpdC1jbGFpbSIsImtpZCI6..."
  },
  { "did": "did:dfos:nzkf838efr424433rn2rzkdv8h7t9ae", "role": "author" }
]
```

| Field   | Type   | Required | Description                                                                      |
| ------- | ------ | -------- | -------------------------------------------------------------------------------- |
| `did`   | string | yes      | The credited identity                                                            |
| `role`  | string | no       | The credited role, open vocabulary, byte-exact. REQUIRED when `claim` is present |
| `name`  | string | no       | Display name at time of publication, a convenience, never authoritative          |
| `claim` | string | no       | A `did:dfos:credit-claim` JWS binding this entry                                 |

- Array **order is display order**, and the **first entry is the primary author**.
- **`name` is a cached display string, not a source of truth.** It records what the document said when it was signed, so a document renders without resolving every credited DID. A consumer that resolves profiles SHOULD prefer the profile name. `name` is never compared during verification.
- **`role` is REQUIRED whenever `claim` is present**, because `role` is a component of the bind. The published schema encodes this as `dependentRequired: { claim: ["role"] }`, and `role` has `minLength: 1`, so an empty role is malformed rather than a wildcard.
- Omit `credits` entirely for unattributed content. An empty entry list and an absent list mean the same thing.

The entry is a closed shape (`additionalProperties: false`).

### The credit claim envelope

A credit claim is a JWS in the same envelope family as credentials and revocations, with its own `typ`.

```json
{
  "alg": "EdDSA",
  "typ": "did:dfos:credit-claim",
  "kid": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr#key_r9ev34fvc23z999veaaft83nn29zvhe",
  "cid": "bafyrei..."
}
```

| Field | Value                     | Description                                         |
| ----- | ------------------------- | --------------------------------------------------- |
| `alg` | `"EdDSA"`                 | Ed25519 signature algorithm                         |
| `typ` | `"did:dfos:credit-claim"` | Protocol-specific type discriminator                |
| `kid` | DID URL                   | `did:dfos:<id>#<keyId>`, identifies the signing key |
| `cid` | CID string                | Content address of the payload                      |

The `kid` MUST be a DID URL containing `#`, and its DID portion MUST equal the payload's `did`. This is the rule that makes a claim self-asserted: **only the claimant can claim its own credit.** A third party signing "Alice is the photographer" produces an invalid claim, not a weaker one; that statement already has a home in `credits[]`, where it reads as the signer's assertion. Any key role signs a claim.

```json
{
  "version": 1,
  "type": "credit-claim",
  "contentId": "cv7n8vkvr64cctf3294h9k4eanhff8z",
  "did": "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr",
  "role": "photography",
  "createdAt": "2026-03-07T00:00:00.000Z"
}
```

| Field             | Type             | Required | Description                                                                                            |
| ----------------- | ---------------- | -------- | ------------------------------------------------------------------------------------------------------ |
| `version`         | `1`              | yes      | Schema version (literal `1`)                                                                           |
| `type`            | `"credit-claim"` | yes      | Literal discriminator                                                                                  |
| `contentId`       | string           | yes      | The 31-char content chain id this claim binds to, the binder                                           |
| `did`             | string           | yes      | The claimant DID. MUST equal the `kid`'s DID                                                           |
| `role`            | string           | yes      | The claimed role, open vocabulary, compared byte-exact                                                 |
| `createdAt`       | string           | yes      | The [timestamp grammar](https://protocol.dfos.com/spec#timestamp-grammar) (millisecond precision, UTC) |
| `asOfDocumentCID` | CID              | no       | Optional pinned document state                                                                         |

Unknown top-level fields are preserved and ignored, per the protocol's MUST-ignore-unknown rule. The CID commits to the exact bytes, so a verifier that stripped unknown keys would fail its own CID check.

**`role` is an open vocabulary** compared by exact, case-sensitive byte equality. `"photography"`, `"editor"`, `"mixed by"`, and `"翻訳"` are all legal, and `"Author"` is a different role from `"author"`. No normalization of any kind is applied: not case folding, not Unicode normalization, not whitespace trimming. Applications that want a controlled vocabulary enforce it at their own layer.

**`createdAt` is provenance metadata.** It records when the claimant signed. Verification never compares it against a clock, and a claim has no expiry. **Signers MUST normalize `createdAt` to whole seconds**, so the millisecond component of a signed claim is always `000`. This binds signers, not verifiers: a verifier accepts any conforming millisecond-precision timestamp. A caller-supplied timestamp is normalized rather than passed through, so re-deriving a claim from the same inputs lands on the same CID on every implementation.

**`asOfDocumentCID`** is an optional stronger statement: _I credit myself on the chain, and this is the document state I was looking at._ It is not part of the bind, and consumers that ignore it are fully conformant. Omitting it is the default and is CID-neutral: an absent `asOfDocumentCID` encodes identically to a claim that never had the field. When the key is present it MUST be a non-empty string.

**CID derivation** is identical to every other protocol object:

```
dagCborCanonicalEncode(payload) -> SHA-256 -> CIDv1 (dag-cbor + SHA-256)
```

The derived CID is embedded in the protected header as `cid`, and verification re-derives it from the parsed payload and compares. Mismatch is a verification failure. As everywhere else in the protocol, dag-cbor is used only for CID derivation; the JWS body carries JSON.

| Bound                  | Value          | Applies to                 |
| ---------------------- | -------------- | -------------------------- |
| credit claim JWS token | **4096 bytes** | the serialized claim token |

Verifiers MUST reject a claim whose serialized JWS token exceeds 4096 bytes, checked **before any decode**. This is the claim's single aggregate byte arbiter: `role` and `contentId` carry no separate per-field length caps. The cap is tight because claims travel inside document bytes, and a document crediting twelve collaborators carries twelve tokens in its blob. This bound is validity-determining and MUST be identical across implementations.

### The bind

The bind is the exact match of `(contentId, did, role)` between the entry plaintext and the signed claim payload:

| Component   | Entry side                     | Claim side          | Comparison                          |
| ----------- | ------------------------------ | ------------------- | ----------------------------------- |
| `contentId` | the chain hosting the document | `payload.contentId` | exact string equality               |
| `did`       | `entry.did`                    | `payload.did`       | exact string equality               |
| `role`      | `entry.role`                   | `payload.role`      | exact, case-sensitive byte equality |

All three MUST match. Nothing is normalized, folded, or coerced on either side. A claim that verifies cryptographically but names a different role than the entry it sits in is a failed bind, and the entry is **invalid**.

An **absent** `entry.role` is a mismatch, not a wildcard. `payload.role` is always present and non-empty, so a claim-bearing entry without a `role` can never satisfy the third row, and verifiers MUST resolve it **invalid**. It is not unclaimed: a `claim` is present, so the entry is making a verifiable assertion and failing it.

What the bind establishes, when it holds, is narrow: **the document's signer and the claimant independently assert the same credit.** It does not establish that the credit is true. What it rules out is a signer attributing work to someone who never agreed to be attributed, and a claimant attaching itself to work no one credited it for. Neither party can produce a claimed entry alone.

The claim binds the chain's `contentId`, not a document CID and not the chain head CID. Binding the chain is what lets a claim survive every subsequent revision verbatim, and naming the chain in the signed bytes is what confines a claim to the one chain it was made about: a claim lifted into another chain's document fails the bind and resolves **invalid**.

### Verification states

Every `credits[]` entry resolves to exactly one of four states. A consumer SHOULD surface the distinction; collapsing all four into "credited" throws away the mechanism.

| State            | Condition                                                                             | How to read it                                                         |
| ---------------- | ------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| **claimed**      | `claim` present, verifies, and all three bind components match                        | Signer and claimant both assert this credit                            |
| **unclaimed**    | No `claim` field                                                                      | The signer asserts this credit; the claimant has not countersigned it  |
| **invalid**      | `claim` present but verification or the bind fails                                    | Something is wrong. Do not present this as either claimed or unclaimed |
| **unverifiable** | `claim` present and well-formed, but the claimant's identity chain cannot be resolved | Verdict unknown. Insufficient information, not a failure               |

**unclaimed is legal and ordinary.** It is the default for most content: the credited party may hold no keys, or may be a person credited by a host that signs on their behalf. A consumer MUST NOT render unclaimed as suspicious. The only thing an unclaimed entry lacks is the second signature.

**invalid is different in kind** and SHOULD be surfaced as such. Rendering it as unclaimed launders a failure into the ordinary case.

**unverifiable is honest ignorance.** A transport failure is unverifiable, never invalid: an outage is not evidence about a signature. Consumers SHOULD NOT cache an unverifiable verdict as invalid.

**The two failure verdicts MUST be machine-distinguishable.** A verifier that signals every failure as one undifferentiated error forces consumers to string-match diagnostic prose. Implementations MUST expose the verdict structurally: the reference implementations carry it as a field on a typed error (TypeScript: `CreditClaimVerifyError.reason`) and as `errors.Is`-able sentinels (Go: `ErrCreditClaimInvalid` and `ErrCreditClaimUnverifiable`). A failure whose cause cannot be attributed, such as an unexpected fault inside the verifier itself, MUST resolve to **unverifiable**.

### Verification algorithm

To verify one `credits[]` entry, given the entry, the `contentId` of the chain whose document contains it, and a way to resolve identities:

1. **No `claim` field?** The entry is **unclaimed**. Stop.
2. **Size.** If the `claim` token exceeds **4096 bytes**, the entry is **invalid**. Check this before any decode.
3. **Decode** the JWS. Failure to decode resolves **invalid**.
4. **`typ`.** MUST be `did:dfos:credit-claim`. Anything else resolves **invalid**. Another envelope type from this family is not a credit claim, no matter how well it verifies.
5. **Payload schema.** `version` MUST be `1`, `type` MUST be `credit-claim`, `contentId` MUST be a 31-char content chain id, `did` MUST be non-empty and carry the `did:` prefix, `role` MUST be non-empty, `createdAt` MUST parse per the [timestamp grammar](https://protocol.dfos.com/spec#timestamp-grammar), and `asOfDocumentCID`, if the key is PRESENT, MUST be a non-empty string. Otherwise **invalid**. The `did:` check is a prefix check, not full `did:dfos` validation: a claimant is not required to be a `did:dfos` identifier.
6. **`kid` to `did`.** The `kid`'s DID portion MUST equal `payload.did`. Otherwise **invalid**.
7. **Resolve the claimant identity** named by `payload.did` at the [basis time](https://protocol.dfos.com/spec#time-basis) and find the key named by the `kid` fragment. Unresolvable identity resolves **unverifiable**. Resolvable identity with no such key resolves **invalid**.
8. **Signature.** Verify the JWS under that key. Failure resolves **invalid**.
9. **CID integrity.** Re-derive the payload CID and compare against the header `cid`. A missing or mismatched `cid` resolves **invalid**.
10. **The bind.** `payload.contentId` MUST equal the hosting chain's `contentId`; `payload.did` MUST equal `entry.did`; `payload.role` MUST equal `entry.role` byte-for-byte. Any mismatch resolves **invalid**.
11. Otherwise the entry is **claimed**.

Step 10 is the step implementations skip. A claim that passes steps 1 to 9 is a valid signed statement by someone about something; verifying it without binding it to the entry that hosts it verifies the wrong proposition. **An empty expected `contentId` MUST be an error, never a skip**, because the empty string is what an unhydrated database column or a failed parse produces. Implementations SHOULD expose a single call that takes the whole entry plus the hosting `contentId` and returns one of the four states; the reference implementations do (`verifyCreditEntry` and `VerifyCreditEntry`), and it is the call consumers reach for.

The algorithm carries no expiry or freshness check, no revocation lookup, no relay query, and no identity-deletion gate. Verification MUST NOT consult the claimant's `isDeleted` state: a claim signed by an identity that has since been tombstoned still verifies, and its entry is still **claimed**. Attribution is history; authorization is standing. Deletion ends an identity's ability to act and does not rewrite what it did. A claim's verifiability depends on the claimant's identity chain remaining resolvable, which is not the same as the identity remaining live: a resolver that returns tombstoned identities with their keys lets old credits keep verifying, and one that returns nothing for a deleted DID yields **unverifiable**.

### Claim stability and renunciation

A given `(contentId, did, role)` triple SHOULD be signed once and the resulting token reused verbatim wherever that credit appears. Re-signing produces a byte-different claim, which changes the embedding document's CID, which appends a chain operation. Store the token; do not re-mint it.

The `did:dfos:credit-renounce` type is **reserved and undefined**. There is no renunciation mechanism, and implementations MUST NOT emit or accept anything under that `typ`. What a claimant does without any new primitive is stop claiming: an entry whose `claim` is dropped on the next revision is **unclaimed**, an ordinary state, and the operation log preserves the earlier revision, so nothing is falsified.

A relay MAY serve a credits index as an optional profile: a `(contentId, did, role)` projection derived exclusively from the current head documents of publicly readable content, where rows are assertion-tier discovery hints that restate what a public document says, never authorization inputs and never a verdict on a claim's validity.

---

## Chain Interpretation

A content chain is a signed append-only log. The protocol enforces ordering, authorship, and integrity. It does not prescribe what the chain _means_. How an application interprets a chain depends on the content types committed to it.

### Living document

The chain represents a single evolving thing: a profile, a post, a policy document. Each operation is a **revision**. The resolved state is the latest `documentCID`, and history is audit trail. This is the default interpretation for the standard schemas. Edit lineage is tracked via `baseDocumentCID` on the content operation payload, so each new operation references the document CID it replaced.

### Stream

The chain represents a sequence: a feed, a journal, a log. Each operation is a discrete emission, not a revision. There is no single current state; the chain is the content. The resolved content is the full ordered list of documents, and applications read a stream by walking the chain log and collecting each operation's `documentCID`.

### Event fold

The chain represents a sequence of events that fold into a computed state. Each operation contributes a delta or event, and the resolved state is the result of replaying them in order. The `$schema` of the documents defines the event types and fold semantics. The chain log is the source of truth; the projected state is derived.

### Projection per schema

| Schema       | Projection                                                                     |
| ------------ | ------------------------------------------------------------------------------ |
| `post/v1`    | Living document. Head `documentCID` is the current post; history is edit trail |
| `profile/v1` | Living document. Head `documentCID` is the current profile                     |
| `index/v1`   | Canonical fold. LWW-Map folded over the operations in the log, every branch    |

Stream and event-fold schemas define their own projection rules in their schema documentation. The protocol does not enforce projections; these are reading conventions that applications agree on.

### Intra-chain references (`targetOperationCID`)

Content documents reference specific operations within their own chain or other chains via `targetOperationCID`: a reply naming the operation it answers, a reaction naming the operation it reacts to, an annotation naming a specific version of another chain's content.

`targetOperationCID` is a content field, inside the document committed by CID, not an operation field. The protocol commits to it via `documentCID` and does not interpret or validate it. Applications resolve the reference by looking up the target operation on a relay.

---

## The Canonical Fold

The [event fold](#event-fold) interpretation says a chain's resolved state is the result of replaying its operations in order. The **canonical fold** makes that order precise: a deterministic total order over the operations a reader holds, all branches rather than only the selected-head branch, so that any implementation holding the same set of operations computes the same folded state. Which operations you hold is a choice of relay.

### Linearization

The fold order is the relay's head-selection comparator generalized from picking one tip to ordering the whole log. Head selection prefers, among the chain's tips, the operation with the **highest `createdAt`**, breaking ties by the **highest operation CID**, both compared byte-wise over the multibase CID string and the fixed-width ASCII [timestamp-grammar](https://protocol.dfos.com/spec#timestamp-grammar) string. It is a code-point comparison, never locale collation, so every implementation agrees.

The linearization lays that same preference out in full, **ascending**, so the operation head selection would prefer sorts **last**:

1. **`createdAt` ascending** (byte-wise string comparison).
2. **Operation CID ascending** as tiebreak (byte-wise multibase string).

The two orderings are exact reverses, so they never disagree: the last operation of a full-log linearization is exactly the operation head selection picks. This holds structurally, because each write's `createdAt` exceeds its predecessor's, so the operation with the greatest `createdAt` is always a tip. Sorting the head-preferred operation last is what makes the fold last-applied-wins.

Head selection and the fold call the same exported comparison function, [`compareHeadPreference`](https://github.com/metalabel/dfos/blob/main/packages/dfos-protocol/src/fold/linearize.ts), so the two cannot drift.

### Branch-inclusive

Folding every branch is a deliberate divergence from the head-selection reading used by living-document schemas. Head selection answers "which single document is current", and a losing fork is simply not the head. The fold answers "what is the merged state of this chain", where concurrent forks converge rather than compete, because dropping a branch would silently lose the writes on it. Both readings coexist on the same wire format: a register chain reads its head, a fold chain folds its whole log.

The fold operates on already-verified operations and applies no wall clock of its own. The future-timestamp bound is enforced at ingest by the relay, and a caller folding operations it verified itself carries that obligation.

### Delete-terminality

The fold assumes a live chain. If the selected head branch is delete-terminal, meaning the highest-ranked tip is a `delete`, the chain is deleted, resolution reports it as such, and the fold is moot: a consumer checks `isDeleted` from chain verification first and does not fold a deleted chain. A `delete` on a non-head branch is another superseded operation and does not delete the chain. Per-branch delete semantics are a content-chain notion; identity chains answer deletion with the explicit `restore` operation instead.

### Library

The fold is a set of pure functions over already-verified operations, published at [`@metalabel/dfos-protocol/fold`](https://github.com/metalabel/dfos/tree/main/packages/dfos-protocol/src/fold), with no cryptographic or network dependencies:

- `linearize(ops)` is the deterministic total order above.
- `foldLwwMap(deltas)` is the generic LWW-Map fold over an ordered delta stream.
- `foldIndexV1(ops)` is the [`index/v1`](#index-httpsschemasdfoscomindexv1) fold built on the two.

---

## Custom Schemas

Any implementation defines custom document schemas following the same pattern: a JSON Schema with a `$schema` const field pointing to a unique URI. The protocol commits to the document via CID regardless of what is inside. The standard schemas are conventions, not constraints.

Custom schema URIs use a namespace you control, for example `https://schemas.example.com/my-type/v1`, to avoid collisions with the standard library.
