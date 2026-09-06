# Reference content stream

The canonical example of the
[stream](https://protocol.dfos.com/content-model#stream) interpretation. Each
operation appends a new entry to the sequence rather than replacing the previous
one. This is a reference schema, not one of the hosted standard schemas, and its
`$id` carries the `reference-content-stream/v1` URI to mark it as such.

The JSON Schema is
[`schemas/reference-content-stream.v1.json`](../../schemas/reference-content-stream.v1.json).

## Document fields

| Field                | Type   | Required    | Description                                                                    |
| -------------------- | ------ | ----------- | ------------------------------------------------------------------------------ |
| `$schema`            | string | yes         | `"https://schemas.dfos.com/reference-content-stream/v1"`                       |
| `action`             | enum   | yes         | `"create-item"`, `"update-item"`, `"delete-item"`, `"react"`, `"unreact"`      |
| `createdByDID`       | string | yes         | DID of the content author, distinct from the operation signer                  |
| `title`              | string | conditional | REQUIRED for `create-item`. Optional on `update-item` and `delete-item`        |
| `body`               | string | no          | Entry body content, carried on `create-item`, `update-item`, and `delete-item` |
| `targetOperationCID` | string | conditional | REQUIRED for `update-item`, `delete-item`, `react`, and `unreact`              |
| `reaction`           | string | conditional | REQUIRED for `react` and `unreact`                                             |

`createdByDID` is a content-layer convention. It names the author, who is not
necessarily the identity that signed the operation: a delegate or a device key
often signs on the author's behalf.

## Projection rules

State is the fold over the operations in chain sequence:

1. `create-item` adds an item to the set, keyed by the operation CID
2. `update-item` replaces the fields of the item at `targetOperationCID`
3. `delete-item` removes the item at `targetOperationCID` and its reactions
4. `react` adds `{ reaction, createdByDID }` to the target's reaction set
5. `unreact` removes the matching reaction from the target's reaction set

## The example chain

`chain.json` is one content chain of six operations. Alice, bob, and carol are
real `did:dfos` identities minted from fixed seeds. Alice created the chain, so
she writes to it directly; bob and carol each hold a `chain:*` write credential
alice issued, carried in the `authorization` field of the operations they sign.
Every `operationCID`, `documentCID`, credential, and `jws` in the file is real
and verifies.

1. `create-item`, alice creates "Hello world"
2. `create-item`, bob creates "Second item"
3. `react`, carol reacts with a thumbs-up to operation 1
4. `update-item`, alice edits operation 1 to "Hello world (edited)"
5. `react`, alice reacts with fire to operation 2
6. `delete-item`, bob deletes operation 2

The chain operation type is `create` for the genesis and `update` for the other
five. `delete-item` is a document action, not a chain `delete`: the chain stays
live and the item leaves the projection.

`projected-state.json` is the state after folding all six. One item survives,
carrying carol's thumbs-up. Item 2 is deleted, and alice's fire reaction on it
is dropped with it.

## What it is for

- testing content chain write-through
- developing relay document endpoints
- validating credential-based access control
- building projection and materialization logic
- cross-language implementation testing

## Regenerate

`mint.ts` mints both files from the fixed seeds it names and verifies the chain
with `verifyContentChain` before writing. It is deterministic: two runs produce
byte-identical files.

```
pnpm --filter @metalabel/dfos-protocol exec tsx ../../examples/reference-content-stream/mint.ts
```
