# Reference Content Stream — Worked Example

This directory contains a worked example of the `reference-content-stream/v1` schema — a toy content model for developing and testing content stream patterns against DFOS content chains.

## Schema

`reference-content-stream/v1` is a discriminated union of five actions:

| Action | Required fields | Description |
|--------|----------------|-------------|
| `create-item` | `title` | Create a new item with optional `body` |
| `update-item` | `targetOperationCID`, `title` | Update an existing item |
| `delete-item` | `targetOperationCID` | Delete an existing item |
| `react` | `targetOperationCID`, `reaction` | Add a reaction to an operation |
| `unreact` | `targetOperationCID`, `reaction` | Remove a reaction from an operation |

Every document also carries `createdByDID` — the DID of the content author. This is a content-layer convention, distinct from the operation signer (who may be a delegate or device key).

## Projection Rules

State = fold over operations in chain sequence:

1. **create-item** — add to item set, keyed by operation CID
2. **update-item** — replace item at `targetOperationCID` with new fields
3. **delete-item** — remove item at `targetOperationCID` + remove associated reactions
4. **react** — add `{ reaction, createdByDID }` to target's reaction set
5. **unreact** — remove matching reaction from target's reaction set

## Example Chain

`chain.json` contains 6 operations demonstrating the full lifecycle:

1. `create-item` — alice creates "Hello world"
2. `create-item` — bob creates "Second item"
3. `react` — carol reacts with a thumbs-up to op 1
4. `update-item` — alice edits op 1 to "Hello world (edited)"
5. `react` — alice reacts with fire to op 2
6. `delete-item` — bob deletes op 2

## Projected State

After folding all 6 operations:

- **Items**: `[{ title: "Hello world (edited)", op: 4 }]` — item 2 was deleted
- **Reactions**: `[{ target: op1, reaction: "thumbsup", by: carol }]` — alice's reaction on the deleted item was dropped

See `projected-state.json` for the expected state.

## Purpose

This schema is intentionally simple — it's a development tool, not a production content model. Use it for:

- Testing content chain write-through
- Developing relay document endpoints
- Validating credential-based access control
- Building projection/materialization logic
- Cross-language implementation testing
