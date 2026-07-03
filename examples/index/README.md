# Index — Worked Example

This directory contains a worked example of the `index/v1` schema — an **index chain**, which is an LWW-Map folded via the [canonical fold](https://protocol.dfos.com/content-model#canonical-fold).

## Schema

`index/v1` documents carry an array of deltas over content-ref keys:

| Delta                        | Effect                                                                                          |
| ---------------------------- | ----------------------------------------------------------------------------------------------- |
| `{ op: "set", key, value? }` | Add or replace entry `key`. `value` is optional metadata; omitted or `{}` = pure set-membership |
| `{ op: "remove", key }`      | Drop entry `key`                                                                                |

`key` is a **content ref** — a 31-char content chain id or a CID (shown here as illustrative placeholders). Unknown delta shapes are **skipped deterministically** (forward compat).

See [`packages/dfos-protocol/schemas/index.v1.json`](../../packages/dfos-protocol/schemas/index.v1.json).

## Projection Rules

Resolved index = **canonical fold** over the operations:

1. **Linearize** all operations (every branch) into a deterministic total order: `createdAt` ascending, `operationCID` ascending as tiebreak.
2. **Flatten** each `index/v1` document's `deltas` array in order.
3. **Fold** the delta stream as an LWW-Map: `set` writes, `remove` deletes, the last delta touching a key wins.

The fold is **branch-inclusive** — it folds every operation in the log, not just the selected-head branch, so concurrent forks converge instead of dropping a branch.

## Example Chain

`chain.json` contains 5 operations across **two concurrent branches** forking from sequence 1. Operations are referred to by their 0-based `sequence` field:

- **sequence 0** — `set aaa` — "First Release" (genesis)
- **sequence 1** — `set bbb` — "Second Release"
- **sequence 2 (branch A)** — `set ccc {}` (membership-only) + `remove aaa`
- **sequence 3 (branch B)** — `set aaa` — "First Release (remastered)"
- **sequence 4 (branch B)** — `set ddd` — "Fourth Release" + an unknown `reorder` delta (skipped)

## Projected State

Canonical order is sequence 0 → 1 → 2(A) → 3(B) → 4(B), by `createdAt`. Folding:

- **aaa** — set, then removed on branch A, then re-set on branch B later in canonical order → **"First Release (remastered)" wins** (last-applied wins)
- **bbb** — "Second Release"
- **ccc** — `{}` (degenerate set-membership)
- **ddd** — "Fourth Release"; the `reorder` delta is an unknown shape and is skipped

See `projected-state.json` for the expected map.

## Fork Convergence

Because linearization is a strict total order over operation `(createdAt, operationCID)` pairs — independent of the order operations were ingested — **any ingest order of the same operation set folds to the same map**. Two relays (or a relay and a client) that have seen the same operations compute an identical index, and the two concurrent branches here converge rather than one being dropped.

The **head** (sequence 4, the highest-`createdAt` tip) is a `set`, so the chain is live. Had the selected head branch been a `delete`, the chain would be deleted and the fold moot.

## Purpose

This example is a development/illustration aid. Use it for building and testing index projection logic against DFOS content chains.
