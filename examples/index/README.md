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

The resolved index is the [canonical fold](https://protocol.dfos.com/content-model#canonical-fold) — the spec defines the linearization and its branch-inclusive convergence. What is `index/v1`-specific is the reduction: each document's `deltas` array is flattened in canonical order and folded as an LWW-Map — `set` writes, `remove` deletes, the last delta touching a key wins.

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

This chain is the convergence property made concrete: fold `chain.json` in any ingest order and the two concurrent branches produce the same `projected-state.json` — branch A's `remove aaa` loses to branch B's later re-set rather than a branch being dropped.

The **head** (sequence 4, the highest-`createdAt` tip) is a `set`, so the chain is live. Had the selected head branch been a `delete`, the chain would be deleted and the fold moot.

## Purpose

This example is a development/illustration aid. Use it for building and testing index projection logic against DFOS content chains.
