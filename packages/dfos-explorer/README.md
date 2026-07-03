# @metalabel/dfos-explorer

A **client-side-only chain explorer** for the DFOS proof plane. Paste a `did:dfos`, a
contentId, or an operation CID; the explorer fetches signed bytes from one or more
_untrusted, swappable_ relays and **re-verifies everything in the tab**. No backend, ever.

This is not an etherscan. Etherscan is a trusted window onto one canonical state — DFOS has
no canonical state, so the explorer inverts the trust direction: you trust _your own
verification_, never the relay. Every view renders in two beats: the relay's claim
(instant, marked relay-asserted), then the local re-verification (async, flips to
verified — or MISMATCH, loudly).

## What it does

- **Verify-in-tab** — signatures, CIDs, chain linkage, and head selection are recomputed
  locally via [`@metalabel/dfos-client`](../dfos-client). The explorer is the client's
  first full consumer.
- **Local index** — the full relay operation log syncs into a normalized IndexedDB store
  (`ops` / `chains` / `sync`); chains fold offline and the index persists across visits.
  The op pool is a union across relays (CIDs are content-addressed).
- **Untrusted relay set** — relays are parameters, like RPC endpoints. Reads fan out
  across the set; provenance (who answered, whether the set agreed) is part of the UI.

## Development

```sh
pnpm --filter @metalabel/dfos-explorer dev        # vite dev server
pnpm --filter @metalabel/dfos-explorer test       # vitest (logic: db, sync, dispatch)
pnpm --filter @metalabel/dfos-explorer typecheck
pnpm --filter @metalabel/dfos-explorer build      # static bundle → dist/
```

The package is `private: true` and does not publish or deploy anywhere (yet); it builds a
static bundle that can be served from any static host.
