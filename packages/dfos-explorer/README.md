# @metalabel/dfos-explorer

A **client-side-only chain explorer** for the DFOS proof plane. Paste a `did:dfos`, a
contentId, an operation CID, or a domain; the explorer fetches signed bytes from one or more
_untrusted, swappable_ relays and **re-verifies everything in the tab**.

There is no backend for protocol data, and there never will be: everything the explorer
renders comes from a relay you chose and is verified locally. The explorer has exactly two
serverless routes, both stateless lookup proxies onto a domain's public surface: one fetches
`/.well-known/dfos-app.json`, the other runs the two origin-binding attest-back methods
(`/.well-known/dfos-did` and the `_dfos` TXT record). They exist solely because a browser
cannot do either honestly — third-party origins don't reliably send CORS headers on their
well-knowns, and a tab cannot query DNS at all. Neither route stores data, keeps state
between requests, or calls a platform API: they forward what they observed and get out of
the way. Every verdict — schema validity, chain verification, the comparison against what
the relays hold, the bound/stale/broken binding verdict — is still computed in the tab. For
all protocol data the explorer remains relay-only.

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
  The op pool is a union across relays (CIDs are content-addressed). Sync runs in two
  phases — log paging, then public-projection resolution (separately abortable) that
  materializes the metadata the browse index renders.
- **Operation browser** — a paged view over the relay's global log. The log route is
  forward-only, so this walks from the first operation the relay holds and says so;
  once you deep-sync, the same panel pages your own store newest-first.
- **Browse** — public identities and documents, 25 rows a page off the relay index's
  keyset cursor, with the page position in the URL so a view can be linked. The browse
  surface mirrors the relay's index capability surface 1:1: what the index projects you
  can browse, what it doesn't you can't (there is no artifacts browse, because no relay
  materializes one). Public-only by default; creator attribution is labeled _attributed_,
  not verified (the detail pages carry the rigorous proof).
- **Names, not hashes** — every DID in a row resolves to its identity's **public** profile
  name: the identity chain folds in the tab, its controller-signed anchor is followed, and
  the bytes must re-hash to the CID the chain commits to. A gated or absent profile stays
  a bare DID, always.
- **Domain lookup** — paste a domain and the explorer reads its app description document
  (`/.well-known/dfos-app.json`), the one place where a domain vouches for a DFOS identity.
  The document's carried identity chain is verified in the tab, its `client_did` must equal
  the DID that chain's genesis operation derives (a mismatch rejects the whole document),
  and the result is compared against the log the relays serve for that DID — agreeing,
  ahead, rolled back, or contradicting. A valid document that carries no chain says so
  plainly and stays amber; nothing goes green without a verified chain.
- **Untrusted relay set** — relays are parameters, like RPC endpoints. Reads fan out
  across the set; provenance (who answered, whether the set agreed) is part of the UI.

## Development

```sh
pnpm --filter @metalabel/dfos-explorer dev        # vite dev server
pnpm --filter @metalabel/dfos-explorer test       # vitest (logic: db, sync, dispatch)
pnpm --filter @metalabel/dfos-explorer typecheck
pnpm --filter @metalabel/dfos-explorer build      # static bundle → dist/
```

## Deploy

Deployed at **https://explore.dfos.com** via Vercel, which builds this package on every
push to `main` (`vercel.json` pins the build command and `dist/` output).

The bundle is fully static and carries no configuration: relays are chosen in the app and
stored in the browser, so the same artifact serves any relay set and can be hosted from
any static host — or opened from a local `file://` build.
