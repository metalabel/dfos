# @metalabel/dfos-explorer

A client-side-only chain explorer for the DFOS proof plane, deployed at
<https://explore.dfos.com>. Paste a `did:dfos`, a contentId, an operation CID,
or a domain; the explorer fetches signed bytes from an untrusted, swappable
relay set and re-verifies everything in the tab — signatures, CIDs, chain
folding, head selection — via [`@metalabel/dfos-client`](../dfos-client). You
trust your own verification, never the relay.

It browses via the relay index
([Web Relay § Index](https://protocol.dfos.com/web-relay#index-v0)) and its
domain lookup checks both origin-binding attest-back methods
([Origin Binding](https://protocol.dfos.com/origin-binding)). Two stateless
serverless routes proxy well-known fetches and DNS lookups a browser cannot do
itself; every verdict is still computed in the tab. Building against the
protocol yourself? Start at the
[developers hub](https://docs.dfos.com/docs/developers/).

## Development

```sh
pnpm --filter @metalabel/dfos-explorer dev        # vite dev server
pnpm --filter @metalabel/dfos-explorer test       # vitest (logic: db, sync, dispatch)
pnpm --filter @metalabel/dfos-explorer typecheck
pnpm --filter @metalabel/dfos-explorer build      # static bundle → dist/
```

## Deploy

Deployed via Vercel on every push to `main` (`vercel.json` pins the build
command and `dist/` output). The bundle is fully static and carries no
configuration: relays are chosen in the app and stored in the browser, so the
same artifact serves any relay set from any static host.
