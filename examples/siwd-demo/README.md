# Sign In With DFOS — demo relying party

## What this is

The smallest possible Sign In With DFOS relying party: one static page, no
server, no secrets, no session backend, and no SDK beyond
[`@metalabel/dfos-client`](https://www.npmjs.com/package/@metalabel/dfos-client)
installed from npm like any third party would. Deployed at
<https://dfos-siwd-demo.vercel.app>.

## How it works

Three functions from `@metalabel/dfos-client/siwd` carry the whole flow —
`createSiwdLoginRequest` mints and builds the redirect, `readSiwdCallback` reads
the return, `verifySiwd` decides whether to believe it. Everything else in
`src/main.ts` is DOM.

1. **Mint and redirect.** The sign-in click calls `createSiwdLoginRequest`, which
   returns the `/authorize` URL to navigate to — carrying `challenge`,
   `redirect_uri`, `scope=identity`, and `client_did` — plus an `expect` object.
   It omits `client_did` by itself for a loopback redirect, because a local port
   cannot prove one.
2. **Persist `expect`.** `request.expect` is `{ domain, nonce }` (plus `did` when
   the challenge is bound to one): exactly what `verifySiwd` takes back, in one
   JSON-serializable value. The demo stores it in `sessionStorage` and rehydrates
   it on the way back, so nothing has to be threaded to both ends of the redirect
   by hand — a `domain` that drifts between mint and verify is a check that
   silently stops checking.
3. **Come back signed.** The platform authenticates the user, shows consent,
   signs the canonical challenge bytes with a key from the user's identity
   chain, and redirects back with `?jws=<signed challenge>&did=<did>`.
   `readSiwdCallback(location.search)` sorts the return into success, denied, or
   "not a callback at all".
4. **Verify, then read.** `verifySiwd(client, jws, expect)` resolves the signer's
   identity chain from a public relay, replays it to current state, and checks
   the signing key is a **current** `authKeys` entry of a non-deleted identity —
   plus the nonce, the domain, and the timestamp window. Only then does the page
   fetch that DID's public profile and render it.

No DFOS platform server is contacted during verification: the only network hop
is to a relay, and the relay is untrusted — the crypto is what convinces us.

Sign in and open **"Show the receipts"** to see the decoded artifact, the list of
checks that ran, and links to look the same chain up yourself.

Spec: [`specs/SIWD.md`](../../specs/SIWD.md) · <https://protocol.dfos.com/siwd>

## Registration = a JSON file

`public/.well-known/dfos-app.json`:

```json
{
  "name": "SIWD Demo",
  "client_did": "did:dfos:8zk83zez862n6ahnvt3h3e4kc4n2dke",
  "redirect_uris": ["https://dfos-siwd-demo.vercel.app/"]
}
```

There is no developer portal and no client secret. Serving that file over https
from the domain you control **is** the registration — domain control is the
credential. The platform fetches it live at authorize time (the JIT tier), and
`redirect_uris` is an **exact-match** allowlist, trailing slash included.

## Run it locally

```sh
npm install
npm run dev
```

Sign-in works unchanged in dev without any well-known file: `http://localhost:5173/`
is accepted as a redirect target for `scope=identity` under the loopback tier
(the RFC 8252 posture — a loopback address cannot be hijacked by a remote
attacker the way a registered https redirect can). One asymmetry: a local port
cannot prove a client identity either, so the demo omits `client_did` on
loopback hosts — the platform rejects one there by design.

## Verification trust ladder

**Tier 1 — this demo.** Verification runs in the browser and the session is held
in the tab. This is sound exactly when your backend grants **nothing** on the
strength of the DID: a public client with no privileged API behind it, the same
trust shape OAuth blesses for SPAs with PKCE.

**Tier 2 — the moment a backend grants anything.** Verification moves server-side.
The backend mints the nonce and sets it in an HttpOnly cookie; the callback POSTs
the JWS to the backend; the **same** `verifySiwd` runs in Node against the
cookie's nonce; the backend mints its own session from the result. The rule that
makes this necessary: **a bare DID is an address, not a proof.** An endpoint that
accepts `{ did }` from a client and believes it has authenticated nobody — anyone
can type any DID.

A runnable backend example is coming. Nothing in the kit has to change for it:
`createSiwdLoginRequest`, `readSiwdCallback`, and `verifySiwd` are pure and
already run unchanged in Node.

## Security notes

- The `expect` object is **single-use** — read from `sessionStorage` and removed
  before verification runs, so its nonce is consumed pass or fail.
- The `?did=` callback param is **never trusted**. The DID rendered and looked
  up is the one inside the verified JWS.
- Every string that reaches the DOM from the URL, the API, or the JWS is
  untrusted text: it is set with `textContent`, never `innerHTML`.
- A signed challenge is a **one-shot authentication proof, not a bearer token**.
  A real app establishes its own session after verification and discards the
  JWS; this demo has no session at all, which is why a refresh signs you out.

## Coordinates

All of them live at the top of `src/main.ts`:

| Constant         | Value                                      |
| ---------------- | ------------------------------------------ |
| `AUTHORIZE_URL`  | `https://app.dfos.com/authorize`           |
| `RELAY_URL`      | `https://relay.dfos.com`                   |
| `PUBLIC_API_URL` | `https://api.dfos.com/v1`                  |
| `EXPLORER_URL`   | `https://explore.dfos.com`                 |
| `CLIENT_DID`     | `did:dfos:8zk83zez862n6ahnvt3h3e4kc4n2dke` |

(`EXPLORER_URL` is only used by the receipts panel, to hand you a second,
independent verifier for the same chain.)

SIWD is on its own `0.x` clock, independent of the frozen protocol surface, so
the hosted consent page URL may move before 1.0. When it does, it is one
constant in `src/main.ts` — the challenge bytes and the verification rules do
not change.
