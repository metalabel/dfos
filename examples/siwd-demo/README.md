# Sign In With DFOS — demo relying party

## What this is

The smallest possible Sign In With DFOS relying party: one static page, no
secrets, no session backend, and no SDK beyond
[`@metalabel/dfos-client`](https://www.npmjs.com/package/@metalabel/dfos-client)
installed from npm like any third party would. Deployed at
<https://dfos-siwd-demo.vercel.app>.

It offers two sign-in paths, which are the two tiers of the
[trust ladder](#verification-trust-ladder) below. The default one verifies
entirely in your browser and touches no server at all. The second adds two tiny
serverless functions so verification happens where a real app would grant a
session — still no secrets, and still no server-side state: the only thing the
backend remembers is a nonce, and it remembers it in a cookie.

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

**Tier 2 — the moment a backend grants anything.** Verification moves server-side,
and **this demo runs it**: the second sign-in button takes the tier-2 path through
two serverless functions.

- `GET /api/nonce` mints a nonce, returns it, and sets it in an `HttpOnly`
  cookie — how the backend remembers what it issued across the redirect.
- The page puts that nonce in the challenge (`createSiwdLoginRequest({ …, nonce })`)
  and redirects as usual.
- On return the page POSTs `{ jws }` to `POST /api/verify`. The body carries the
  JWS and nothing else; the cookie rides along on its own.
- The function reads the nonce **from the cookie, never from the body**, and runs
  the same `verifySiwd` in Node.

Two rules make this shape non-negotiable. **A bare DID is an address, not a
proof**: an endpoint that accepts `{ did }` from a client and believes it has
authenticated nobody, because anyone can type any DID. And **the presenter never
chooses the expectation**: a verifier that reads the expected nonce out of the
request it is verifying is comparing a value against itself.

**What this demo does not do, and your app must.** The cookie is a carrier, not a
replay defense: the nonce travels inside the signed challenge, so anyone holding
a JWS can read it out of the payload and send it back in a `Cookie` header of
their own — `HttpOnly` constrains browser scripts, not `curl`. Making a nonce
single-use requires server-side consumption, which requires a store, which a
zero-infrastructure demo does not have. The missing line is one atomic read:

```js
const fresh = await store.getdel(nonce); // Redis GETDEL, KV, a row — but atomic
if (!fresh) return unauthorized('nonce already used');
```

[`specs/SIWD.md`](../../specs/SIWD.md) §Security Considerations makes that a
**MUST** for third parties. Without it this demo accepts replay bounded only by
the acceptance window, and says so at the call site rather than implying the
cookie covers it. Production adds that store — and the session mint, which needs
a signing secret this repo deliberately does not carry.

Run the functions locally with `vercel dev`; the plain `npm run dev` static
server exercises tier 1 only.

## Security notes

- The `expect` object is removed from `sessionStorage` before verification runs,
  so this tab cannot reuse it pass or fail. That is tab hygiene, not a replay
  defense — see the tier-2 note above for what a real one costs.
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
