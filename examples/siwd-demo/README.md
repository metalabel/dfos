# Sign In With DFOS — demo relying party

## What this is

The smallest possible Sign In With DFOS relying party: one static page, no
server, no secrets, no session backend, and no SDK beyond
[`@metalabel/dfos-client`](https://www.npmjs.com/package/@metalabel/dfos-client)
installed from npm like any third party would. Deployed at
<https://dfos-siwd-demo.vercel.app>.

## How it works

1. **Mint a challenge.** The sign-in click calls `createSiwdChallenge({ domain, statement })`
   and stashes the returned nonce in `sessionStorage`.
2. **Redirect.** The browser goes to the platform's hosted `/authorize` with
   `challenge`, `redirect_uri`, `scope=identity`, and `client_did`.
3. **Come back signed.** The platform authenticates the user, shows consent,
   signs the canonical challenge bytes with a key from the user's identity
   chain, and redirects back with `?jws=<signed challenge>&did=<did>`.
4. **Verify, then read.** `verifySiwd(client, jws, { domain, nonce })` resolves
   the signer's identity chain from a public relay, replays it to current state,
   and checks the signing key is a **current** `authKeys` entry of a non-deleted
   identity — plus the nonce, the domain, and the timestamp window. Only then
   does the page fetch that DID's public profile and render it.

No DFOS platform server is contacted during verification: the only network hop
is to a relay, and the relay is untrusted — the crypto is what convinces us.

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

## Security notes

- The nonce is **single-use** — read from `sessionStorage` and removed before
  verification runs, so it is consumed pass or fail.
- The `?did=` callback param is **never trusted**. The DID rendered and looked
  up is the one inside the verified JWS.
- Every string that reaches the DOM from the URL, the API, or the JWS is
  untrusted text: it is set with `textContent`, never `innerHTML`.
- A signed challenge is a **one-shot authentication proof, not a bearer token**.
  A real app establishes its own session after verification and discards the
  JWS; this demo has no session at all, which is why a refresh signs you out.

## Coordinates

All four live at the top of `src/main.ts`:

| Constant          | Value                                       |
| ----------------- | ------------------------------------------- |
| `AUTHORIZE_URL`   | `https://app.dfos.com/authorize`            |
| `RELAY_URL`       | `https://relay.dfos.com`                    |
| `PUBLIC_API_URL`  | `https://api.dfos.com/v1`                   |
| `CLIENT_DID`      | `did:dfos:8zk83zez862n6ahnvt3h3e4kc4n2dke`  |

SIWD is on its own `0.x` clock, independent of the frozen protocol surface, so
the hosted consent page URL may move before 1.0. When it does, it is one
constant in `src/main.ts` — the challenge bytes and the verification rules do
not change.
