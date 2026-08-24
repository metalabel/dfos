# Sign In With DFOS — demo relying party

## What this is

A complete Sign In With DFOS login: challenge minted server-side, JWS verified
server-side, session cookie granted server-side. One static page, four serverless
functions, no database, and no SDK beyond
[`@metalabel/dfos-client`](https://www.npmjs.com/package/@metalabel/dfos-client)
from npm, like any third party would. Deployed at
<https://dfos-siwd-demo.vercel.app>.

Verification happens in `api/verify.ts`, because that is where the session is
granted.
[SIWD.md §Security Considerations](../../specs/SIWD.md#a-did-is-an-address-not-a-proof)
gives the rule: a bare DID is an address, not a proof, and the JWS MUST be
verified wherever a session is granted.

Verification contacts **no DFOS platform server**. The one network hop is to a
public relay, to resolve the signer's identity chain to current state — and the
relay is untrusted; the crypto is what convinces us.

**The authorize request carries three params:** `challenge`, `redirect_uri`, and
`scope=identity`. Not `client_did`: the platform learns who this app is by
fetching `/.well-known/dfos-app.json` from the redirect's own origin, so that
file _is_ the app identity and the param is only an optional assertion that has
to agree with it. `client_did` determines the `aud` of a returned credential
([SIWD.md §Client identity](../../specs/SIWD.md#client-identity-client_did)), and
an identity-scope sign-in returns none — so sending one buys an RP nothing but
another thing to keep in sync.

## How it works

| Endpoint       | What it does                                                                                                |
| -------------- | ----------------------------------------------------------------------------------------------------------- |
| `POST /login`  | Mints the challenge, seals the nonce into an `httpOnly` cookie, returns the `/authorize` URL to navigate to |
| `POST /verify` | Unseals that nonce, runs `verifySiwd` against a relay, grants the session cookie                            |
| `GET /me`      | Reads the session cookie back — the one source the signed-in view renders from                              |
| `POST /logout` | Expires it                                                                                                  |

1. **Mint and redirect.** The sign-in click posts to `/api/login`.
   `createSiwdLoginRequest` returns the `/authorize` URL — `challenge`,
   `redirect_uri`, `scope=identity` — plus the nonce it minted. The server seals
   that nonce under its own key as `siwd_flight`, `httpOnly`, `Max-Age=300`.
   Minting here also puts the timestamp on the server's clock, retiring a failure
   mode: a browser running minutes off produced challenges born stale and
   correctly refused on the way back.
2. **Come back signed.** The platform authenticates the user, shows consent,
   signs the canonical challenge bytes with a key from the user's identity chain,
   and redirects back with `?jws=<signed challenge>&did=<did>`.
   `readSiwdCallback(location.search)` sorts that into success, denied, or "not a
   callback at all", and the page scrubs the JWS out of the address bar.
3. **Verify where the grant happens.** The page posts `{ jws }` and nothing else
   — no nonce, no DID. The server unseals `siwd_flight` back to the nonce it
   minted, then `verifySiwd(client, jws, { domain, nonce })` resolves the
   signer's identity chain from a public relay, replays it to current state, and
   checks that the signing key is a **current** `authKeys` entry of a non-deleted
   identity — plus the domain, the timestamp window, and the nonce last.
4. **Grant.** The flight cookie is cleared in the same response that sets
   `siwd_session` — the DID, the `kid`, and an expiry, sealed under the same key.
   The JWS is discarded: a signed challenge is a one-shot authentication proof,
   not a bearer token.

The browser also decodes the returned JWS for display, in a panel labelled for
what it is: `decodeJwsUnsafe` does no verification and says so in its name. Sign
in and open **"Show the receipts"** for the decoded artifact, the checks the
server ran, and links to look the same chain up yourself.

Spec: [`specs/SIWD.md`](../../specs/SIWD.md) · <https://protocol.dfos.com/siwd>

## The two replay disciplines

SIWD admits two, and
[which one you owe is decided by what success grants](../../specs/SIWD.md#replay-prevention).
This demo grants one thing — a session with the browser in front of it — so it
runs the **flow-bound** discipline.

**The sealed cookie.** At mint time the server binds the nonce to the agent that
started the flow, statelessly:
`nonce.exp.base64url(HMAC-SHA256(SESSION_SECRET, "flight:" + nonce + "." + exp))`.
The expiry is inside the sealed bytes, so the server's own clock enforces it
(`Max-Age` is only the honest browser's copy), and the tag is domain-separated by
purpose, so a seal of one class cannot be replayed as another. It rides in an
`httpOnly` cookie scoped to `/api` that expires with the acceptance window. At
verification the expectation comes from that seal and nowhere else.

**Why sealed, not just a cookie.** A bare cookie value is no defense: cookies are
presenter-supplied on every request, so an attacker reads the nonce out of a
captured JWS and sends it back as the cookie — `HttpOnly` constrains a browser's
scripts, not `curl`. The tag binds because only this server's key can produce it.

**The guarantee, exactly.** _The artifact redeems only through the channel that
initiated the flow, inside the timestamp window._ It is **not** global
single-use: a party holding both the artifact and the cookie jar can redeem again
within the window. That is the accepted trade for a session-only grant, since
they already hold the session they would gain. It is the discipline the
surrounding ecosystem applies to browser login: OpenID Connect's `state` and
`nonce` checked against browser-carried session state, Sign in with Ethereum's
session-bound nonce.

**When you must switch.** The moment success yields anything beyond a session
with the presenting browser — a credential-returning scope, a token or grant
redeemable outside the originating channel, any of profile B (a mailbox flow has
no presenting channel to bind) — flow-binding is no longer admissible and
**consumed verification is REQUIRED**. Store each minted nonce server-side and
consume it atomically:

```js
const result = await verifySiwd(client, jws, {
  domain,
  // Redis GETDEL, KV, a DELETE … RETURNING row — but atomic, and answering as a boolean
  consumeNonce: async (nonce) => (await store.getdel(nonce)) !== null,
});
```

That is a one-field change to this demo's `api/verify.ts` plus a store, because
the kit runs the nonce check last under both disciplines — after signature, key
currency, domain, and timestamp — so an invalid presentation never spends a nonce
its legitimate holder is still carrying. A non-atomic read-then-delete is not a
substitute: it is a race with a login in it. `consumeNonce` ships in
`@metalabel/dfos-client` ≥ 0.31.

**Either way, the expectation must be something only the verifier could have
produced.** A nonce handed to the verifier by the presenting party — in a
callback parameter, a request body, or an unsealed cookie — is not a replay
defense at all.

## `SESSION_SECRET`

One environment variable, and it is the key both seals use. Any long random
string, 32+ characters (the deploy button prompts you for it):

```sh
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

**Deployed without it, sign-in refuses by name:** the click answers
`SESSION_SECRET is not set — add it in your Vercel project settings` instead of
failing three redirects later as a mystery. It has to. On Vercel every file in
`api/` is its own function with its own module instance, so a per-instance random
key would have `/api/login` sealing with one key and `/api/verify` unsealing with
another, and every deployed sign-in would die as "no sign-in in flight" — while
local dev, one process, concealed it.

**Locally the dev server does fall back.** One process is guaranteed there, so it
mints a random key at startup and keeps running. Sessions then die with the
process: the page renders a notice saying so, and every response carries
`ephemeral: true` while it holds. A secret shorter than 32 characters is refused
outright, in dev too — a guessable key makes every cookie forgeable offline.

## Registration = a JSON file

`public/.well-known/dfos-app.json`:

```json
{
  "name": "SIWD Demo",
  "client_did": "did:dfos:8zk83zez862n6ahnvt3h3e4kc4n2dke",
  "redirect_uris": ["https://dfos-siwd-demo.vercel.app/"]
}
```

No developer portal, no client secret. Serving that file over https from the
domain you control **is** the registration: domain control is the credential. The
platform fetches it live at authorize time (the JIT tier of
[SIWD.md §Redirect URI validation](../../specs/SIWD.md#redirect-uri-validation-profile-a)),
and `redirect_uris` is an **exact-match** allowlist, trailing slash included.
`name` is rendered at consent as the app's own claim about itself, and labelled
there as self-asserted; nothing in the protocol vouches for it, and the domain is
what the user is asked to trust.

`client_did` is optional at identity scope. Add one to name your app's own
identity (`dfos identity create`); it becomes required only when
credential-returning scopes arrive, because a credential has to be issued _to_
someone.

**The page checks its own registration at boot**, fetching
`/.well-known/dfos-app.json` and looking for its exact redirect target in
`redirect_uris`. If the file is missing, or the string is not in it, the page says
so — naming both — before you click anything. The button stays live either way,
so you can watch the host refuse.

The server derives that same string from the request's own origin rather than
hardcoding it, so the target the page checks and the target the server sends
cannot drift apart.

## Fork it

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fmetalabel%2Fdfos%2Ftree%2Fmain%2Fexamples%2Fsiwd-demo&project-name=dfos-siwd-demo&repository-name=dfos-siwd-demo&env=SESSION_SECRET&envDescription=Signs%20login%20sessions%20-%20set%20to%20any%20long%20random%20string)

That clones this directory alone into your own repo, prompts you for
`SESSION_SECRET`, and deploys it. Then make **one edit** — your deployment's
origin in `redirect_uris`, exactly, with the trailing slash:

```json
{ "redirect_uris": ["https://your-app.example.com/"] }
```

Commit, redeploy, done. Forget it and the boot self-check prints the exact string
it needs to see. Update `name` while you are there — it is what your users read
at consent.

Preview-deploy URLs are **not** in the allowlist, by design: each preview gets a
fresh hostname, and an allowlist admitting arbitrary subdomains would be an open
redirector. Sign-in works on the origins you listed; everywhere else the page
says which string is missing.

## Run it locally

```sh
npm install
npm run dev
```

The whole flow works locally, backend included and with **no well-known file at
all**: `http://localhost:5173/` is an accepted redirect target for
`scope=identity` under the loopback tier. That is the RFC 8252 posture — an
application on the user's own machine holds no domain, so no host could check the
binding a hosted redirect asserts, and rather than refuse the case the host
consents under its own tier and says so. The boot self-check knows this and skips
itself on a loopback host.

There is no `vercel` CLI in the loop. Vercel's Node runtime adds exactly two
things to Node's own request/response pair — a pre-parsed JSON `body` and
`status()` / `send()` — so `vite.config.ts` carries a ~50-line plugin that shims
those two and mounts the **same handler files** as dev-server middleware. Nothing
is reimplemented, so nothing can drift.

## Security notes

- **The verifier minted the nonce it checks.** It comes out of a cookie sealed
  under this server's key, never out of the callback, the request body, or an
  unsealed cookie.
- **The nonce is checked last** — after signature, key currency, domain, and
  timestamp — which is [SIWD.md's step 6](../../specs/SIWD.md#third-party-verification)
  and what makes the move to `consumeNonce` a one-field change.
- **The `?did=` callback param is never trusted.** The DID in the session is the
  one inside the verified JWS.
- **Every POST is origin-checked.** A present `Origin` header that is not this
  deployment's own gets a 403; an absent one means a non-browser caller, which is
  riding nobody's cookie jar.
- **Cookies are `HttpOnly; Secure; SameSite=Lax; Path=/api`.** `Secure` is set
  even in dev — browsers treat `http://localhost` as a secure context — and
  `Path=/api` keeps them off every static asset request.
- **The JWS is scrubbed** out of the address bar with `history.replaceState` the
  moment it is read, so it does not linger in history or in the referrer of
  anything the page loads next.
- **Everything that reaches the DOM is untrusted text.** Strings from the URL,
  the API, the JWS, and the served well-known file are set with `textContent`,
  never `innerHTML`.
- **A signed challenge is a one-shot authentication proof, not a bearer token.**
  The server establishes its own session after verification and discards the JWS.

## Coordinates

The backend's are at the top of `api/_lib.ts`:

| Constant        | Value                            |
| --------------- | -------------------------------- |
| `AUTHORIZE_URL` | `https://app.dfos.com/authorize` |
| `RELAY_URL`     | `https://relay.dfos.com`         |

`src/main.ts` holds `RELAY_URL` and `EXPLORER_URL` for the receipts panel alone,
to hand you a second, independent verifier for the same chain.

SIWD is on its own `0.x` clock, independent of the frozen protocol surface, so
the hosted consent page URL may move before 1.0. When it does, it is one constant
in `api/_lib.ts` — the challenge bytes and the verification rules do not change.
