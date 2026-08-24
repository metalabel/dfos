# Sign In With DFOS — demo relying party

## What this is

The smallest possible Sign In With DFOS relying party: one static page, no
secrets, no backend, no session store, and no SDK beyond
[`@metalabel/dfos-client`](https://www.npmjs.com/package/@metalabel/dfos-client)
installed from npm like any third party would. Deployed at
<https://dfos-siwd-demo.vercel.app>.

Verification runs **in your browser, against a public relay**. No DFOS platform
server is contacted to check the signature: the only network hop is to a relay,
and the relay is untrusted — the crypto is what convinces us. Three functions
from `@metalabel/dfos-client/siwd` carry the whole flow, and everything else in
`src/main.ts` is DOM.

**The authorize request carries three params:** `challenge`, `redirect_uri`, and
`scope=identity`. It does **not** send `client_did`, and that is deliberate. The
platform learns who this app is by fetching `/.well-known/dfos-app.json` from the
redirect's own origin — the served file _is_ the app identity, and the request
param is only an optional assertion that has to agree with it. What `client_did`
actually determines is the `aud` of a returned credential
([SIWD.md §Client identity](../../specs/SIWD.md#client-identity-client_did)), and
an identity-scope sign-in returns none. So an RP that only wants to know who you
are gains nothing by sending one, and gains one more thing to keep in sync.

## How it works

1. **Mint and redirect.** The sign-in click calls `createSiwdLoginRequest`, which
   returns the `/authorize` URL to navigate to — carrying `challenge`,
   `redirect_uri`, and `scope=identity` — plus an `expect` object.
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
credential. The platform fetches it live at authorize time (the JIT tier of
[SIWD.md §Redirect URI validation](../../specs/SIWD.md#redirect-uri-validation-profile-a)),
and `redirect_uris` is an **exact-match** allowlist, trailing slash included.
`name` is rendered on the consent screen as the app's own claim about itself, and
the consent screen says so — nothing in the protocol vouches for it; the domain
is what the user is being asked to trust.

`client_did` is optional at identity scope. Add one to name your app's own
identity (mint it with `dfos identity create`); it becomes required only when
credential-returning scopes arrive, because a credential has to be issued _to_
someone.

**The page checks its own registration at boot.** It fetches its
`/.well-known/dfos-app.json` and looks for its exact redirect target in
`redirect_uris`. If the file is missing, or the string is not in it, the page
says so — naming the exact string and the exact file — before you click
anything. The sign-in button stays live either way: the host's refusal is part of
the lesson, and the notice just tells you why it is about to happen.

## Fork it

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fmetalabel%2Fdfos%2Ftree%2Fmain%2Fexamples%2Fsiwd-demo&project-name=dfos-siwd-demo&repository-name=dfos-siwd-demo)

That clones this directory alone into your own repo and deploys it. Then make
**one edit** — put your deployment's origin in `redirect_uris`, exactly, with the
trailing slash:

```json
{ "redirect_uris": ["https://your-app.example.com/"] }
```

Commit, redeploy, done. If you forget, the page tells you: the boot self-check
renders the exact string it needs to see. Update `name` too while you are there —
it is what your users read at consent.

Preview-deploy URLs are **not** in the allowlist, by design. Each preview gets a
fresh hostname, and an allowlist that admitted arbitrary subdomains would be an
open redirector wearing a JSON file. Sign-in works on the origins you listed;
everywhere else the page says which string is missing.

## Run it locally

```sh
npm install
npm run dev
```

Sign-in works unchanged in dev with **no well-known file at all**:
`http://localhost:5173/` is accepted as a redirect target for `scope=identity`
under the loopback tier (the RFC 8252 posture — an application on the user's own
machine holds no domain, so the binding a hosted redirect asserts is one no host
could ever check; rather than refuse the case, the host consents to it under its
own tier and says plainly what it is). The boot self-check knows this and skips
itself on a loopback host.

## When your backend grants anything

This demo verifies in the browser, which is sound for exactly one reason:
**nothing is granted here.** There is no API behind it and no session to mint —
the same trust shape OAuth blesses for SPAs with PKCE. The moment a backend
grants something, verification has to move to where the granting happens.

Two rules make that non-negotiable, both from
[SIWD.md §Security Considerations](../../specs/SIWD.md#security-considerations):

- **A bare DID is an address, not a proof.** An endpoint that accepts `{ did }`
  from a client and believes it has authenticated nobody — anyone can type any
  DID. Verification of the JWS MUST happen wherever the session is granted; if
  the two are split across a trust boundary, carry the verdict across it, not the
  identifier.
- **The verifier MUST have minted the nonce it checks.** A verifier that reads
  the expected nonce out of the request it is verifying is comparing a value
  against itself. An attacker replaying a captured JWS supplies the nonce that
  JWS already contains, and the comparison passes trivially.

And a nonce is only a replay defense once it is **consumed atomically** — read
and deleted in one operation, so two concurrent replays cannot both win. The kit
takes that as a callback:

```js
const result = await verifySiwd(client, jws, {
  domain,
  consumeNonce: (nonce) => store.getdel(nonce), // Redis GETDEL, KV, a deleted row — but atomic
});
```

`consumeNonce` ships in `@metalabel/dfos-client` ≥ 0.31. A non-atomic
read-then-delete is not a substitute: it is a race with a login in it. Verify,
consume, then mint **your own** session and discard the JWS — a signed challenge
is a one-shot authentication proof, not a bearer token.

## Security notes

- The `expect` object is removed from `sessionStorage` before verification runs,
  so this tab cannot reuse it pass or fail. That is tab hygiene, not a replay
  defense — a real one is server-side consumption, above.
- The `?did=` callback param is **never trusted**. The DID rendered and looked
  up is the one inside the verified JWS.
- The JWS is scrubbed out of the address bar with `history.replaceState` the
  moment it is read, so it does not linger in history or in the referrer of
  anything the page loads next.
- Every string that reaches the DOM from the URL, the API, the JWS, or the
  served well-known file is untrusted text: it is set with `textContent`, never
  `innerHTML`.
- A signed challenge is a **one-shot authentication proof, not a bearer token**.
  A real app establishes its own session after verification and discards the
  JWS; this demo has no session at all, which is why a refresh signs you out.

## Coordinates

All of them live at the top of `src/main.ts`:

| Constant         | Value                            |
| ---------------- | -------------------------------- |
| `AUTHORIZE_URL`  | `https://app.dfos.com/authorize` |
| `RELAY_URL`      | `https://relay.dfos.com`         |
| `PUBLIC_API_URL` | `https://api.dfos.com/v1`        |
| `EXPLORER_URL`   | `https://explore.dfos.com`       |

(`EXPLORER_URL` is only used by the receipts panel, to hand you a second,
independent verifier for the same chain.)

SIWD is on its own `0.x` clock, independent of the frozen protocol surface, so
the hosted consent page URL may move before 1.0. When it does, it is one
constant in `src/main.ts` — the challenge bytes and the verification rules do
not change.
